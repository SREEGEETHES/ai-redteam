"""Regression Engine - Sprint 8 Real Implementation.

Implements FAIL -> remediation -> PASS verification with before/after comparison,
finding lifecycle, fix verification, and regression history.
Not a mockup: actually re-executes the attack against the (now fixed) target.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.attacks.registry import registry
from app.core.logging import get_logger
from app.database.models import (
    Evidence,
    Finding,
    RegressionStatus,
    Retest,
    Scan,
    ScanStatus,
    Test,
    TestResult,
)

logger = get_logger(__name__)


def _resolve_attack(finding: Finding):
    attack = registry.get(finding.attack_id)
    if not attack:
        raise ValueError(f"Attack {finding.attack_id} not in registry")
    return attack


def retest_finding(
    finding_id: int,
    db: Session,
    notes: str | None = None,
) -> tuple[Retest, Finding, Scan]:
    """
    Real retest: creates a new scan for the single attack, runs it against the current target,
    compares before/after, updates finding.regression_status, stores Retest history.

    Returns (retest, updated_finding, retest_scan).
    """
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise ValueError(f"Finding {finding_id} not found")
    if finding.regression_status == RegressionStatus.VERIFIED:
        logger.warning("retest_already_verified", finding_id=finding_id)

    original_test = db.query(Test).filter(Test.id == finding.test_id).first()
    original_scan = db.query(Scan).filter(Scan.id == finding.scan_id).first()
    if not original_test or not original_scan:
        raise ValueError("Original test/scan not found for finding")

    attack = _resolve_attack(finding)

    # Load target (same as original scan's target, but current URL may have changed if lab was fixed in place)
    from app.database.models import Target

    target = db.query(Target).filter(Target.id == original_scan.target_id).first()
    if not target:
        raise ValueError(f"Target {original_scan.target_id} not found")

    # Create retest scan - single attack, same taxonomy, same target
    retest_scan = Scan(
        target_id=target.id,
        taxonomy_version=original_scan.taxonomy_version,
        configuration={
            "attack_ids": [attack.id],
            "is_retest": True,
            "original_finding_id": finding.id,
        },
        status=ScanStatus.PENDING,
    )
    db.add(retest_scan)
    db.commit()
    db.refresh(retest_scan)

    # Run the single attack via orchestrator (real execution)
    from app.core.orchestrator import run_scan

    # run_scan will create Test/Evidence/Finding for the retest scan, but we need to capture the result
    # for this specific attack to compare.
    try:
        run_scan(retest_scan.id, db)
    except Exception as e:
        logger.exception("retest_scan_failed", finding_id=finding_id, error=str(e))
        retest_scan.status = ScanStatus.FAILED
        db.commit()
        raise

    # Find the retest test for this attack
    retest_test = (
        db.query(Test).filter(Test.scan_id == retest_scan.id, Test.attack_id == attack.id).first()
    )
    if not retest_test:
        raise ValueError("Retest test not created")

    # Compare before/after
    before_result = original_test.result
    after_result = retest_test.result

    # Determine regression status per spec 28
    if before_result == TestResult.FAIL and after_result == TestResult.PASS:
        new_status = RegressionStatus.VERIFIED
        notes_final = notes or f"Fix verified: {before_result.value} -> {after_result.value}"
    elif before_result == TestResult.FAIL and after_result == TestResult.FAIL:
        new_status = RegressionStatus.REGRESSION_FAILED
        notes_final = notes or f"Regression failed: still {after_result.value} after fix"
    elif before_result == TestResult.FAIL and after_result in (
        TestResult.INCONCLUSIVE,
        TestResult.ERROR,
        TestResult.NOT_APPLICABLE,
    ):
        new_status = RegressionStatus.FIX_PENDING
        notes_final = (
            notes or f"Fix pending: retest returned {after_result.value} (inconclusive/error)"
        )
    # For other before states (e.g., PASS -> PASS), keep VERIFIED if still PASS
    elif after_result == TestResult.PASS:
        new_status = RegressionStatus.VERIFIED
        notes_final = notes or f"Retest {after_result.value}"
    else:
        new_status = RegressionStatus.FIX_PENDING
        notes_final = notes or f"Retest {after_result.value}"

    # Collect evidence for retest record
    retest_evidence = db.query(Evidence).filter(Evidence.test_id == retest_test.id).first()
    evidence_blob: dict[str, Any] = {}
    if retest_evidence:
        evidence_blob = {
            "request": retest_evidence.request,
            "response": retest_evidence.response,
            "http_status": retest_evidence.http_status,
            "detectors_triggered": retest_evidence.detectors_triggered,
            "observed_behavior": retest_evidence.observed_behavior,
            "evidence_metadata": retest_evidence.evidence_metadata,
        }

    # Update finding lifecycle
    finding.regression_status = new_status
    finding.updated_at = datetime.now(UTC)
    db.add(finding)

    # Create Retest history record
    retest = Retest(
        finding_id=finding.id,
        scan_id=retest_scan.id,
        result=after_result,
        evidence=evidence_blob,
        notes=notes_final,
    )
    db.add(retest)
    db.commit()
    db.refresh(retest)
    db.refresh(finding)

    logger.info(
        "retest_completed",
        finding_id=finding.id,
        before=before_result.value if hasattr(before_result, "value") else str(before_result),
        after=after_result.value if hasattr(after_result, "value") else str(after_result),
        regression_status=new_status.value,
        retest_id=retest.id,
    )

    return retest, finding, retest_scan


def get_regression_history(finding_id: int, db: Session) -> list[Retest]:
    return (
        db.query(Retest)
        .filter(Retest.finding_id == finding_id)
        .order_by(Retest.created_at.desc())
        .all()
    )


def compare_before_after(finding_id: int, db: Session) -> dict[str, Any]:
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise ValueError(f"Finding {finding_id} not found")
    original_test = db.query(Test).filter(Test.id == finding.test_id).first()
    original_evidence = (
        db.query(Evidence).filter(Evidence.test_id == finding.test_id).first()
        if original_test
        else None
    )
    history = get_regression_history(finding_id, db)
    latest_retest = history[0] if history else None
    return {
        "finding_id": finding.id,
        "attack_id": finding.attack_id,
        "original_scan_id": finding.scan_id,
        "original_test_id": finding.test_id,
        "original_result": original_test.result.value if original_test else None,
        "original_evidence": {
            "request": original_evidence.request if original_evidence else None,
            "response": original_evidence.response if original_evidence else None,
            "detectors": original_evidence.detectors_triggered if original_evidence else None,
        }
        if original_evidence
        else None,
        "regression_status": finding.regression_status.value
        if hasattr(finding.regression_status, "value")
        else str(finding.regression_status),
        "retest_history": [
            {
                "retest_id": r.id,
                "scan_id": r.scan_id,
                "result": r.result.value if hasattr(r.result, "value") else str(r.result),
                "evidence": r.evidence,
                "notes": r.notes,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in history
        ],
        "latest_retest": {
            "scan_id": latest_retest.scan_id,
            "result": latest_retest.result.value
            if hasattr(latest_retest.result, "value")
            else str(latest_retest.result),
            "evidence": latest_retest.evidence,
        }
        if latest_retest
        else None,
        "verified": finding.regression_status == RegressionStatus.VERIFIED,
    }


def finding_lifecycle(finding_id: int, db: Session) -> dict[str, Any]:
    """Return lifecycle timeline for a finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise ValueError(f"Finding {finding_id} not found")
    history = get_regression_history(finding_id, db)
    return {
        "finding_id": finding.id,
        "attack_id": finding.attack_id,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
        "updated_at": finding.updated_at.isoformat() if finding.updated_at else None,
        "original_result": db.query(Test).filter(Test.id == finding.test_id).first().result.value
        if db.query(Test).filter(Test.id == finding.test_id).first()
        else None,
        "current_status": finding.regression_status.value
        if hasattr(finding.regression_status, "value")
        else str(finding.regression_status),
        "retest_count": len(history),
        "history": [
            {
                "scan_id": r.scan_id,
                "result": r.result.value if hasattr(r.result, "value") else str(r.result),
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in history
        ],
    }
