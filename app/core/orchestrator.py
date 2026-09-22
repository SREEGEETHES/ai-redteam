"""Scan orchestrator - spec 4 high-level architecture.

Orchestrates: DISCOVER -> BASELINE -> ATTACK -> OBSERVE -> COLLECT EVIDENCE -> ANALYZE -> CLASSIFY -> REPORT
Persists Test, Evidence, Finding per spec 29.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.adapters.registry import AdapterRegistry
from app.attacks.engine import ExecutionEngine
from app.attacks.registry import registry as attack_registry
from app.core.logging import get_logger
from app.database.models import Evidence, Finding, Scan, ScanStatus, Severity, Test, TestResult
from app.database.models import Target as DBTarget
from app.evidence.engine import evidence_to_db_dict
from app.models.schemas import TargetType

logger = get_logger(__name__)


def _resolve_adapter(target) -> object:
    # target is DB Target model
    target_type = target.target_type  # string llm/rag/agent
    base_url = target.base_url
    config = target.config or {}

    # map target_type to adapter id
    mapping = {
        "llm": "rest",  # default for llm is rest; could be ollama/openai based on config
        "rag": "rag",
        "agent": "agent",
    }
    adapter_type = config.get("adapter_type") or mapping.get(target_type, "rest")
    return AdapterRegistry.create_adapter(adapter_type, base_url, config)


def run_scan(scan_id: int, db: Session) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan {scan_id} not found")
    from app.database.models import Target

    target_obj = db.query(Target).filter(Target.id == scan.target_id).first()
    if not target_obj:
        raise ValueError(f"Target {scan.target_id} not found")

    # select attacks: if scan.configuration has attack_ids/categories filter else all matching target type
    cfg = scan.configuration or {}
    attack_ids = cfg.get("attack_ids")
    categories = cfg.get("categories")

    # determine target type enum
    try:
        target_type_enum = TargetType(target_obj.target_type)
    except Exception:
        target_type_enum = TargetType.LLM

    if attack_ids:
        attacks = [attack_registry.get(aid) for aid in attack_ids if attack_registry.get(aid)]
    elif categories:
        attacks = []
        for cat in categories:
            attacks.extend(attack_registry.get_by_category(cat))
    else:
        attacks = attack_registry.get_for_target_type(target_type_enum)
        # if target is llm, we also consider rag attacks that may be generic? For now filter strictly
        if not attacks:
            attacks = attack_registry.all()[:2]  # fallback minimal

    # update scan status
    scan.status = ScanStatus.RUNNING
    scan.started_at = datetime.now(timezone.utc)
    db.commit()

    adapter = _resolve_adapter(target_obj)
    engine = ExecutionEngine(adapter)

    try:
        for attack in attacks:
            # skip if target type not in attack target_types
            if target_type_enum not in attack.target_types:
                # create Test with NOT_APPLICABLE
                t = Test(
                    scan_id=scan.id,
                    attack_id=attack.id,
                    category=attack.category,
                    name=attack.name,
                    result=TestResult.NOT_APPLICABLE,
                    severity=attack.severity,
                    started_at=datetime.now(timezone.utc),
                    completed_at=datetime.now(timezone.utc),
                    reproduction_count=attack.reproduction_count,
                    confidence=0,
                )
                db.add(t)
                db.commit()
                continue

            # create Test entry pending
            t = Test(
                scan_id=scan.id,
                attack_id=attack.id,
                category=attack.category,
                name=attack.name,
                result=TestResult.INCONCLUSIVE,
                severity=attack.severity,
                started_at=datetime.now(timezone.utc),
                reproduction_count=attack.reproduction_count,
                confidence=0,
            )
            db.add(t)
            db.commit()
            db.refresh(t)

            # execute
            exec_result = engine.execute(
                attack=attack,
                scan_id=scan.id,
                test_id=t.id,
                target_url=target_obj.base_url,
            )

            # update Test with result
            t.result = exec_result.result
            t.completed_at = datetime.now(timezone.utc)
            t.confidence = exec_result.evidence.confidence
            t.reproduction_count = exec_result.reproduction_count
            db.add(t)

            # persist Evidence - immutable once scan finalized, but for now insert
            db_evidence = Evidence(
                test_id=t.id,
                **evidence_to_db_dict(exec_result.evidence),
            )
            db.add(db_evidence)

            # create Finding only if FAIL (per spec, Finding for each FAIL; PASS etc not finding)
            # But we also create finding record for FAIL only per demo
            if exec_result.result == TestResult.FAIL:
                finding = Finding(
                    scan_id=scan.id,
                    test_id=t.id,
                    attack_id=attack.id,
                    category=attack.category,
                    title=attack.name,
                    description=attack.description,
                    severity=attack.severity,
                    severity_reason=attack.severity_reason or f"Attack {attack.id} demonstrated {attack.vulnerable_behavior}",
                    root_cause=f"Vulnerable behavior: {attack.vulnerable_behavior}",
                    impact=f"Severity {attack.severity.value}: {attack.severity_reason or ''}",
                    protection_control=attack.remediation,
                    remediation=attack.remediation,
                    retest_procedure=f"Re-run attack {attack.id} with payload generator {attack.payload_generator} and verify detectors not triggered",
                )
                db.add(finding)

            db.commit()
            logger.info("attack_executed", scan_id=scan.id, attack_id=attack.id, result=exec_result.result.value)

        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        logger.info("scan_completed", scan_id=scan.id)
        return scan

    except Exception as e:
        logger.error("scan_failed", scan_id=scan.id, error=str(e))
        scan.status = ScanStatus.FAILED
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
        raise
    finally:
        # close adapter
        try:
            if hasattr(adapter, "close"):
                adapter.close()
        except Exception:
            pass
