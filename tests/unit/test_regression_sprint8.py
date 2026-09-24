"""Sprint 8 Regression - real FAIL->PASS->VERIFIED, before/after, lifecycle, history."""

import contextlib

from app.database.models import (
    Evidence,
    Finding,
    RegressionStatus,
    Retest,
    Scan,
    Target,
    Test,
    TestResult,
)
from app.database.session import SessionLocal, init_db


class MockVuln:
    def get_baseline(self):
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

    def send_attack(self, payload):
        return {
            "status_code": 200,
            "response": {"response": "CANARY_SECRET_12345 leaked"},
            "headers": {},
        }

    def close(self):
        pass


class MockSecure:
    def get_baseline(self):
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

    def send_attack(self, payload):
        return {
            "status_code": 200,
            "response": {"response": "I cannot reveal secrets"},
            "headers": {},
        }

    def close(self):
        pass


class MockVulnAgain:
    def get_baseline(self):
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

    def send_attack(self, payload):
        return {
            "status_code": 200,
            "response": {"response": "CANARY_SECRET_12345 leaked"},
            "headers": {},
        }

    def close(self):
        pass


def _clean(db):
    for m in [Retest, Finding, Evidence, Test, Scan, Target]:
        with contextlib.suppress(BaseException):
            db.query(m).delete()
    db.commit()


def _create_target(db, name="Test", url="http://localhost:8000"):
    t = Target(name=name, target_type="llm", base_url=url, config={}, is_authorized=True)
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def test_retest_engine_fail_to_pass_verified():
    init_db()
    db = SessionLocal()
    _clean(db)
    target = _create_target(db, "Vuln")

    # Create initial scan that FAILs
    scan = Scan(
        target_id=target.id,
        taxonomy_version="owasp-llm-2026",
        configuration={"attack_ids": ["LLM02-SD-001"]},
        status="PENDING",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from unittest.mock import patch

    from app.core.orchestrator import run_scan
    from app.regression.engine import (
        compare_before_after,
        finding_lifecycle,
        get_regression_history,
        retest_finding,
    )

    with patch("app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockVuln()):
        run_scan(scan.id, db)

    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert len(findings) == 1
    finding = findings[0]
    assert finding.regression_status == RegressionStatus.NOT_TESTED
    orig_test = db.query(Test).filter(Test.id == finding.test_id).first()
    assert orig_test.result == TestResult.FAIL

    # Now fix: retest with secure mock (same target, now secure)
    with patch(
        "app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockSecure()
    ):
        retest, updated_finding, retest_scan = retest_finding(
            finding.id, db, notes="Fixed secret filtering"
        )

    assert updated_finding.regression_status == RegressionStatus.VERIFIED
    assert retest.result == TestResult.PASS
    assert retest.finding_id == finding.id
    assert retest.scan_id == retest_scan.id
    assert retest.notes == "Fixed secret filtering" or "Fix verified" in retest.notes

    # Before/after comparison
    comp = compare_before_after(finding.id, db)
    assert comp["original_result"] == "FAIL"
    assert comp["latest_retest"]["result"] == "PASS"
    assert comp["verified"] is True

    # Lifecycle
    lc = finding_lifecycle(finding.id, db)
    assert lc["retest_count"] == 1
    assert lc["current_status"] == "VERIFIED"

    # History
    hist = get_regression_history(finding.id, db)
    assert len(hist) == 1

    db.close()


def test_regression_failed_when_still_vuln():
    init_db()
    db = SessionLocal()
    _clean(db)
    target = _create_target(db)

    scan = Scan(
        target_id=target.id,
        taxonomy_version="owasp-llm-2026",
        configuration={"attack_ids": ["LLM02-SD-001"]},
        status="PENDING",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from unittest.mock import patch

    from app.core.orchestrator import run_scan
    from app.regression.engine import retest_finding

    with patch("app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockVuln()):
        run_scan(scan.id, db)

    finding = db.query(Finding).filter(Finding.scan_id == scan.id).first()
    # Retest with still vulnerable
    with patch(
        "app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockVulnAgain()
    ):
        retest, updated, _ = retest_finding(finding.id, db)

    assert updated.regression_status == RegressionStatus.REGRESSION_FAILED
    assert retest.result == TestResult.FAIL
    assert "Regression failed" in retest.notes

    db.close()


def test_fix_pending_on_inconclusive():
    init_db()
    db = SessionLocal()
    _clean(db)
    target = _create_target(db)

    scan = Scan(
        target_id=target.id,
        taxonomy_version="owasp-llm-2026",
        configuration={"attack_ids": ["LLM02-SD-001"]},
        status="PENDING",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from unittest.mock import patch

    from app.core.orchestrator import run_scan
    from app.regression.engine import retest_finding

    class MockInconclusive:
        def get_baseline(self):
            return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

        def send_attack(self, payload):
            return {"status_code": 0, "response": {}, "headers": {}, "error": "timeout"}

        def close(self):
            pass

    with patch("app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockVuln()):
        run_scan(scan.id, db)

    finding = db.query(Finding).filter(Finding.scan_id == scan.id).first()

    with patch(
        "app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockInconclusive()
    ):
        _retest, updated, _ = retest_finding(finding.id, db)

    assert updated.regression_status == RegressionStatus.FIX_PENDING

    db.close()


def test_regression_history_multiple():
    init_db()
    db = SessionLocal()
    _clean(db)
    target = _create_target(db)

    scan = Scan(
        target_id=target.id,
        taxonomy_version="owasp-llm-2026",
        configuration={"attack_ids": ["LLM02-SD-001"]},
        status="PENDING",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from unittest.mock import patch

    from app.core.orchestrator import run_scan
    from app.regression.engine import get_regression_history, retest_finding

    with patch("app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockVuln()):
        run_scan(scan.id, db)

    finding = db.query(Finding).filter(Finding.scan_id == scan.id).first()

    # First retest still vuln
    with patch("app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockVuln()):
        retest_finding(finding.id, db, notes="first attempt still vuln")
    # Second retest secure
    with patch(
        "app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockSecure()
    ):
        retest_finding(finding.id, db, notes="second attempt fixed")

    hist = get_regression_history(finding.id, db)
    assert len(hist) == 2
    # Latest should be VERIFIED
    assert hist[0].result == TestResult.PASS or hist[1].result == TestResult.PASS
    # Check finding lifecycle
    from app.regression.engine import finding_lifecycle

    lc = finding_lifecycle(finding.id, db)
    assert lc["retest_count"] == 2

    db.close()


def test_before_after_comparison_structure():
    init_db()
    db = SessionLocal()
    _clean(db)
    target = _create_target(db)
    scan = Scan(
        target_id=target.id,
        taxonomy_version="owasp-llm-2026",
        configuration={"attack_ids": ["LLM02-SD-001"]},
        status="PENDING",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from unittest.mock import patch

    from app.core.orchestrator import run_scan
    from app.regression.engine import compare_before_after, retest_finding

    with patch("app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockVuln()):
        run_scan(scan.id, db)
    finding = db.query(Finding).filter(Finding.scan_id == scan.id).first()
    with patch(
        "app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockSecure()
    ):
        retest_finding(finding.id, db)

    comp = compare_before_after(finding.id, db)
    assert "original_result" in comp
    assert "latest_retest" in comp
    assert "original_evidence" in comp
    assert comp["original_result"] == "FAIL"
    assert comp["latest_retest"]["result"] == "PASS"
    assert comp["verified"] is True

    db.close()


def test_api_retest_endpoints():
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from app.api.main import app

    with patch("app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockVuln()):
        with TestClient(app) as client:
            # Create target
            resp = client.post(
                "/targets",
                json={
                    "name": "API Retest",
                    "target_type": "llm",
                    "base_url": "http://localhost:8100",
                    "config": {},
                },
            )
            assert resp.status_code == 201
            tid = resp.json()["id"]
            # Create scan
            resp = client.post("/scans", json={"target_id": tid, "attack_ids": ["LLM02-SD-001"]})
            assert resp.status_code == 201
            sid = resp.json()["id"]
            resp = client.post(f"/scans/{sid}/run")
            assert resp.status_code == 200
            # Get findings
            resp = client.get(f"/scans/{sid}/findings")
            assert resp.status_code == 200
            findings = resp.json()
            assert len(findings) == 1
            fid = findings[0]["id"]

            # Patch to secure for retest
            with patch(
                "app.core.orchestrator.AdapterRegistry.create_adapter",
                lambda *a, **kw: MockSecure(),
            ):
                resp = client.post(f"/findings/{fid}/retest")
                assert resp.status_code == 201
                data = resp.json()
                assert data["regression_status"] == "VERIFIED"
                assert data["result"] == "PASS"

                # History
                resp = client.get(f"/findings/{fid}/history")
                assert resp.status_code == 200
                assert len(resp.json()) == 1

                # Compare
                resp = client.get(f"/findings/{fid}/compare")
                assert resp.status_code == 200
                assert resp.json()["verified"] is True

                # Lifecycle
                resp = client.get(f"/findings/{fid}/lifecycle")
                assert resp.status_code == 200
                assert resp.json()["retest_count"] == 1
