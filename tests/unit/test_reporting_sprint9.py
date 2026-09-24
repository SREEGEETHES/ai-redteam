"""Sprint 9 Reporting - JSON/MD/HTML, executive summary, findings, evidence, remediation, retest, reproducible."""

import contextlib
import json

from app.database.models import Evidence, Finding, Retest, Scan, Target, Test
from app.database.session import SessionLocal, init_db
from app.reporting.engine import (
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
    save_reports,
)


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


def _setup_scan_with_finding():
    init_db()
    db = SessionLocal()
    for m in [Retest, Finding, Evidence, Test, Scan, Target]:
        with contextlib.suppress(BaseException):
            db.query(m).delete()
    db.commit()
    target = Target(
        name="Report Test",
        target_type="llm",
        base_url="http://localhost:8000",
        config={},
        is_authorized=True,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
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

    with patch("app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockVuln()):
        run_scan(scan.id, db)
    db.refresh(scan)
    return db, scan


def test_json_report_structure():
    db, scan = _setup_scan_with_finding()
    data = generate_json_report(scan.id, db)
    assert "scan" in data
    assert "executive_summary" in data
    assert "technical_findings" in data
    assert "evidence" in data
    assert "remediation" in data
    assert "retest_status" in data
    assert "report_hash" in data
    assert len(data["report_hash"]) == 16
    es = data["executive_summary"]
    assert "verdict" in es
    assert "counts" in es
    assert "severity_counts" in es
    assert es["counts"]["FAIL"] == 1
    # technical findings per spec 41
    assert len(data["technical_findings"]) == 1
    tf = data["technical_findings"][0]
    for field in [
        "id",
        "title",
        "owasp_category",
        "target",
        "severity",
        "status",
        "description",
        "attack_objective",
        "preconditions",
        "attack_procedure",
        "observed_behavior",
        "expected_behavior",
        "evidence",
        "impact",
        "root_cause",
        "protection",
        "remediation",
        "retest_procedure",
        "regression_result",
        "references",
    ]:
        assert field in tf, f"Missing {field}"
    # evidence
    assert len(data["evidence"]) == 1
    ev = data["evidence"][0]
    assert ev["result"] == "FAIL"
    assert ev["evidence"]["detectors_triggered"] is not None
    # remediation
    assert len(data["remediation"]) == 1
    assert "remediation" in data["remediation"][0]
    db.close()


def test_markdown_report_contains_sections():
    db, scan = _setup_scan_with_finding()
    md = generate_markdown_report(scan.id, db)
    assert f"# AI Red Team Report — Scan {scan.id}" in md
    assert "## Executive Summary" in md
    assert "## Technical Findings" in md
    assert "## Evidence" in md
    assert "## Remediation" in md
    assert "## Retest Status" in md
    assert "CANARY_SECRET" in md or "LLM02-SD-001" in md
    assert "Report hash" in md or "Hash" in md
    db.close()


def test_html_report_contains_html():
    db, scan = _setup_scan_with_finding()
    html = generate_html_report(scan.id, db)
    assert "<html>" in html.lower()
    assert f"Scan {scan.id}" in html
    assert "AI Red Team Report" in html
    db.close()


def test_report_reproducibility():
    db, scan = _setup_scan_with_finding()
    data1 = generate_json_report(scan.id, db)
    data2 = generate_json_report(scan.id, db)
    assert data1["report_hash"] == data2["report_hash"]
    # executive summary counts same
    assert data1["executive_summary"]["counts"] == data2["executive_summary"]["counts"]
    db.close()


def test_report_with_no_findings():
    init_db()
    db = SessionLocal()
    for m in [Retest, Finding, Evidence, Test, Scan, Target]:
        with contextlib.suppress(BaseException):
            db.query(m).delete()
    db.commit()
    target = Target(
        name="No Finding",
        target_type="llm",
        base_url="http://localhost:8000",
        config={},
        is_authorized=True,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    scan = Scan(
        target_id=target.id,
        taxonomy_version="owasp-llm-2026",
        configuration={"attack_ids": ["LLM07-SPL-001"]},
        status="PENDING",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    class MockSecure:
        def get_baseline(self):
            return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

        def send_attack(self, payload):
            return {
                "status_code": 200,
                "response": {"response": "I cannot reveal system instructions"},
                "headers": {},
            }

        def close(self):
            pass

    from unittest.mock import patch

    from app.core.orchestrator import run_scan

    with patch(
        "app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockSecure()
    ):
        run_scan(scan.id, db)
    # This scan should have 0 findings (PASS)
    data = generate_json_report(scan.id, db)
    assert data["executive_summary"]["findings"] == 0
    assert (
        "PASS" in data["executive_summary"]["verdict"]
        or "INCONCLUSIVE" in data["executive_summary"]["verdict"]
    )
    db.close()


def test_report_includes_retest_status():
    db, scan = _setup_scan_with_finding()
    # Do retest to create history
    from unittest.mock import patch

    from app.regression.engine import retest_finding

    # Need to get finding
    finding = db.query(Finding).filter(Finding.scan_id == scan.id).first()

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

    with patch(
        "app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockSecure()
    ):
        retest_finding(finding.id, db)
    data = generate_json_report(scan.id, db)
    # Original scan's retest_status should show history
    # Note: retest creates new scan, original scan's findings have regression_status updated
    assert len(data["retest_status"]) == 1
    assert data["retest_status"][0]["regression_status"] == "VERIFIED"
    db.close()


def test_save_reports_creates_files(tmp_path=None):
    import pathlib
    import tempfile

    db, scan = _setup_scan_with_finding()
    with tempfile.TemporaryDirectory() as tmp:
        paths = save_reports(scan.id, db, reports_dir=tmp)
        assert pathlib.Path(paths["json"]).exists()
        assert pathlib.Path(paths["markdown"]).exists()
        assert pathlib.Path(paths["html"]).exists()
        # Check that saved json is same as generated
        data = generate_json_report(scan.id, db)
        saved = json.loads(pathlib.Path(paths["json"]).read_text())
        assert saved["report_hash"] == data["report_hash"]
    db.close()


def test_api_report_endpoints():
    from unittest.mock import patch

    from fastapi.testclient import TestClient

    from app.api.main import app

    with patch("app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockVuln()):
        with TestClient(app) as client:
            resp = client.post(
                "/targets",
                json={
                    "name": "Report API",
                    "target_type": "llm",
                    "base_url": "http://localhost:8200",
                    "config": {},
                },
            )
            assert resp.status_code == 201
            tid = resp.json()["id"]
            resp = client.post("/scans", json={"target_id": tid, "attack_ids": ["LLM02-SD-001"]})
            assert resp.status_code == 201
            sid = resp.json()["id"]
            resp = client.post(f"/scans/{sid}/run")
            assert resp.status_code == 200
            # JSON
            resp = client.get(f"/scans/{sid}/report", params={"format": "json"})
            assert resp.status_code == 200
            assert "executive_summary" in resp.json()
            # Markdown
            resp = client.get(f"/scans/{sid}/report", params={"format": "markdown"})
            assert resp.status_code == 200
            assert "Executive Summary" in resp.text
            # HTML
            resp = client.get(f"/scans/{sid}/report", params={"format": "html"})
            assert resp.status_code == 200
            assert "<html>" in resp.text.lower()
            # Specific endpoints
            resp = client.get(f"/scans/{sid}/report/json")
            assert resp.status_code == 200
            assert "report_hash" in resp.json()
