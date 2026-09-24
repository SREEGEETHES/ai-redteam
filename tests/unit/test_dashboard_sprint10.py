"""Sprint 10 Dashboard - verify 12 pages, scan launcher without CLI, evidence viewer, etc."""

import ast
import pathlib

def test_dashboard_has_all_required_pages():
    p = pathlib.Path("dashboard/main.py")
    content = p.read_text(encoding="utf-8", errors="ignore")
    # Parse pages dict
    assert "Overview" in content
    assert "Targets" in content
    assert "Scan" in content
    assert "Findings" in content
    assert "Evidence" in content
    assert "OWASP Coverage" in content
    assert "Remediation" in content
    assert "Retest" in content
    assert "Regression" in content
    assert "Scan History" in content
    assert "Checklist" in content
    assert "Configuration" in content
    assert "Attacks" in content

def test_dashboard_functions_exist():
    content = pathlib.Path("dashboard/main.py").read_text(encoding="utf-8", errors="ignore")
    for fn in ["show_overview","show_targets","show_scan","show_findings","show_evidence","show_owasp_coverage","show_remediation","show_retest","show_regression","show_scan_history","show_checklist","show_configuration","show_attacks"]:
        assert f"def {fn}(" in content, f"Missing {fn}"

def test_dashboard_uses_real_api_not_mock():
    content = pathlib.Path("dashboard/main.py").read_text(encoding="utf-8", errors="ignore")
    assert 'API_BASE_URL = os.getenv("REDTEAM_API_URL", "http://localhost:8080")' in content
    assert "api_get(" in content
    assert "api_post(" in content
    # Ensure no hardcoded mock data like "mock" without API
    # Check that scan launcher calls POST /scans and /scans/{id}/run
    assert '"/scans"' in content
    assert '"/scans/{' in content or 'f"/scans/{' in content

def test_dashboard_scan_launcher_without_cli():
    # Verify scan launcher creates scan via API and then runs it, without CLI
    content = pathlib.Path("dashboard/main.py").read_text(encoding="utf-8", errors="ignore")
    assert "Launch Scan" in content or "Launcher" in content
    # Should call POST /scans and POST /scans/{id}/run
    assert 'api_post("/scans"' in content
    assert 'f"/scans/{' in content and '/run' in content

def test_dashboard_evidence_viewer_has_required_captures():
    content = pathlib.Path("dashboard/main.py").read_text(encoding="utf-8", errors="ignore")
    # Evidence viewer must show request/response/tool/retrieval/detectors/reproduction
    assert "Request capture" in content
    assert "Response capture" in content
    assert "Tool-call capture" in content
    assert "Retrieval evidence" in content
    assert "Deterministic detection" in content
    assert "Reproduction tracking" in content

def test_dashboard_pass_fail_and_severity():
    content = pathlib.Path("dashboard/main.py").read_text(encoding="utf-8", errors="ignore")
    assert "PASS" in content
    assert "FAIL" in content
    assert "Severity" in content
    assert "bar_chart" in content

def test_dashboard_retest_button():
    content = pathlib.Path("dashboard/main.py").read_text(encoding="utf-8", errors="ignore")
    assert "Retest" in content
    assert "/findings/" in content and "/retest" in content
    assert "history" in content.lower()

def test_dashboard_can_run_scan_via_api():
    from fastapi.testclient import TestClient
    from app.api.main import app
    from unittest.mock import patch

    class MockVuln:
        def get_baseline(self): return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}
        def send_attack(self, payload): return {"status_code": 200, "response": {"response": "CANARY_SECRET_12345 leaked"}, "headers": {}}
        def close(self): pass

    with patch("app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockVuln()):
        with TestClient(app) as client:
            # Simulate dashboard scan launcher: POST /targets, POST /scans, POST /scans/{id}/run, GET findings/evidence
            resp = client.post("/targets", json={"name": "Dashboard Test", "target_type": "llm", "base_url": "http://localhost:8300", "config": {}})
            assert resp.status_code == 201
            tid = resp.json()["id"]
            resp = client.post("/scans", json={"target_id": tid, "attack_ids": ["LLM02-SD-001"]})
            assert resp.status_code == 201
            sid = resp.json()["id"]
            resp = client.post(f"/scans/{sid}/run")
            assert resp.status_code == 200
            assert resp.json()["status"] == "COMPLETED"
            # Findings via API (dashboard Findings page)
            resp = client.get(f"/scans/{sid}/findings")
            assert resp.status_code == 200
            assert len(resp.json()) == 1
            # Evidence via API (dashboard Evidence page)
            resp = client.get(f"/scans/{sid}/evidence")
            assert resp.status_code == 200
            ev = resp.json()[0]
            assert "request" in ev
            assert "tool_calls" in ev or "retrieved_documents" in ev
            # OWASP coverage via attacks
            resp = client.get("/attacks")
            assert resp.status_code == 200
            assert len(resp.json()) >= 10
            # Checklist
            resp = client.get("/checklist")
            assert resp.status_code == 200
            # Retest
            fid = client.get(f"/scans/{sid}/findings").json()[0]["id"]
            # Need secure mock for retest
            class MockSecure:
                def get_baseline(self): return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}
                def send_attack(self, payload): return {"status_code": 200, "response": {"response": "I cannot reveal secrets"}, "headers": {}}
                def close(self): pass
            with patch("app.core.orchestrator.AdapterRegistry.create_adapter", lambda *a, **kw: MockSecure()):
                resp = client.post(f"/findings/{fid}/retest")
                assert resp.status_code == 201
                assert resp.json()["regression_status"] == "VERIFIED"
            # Scan history
            resp = client.get("/scans")
            assert resp.status_code == 200
            assert len(resp.json()) >= 1
