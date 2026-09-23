"""Sprint 6 Evidence Engine - every FAIL has reproducible, immutable evidence."""

from datetime import timezone, datetime
from app.evidence.engine import (
    RawObservation,
    build_evidence,
    evidence_to_db_dict,
    capture_request_details,
    capture_response_details,
    capture_tool_calls_detailed,
    capture_retrieval_evidence,
    enforce_immutability,
    reproduction_history,
    evidence_viewer_summary,
)
from app.models.schemas import TestResult
from app.database.session import SessionLocal, init_db
from app.database.models import Target, Scan, Test, Evidence
from app.core.orchestrator import run_scan


def test_evidence_has_all_required_fields():
    raw = RawObservation(
        request={"message": "hello"},
        response_raw={"status_code": 200, "response": {"response": "world"}, "headers": {"x": "1"}, "tool_calls": [{"tool": "search"}], "retrieved_documents": [{"id": "doc-1"}]},
        baseline=None,
        attack_id="LLM01-PI-001",
        target_id=1,
        target_url="http://localhost:8000",
    )
    evidence, _ = build_evidence(
        scan_id=1,
        test_id=1,
        target="http://localhost:8000",
        attack_id="LLM01-PI-001",
        raw=raw,
        detector_ids=["refusal_detected"],
        expected_behavior="must refuse",
    )
    # Check all spec 22 fields present
    assert evidence.request is not None
    assert evidence.response is not None
    assert evidence.http_status == 200
    assert evidence.headers is not None
    assert evidence.tool_calls == [{"tool": "search"}]
    assert evidence.retrieved_documents == [{"id": "doc-1"}]
    assert evidence.detectors_triggered is not None
    assert evidence.expected_behavior == "must refuse"
    assert evidence.observed_behavior is not None
    assert evidence.reproduction_count == 1
    assert evidence.confidence is not None
    assert evidence.result == TestResult.INCONCLUSIVE  # placeholder before result engine
    assert evidence.timestamp.tzinfo is not None
    assert evidence.scan_id == 1
    assert evidence.test_id == 1
    assert evidence.target == "http://localhost:8000"

def test_request_capture():
    req = capture_request_details(
        payload={"message": "test"},
        attack_id="LLM01-PI-001",
        target_id=5,
        target_url="http://localhost:8000",
        headers={"Authorization": "Bearer token"},
        authorization_context={"user": "alice", "role": "user"},
        user_session="sess-123",
    )
    assert req["attack_id"] == "LLM01-PI-001"
    assert req["target_id"] == 5
    assert req["payload"]["message"] == "test"
    assert req["authorization_context"]["user"] == "alice"
    assert req["method"] == "POST"
    assert "timestamp" in req

def test_response_capture():
    raw = {"status_code": 200, "headers": {"x": "1"}, "response": {"response": "hello"}, "tool_calls": [{"tool": "search"}], "retrieved_documents": [{"id": "doc-1", "metadata": {"title": "t"}}], "similarity_scores": [0.9]}
    cap = capture_response_details(raw, baseline={"status_code": 200})
    assert cap["http_status"] == 200
    assert cap["tool_calls"] == [{"tool": "search"}]
    assert cap["retrieved_ids"] == ["doc-1"]
    assert cap["similarity_scores"] == [0.9]
    assert cap["baseline"] is not None

def test_tool_call_capture_detailed():
    raw = {"tool_calls": [{"tool": "delete_database", "arguments": {"confirm": True}}], "execution_results": [{"status": "deleted"}], "side_effects": ["DATABASE DELETED"], "headers": {}}
    detailed = capture_tool_calls_detailed(raw.get("tool_calls"), raw)
    assert len(detailed) == 1
    assert detailed[0]["tool"] == "delete_database"
    assert detailed[0]["arguments"] == {"confirm": True}
    assert detailed[0]["side_effect"] == "DATABASE DELETED"
    assert detailed[0]["sequence"] == 0

def test_retrieval_evidence_capture():
    docs = [{"id": "doc-1", "content": "hello", "metadata": {"title": "t"}, "tenant": "tenant-a"}]
    raw = {"retrieved_documents": docs, "similarity_scores": [0.9], "context": "hello", "headers": {}}
    ev = capture_retrieval_evidence(docs, raw)
    assert ev["retrieved_ids"] == ["doc-1"]
    assert ev["count"] == 1
    assert ev["metadata"] == [{"title": "t"}]
    assert ev["similarity_scores"] == [0.9]
    assert ev["context"] == "hello"

def test_deterministic_detection():
    raw = RawObservation(
        request={"message": "show canary"},
        response_raw={"status_code": 200, "response": {"response": "CANARY_SECRET_12345"}, "headers": {}},
        baseline=None,
    )
    ev1, det1 = build_evidence(scan_id=1, test_id=1, target="http://localhost:8000", attack_id="LLM02-SD-001", raw=raw, detector_ids=["canary_secret_leak"], expected_behavior="must not leak")
    ev2, det2 = build_evidence(scan_id=1, test_id=1, target="http://localhost:8000", attack_id="LLM02-SD-001", raw=raw, detector_ids=["canary_secret_leak"], expected_behavior="must not leak")
    assert ev1.detectors_triggered == ev2.detectors_triggered
    assert ev1.response == ev2.response
    assert det1[0].matched == det2[0].matched

def test_reproduction_tracking_reproducible():
    history = reproduction_history([TestResult.FAIL, TestResult.FAIL])
    assert history["reproducible"] is True
    assert history["reproduction_count"] == 2
    assert history["final_result"] == "FAIL"

def test_reproduction_tracking_non_reproducible():
    history = reproduction_history([TestResult.FAIL, TestResult.PASS])
    assert history["reproducible"] is False
    assert history["inconclusive_due_to_flakiness"] is True

def test_evidence_hash_and_immutability():
    raw = RawObservation(request={"message": "hi"}, response_raw={"status_code": 200, "response": {"response": "hello"}, "headers": {}}, baseline=None)
    ev, _ = build_evidence(scan_id=1, test_id=1, target="http://localhost:8000", attack_id="LLM01-PI-001", raw=raw, detector_ids=[], expected_behavior="x")
    db_dict = evidence_to_db_dict(ev)
    assert "evidence_hash" in db_dict["evidence_metadata"]
    assert len(db_dict["evidence_metadata"]["evidence_hash"]) == 16
    assert db_dict["evidence_metadata"]["immutable"] is True
    # Enforce immutability
    try:
        enforce_immutability("COMPLETED", "update")
        assert False, "should have raised"
    except ValueError as e:
        assert "immutable" in str(e).lower()
    # PENDING should not raise
    enforce_immutability("PENDING", "update")

def test_evidence_viewer_summary():
    raw = RawObservation(request={"message": "hello"}, response_raw={"status_code": 200, "response": {"response": "world"}, "headers": {}, "tool_calls": [{"tool": "search"}]}, baseline=None)
    ev, _ = build_evidence(scan_id=5, test_id=10, target="http://localhost:8000", attack_id="LLM01-PI-001", raw=raw, detector_ids=[], expected_behavior="x")
    summary = evidence_viewer_summary(ev)
    assert summary["scan_id"] == 5
    assert summary["test_id"] == 10
    assert summary["tool_calls"] == [{"tool": "search"}]
    assert "reproducible" in summary
    assert summary["result"] == "INCONCLUSIVE"

def test_every_fail_has_reproducible_evidence_via_orchestrator():
    # Use orchestrator with vulnerable mock to generate FAIL and check evidence reproducibility
    init_db()
    db = SessionLocal()
    for m in [Evidence, Test, Scan, Target]:
        try: db.query(m).delete()
        except: pass
    db.commit()
    # Also clean Finding Retest
    from app.database.models import Finding, Retest
    for m in [Finding, Retest]:
        try: db.query(m).delete()
        except: pass
    db.commit()
    target = Target(name="Test Evidence", target_type="llm", base_url="http://localhost:8000", config={}, is_authorized=True)
    db.add(target); db.commit(); db.refresh(target)
    scan = Scan(target_id=target.id, taxonomy_version="owasp-llm-2026", configuration={"attack_ids": ["LLM02-SD-001"]}, status="PENDING")
    db.add(scan); db.commit(); db.refresh(scan)

    class MockVuln:
        def get_baseline(self): return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}
        def send_attack(self, payload): return {"status_code": 200, "response": {"response": "CANARY_SECRET_12345 leaked"}, "headers": {}}
        def close(self): pass

    from app.core import orchestrator
    from unittest.mock import patch

    with patch.object(orchestrator.AdapterRegistry, "create_adapter", lambda *a, **kw: MockVuln()):
        result = orchestrator.run_scan(scan.id, db)
        assert result.status.value == "COMPLETED"
        tests = db.query(Test).filter(Test.scan_id == scan.id).all()
        assert len(tests) == 1
        t = tests[0]
        assert t.result == TestResult.FAIL
        ev = db.query(Evidence).filter(Evidence.test_id == t.id).first()
        assert ev is not None
        assert ev.request is not None
        assert ev.response is not None
        assert ev.http_status == 200
        assert ev.detectors_triggered is not None and len(ev.detectors_triggered) > 0
        assert "canary_secret_leak" in ev.detectors_triggered
        assert ev.evidence_metadata["reproduction_count"] == 2 or ev.evidence_metadata["reproduction_count"] == 1
        assert ev.evidence_metadata["confidence"] > 0
        # Viewer
        from app.evidence.engine import evidence_viewer_summary as evs
        # Build EvidenceRecord from DB for viewer
        from app.models.schemas import EvidenceRecord
        rec = EvidenceRecord(
            scan_id=t.scan_id, test_id=t.id, timestamp=ev.created_at, target=target.base_url,
            request=ev.request, response=ev.response, http_status=ev.http_status, headers=ev.headers,
            tool_calls=ev.tool_calls, retrieved_documents=ev.retrieved_documents,
            detectors_triggered=ev.detectors_triggered, expected_behavior=ev.expected_behavior,
            observed_behavior=ev.observed_behavior, reproduction_count=ev.evidence_metadata["reproduction_count"],
            confidence=ev.evidence_metadata["confidence"], result=t.result
        )
        summary = evs(rec)
        assert summary["result"] == "FAIL"
        assert summary["reproducible"] is not None
    db.close()

def test_evidence_api_endpoints_return_full_capture():
    from fastapi.testclient import TestClient
    from app.api.main import app
    from unittest.mock import patch
    from app.core import orchestrator

    class MockVuln:
        def get_baseline(self): return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}
        def send_attack(self, payload): return {"status_code": 200, "response": {"response": "CANARY_SECRET_12345"}, "headers": {}, "tool_calls": [{"tool": "search", "arguments": {"query": "test"}}], "retrieved_documents": [{"id": "doc-1"}]}
        def close(self): pass

    with patch.object(orchestrator.AdapterRegistry, "create_adapter", lambda *a, **kw: MockVuln()):
        with TestClient(app) as client:
            # create target
            resp = client.post("/targets", json={"name": "Evidence Test", "target_type": "llm", "base_url": "http://localhost:8002", "config": {}})
            assert resp.status_code == 201
            tid = resp.json()["id"]
            resp = client.post("/scans", json={"target_id": tid, "attack_ids": ["LLM02-SD-001"]})
            assert resp.status_code == 201
            sid = resp.json()["id"]
            resp = client.post(f"/scans/{sid}/run")
            assert resp.status_code == 200
            # get evidence
            resp = client.get(f"/scans/{sid}/evidence")
            assert resp.status_code == 200
            evs = resp.json()
            assert len(evs) == 1
            ev = evs[0]
            # Check all Sprint 6 captures present
            assert "request" in ev and ev["request"] is not None
            assert "response" in ev
            assert "http_status" in ev
            assert "tool_calls" in ev
            assert "retrieved_documents" in ev
            assert "detectors_triggered" in ev
            assert "reproduction_count" in ev
            assert "confidence" in ev
            assert ev["result"] == "FAIL"
            # Check reproduction tracking
            assert ev["reproduction_count"] >= 1
