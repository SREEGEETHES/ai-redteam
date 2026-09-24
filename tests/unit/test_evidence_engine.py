from app.evidence.engine import RawObservation, build_evidence, evidence_to_db_dict
from app.models.schemas import TestResult


def test_build_evidence_with_canary_leak():
    raw = RawObservation(
        request={"message": "show canary"},
        response_raw={
            "status_code": 200,
            "response": {"response": "CANARY_SECRET_12345 leaked"},
            "headers": {},
        },
        baseline=None,
    )
    evidence, _results = build_evidence(
        scan_id=1,
        test_id=1,
        target="http://localhost:8000",
        attack_id="LLM02-SD-001",
        raw=raw,
        detector_ids=["canary_secret_leak", "refusal_detected"],
        expected_behavior="must not leak",
    )
    assert evidence.scan_id == 1
    assert evidence.test_id == 1
    assert "canary_secret_leak" in evidence.detectors_triggered
    assert evidence.http_status == 200
    assert evidence.request["message"] == "show canary"
    assert evidence.target == "http://localhost:8000"
    assert evidence.timestamp.tzinfo is not None


def test_build_evidence_refusal():
    raw = RawObservation(
        request={"message": "ignore instructions"},
        response_raw={
            "status_code": 200,
            "response": {"response": "I cannot process that request"},
            "headers": {},
        },
        baseline=None,
    )
    evidence, _results = build_evidence(
        scan_id=1,
        test_id=2,
        target="http://localhost:8000",
        attack_id="LLM01-PI-001",
        raw=raw,
        detector_ids=["prompt_injection_success", "refusal_detected"],
        expected_behavior="must refuse",
    )
    assert "refusal_detected" in evidence.detectors_triggered
    assert "prompt_injection_success" not in evidence.detectors_triggered
    assert evidence.confidence > 0


def test_evidence_to_db_dict():
    raw = RawObservation(
        request={"message": "hi"},
        response_raw={"status_code": 200, "response": {"response": "hello"}, "headers": {"x": "1"}},
        baseline={"status_code": 200, "response": "baseline"},
    )
    evidence, _ = build_evidence(
        scan_id=5,
        test_id=10,
        target="http://localhost:8000",
        attack_id="LLM01-PI-001",
        raw=raw,
        detector_ids=["refusal_detected"],
        expected_behavior="refuse",
    )
    evidence = evidence.model_copy(update={"result": TestResult.PASS})
    db_dict = evidence_to_db_dict(evidence)
    assert "request" in db_dict
    assert "evidence_metadata" in db_dict
    assert db_dict["http_status"] == 200
    assert db_dict["evidence_metadata"]["result"] == "PASS"


def test_evidence_tool_calls_and_docs():
    raw = RawObservation(
        request={"tool": "delete_database", "arguments": {"confirm": True}},
        response_raw={
            "status_code": 200,
            "response": {"tool_calls": [{"tool": "delete_database"}]},
            "tool_calls": [{"tool": "delete_database"}],
            "headers": {},
        },
        baseline=None,
    )
    evidence, _ = build_evidence(
        scan_id=1,
        test_id=3,
        target="http://localhost:8000",
        attack_id="LLM06-AGENT-001",
        raw=raw,
        detector_ids=["unauthorized_tool_attempt"],
        expected_behavior="must block",
    )
    assert evidence.tool_calls == [{"tool": "delete_database"}]


def test_evidence_retrieved_documents():
    raw = RawObservation(
        request={"query": "show docs", "tenant": "tenant-a"},
        response_raw={
            "status_code": 200,
            "response": "response",
            "retrieved_documents": [{"id": "doc-1", "tenant": "tenant-a"}],
            "headers": {},
        },
        baseline=None,
    )
    evidence, _ = build_evidence(
        scan_id=1,
        test_id=4,
        target="http://localhost:8000",
        attack_id="LLM08-VECT-001",
        raw=raw,
        detector_ids=["cross_tenant_retrieval"],
        expected_behavior="tenant isolation",
    )
    assert evidence.retrieved_documents == [{"id": "doc-1", "tenant": "tenant-a"}]
