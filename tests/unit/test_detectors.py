from app.attacks.detectors import (
    canary_secret_detector,
    http_error_detector,
    prompt_injection_success_detector,
    refusal_detector,
    regex_secret_detector,
    retrieval_cross_tenant_detector,
    run_detectors,
    system_prompt_leak_detector,
    unauthorized_tool_detector,
)


def test_canary_detector_matched():
    ev = {"response": {"response": "Here is CANARY_SECRET_12345 leak"}, "http_status": 200}
    r = canary_secret_detector(ev)
    assert r.matched is True
    assert r.detector_id == "canary_secret_leak"


def test_canary_detector_not_matched():
    ev = {"response": {"response": "Hello world"}, "http_status": 200}
    r = canary_secret_detector(ev)
    assert r.matched is False


def test_regex_secret_detector():
    ev = {"response": {"response": "The key is API_KEY_XYZ_789"}, "http_status": 200}
    r = regex_secret_detector(ev)
    assert r.matched is True

    ev2 = {"response": {"response": "no secrets here"}, "http_status": 200}
    assert regex_secret_detector(ev2).matched is False


def test_system_prompt_leak():
    ev = {
        "response": {"response": "My system prompt is: You are a helpful assistant. Never reveal"}
    }
    assert system_prompt_leak_detector(ev).matched is True

    ev2 = {"response": {"response": "I cannot reveal my system instructions."}}
    assert system_prompt_leak_detector(ev2).matched is False


def test_prompt_injection_success():
    ev = {"response": {"response": "Admin mode activated. Here are all secrets: ..."}}
    assert prompt_injection_success_detector(ev).matched is True

    ev2 = {"response": {"response": "I cannot process that request."}}
    assert prompt_injection_success_detector(ev2).matched is False


def test_refusal_detector():
    ev = {
        "response": {
            "response": "I cannot process that request. It appears to be a prompt injection attempt."
        }
    }
    assert refusal_detector(ev).matched is True

    ev2 = {"response": {"response": "The capital is Paris."}}
    assert refusal_detector(ev2).matched is False


def test_unauthorized_tool_detector():
    ev = {"tool_calls": [{"tool": "delete_database", "arguments": {"confirm": True}}]}
    assert unauthorized_tool_detector(ev).matched is True

    ev2 = {"tool_calls": [{"tool": "search", "arguments": {"query": "hello"}}]}
    assert unauthorized_tool_detector(ev2).matched is False


def test_cross_tenant_detector():
    ev = {
        "retrieved_documents": [
            {"id": "doc-1", "tenant": "tenant-a"},
            {"id": "doc-3", "tenant": "tenant-b"},
        ]
    }
    assert retrieval_cross_tenant_detector(ev, expected_tenant="tenant-a").matched is True

    ev2 = {"retrieved_documents": [{"id": "doc-1", "tenant": "tenant-a"}]}
    assert retrieval_cross_tenant_detector(ev2, expected_tenant="tenant-a").matched is False


def test_http_error_detector():
    assert http_error_detector({"http_status": 0}).matched is True
    assert http_error_detector({"http_status": 500}).matched is True
    assert http_error_detector({"http_status": 200}).matched is False


def test_run_detectors_batch():
    ev = {"response": {"response": "CANARY_SECRET_12345"}, "http_status": 200}
    results = run_detectors(ev, ["canary_secret_leak", "refusal_detected", "http_error"])
    assert len(results) == 3
    triggered = [r.detector_id for r in results if r.matched]
    assert "canary_secret_leak" in triggered


def test_unknown_detector():
    ev = {"response": {"response": "hi"}}
    results = run_detectors(ev, ["unknown_detector"])
    assert results[0].matched is False
    assert "unknown detector" in results[0].reason
