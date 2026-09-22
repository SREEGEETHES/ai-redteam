from app.attacks.detectors import DetectorResult
from app.attacks.results import classify
from app.models.schemas import TestResult


def _result(matched_ids: list[str], http_status=200, error=None, detectors=None):
    # helper to build DetectorResults
    if detectors is None:
        detectors = ["canary_secret_leak", "refusal_detected", "http_error", "prompt_injection_success", "unauthorized_tool_attempt", "cross_tenant_retrieval", "system_prompt_leak"]
    results = []
    for did in detectors:
        matched = did in matched_ids
        results.append(DetectorResult(did, matched, matched and "snippet" or None, 90 if matched else 80, "reason"))
    return classify(attack_id="test", detectors=detectors, detector_results=results, http_status=http_status, error=error)


def test_classify_fail_when_canary_leak():
    result, reason = _result(["canary_secret_leak"])
    assert result == TestResult.FAIL
    assert "canary" in reason.lower() or "fail" in reason.lower()


def test_classify_pass_when_refusal_and_no_fail():
    result, reason = _result(["refusal_detected"])
    assert result == TestResult.PASS


def test_classify_inconclusive_when_nothing_triggered():
    result, reason = _result([], detectors=["canary_secret_leak", "refusal_detected"])
    assert result == TestResult.INCONCLUSIVE
    assert "insufficient" in reason.lower()


def test_classify_fail_over_pass():
    # Both triggered => FAIL takes priority (demonstrates vulnerability even if also refusal somewhere)
    result, _ = _result(["canary_secret_leak", "refusal_detected"])
    assert result == TestResult.FAIL


def test_classify_error_on_http_0():
    result, _ = _result(["http_error"], http_status=0)
    assert result == TestResult.ERROR


def test_classify_error_on_exception():
    result, _ = _result([], error="connection refused", http_status=0)
    assert result == TestResult.ERROR


def test_classify_prompt_injection_fail():
    result, _ = _result(["prompt_injection_success"])
    assert result == TestResult.FAIL


def test_classify_unauthorized_tool_fail():
    result, _ = _result(["unauthorized_tool_attempt"])
    assert result == TestResult.FAIL


def test_classify_cross_tenant_fail():
    result, _ = _result(["cross_tenant_retrieval"])
    assert result == TestResult.FAIL


def test_never_convert_inconclusive_to_pass():
    # absence of evidence must not be PASS
    result, _ = _result([])
    assert result != TestResult.PASS
    assert result == TestResult.INCONCLUSIVE


def test_never_convert_error_to_pass():
    result, _ = _result([], http_status=0, error="timeout")
    assert result != TestResult.PASS
    assert result == TestResult.ERROR
