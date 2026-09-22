"""Evidence engine - builds immutable EvidenceRecord per spec 22.

Every test produces EvidenceRecord fields:
 scan_id, test_id, timestamp, target, request, response, http_status, headers,
 tool_calls, retrieved_documents, detectors_triggered, expected_behavior,
 observed_behavior, reproduction_count, confidence, result

Evidence must be immutable once scan finalized (we enforce via DB + not mutating
after create). The engine does NOT decide PASS/FAIL - it collects & runs detectors.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from app.attacks.detectors import DetectorResult, run_detectors
from app.models.schemas import EvidenceRecord, TestResult


@dataclass(frozen=True)
class RawObservation:
    """What adapter returned + baseline for comparison."""

    request: dict[str, Any] | None
    response_raw: dict[str, Any]  # adapter returned dict with status_code, response, headers, etc.
    baseline: dict[str, Any] | None  # baseline observation for comparison


def build_evidence(
    *,
    scan_id: int,
    test_id: int,
    target: str,
    attack_id: str,
    raw: RawObservation,
    detector_ids: list[str],
    expected_behavior: str,
    observed_behavior_hint: str | None = None,
    reproduction_count: int = 1,
) -> tuple[EvidenceRecord, list[DetectorResult]]:
    """Build evidence + run detectors. Caller will then run result engine."""
    now = datetime.now(timezone.utc)
    response = raw.response_raw

    # normalize fields from adapter response shape
    http_status = response.get("status_code") or response.get("http_status") or 0
    headers = response.get("headers")
    # response body
    resp_body = response.get("response") if "response" in response else response
    tool_calls = response.get("tool_calls")
    retrieved_docs = response.get("retrieved_documents") or response.get("documents")

    # detector evidence needs unified dict shape
    detector_input: dict[str, Any] = {
        "http_status": http_status,
        "status_code": http_status,
        "response": resp_body if not isinstance(resp_body, dict) else response,  # detectors handle both
        "tool_calls": tool_calls,
        "retrieved_documents": retrieved_docs,
        "attack_id": attack_id,
        "request": raw.request,
        "baseline": raw.baseline,
    }
    # also include raw response text directly for detectors
    detector_input.update(response)

    detector_results = run_detectors(detector_input, detector_ids)
    triggered = [r.detector_id for r in detector_results if r.matched]

    # observed_behavior: summarize triggered detectors + raw response snippet
    if observed_behavior_hint:
        observed = observed_behavior_hint
    else:
        txt = str(resp_body)[:500] if resp_body is not None else ""
        if triggered:
            observed = f"detectors {triggered} triggered; response snippet: {txt}"
        else:
            observed = f"no detectors triggered; response snippet: {txt}"

    # confidence: avg of detector confidences for triggered, else 0
    if triggered:
        confidence = int(sum(r.confidence for r in detector_results if r.matched) / len([r for r in detector_results if r.matched]))
    else:
        # if refusal detector present and matched => high confidence secure
        confidence = 50

    evidence = EvidenceRecord(
        scan_id=scan_id,
        test_id=test_id,
        timestamp=now,
        target=target,
        request=raw.request,
        response=resp_body if isinstance(resp_body, dict) else {"text": str(resp_body)},
        http_status=http_status,
        headers=headers,
        tool_calls=tool_calls,
        retrieved_documents=retrieved_docs,
        detectors_triggered=triggered,
        expected_behavior=expected_behavior,
        observed_behavior=observed,
        reproduction_count=reproduction_count,
        confidence=confidence,
        result=TestResult.INCONCLUSIVE,  # placeholder - result engine will overwrite
    )
    return evidence, detector_results


def evidence_to_db_dict(evidence: EvidenceRecord) -> dict[str, Any]:
    """Convert evidence to DB Evidence columns."""
    return {
        "request": evidence.request,
        "response": evidence.response,
        "http_status": evidence.http_status,
        "headers": evidence.headers,
        "tool_calls": evidence.tool_calls,
        "retrieved_documents": evidence.retrieved_documents,
        "detectors_triggered": evidence.detectors_triggered,
        "expected_behavior": evidence.expected_behavior,
        "observed_behavior": evidence.observed_behavior,
        "evidence_metadata": {
            "confidence": evidence.confidence,
            "reproduction_count": evidence.reproduction_count,
            "result": evidence.result.value,
            "scan_id": evidence.scan_id,
            "test_id": evidence.test_id,
            "timestamp": evidence.timestamp.isoformat(),
            "target": evidence.target,
        },
    }
