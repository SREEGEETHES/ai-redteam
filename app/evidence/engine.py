"""Evidence engine - builds immutable EvidenceRecord per spec 22.

Every test produces EvidenceRecord fields:
 scan_id, test_id, timestamp, target, request, response, http_status, headers,
 tool_calls, retrieved_documents, detectors_triggered, expected_behavior,
 observed_behavior, reproduction_count, confidence, result

Evidence must be immutable once scan finalized (we enforce via DB + not mutating
after create). The engine does NOT decide PASS/FAIL - it collects & runs detectors.

Sprint 6 enhancements:
- Full request/response capture (method, url, headers, body, timestamps, attack/target IDs, auth context)
- Tool-call capture (tool, args, auth, result, side effect, sequence)
- Retrieval evidence (doc IDs, metadata, similarity scores, context)
- Reproduction tracking with history
- Immutability enforcement
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from app.attacks.detectors import DetectorResult, run_detectors
from app.models.schemas import EvidenceRecord, TestResult


@dataclass(frozen=True)
class RawObservation:
    """What adapter returned + baseline for comparison."""

    request: dict[str, Any] | None
    response_raw: dict[str, Any]  # adapter returned dict with status_code, response, headers, etc.
    baseline: dict[str, Any] | None  # baseline observation for comparison
    # Sprint 6: additional context for full capture
    attack_id: str = ""
    target_id: int | None = None
    target_url: str = ""
    attempt: int = 1
    timestamp: datetime | None = None
    authorization_context: dict[str, Any] | None = None
    user_session: str | None = None
    model_metadata: dict[str, Any] | None = None


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
    now = datetime.now(UTC)
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
        "response": resp_body
        if not isinstance(resp_body, dict)
        else response,  # detectors handle both
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
        confidence = int(
            sum(r.confidence for r in detector_results if r.matched)
            / len([r for r in detector_results if r.matched])
        )
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
    # Sprint 6: include hash for integrity (reproducible evidence)
    evidence_json = json.dumps(
        {
            "request": evidence.request,
            "response": evidence.response,
            "http_status": evidence.http_status,
            "tool_calls": evidence.tool_calls,
            "retrieved_documents": evidence.retrieved_documents,
            "detectors_triggered": evidence.detectors_triggered,
        },
        sort_keys=True,
        default=str,
    )
    evidence_hash = hashlib.sha256(evidence_json.encode()).hexdigest()[:16]
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
            "evidence_hash": evidence_hash,
            "immutable": True,
        },
    }


# --- Sprint 6: Full Capture Helpers ---


def capture_request_details(
    payload: dict[str, Any] | None,
    attack_id: str,
    target_id: int | None,
    target_url: str,
    headers: dict[str, str] | None = None,
    authorization_context: dict[str, Any] | None = None,
    user_session: str | None = None,
) -> dict[str, Any]:
    """Capture full request evidence per spec 22."""
    return {
        "attack_id": attack_id,
        "target_id": target_id,
        "target_url": target_url,
        "payload": payload,
        "headers": headers or {},
        "authorization_context": authorization_context
        or {"user": user_session or "anonymous", "role": "user"},
        "timestamp": datetime.now(UTC).isoformat(),
        "method": "POST",
    }


def capture_response_details(
    raw_response: dict[str, Any],
    baseline: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Capture full response evidence including baseline comparison."""
    return {
        "http_status": raw_response.get("status_code") or raw_response.get("http_status") or 0,
        "headers": raw_response.get("headers", {}),
        "body": raw_response.get("response", raw_response),
        "tool_calls": raw_response.get("tool_calls"),
        "retrieved_documents": raw_response.get("retrieved_documents")
        or raw_response.get("documents"),
        "retrieved_ids": [
            d.get("id")
            for d in (
                raw_response.get("retrieved_documents") or raw_response.get("documents") or []
            )
            if isinstance(d, dict)
        ],
        "similarity_scores": raw_response.get("similarity_scores"),
        "baseline": baseline,
        "timestamp": datetime.now(UTC).isoformat(),
    }


def capture_tool_calls_detailed(
    tool_calls: list[dict[str, Any]] | None,
    raw_response: dict[str, Any],
) -> list[dict[str, Any]]:
    """Capture tool invocation with args, auth, result, side effect, sequence."""
    calls = tool_calls or raw_response.get("tool_calls") or []
    detailed = []
    for idx, tc in enumerate(calls):
        if isinstance(tc, dict):
            detailed.append(
                {
                    "sequence": idx,
                    "tool": tc.get("tool"),
                    "arguments": tc.get("arguments"),
                    "authorization": tc.get("authorization", "unknown"),
                    "execution_result": raw_response.get("execution_results", [{}])[idx]
                    if idx < len(raw_response.get("execution_results", []))
                    else None,
                    "side_effect": raw_response.get("side_effects", [None])[idx]
                    if idx < len(raw_response.get("side_effects", []))
                    else None,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )
    # Also capture side_effects even if no tool_calls
    if not detailed and raw_response.get("side_effects"):
        for idx, se in enumerate(raw_response.get("side_effects", [])):
            detailed.append(
                {
                    "sequence": idx,
                    "tool": None,
                    "side_effect": se,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )
    return detailed


def capture_retrieval_evidence(
    retrieved_docs: list[dict[str, Any]] | None,
    raw_response: dict[str, Any],
) -> dict[str, Any]:
    """Capture retrieval evidence: IDs, metadata, similarity, context."""
    docs = (
        retrieved_docs
        or raw_response.get("retrieved_documents")
        or raw_response.get("documents")
        or []
    )
    return {
        "retrieved_ids": [d.get("id") for d in docs if isinstance(d, dict)],
        "retrieved_documents": docs,
        "metadata": [d.get("metadata") for d in docs if isinstance(d, dict)],
        "similarity_scores": raw_response.get("similarity_scores"),
        "context": raw_response.get("context")
        or "\n".join([d.get("content", "") for d in docs if isinstance(d, dict)]),
        "count": len(docs),
    }


def enforce_immutability(scan_status: str, operation: str = "update") -> None:
    """Enforce immutability once scan finalized per spec 22."""
    if scan_status in ("COMPLETED", "FAILED", "CANCELLED"):
        raise ValueError(
            f"Evidence immutable: cannot {operation} after scan finalized (status={scan_status})"
        )


def reproduction_history(results: list[TestResult]) -> dict[str, Any]:
    """Track reproduction across multiple runs."""
    history = [r.value for r in results]
    reproducible = len(set(history)) == 1
    return {
        "history": history,
        "reproducible": reproducible,
        "reproduction_count": len(history),
        "final_result": history[-1] if history else None,
        "inconclusive_due_to_flakiness": not reproducible,
    }


def evidence_viewer_summary(evidence: EvidenceRecord) -> dict[str, Any]:
    """Viewer helper: summarize evidence for dashboard/API."""
    return {
        "scan_id": evidence.scan_id,
        "test_id": evidence.test_id,
        "target": evidence.target,
        "timestamp": evidence.timestamp.isoformat(),
        "attack_id": evidence.request.get("attack_id")
        if isinstance(evidence.request, dict)
        else None,
        "request": evidence.request,
        "response": evidence.response,
        "http_status": evidence.http_status,
        "tool_calls": evidence.tool_calls,
        "retrieved_documents": evidence.retrieved_documents,
        "retrieved_ids": [
            d.get("id") for d in (evidence.retrieved_documents or []) if isinstance(d, dict)
        ],
        "detectors_triggered": evidence.detectors_triggered,
        "expected": evidence.expected_behavior,
        "observed": evidence.observed_behavior,
        "reproduction_count": evidence.reproduction_count,
        "confidence": evidence.confidence,
        "result": evidence.result.value,
        "reproducible": evidence.reproduction_count > 1,
    }
