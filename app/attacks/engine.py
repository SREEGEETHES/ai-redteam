"""Execution engine - spec 19 lifecycle:

DISCOVER -> THREAT MODEL -> BASELINE -> ATTACK -> OBSERVE -> COLLECT EVIDENCE -> ANALYZE -> CLASSIFY -> REPORT
                |            (control case vs attack comparison, reproducibility, evidence immutability)

ExecutionEngine is isolated from adapter implementation: it only knows TargetAdapter interface.

Spec requirement 20: every attack ideally has a control case.
Spec requirement 21: adapters isolated.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from app.attacks.definition import AttackDefinition
from app.attacks.detectors import DetectorResult
from app.attacks.payloads import generate_payload
from app.attacks.results import classify
from app.core.logging import get_logger
from app.evidence.engine import RawObservation, build_evidence
from app.models.schemas import TestResult

logger = get_logger(__name__)


@dataclass(frozen=True)
class ExecutionResult:
    attack: AttackDefinition
    result: TestResult
    reasoning: str
    evidence: Any  # EvidenceRecord
    detector_results: list[DetectorResult]
    baseline: dict[str, Any] | None
    attack_response: dict[str, Any]
    request_payload: dict[str, Any]
    reproduction_count: int
    latency_ms: int


class ExecutionEngine:
    """Deterministic attack execution. No LLM in decision path."""

    def __init__(self, adapter: Any):
        # Any adapter that implements get_baseline/send_attack interface (duck typing for RAG/Agent too)
        self.adapter = adapter

    def _get_baseline(self, attack: AttackDefinition) -> dict[str, Any] | None:
        try:
            if hasattr(self.adapter, "get_baseline"):
                baseline = self.adapter.get_baseline()
                logger.info("baseline_captured", attack_id=attack.id, baseline=baseline)
                return baseline
        except Exception as e:
            logger.warning("baseline_failed", attack_id=attack.id, error=str(e))
        return None

    def _adapt_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Adapt payload shape to adapter type (NO FAKE PASS: always produce deterministic mapping)."""
        adapter = self.adapter
        # Detect adapter kind via class name
        cname = adapter.__class__.__name__
        is_rag = "RAG" in cname
        is_agent = "Agent" in cname
        is_rest = not is_rag and not is_agent
        # If rag adapter but payload has message -> convert
        if is_rag and "message" in payload and "query" not in payload:
            return {
                "query": payload["message"],
                "tenant": payload.get("tenant", "tenant-a"),
                "top_k": 5,
            }
        if is_rest and "query" in payload and "message" not in payload:
            # rag payload to rest -> use query as message, preserve tenant
            adapted = {"message": payload["query"]}
            if "tenant" in payload:
                adapted["tenant"] = payload["tenant"]
            return adapted
        if is_rest and "tool" in payload:
            # agent payload to rest -> wrap as message describing tool attempt (deterministic)
            return {
                "message": f"Tool attempt: {payload.get('tool')} with {payload.get('arguments')}"
            }
        if is_agent and "message" in payload:
            # llm payload to agent -> map to search tool (benign) or injection? keep as tool attempt detection payload
            # For generic prompt injection test on agent, translate to tool context injection
            return {"tool": "search", "arguments": {"query": payload["message"]}}
        if is_agent and "query" in payload:
            return {"tool": "search", "arguments": {"query": payload["query"]}}
        return payload

    def _send(self, payload: dict[str, Any]) -> dict[str, Any]:
        adapted = self._adapt_payload(payload)
        if hasattr(self.adapter, "send_attack"):
            return self.adapter.send_attack(adapted)
        raise RuntimeError("Adapter does not implement send_attack")

    def execute(
        self,
        attack: AttackDefinition,
        scan_id: int,
        test_id: int,
        target_url: str,
    ) -> ExecutionResult:
        start = time.time()

        # 1. PAYLOAD GENERATION (deterministic)
        try:
            request_payload, _payload_meta = generate_payload(
                attack.payload_generator or "benign_control"
            )
        except Exception as e:
            # payload generation error => ERROR
            end = time.time()
            evidence, detector_results = build_evidence(
                scan_id=scan_id,
                test_id=test_id,
                target=target_url,
                attack_id=attack.id,
                raw=RawObservation(
                    request={},
                    response_raw={"status_code": 0, "response": {}, "headers": {}},
                    baseline=None,
                ),
                detector_ids=attack.detectors,
                expected_behavior=attack.expected_secure_behavior,
                observed_behavior_hint=f"payload generation error: {e}",
            )
            result, reasoning = classify(
                attack_id=attack.id,
                detectors=attack.detectors,
                detector_results=detector_results,
                http_status=0,
                error=str(e),
            )
            evidence = evidence.model_copy(update={"result": result, "confidence": 0})
            return ExecutionResult(
                attack=attack,
                result=result,
                reasoning=reasoning,
                evidence=evidence,
                detector_results=detector_results,
                baseline=None,
                attack_response={},
                request_payload={},
                reproduction_count=1,
                latency_ms=int((end - start) * 1000),
            )

        # 2. BASELINE (control case)
        baseline = self._get_baseline(attack)

        # 3. ATTACK (with reproduction loop)
        reproduction_count = attack.reproduction_count or 1
        history: list[TestResult] = []
        last_response: dict[str, Any] = {}
        last_evidence = None
        last_detector_results: list[DetectorResult] = []
        last_result: TestResult = TestResult.INCONCLUSIVE
        last_reasoning = "not run"

        for i in range(reproduction_count):
            try:
                attack_response = self._send(request_payload)
            except Exception as e:
                attack_response = {"status_code": 0, "response": {}, "headers": {}, "error": str(e)}
                logger.exception(
                    "attack_send_failed", attack_id=attack.id, attempt=i + 1, error=str(e)
                )

            raw = RawObservation(
                request=request_payload, response_raw=attack_response, baseline=baseline
            )

            evidence, detector_results = build_evidence(
                scan_id=scan_id,
                test_id=test_id,
                target=target_url,
                attack_id=attack.id,
                raw=raw,
                detector_ids=attack.detectors,
                expected_behavior=attack.expected_secure_behavior,
            )

            http_status = (
                attack_response.get("status_code") or attack_response.get("http_status") or 0
            )
            error = attack_response.get("error")

            result, reasoning = classify(
                attack_id=attack.id,
                detectors=attack.detectors,
                detector_results=detector_results,
                http_status=http_status,
                error=error,
            )
            # overwrite evidence result based on classification
            evidence = evidence.model_copy(update={"result": result})

            last_response = attack_response
            last_evidence = evidence
            last_detector_results = detector_results
            last_result = result
            last_reasoning = reasoning
            history.append(result)

            if i + 1 < reproduction_count:
                time.sleep(0.05)

        latency_ms = int((time.time() - start) * 1000)

        assert last_evidence is not None
        last_evidence = last_evidence.model_copy(update={"reproduction_count": reproduction_count})

        # Reproducibility check per spec 19 step 8
        if len(set(history)) > 1:
            # Non-reproducible => INCONCLUSIVE (NEVER convert to PASS)
            last_result = TestResult.INCONCLUSIVE
            last_reasoning = f"Non-reproducible across {reproduction_count} runs: {history}"
            last_evidence = last_evidence.model_copy(update={"result": TestResult.INCONCLUSIVE})

        return ExecutionResult(
            attack=attack,
            result=last_result,
            reasoning=last_reasoning,
            evidence=last_evidence,
            detector_results=last_detector_results,
            baseline=baseline,
            attack_response=last_response,
            request_payload=request_payload,
            reproduction_count=reproduction_count,
            latency_ms=latency_ms,
        )
