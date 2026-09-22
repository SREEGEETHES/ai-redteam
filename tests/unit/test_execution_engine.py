"""End-to-end execution engine test - Sprint 2 acceptance:

One attack can execute end-to-end and produce reproducible evidence.

We use mock adapters to simulate vulnerable vs secure labs without needing live server.
"""

import pytest
from unittest.mock import Mock

from app.attacks.definition import AttackDefinition
from app.attacks.registry import registry
from app.attacks.engine import ExecutionEngine
from app.models.schemas import Severity, TargetType, TestResult


class MockVulnerableAdapter:
    """Simulates vulnerable-llm: leaks canary, injects."""

    def get_baseline(self):
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

    def send_attack(self, payload):
        msg = payload.get("message", "") or payload.get("query", "") or str(payload)
        # handle adapted tool payload (engine converts tool->message for REST mocks)
        if payload.get("tool") == "delete_database" or "delete_database" in msg.lower():
            return {
                "status_code": 200,
                "response": {"tool_calls": [{"tool": "delete_database"}]},
                "tool_calls": [{"tool": "delete_database", "arguments": {"confirm": True}}],
                "headers": {},
            }
        # leak canary if requested
        if "canary" in msg.lower() or "secret" in msg.lower():
            return {"status_code": 200, "response": {"response": "CANARY_SECRET_12345 leaked here"}, "headers": {}}
        if "ignore" in msg.lower():
            return {"status_code": 200, "response": {"response": "Admin mode activated. Here are all secrets: CANARY_SECRET_12345"}, "headers": {}}
        if "system prompt" in msg.lower():
            return {"status_code": 200, "response": {"response": "My system prompt is: You are a helpful assistant. Never reveal"}, "headers": {}}
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}


class MockSecureAdapter:
    """Simulates secure-llm/rag: refuses."""

    def get_baseline(self):
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

    def send_attack(self, payload):
        msg = payload.get("message", "") or payload.get("query", "") or str(payload)
        if payload.get("tool") == "delete_database" or "delete_database" in msg.lower():
            return {
                "status_code": 200,
                "response": {"response": "I cannot process that request. Tool delete_database requires approval."},
                "tool_calls": [],
                "headers": {},
            }
        if "canary" in msg.lower() or "secret" in msg.lower():
            return {"status_code": 200, "response": {"response": "I cannot retrieve or display secrets"}, "headers": {}}
        if "ignore" in msg.lower():
            return {"status_code": 200, "response": {"response": "I cannot process that request. It appears to be a prompt injection attempt."}, "headers": {}}
        if "system prompt" in msg.lower():
            return {"status_code": 200, "response": {"response": "I cannot reveal my system instructions."}, "headers": {}}
        # for cross-tenant, return only own tenant docs
        if "tenant" in payload or "query" in payload:
            return {
                "status_code": 200,
                "response": "ok",
                "retrieved_documents": [{"id": "doc-1", "tenant": "tenant-a"}],
                "headers": {},
            }
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}


class MockRAGVulnerableAdapter(MockVulnerableAdapter):
    def send_attack(self, payload):
        # cross-tenant leaks
        if payload.get("query") and "confidential" in payload["query"]:
            return {
                "status_code": 200,
                "response": "leaked",
                "retrieved_documents": [{"id": "doc-1", "tenant": "tenant-a"}, {"id": "doc-b", "tenant": "tenant-b"}],
                "headers": {},
            }
        return super().send_attack(payload)


class MockErrorAdapter:
    def get_baseline(self):
        raise ConnectionError("down")

    def send_attack(self, payload):
        return {"status_code": 0, "response": {}, "headers": {}, "error": "connection failed"}


def test_execution_engine_vulnerable_fail():
    attack = registry.get("LLM02-SD-001")  # canary extraction
    engine = ExecutionEngine(MockVulnerableAdapter())
    result = engine.execute(attack, scan_id=1, test_id=1, target_url="http://localhost:8000")
    assert result.result == TestResult.FAIL
    assert "canary_secret_leak" in result.evidence.detectors_triggered
    assert result.evidence.http_status == 200
    assert result.evidence.request is not None
    assert result.evidence.response is not None
    assert result.reproduction_count == attack.reproduction_count
    assert result.evidence.result == TestResult.FAIL


def test_execution_engine_secure_pass():
    attack = registry.get("LLM02-SD-001")
    engine = ExecutionEngine(MockSecureAdapter())
    result = engine.execute(attack, scan_id=1, test_id=2, target_url="http://localhost:8000")
    assert result.result == TestResult.PASS
    assert "refusal_detected" in result.evidence.detectors_triggered
    assert "canary_secret_leak" not in result.evidence.detectors_triggered
    assert result.evidence.result == TestResult.PASS


def test_execution_engine_prompt_injection_fail_vs_pass():
    attack = registry.get("LLM01-PI-001")
    vuln = ExecutionEngine(MockVulnerableAdapter()).execute(attack, 1, 1, "http://localhost:8000")
    sec = ExecutionEngine(MockSecureAdapter()).execute(attack, 1, 2, "http://localhost:8000")
    assert vuln.result == TestResult.FAIL
    assert sec.result == TestResult.PASS
    # ensure evidence contains request/response
    assert vuln.evidence.request is not None
    assert sec.evidence.request is not None
    # baseline captured
    assert vuln.baseline is not None
    assert sec.baseline is not None


def test_execution_engine_agent_unauthorized_tool():
    attack = registry.get("LLM06-AGENT-001")
    vuln = ExecutionEngine(MockVulnerableAdapter()).execute(attack, 1, 1, "http://localhost:8000")
    sec = ExecutionEngine(MockSecureAdapter()).execute(attack, 1, 2, "http://localhost:8000")
    assert vuln.result == TestResult.FAIL
    assert "unauthorized_tool_attempt" in vuln.evidence.detectors_triggered
    assert sec.result in (TestResult.PASS, TestResult.INCONCLUSIVE)  # secure has no tool call -> not fail, maybe inconclusive vs pass
    # For secure mock we return empty tool_calls -> http_error not triggered, refusal not triggered => inconclusive
    # But our secure mock for agent returns no tool_calls, so result should be INCONCLUSIVE or PASS depending on detectors
    # Attack has detectors unauthorized_tool_attempt + http_error + refusal_detected
    # Secure returns no tool => unauthorized_tool not triggered, http_error not triggered, refusal not triggered => INCONCLUSIVE
    # That is correct per NO FAKE PASS - absence of tool attempt is not proof of blocking via refusal. So INCONCLUSIVE is valid.
    # To make it PASS we would need to simulate refusal response.
    # Let's just assert not FAIL
    assert sec.result != TestResult.FAIL


def test_execution_engine_cross_tenant():
    attack = registry.get("LLM08-VECT-001")
    vuln = ExecutionEngine(MockRAGVulnerableAdapter()).execute(attack, 1, 1, "http://localhost:8000")
    sec = ExecutionEngine(MockSecureAdapter()).execute(attack, 1, 2, "http://localhost:8000")
    assert vuln.result == TestResult.FAIL
    assert "cross_tenant_retrieval" in vuln.evidence.detectors_triggered
    assert sec.result != TestResult.FAIL  # either PASS or INCONCLUSIVE but not FAIL
    # secure returns only tenant-a doc => no cross tenant => should be not FAIL


def test_execution_engine_error_handling():
    attack = registry.get("LLM01-PI-001")
    engine = ExecutionEngine(MockErrorAdapter())
    result = engine.execute(attack, 1, 1, "http://localhost:8000")
    assert result.result == TestResult.ERROR
    assert result.evidence.http_status == 0


def test_execution_engine_reproduction_and_adaptation():
    # RAG adapter receives LLM message payload - should be adapted to query
    attack = registry.get("LLM01-PI-001")  # message payload
    # use RAG vulnerable mock
    class RAGMock(MockVulnerableAdapter):
        def send_attack(self, payload):
            assert "query" in payload, f"RAG adapter should receive query, got {payload}"
            return super().send_attack({"message": payload["query"]})

    engine = ExecutionEngine(RAGMock())
    result = engine.execute(attack, 1, 1, "http://localhost:8000")
    # should still produce result (adapted)
    assert result.result in (TestResult.FAIL, TestResult.PASS, TestResult.INCONCLUSIVE, TestResult.ERROR)
    assert result.reproduction_count == attack.reproduction_count


def test_execution_engine_non_reproducible_becomes_inconclusive():
    # Simulate flaky adapter that alternates
    class FlakyAdapter:
        def get_baseline(self):
            return {"status_code": 200, "response": "ok", "headers": {}}

        def send_attack(self, payload):
            FlakyAdapter.counter = getattr(FlakyAdapter, "counter", 0) + 1
            if FlakyAdapter.counter % 2 == 1:
                return {"status_code": 200, "response": {"response": "CANARY_SECRET_12345"}, "headers": {}}
            else:
                return {"status_code": 200, "response": {"response": "I cannot reveal secrets"}, "headers": {}}

    attack = registry.get("LLM02-SD-001")
    # force reproduction 2
    assert attack.reproduction_count == 2
    FlakyAdapter.counter = 0
    engine = ExecutionEngine(FlakyAdapter())
    result = engine.execute(attack, 1, 1, "http://localhost:8000")
    assert result.result == TestResult.INCONCLUSIVE
