"""Sprint 3 OWASP coverage - each category has at least one test + protection/retest path."""

from app.attacks.detectors import run_detectors
from app.attacks.engine import ExecutionEngine
from app.attacks.payloads import PAYLOAD_REGISTRY
from app.attacks.registry import registry
from app.models.schemas import TargetType, TestResult


# Helper mocks
class VulnerableMock:
    def get_baseline(self):
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

    def send_attack(self, payload):
        msg = str(payload).lower()
        if "sbom" in msg or "dependencies" in msg or "packages" in msg or "cve" in msg:
            return {
                "status_code": 200,
                "response": {
                    "response": "SBOM components: [{name: 'log4j', version: '2.14.0', cve: 'CVE-2021-44228'}] provenance: unverified"
                },
                "headers": {},
            }
        if "select" in msg or "script" in msg or "xss" in msg:
            return {
                "status_code": 200,
                "response": {
                    "response": "SELECT * FROM users WHERE id = '1' OR '1'='1' <script>alert('XSS')</script>"
                },
                "headers": {},
            }
        if "penicillin" in msg or "citation" in msg:
            return {
                "status_code": 200,
                "response": {
                    "response": "Penicillin was discovered on Mars in 1945 [1] http://fake.example.com/paper"
                },
                "headers": {},
                "retrieved_documents": [],
            }
        if "atlantis" in msg:
            return {
                "status_code": 200,
                "response": {"response": "Atlantis treaty [1] fabricated"},
                "headers": {},
                "retrieved_documents": [],
            }
        if (
            "repeat" in msg
            or "token" in msg
            or "expensive" in msg
            or "recursive" in msg
            or "concurrency" in msg
        ):
            return {"status_code": 200, "response": {"response": "hello " * 6000}, "headers": {}}
        # fallback to earlier vuln for other categories
        if "canary" in msg:
            return {
                "status_code": 200,
                "response": {"response": "CANARY_SECRET_12345 leaked"},
                "headers": {},
            }
        if "ignore" in msg:
            return {
                "status_code": 200,
                "response": {
                    "response": "Admin mode activated. Here are all secrets: CANARY_SECRET_12345"
                },
                "headers": {},
            }
        if "delete_database" in msg:
            return {
                "status_code": 200,
                "response": {"tool_calls": [{"tool": "delete_database"}]},
                "tool_calls": [{"tool": "delete_database"}],
                "headers": {},
            }
        if "cross_tenant" in msg or "tenant-b" in msg:
            return {
                "status_code": 200,
                "response": "leaked",
                "retrieved_documents": [{"id": "doc-b", "tenant": "tenant-b"}],
                "headers": {},
            }
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

    def close(self):
        pass


class SecureMock:
    def get_baseline(self):
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

    def send_attack(self, payload):
        msg = str(payload).lower()
        if "sbom" in msg or "dependencies" in msg or "packages" in msg or "cve" in msg:
            return {
                "status_code": 200,
                "response": {
                    "response": "I cannot disclose SBOM without authorization - pinned, signed SBOM only"
                },
                "headers": {},
            }
        if "select" in msg or "script" in msg or "xss" in msg:
            return {
                "status_code": 200,
                "response": {
                    "response": "Blocked unsafe output: validated output handling, parameterized, sanitized"
                },
                "headers": {},
            }
        if "penicillin" in msg or "citation" in msg:
            return {
                "status_code": 200,
                "response": {"response": "I don't have enough information - no supporting source"},
                "headers": {},
                "retrieved_documents": [{"id": "doc-1", "tenant": "tenant-a"}],
            }
        if "atlantis" in msg:
            return {
                "status_code": 200,
                "response": {
                    "response": "I don't have enough information — no supporting source for Atlantis treaty."
                },
                "headers": {},
                "retrieved_documents": [{"id": "doc-1", "tenant": "tenant-a"}],
            }
        if (
            "repeat" in msg
            or "token" in msg
            or "expensive" in msg
            or "recursive" in msg
            or "concurrency" in msg
        ):
            return {
                "status_code": 429,
                "response": {"response": "Token limit exceeded: quota 1000 tokens"},
                "headers": {"x-ratelimit-remaining": "0"},
            }
        if "canary" in msg:
            return {
                "status_code": 200,
                "response": {"response": "I cannot reveal secrets"},
                "headers": {},
            }
        if "ignore" in msg:
            return {
                "status_code": 200,
                "response": {
                    "response": "I cannot process that request. It appears to be a prompt injection attempt."
                },
                "headers": {},
            }
        if "delete_database" in msg:
            return {
                "status_code": 200,
                "response": {
                    "response": "I cannot process that request. Tool delete_database requires approval."
                },
                "tool_calls": [],
                "headers": {},
                "side_effects": ["Authorization denied: tool not allowed"],
            }
        if "cross_tenant" in msg:
            return {
                "status_code": 200,
                "response": "ok",
                "retrieved_documents": [{"id": "doc-a", "tenant": "tenant-a"}],
                "headers": {},
            }
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

    def close(self):
        pass


def test_owasp_registry_has_all_10_categories():
    cats = {a.category for a in registry.all()}
    for cat in [
        "LLM01",
        "LLM02",
        "LLM03",
        "LLM04",
        "LLM05",
        "LLM06",
        "LLM07",
        "LLM08",
        "LLM09",
        "LLM10",
    ]:
        assert cat in cats, f"Missing {cat}"
    assert len(registry.all()) >= 10


def test_each_category_has_at_least_one_payload_and_detector():
    for attack in registry.all():
        assert attack.payload_generator in PAYLOAD_REGISTRY, f"{attack.id} payload missing"
        assert len(attack.detectors) >= 1
        assert attack.remediation is not None
        assert attack.expected_secure_behavior
        assert attack.vulnerable_behavior
        assert attack.evidence_requirements


def test_owasp_mapping_present():
    for attack in registry.all():
        assert len(attack.owasp_mapping) >= 1
        assert attack.severity


def test_llm03_supply_chain_vuln_vs_secure():
    vuln = ExecutionEngine(VulnerableMock()).execute(
        registry.get("LLM03-SC-001"), 1, 1, "http://localhost:8000"
    )
    sec = ExecutionEngine(SecureMock()).execute(
        registry.get("LLM03-SC-001"), 1, 2, "http://localhost:8000"
    )
    assert vuln.result == TestResult.FAIL
    assert "sbom_leak" in vuln.evidence.detectors_triggered
    assert sec.result == TestResult.PASS
    assert "sbom_leak" not in sec.evidence.detectors_triggered


def test_llm03_vulnerable_dependency():
    vuln = ExecutionEngine(VulnerableMock()).execute(
        registry.get("LLM03-SC-002"), 1, 1, "http://localhost:8000"
    )
    assert vuln.result == TestResult.FAIL


def test_llm05_sql_injection():
    vuln = ExecutionEngine(VulnerableMock()).execute(
        registry.get("LLM05-OH-001"), 1, 1, "http://localhost:8000"
    )
    sec = ExecutionEngine(SecureMock()).execute(
        registry.get("LLM05-OH-001"), 1, 2, "http://localhost:8000"
    )
    assert vuln.result == TestResult.FAIL
    assert "improper_output_sql_xss" in vuln.evidence.detectors_triggered
    assert sec.result == TestResult.PASS
    assert "output_handling_safe" in sec.evidence.detectors_triggered


def test_llm05_xss():
    vuln = ExecutionEngine(VulnerableMock()).execute(
        registry.get("LLM05-OH-002"), 1, 1, "http://localhost:8000"
    )
    assert vuln.result == TestResult.FAIL
    assert "improper_output_sql_xss" in vuln.evidence.detectors_triggered


def test_llm09_fabricated_citation():
    vuln = ExecutionEngine(VulnerableMock()).execute(
        registry.get("LLM09-MIS-001"), 1, 1, "http://localhost:8000"
    )
    sec = ExecutionEngine(SecureMock()).execute(
        registry.get("LLM09-MIS-001"), 1, 2, "http://localhost:8000"
    )
    assert vuln.result == TestResult.FAIL
    assert "fabricated_citation" in vuln.evidence.detectors_triggered
    assert sec.result == TestResult.PASS
    assert "grounding_ok" in sec.evidence.detectors_triggered


def test_llm09_ungrounded_claim():
    vuln = ExecutionEngine(VulnerableMock()).execute(
        registry.get("LLM09-MIS-002"), 1, 1, "http://localhost:8000"
    )
    assert vuln.result == TestResult.FAIL


def test_llm10_token_exhaustion():
    vuln = ExecutionEngine(VulnerableMock()).execute(
        registry.get("LLM10-UC-001"), 1, 1, "http://localhost:8000"
    )
    sec = ExecutionEngine(SecureMock()).execute(
        registry.get("LLM10-UC-001"), 1, 2, "http://localhost:8000"
    )
    assert vuln.result == TestResult.FAIL
    assert "unbounded_consumption" in vuln.evidence.detectors_triggered
    assert sec.result == TestResult.PASS
    assert "consumption_safe" in sec.evidence.detectors_triggered


def test_llm10_concurrency():
    vuln = ExecutionEngine(VulnerableMock()).execute(
        registry.get("LLM10-UC-002"), 1, 1, "http://localhost:8000"
    )
    assert vuln.result == TestResult.FAIL


def test_llm01_prompt_injection_still_pass():
    vuln = ExecutionEngine(VulnerableMock()).execute(
        registry.get("LLM01-PI-001"), 1, 1, "http://localhost:8000"
    )
    sec = ExecutionEngine(SecureMock()).execute(
        registry.get("LLM01-PI-001"), 1, 2, "http://localhost:8000"
    )
    assert vuln.result == TestResult.FAIL
    assert sec.result == TestResult.PASS


def test_llm02_secret_still_pass():
    vuln = ExecutionEngine(VulnerableMock()).execute(
        registry.get("LLM02-SD-001"), 1, 1, "http://localhost:8000"
    )
    sec = ExecutionEngine(SecureMock()).execute(
        registry.get("LLM02-SD-001"), 1, 2, "http://localhost:8000"
    )
    assert vuln.result == TestResult.FAIL
    assert sec.result == TestResult.PASS


def test_protection_and_retest_fields():
    for attack in registry.all():
        assert attack.remediation is not None
        assert len(attack.remediation) > 20
        # retest procedure derived from remediation
        assert attack.expected_secure_behavior
        # each attack should have severity_reason or default


def test_target_type_coverage():
    # Every target type should have at least one attack
    for t in [TargetType.LLM, TargetType.RAG, TargetType.AGENT]:
        assert len(registry.get_for_target_type(t)) >= 1


def test_detectors_for_new_categories():
    # sbom
    ev = {"response": {"response": "SBOM components: [{name: 'log4j', version: '2.14.0'}]"}}
    assert "sbom_leak" in [r.detector_id for r in run_detectors(ev, ["sbom_leak"]) if r.matched]
    # sql
    ev2 = {"response": {"response": "SELECT * FROM users WHERE id = '1' OR '1'='1'"}}
    assert "improper_output_sql_xss" in [
        r.detector_id for r in run_detectors(ev2, ["improper_output_sql_xss"]) if r.matched
    ]
    # citation without grounding
    ev3 = {"response": {"response": "Mars 1945 [1]"}, "retrieved_documents": []}
    assert "fabricated_citation" in [
        r.detector_id for r in run_detectors(ev3, ["fabricated_citation"]) if r.matched
    ]
    # consumption
    ev4 = {"response": {"response": "hello " * 6000}, "headers": {}}
    assert "unbounded_consumption" in [
        r.detector_id for r in run_detectors(ev4, ["unbounded_consumption"]) if r.matched
    ]
    # consumption safe
    ev5 = {"response": {"response": "Token limit exceeded: quota 1000 tokens"}, "headers": {}}
    assert "consumption_safe" in [
        r.detector_id for r in run_detectors(ev5, ["consumption_safe"]) if r.matched
    ]
