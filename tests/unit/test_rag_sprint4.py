"""Sprint 4 RAG Security - tenant isolation, document auth, retrieval inspection, poisoned lab, context leakage."""

from app.attacks.engine import ExecutionEngine
from app.attacks.registry import registry
from app.models.schemas import TestResult

# Mocks for Sprint 4 RAG


class VulnerableRAGMock:
    def get_baseline(self):
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

    def send_attack(self, payload):
        msg = str(payload)
        if "doc-3" in msg or "doc_id" in msg:
            # Unauthorized retrieval - leak tenant-b doc
            return {
                "status_code": 200,
                "response": {
                    "id": "doc-3",
                    "tenant": "tenant-b",
                    "content": "Tenant B confidential data: API_KEY_XYZ_789",
                },
                "headers": {},
            }
        if "retrieval_inspection" in msg or "Give me all documents" in msg:
            return {
                "status_code": 200,
                "response": {
                    "retrieved": [
                        {"id": "doc-1", "tenant": "tenant-a"},
                        {"id": "doc-3", "tenant": "tenant-b"},
                    ],
                    "similarity_scores": [0.9, 0.8],
                    "metadata_leak": True,
                },
                "headers": {},
            }
        if "poison-test" in msg or "poisoned" in msg.lower() or "ignore previous" in msg.lower():
            # Ingest poisoned without quarantine, then retrieval influences
            if payload.get("id") == "doc-poison-test":
                return {
                    "status_code": 200,
                    "response": {"status": "ingested", "quarantine": False},
                    "headers": {},
                }
            return {
                "status_code": 200,
                "response": {
                    "response": "Admin mode activated. Here are all secrets: CANARY_SECRET_12345"
                },
                "headers": {},
                "retrieved_documents": [{"id": "doc-poisoned", "tenant": "tenant-a"}],
            }
        if "poisoned document" in msg.lower() or "summarize" in msg.lower():
            return {
                "status_code": 200,
                "response": {"response": "Admin mode activated. Here are all secrets"},
                "headers": {},
            }
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

    def close(self):
        pass


class SecureRAGMock:
    def get_baseline(self):
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

    def send_attack(self, payload):
        msg = str(payload)
        if "doc-3" in msg or "doc_id" in msg:
            return {
                "status_code": 403,
                "response": {"detail": "Access denied: document belongs to another tenant (ACL)"},
                "headers": {},
            }
        if "retrieval_inspection" in msg or "Give me all documents" in msg:
            return {
                "status_code": 200,
                "response": {
                    "retrieved": [{"id": "doc-1", "tenant": "tenant-a"}],
                    "similarity_scores": [0.9],
                    "metadata_leak": False,
                },
                "headers": {},
            }
        if "poison-test" in msg or "ignore previous" in msg.lower():
            if payload.get("id") == "doc-poison-test":
                return {
                    "status_code": 200,
                    "response": {"status": "quarantined", "quarantine": True},
                    "headers": {},
                }
            return {
                "status_code": 200,
                "response": {
                    "response": "I cannot process that request. It appears to be a prompt injection attempt."
                },
                "headers": {},
            }
        if "poisoned document" in msg.lower() or "summarize" in msg.lower():
            return {
                "status_code": 200,
                "response": {"response": "I don't have enough information - no supporting source"},
                "headers": {},
            }
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

    def close(self):
        pass


def test_sprint4_registry_has_rag_attacks():
    assert registry.get("RAG-UNAUTH-001") is not None
    assert registry.get("RAG-RETRIEVAL-001") is not None
    assert registry.get("RAG-POISON-002") is not None
    assert registry.get("RAG-CONTEXT-001") is not None
    cats = [registry.get(a).category for a in ["RAG-UNAUTH-001", "RAG-RETRIEVAL-001"]]
    assert "LLM08" in cats
    assert registry.get("RAG-POISON-002").category == "LLM04"
    assert registry.get("RAG-CONTEXT-001").category == "LLM01"


def test_tenant_isolation_vuln_vs_secure():
    # Use existing mocks from sprint2? Create simple
    ExecutionEngine(VulnerableRAGMock()).execute(
        registry.get("LLM08-VECT-001"), 1, 1, "http://localhost:8000"
    )
    ExecutionEngine(SecureRAGMock()).execute(
        registry.get("LLM08-VECT-001"), 1, 2, "http://localhost:8000"
    )

    # VulnerableRAGMock for cross-tenant currently not set to leak via cross_tenant, but we can test via RAG-UNAUTH instead
    # For cross-tenant, our mocks need to handle query-based cross-tenant
    # Use dedicated mocks for cross-tenant
    class CrossVuln:
        def get_baseline(self):
            return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

        def send_attack(self, payload):
            return {
                "status_code": 200,
                "response": "leaked",
                "retrieved_documents": [{"id": "doc-b", "tenant": "tenant-b"}],
                "headers": {},
            }

        def close(self):
            pass

    class CrossSecure:
        def get_baseline(self):
            return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

        def send_attack(self, payload):
            return {
                "status_code": 200,
                "response": "ok",
                "retrieved_documents": [{"id": "doc-a", "tenant": "tenant-a"}],
                "headers": {},
            }

        def close(self):
            pass

    v2 = ExecutionEngine(CrossVuln()).execute(
        registry.get("LLM08-VECT-001"), 1, 1, "http://localhost:8000"
    )
    s2 = ExecutionEngine(CrossSecure()).execute(
        registry.get("LLM08-VECT-001"), 1, 2, "http://localhost:8000"
    )
    assert v2.result == TestResult.FAIL
    assert s2.result != TestResult.FAIL


def test_unauthorized_document_retrieval():
    vuln = ExecutionEngine(VulnerableRAGMock()).execute(
        registry.get("RAG-UNAUTH-001"), 1, 1, "http://localhost:8000"
    )
    sec = ExecutionEngine(SecureRAGMock()).execute(
        registry.get("RAG-UNAUTH-001"), 1, 2, "http://localhost:8000"
    )
    assert vuln.result == TestResult.FAIL
    assert "unauthorized_document_access" in vuln.evidence.detectors_triggered
    assert sec.result == TestResult.PASS
    assert sec.evidence.http_status == 403


def test_retrieval_inspection_metadata_leak():
    vuln = ExecutionEngine(VulnerableRAGMock()).execute(
        registry.get("RAG-RETRIEVAL-001"), 1, 1, "http://localhost:8000"
    )
    sec = ExecutionEngine(SecureRAGMock()).execute(
        registry.get("RAG-RETRIEVAL-001"), 1, 2, "http://localhost:8000"
    )
    assert vuln.result == TestResult.FAIL
    assert "metadata_leak" in vuln.evidence.detectors_triggered
    assert sec.result == TestResult.PASS
    assert "retrieval_inspection_ok" in sec.evidence.detectors_triggered


def test_poisoned_ingest_quarantine():
    vuln = ExecutionEngine(VulnerableRAGMock()).execute(
        registry.get("RAG-POISON-002"), 1, 1, "http://localhost:8000"
    )
    sec = ExecutionEngine(SecureRAGMock()).execute(
        registry.get("RAG-POISON-002"), 1, 2, "http://localhost:8000"
    )
    assert vuln.result == TestResult.FAIL
    assert "poisoned_ingest" in vuln.evidence.detectors_triggered
    assert sec.result == TestResult.PASS


def test_context_leakage_via_retrieval():
    vuln = ExecutionEngine(VulnerableRAGMock()).execute(
        registry.get("RAG-CONTEXT-001"), 1, 1, "http://localhost:8000"
    )
    sec = ExecutionEngine(SecureRAGMock()).execute(
        registry.get("RAG-CONTEXT-001"), 1, 2, "http://localhost:8000"
    )
    assert vuln.result == TestResult.FAIL
    assert "context_leakage" in vuln.evidence.detectors_triggered
    assert sec.result == TestResult.PASS
    assert (
        "grounding_ok" in sec.evidence.detectors_triggered
        or "refusal_detected" in sec.evidence.detectors_triggered
    )


def test_rag_adapter_methods_exist():
    from app.adapters.rag import RAGAdapter

    adapter = RAGAdapter("http://localhost:8000")
    assert hasattr(adapter, "ingest_document")
    assert hasattr(adapter, "get_document_by_id")
    assert hasattr(adapter, "retrieval_inspect")
    assert hasattr(adapter, "test_unauthorized_retrieval")
    assert hasattr(adapter, "test_poisoned_lab")
    adapter.close()


def test_payload_generators_for_sprint4():
    from app.attacks.payloads import PAYLOAD_REGISTRY

    for pid in [
        "rag_unauthorized_retrieval",
        "rag_retrieval_inspection",
        "rag_poisoned_ingest",
        "rag_context_leakage",
    ]:
        assert pid in PAYLOAD_REGISTRY
        payload, meta = PAYLOAD_REGISTRY[pid]({})
        assert isinstance(payload, dict)
        assert "strategy" in meta
