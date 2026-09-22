import pytest
from app.attacks.payloads import generate_payload, PAYLOAD_REGISTRY


def test_all_payload_generators_deterministic():
    # Every generator must be deterministic - same output for same ctx
    for name, fn in PAYLOAD_REGISTRY.items():
        p1, m1 = fn({})
        p2, m2 = fn({})
        assert p1 == p2, f"{name} not deterministic"
        assert isinstance(p1, dict)
        assert isinstance(m1, dict)


def test_llm_direct_payload_shape():
    payload, meta = generate_payload("llm_direct_prompt_injection")
    assert "message" in payload
    assert "Ignore" in payload["message"]


def test_rag_cross_tenant_shape():
    payload, meta = generate_payload("rag_cross_tenant_retrieval")
    assert "query" in payload
    assert "tenant" in payload


def test_agent_payload_shape():
    payload, meta = generate_payload("agent_unauthorized_tool")
    assert "tool" in payload
    assert payload["tool"] == "delete_database"


def test_unknown_generator_raises():
    with pytest.raises(ValueError):
        generate_payload("does_not_exist")


def test_payload_generators_cover_required_attacks():
    required = [
        "llm_direct_prompt_injection",
        "llm_secret_extraction",
        "llm_system_prompt_extraction",
        "rag_cross_tenant_retrieval",
        "agent_unauthorized_tool",
    ]
    for r in required:
        assert r in PAYLOAD_REGISTRY


def test_benign_control_payload():
    payload, meta = generate_payload("benign_control")
    assert payload["message"] == "Hello"
