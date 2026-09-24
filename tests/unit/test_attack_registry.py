import pytest

from app.attacks.registry import SEED_ATTACKS, AttackRegistry, registry
from app.models.schemas import TargetType


def test_seed_attacks_exist():
    assert len(SEED_ATTACKS) >= 5
    ids = [a.id for a in SEED_ATTACKS]
    assert "LLM01-PI-001" in ids
    assert "LLM02-SD-001" in ids
    assert "LLM06-AGENT-001" in ids
    assert "LLM08-VECT-001" in ids


def test_registry_all():
    reg = AttackRegistry()
    assert len(reg.all()) == len(SEED_ATTACKS)


def test_registry_get():
    reg = AttackRegistry()
    atk = reg.get("LLM01-PI-001")
    assert atk is not None
    assert atk.category == "LLM01"
    assert atk.payload_generator == "llm_direct_prompt_injection"


def test_registry_get_unknown_returns_none():
    reg = AttackRegistry()
    assert reg.get("NONEXISTENT") is None


def test_registry_get_by_category():
    reg = AttackRegistry()
    llm01 = reg.get_by_category("LLM01")
    assert len(llm01) >= 1
    assert all(a.category == "LLM01" for a in llm01)


def test_registry_get_for_target_type_llm():
    reg = AttackRegistry()
    llm_attacks = reg.get_for_target_type(TargetType.LLM)
    assert len(llm_attacks) >= 2
    assert all(TargetType.LLM in a.target_types for a in llm_attacks)


def test_registry_get_for_target_type_rag():
    reg = AttackRegistry()
    rag_attacks = reg.get_for_target_type(TargetType.RAG)
    assert len(rag_attacks) >= 3
    assert any(a.id == "LLM08-VECT-001" for a in rag_attacks)


def test_registry_get_for_target_type_agent():
    reg = AttackRegistry()
    agent_attacks = reg.get_for_target_type(TargetType.AGENT)
    assert len(agent_attacks) >= 1
    assert any(a.id == "LLM06-AGENT-001" for a in agent_attacks)


def test_registry_register_new():
    reg = AttackRegistry()
    from app.attacks.definition import AttackDefinition

    new = AttackDefinition(
        id="TEST-NEW-001",
        name="New Test",
        category="LLM01",
        description="desc",
        target_types=[TargetType.LLM],
        expected_secure_behavior="a",
        vulnerable_behavior="b",
    )
    reg.register(new)
    assert reg.get("TEST-NEW-001") is not None


def test_registry_register_duplicate_raises():
    reg = AttackRegistry()
    dup = reg.get("LLM01-PI-001")
    with pytest.raises(ValueError):
        reg.register(dup)


def test_global_registry_singleton():
    assert registry.get("LLM01-PI-001") is not None
