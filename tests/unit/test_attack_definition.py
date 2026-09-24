from app.attacks.definition import AttackDefinition
from app.models.schemas import Severity, TargetType


def test_attack_definition_create_valid():
    atk = AttackDefinition(
        id="LLM01-PI-001",
        name="Test",
        category="LLM01",
        description="desc",
        target_types=[TargetType.LLM],
        expected_secure_behavior="must refuse",
        vulnerable_behavior="follows injection",
    )
    assert atk.id == "LLM01-PI-001"
    assert atk.severity == Severity.MEDIUM


def test_attack_definition_requires_fields():
    try:
        AttackDefinition(
            id="",
            name="x",
            category="LLM01",
            description="d",
            target_types=[TargetType.LLM],
            expected_secure_behavior="a",
            vulnerable_behavior="b",
        )
        raise AssertionError("should have raised")
    except ValueError:
        pass


def test_attack_definition_to_dict_roundtrip():
    atk = AttackDefinition(
        id="LLM02-SD-001",
        name="Sensitive",
        category="LLM02",
        description="d",
        target_types=[TargetType.RAG],
        expected_secure_behavior="no leak",
        vulnerable_behavior="leaks canary",
        severity=Severity.HIGH,
        payload_generator="llm_secret_extraction",
        detectors=["canary_secret_leak"],
    )
    d = atk.to_dict()
    atk2 = AttackDefinition.from_dict(d)
    assert atk2.id == atk.id
    assert atk2.severity == atk.severity
    assert atk2.target_types == atk.target_types


def test_attack_definition_frozen():
    atk = AttackDefinition(
        id="LLM07-SPL-001",
        name="x",
        category="LLM07",
        description="d",
        target_types=[TargetType.LLM],
        expected_secure_behavior="a",
        vulnerable_behavior="b",
    )
    try:
        atk.id = "new"  # type: ignore
        raise AssertionError("frozen should prevent")
    except Exception:
        pass
