
import pytest

from app.database.models import (
    AttackDefinition,
    ChecklistItem,
    Evidence,
    Finding,
    RegressionStatus,
    Retest,
    Scan,
    ScanStatus,
    Severity,
    Target,
    Test,
    TestResult,
)
from app.database.session import init_db


@pytest.fixture(scope="function")
def db_session():
    init_db()
    from app.database.session import SessionLocal
    session = SessionLocal()
    yield session
    session.rollback()
    session.close()


def test_target_crud(db_session):
    target = Target(
        name="Test LLM",
        target_type="llm",
        base_url="http://localhost:8000",
        config={"model": "llama2"},
        is_authorized=True,
    )
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)

    assert target.id is not None
    assert target.name == "Test LLM"
    assert target.target_type == "llm"
    assert target.is_authorized is True

    # Query back
    found = db_session.query(Target).filter(Target.id == target.id).first()
    assert found is not None
    assert found.name == "Test LLM"


def test_scan_crud(db_session):
    target = Target(
        name="Test Target",
        target_type="llm",
        base_url="http://localhost:8000",
        is_authorized=True,
    )
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)

    scan = Scan(
        target_id=target.id,
        taxonomy_version="owasp-llm-2026",
        configuration={"budget": {"max_requests": 50}},
        status=ScanStatus.PENDING,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    assert scan.id is not None
    assert scan.target_id == target.id
    assert scan.taxonomy_version == "owasp-llm-2026"
    assert scan.status == ScanStatus.PENDING


def test_test_and_evidence(db_session):
    target = Target(name="Test", target_type="llm", base_url="http://localhost:8000", is_authorized=True)
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)

    scan = Scan(target_id=target.id, taxonomy_version="owasp-llm-2026", status=ScanStatus.RUNNING)
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    test = Test(
        scan_id=scan.id,
        attack_id="LLM01-PI-001",
        category="LLM01",
        name="Direct Prompt Injection",
        result=TestResult.FAIL,
        severity=Severity.HIGH,
    )
    db_session.add(test)
    db_session.commit()
    db_session.refresh(test)

    evidence = Evidence(
        test_id=test.id,
        request={"prompt": "Ignore instructions"},
        response={"text": "I cannot ignore instructions"},
        http_status=200,
        detectors_triggered=["instruction_conflict"],
        expected_behavior="Model should refuse",
        observed_behavior="Model refused",
    )
    db_session.add(evidence)
    db_session.commit()
    db_session.refresh(evidence)

    assert evidence.test_id == test.id
    assert evidence.detectors_triggered == ["instruction_conflict"]


def test_finding_and_retest(db_session):
    target = Target(name="Test", target_type="llm", base_url="http://localhost:8000", is_authorized=True)
    db_session.add(target)
    db_session.commit()
    db_session.refresh(target)

    scan = Scan(target_id=target.id, taxonomy_version="owasp-llm-2026", status=ScanStatus.COMPLETED)
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    test = Test(scan_id=scan.id, attack_id="LLM01-PI-001", category="LLM01", name="Test", result=TestResult.FAIL)
    db_session.add(test)
    db_session.commit()
    db_session.refresh(test)

    finding = Finding(
        scan_id=scan.id,
        test_id=test.id,
        attack_id="LLM01-PI-001",
        category="LLM01",
        title="Prompt Injection Vulnerability",
        description="Model accepts injected instructions",
        severity=Severity.HIGH,
        severity_reason="Unauthorized instruction override",
        root_cause="Missing input validation",
        remediation="Add instruction hierarchy enforcement",
        retest_procedure="Send injected prompt and verify refusal",
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)

    assert finding.regression_status == RegressionStatus.NOT_TESTED

    retest = Retest(
        finding_id=finding.id,
        scan_id=scan.id,
        result=TestResult.PASS,
        evidence={"response": "I cannot comply"},
        notes="Fix verified",
    )
    db_session.add(retest)
    db_session.commit()
    db_session.refresh(retest)

    assert retest.result == TestResult.PASS


def test_checklist_item(db_session):
    item = ChecklistItem(
        sprint="SPRINT 0",
        task="Repository initialized",
        status="VERIFIED",
        tests_exist=True,
        tests_pass=True,
        docs_updated=True,
        acceptance_criteria_met=True,
    )
    db_session.add(item)
    db_session.commit()
    db_session.refresh(item)

    assert item.status == "VERIFIED"
    assert item.tests_pass is True


def test_attack_definition(db_session):
    import uuid

    unique_id = f"TEST-ATTACK-{uuid.uuid4().hex[:8]}"
    # use unique id to avoid collision with seeded SEED_ATTACKS
    attack = AttackDefinition(
        attack_id=unique_id,
        category="LLM01",
        name="Direct Prompt Injection",
        description="Test direct instruction override",
        target_types=["llm", "rag", "agent"],
        preconditions=["Model accepts user input"],
        expected_secure_behavior="Model refuses injected instruction",
        vulnerable_behavior="Model follows injected instruction",
        evidence_requirements=["request", "response", "refusal_detected"],
        detectors=["instruction_conflict", "refusal_check"],
        severity=Severity.HIGH,
        remediation="Implement instruction hierarchy",
        references=["https://owasp.org/..."],
    )
    db_session.add(attack)
    db_session.commit()
    db_session.refresh(attack)

    assert attack.attack_id == unique_id
    assert attack.target_types == ["llm", "rag", "agent"]
    assert attack.severity == Severity.HIGH
