import pytest
from app.database.models import Target, Scan
from app.database.session import SessionLocal, init_db
from app.models.schemas import TestResult


class MockLLMVuln:
    def get_baseline(self):
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

    def send_attack(self, payload):
        return {"status_code": 200, "response": {"response": "CANARY_SECRET_12345 leaked"}, "headers": {}}

    def close(self):
        pass


class MockLLMSecure:
    def get_baseline(self):
        return {"status_code": 200, "response": {"response": "hello"}, "headers": {}}

    def send_attack(self, payload):
        return {"status_code": 200, "response": {"response": "I cannot reveal secrets"}, "headers": {}}

    def close(self):
        pass


def _clean(db):
    from app.database.models import Evidence, Finding, Retest, Test

    db.query(Evidence).delete()
    db.query(Finding).delete()
    db.query(Retest).delete()
    db.query(Test).delete()
    db.query(Scan).delete()
    db.query(Target).delete()
    db.commit()


def test_orchestrator_end_to_end_vulnerable(monkeypatch):
    init_db()
    db = SessionLocal()
    _clean(db)

    target = Target(name="Test LLM vuln", target_type="llm", base_url="http://localhost:8000", config={}, is_authorized=True)
    db.add(target)
    db.commit()
    db.refresh(target)

    scan = Scan(target_id=target.id, taxonomy_version="owasp-llm-2026", configuration={"attack_ids": ["LLM02-SD-001"]}, status="PENDING")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from app.core import orchestrator

    monkeypatch.setattr(orchestrator.AdapterRegistry, "create_adapter", lambda *a, **kw: MockLLMVuln())

    result_scan = orchestrator.run_scan(scan.id, db)
    assert result_scan.status.value == "COMPLETED"

    from app.database.models import Test, Evidence, Finding

    tests = db.query(Test).filter(Test.scan_id == scan.id).all()
    assert len(tests) == 1
    assert tests[0].result == TestResult.FAIL
    assert tests[0].attack_id == "LLM02-SD-001"

    ev = db.query(Evidence).filter(Evidence.test_id == tests[0].id).first()
    assert ev is not None
    assert ev.request is not None
    assert ev.response is not None
    assert "canary_secret_leak" in (ev.detectors_triggered or [])

    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert len(findings) == 1
    assert findings[0].attack_id == "LLM02-SD-001"

    db.close()


def test_orchestrator_end_to_end_secure(monkeypatch):
    init_db()
    db = SessionLocal()
    _clean(db)

    target = Target(name="Test LLM secure", target_type="llm", base_url="http://localhost:8000", config={}, is_authorized=True)
    db.add(target)
    db.commit()
    db.refresh(target)

    scan = Scan(target_id=target.id, taxonomy_version="owasp-llm-2026", configuration={"attack_ids": ["LLM02-SD-001"]}, status="PENDING")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from app.core import orchestrator

    monkeypatch.setattr(orchestrator.AdapterRegistry, "create_adapter", lambda *a, **kw: MockLLMSecure())

    result_scan = orchestrator.run_scan(scan.id, db)
    assert result_scan.status.value == "COMPLETED"

    from app.database.models import Test, Evidence, Finding

    tests = db.query(Test).filter(Test.scan_id == scan.id).all()
    assert len(tests) == 1
    assert tests[0].result == TestResult.PASS

    findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
    assert len(findings) == 0  # no finding for PASS

    db.close()


def test_orchestrator_not_applicable_filter(monkeypatch):
    init_db()
    db = SessionLocal()
    _clean(db)

    target = Target(name="RAG target", target_type="rag", base_url="http://localhost:8000", config={}, is_authorized=True)
    db.add(target)
    db.commit()
    db.refresh(target)

    scan = Scan(target_id=target.id, taxonomy_version="owasp-llm-2026", configuration={"attack_ids": ["LLM06-AGENT-001"]}, status="PENDING")
    db.add(scan)
    db.commit()
    db.refresh(scan)

    from app.core import orchestrator

    monkeypatch.setattr(orchestrator.AdapterRegistry, "create_adapter", lambda *a, **kw: MockLLMVuln())

    orchestrator.run_scan(scan.id, db)

    from app.database.models import Test

    tests = db.query(Test).filter(Test.scan_id == scan.id).all()
    assert len(tests) == 1
    assert tests[0].result == TestResult.NOT_APPLICABLE

    db.close()
