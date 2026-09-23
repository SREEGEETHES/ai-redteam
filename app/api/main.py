from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.database.models import AttackDefinition, ChecklistItem, Evidence, Finding, Scan, Target, Test
from app.database.session import get_db, init_db
from app.models.schemas import (
    AttackDefinition as AttackDefinitionSchema,
)
from app.models.schemas import (
    ChecklistItemRecord,
    EvidenceRecord,
    FindingRecord,
    ScanConfig,
    ScanRecord,
    ScanStatus,
    TargetConfig,
    TargetResponse,
    TargetType,
    TestRecord,
)
from app.protections.checks import run_all_checks
from app.protections.remediation import build_remediation
from app.security.authorization import AuthorizationError, TargetAuthorizationGuard

logger = get_logger(__name__)
guard = TargetAuthorizationGuard()


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(settings.log_level, settings.log_format)
    init_db()
    # seed attack definitions for SPRINT 2
    try:
        from app.database.session import SessionLocal
        from app.attacks.registry import SEED_ATTACKS

        db = SessionLocal()
        from app.database.models import AttackDefinition as DBAttack

        for atk in SEED_ATTACKS:
            exists = db.query(DBAttack).filter(DBAttack.attack_id == atk.id).first()
            if not exists:
                db_atk = DBAttack(
                    attack_id=atk.id,
                    category=atk.category,
                    name=atk.name,
                    description=atk.description,
                    target_types=[t.value for t in atk.target_types],
                    preconditions=atk.preconditions,
                    payload_generator=atk.payload_generator,
                    execution_strategy=atk.execution_strategy,
                    expected_secure_behavior=atk.expected_secure_behavior,
                    vulnerable_behavior=atk.vulnerable_behavior,
                    evidence_requirements=atk.evidence_requirements,
                    detectors=atk.detectors,
                    severity=atk.severity,
                    remediation=atk.remediation,
                    references=atk.references,
                )
                db.add(db_atk)
        db.commit()
        db.close()
    except Exception as e:
        logger.warning("attack_seed_failed", error=str(e))
    logger.info("application_startup", version=settings.app_version)
    yield
    logger.info("application_shutdown")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": settings.app_version}


@app.post("/targets", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(target: TargetConfig, db: Session = Depends(get_db)):
    try:
        guard.authorize_or_raise(str(target.base_url))
    except AuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

    db_target = Target(
        name=target.name,
        target_type=target.target_type.value,
        base_url=str(target.base_url),
        config=target.config,
        is_authorized=True,
    )
    db.add(db_target)
    db.commit()
    db.refresh(db_target)

    logger.info("target_created", target_id=db_target.id, name=target.name)
    return TargetResponse(
        id=db_target.id,
        name=db_target.name,
        target_type=TargetType(db_target.target_type),
        base_url=db_target.base_url,
        config=db_target.config,
        is_authorized=db_target.is_authorized,
        created_at=db_target.created_at,
    )


@app.get("/targets", response_model=list[TargetResponse])
async def list_targets(db: Session = Depends(get_db)):
    targets = db.query(Target).all()
    return [
        TargetResponse(
            id=t.id,
            name=t.name,
            target_type=TargetType(t.target_type),
            base_url=t.base_url,
            config=t.config,
            is_authorized=t.is_authorized,
            created_at=t.created_at,
        )
        for t in targets
    ]


@app.get("/targets/{target_id}", response_model=TargetResponse)
async def get_target(target_id: int, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return TargetResponse(
        id=target.id,
        name=target.name,
        target_type=TargetType(target.target_type),
        base_url=target.base_url,
        config=target.config,
        is_authorized=target.is_authorized,
        created_at=target.created_at,
    )


@app.post("/scans", response_model=ScanRecord, status_code=status.HTTP_201_CREATED)
async def create_scan(scan: ScanConfig, db: Session = Depends(get_db)):
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    if not target.is_authorized:
        raise HTTPException(status_code=403, detail="Target not authorized for scanning")

    db_scan = Scan(
        target_id=scan.target_id,
        taxonomy_version=settings.taxonomy_version,
        configuration={"budget": scan.budget, "attack_ids": scan.attack_ids, "categories": scan.categories},
        status=ScanStatus.PENDING,
    )
    db.add(db_scan)
    db.commit()
    db.refresh(db_scan)

    logger.info("scan_created", scan_id=db_scan.id, target_id=scan.target_id)
    return ScanRecord(
        id=db_scan.id,
        target_id=db_scan.target_id,
        taxonomy_version=db_scan.taxonomy_version,
        git_commit=db_scan.git_commit,
        configuration=db_scan.configuration,
        status=db_scan.status,
        started_at=db_scan.started_at,
        completed_at=db_scan.completed_at,
    )


@app.get("/scans", response_model=list[ScanRecord])
async def list_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.created_at.desc()).all()
    return [
        ScanRecord(
            id=s.id,
            target_id=s.target_id,
            taxonomy_version=s.taxonomy_version,
            git_commit=s.git_commit,
            configuration=s.configuration,
            status=s.status,
            started_at=s.started_at,
            completed_at=s.completed_at,
        )
        for s in scans
    ]


@app.get("/scans/{scan_id}", response_model=ScanRecord)
async def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanRecord(
        id=scan.id,
        target_id=scan.target_id,
        taxonomy_version=scan.taxonomy_version,
        git_commit=scan.git_commit,
        configuration=scan.configuration,
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )


@app.get("/scans/{scan_id}/findings", response_model=list[FindingRecord])
async def get_scan_findings(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    return [
        FindingRecord(
            id=f.id,
            scan_id=f.scan_id,
            test_id=f.test_id,
            attack_id=f.attack_id,
            category=f.category,
            title=f.title,
            description=f.description,
            severity=f.severity,
            severity_reason=f.severity_reason,
            root_cause=f.root_cause,
            impact=f.impact,
            protection_control=f.protection_control,
            remediation=f.remediation,
            retest_procedure=f.retest_procedure,
            regression_status=f.regression_status,
        )
        for f in findings
    ]


@app.post("/scans/{scan_id}/run", response_model=ScanRecord)
async def run_scan_endpoint(scan_id: int, db: Session = Depends(get_db)):
    from app.core.orchestrator import run_scan

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status == "RUNNING":
        raise HTTPException(status_code=409, detail="Scan already running")
    try:
        result = run_scan(scan_id, db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return ScanRecord(
        id=result.id,
        target_id=result.target_id,
        taxonomy_version=result.taxonomy_version,
        git_commit=result.git_commit,
        configuration=result.configuration,
        status=result.status,
        started_at=result.started_at,
        completed_at=result.completed_at,
    )


@app.get("/scans/{scan_id}/tests", response_model=list[TestRecord])
async def get_scan_tests(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    tests = db.query(Test).filter(Test.scan_id == scan_id).all()
    return [
        TestRecord(
            id=t.id,
            scan_id=t.scan_id,
            attack_id=t.attack_id,
            category=t.category,
            name=t.name,
            result=t.result,
            severity=t.severity,
            started_at=t.started_at,
            completed_at=t.completed_at,
            reproduction_count=t.reproduction_count,
            confidence=t.confidence,
        )
        for t in tests
    ]


@app.get("/tests/{test_id}/evidence", response_model=EvidenceRecord)
async def get_test_evidence(test_id: int, db: Session = Depends(get_db)):
    test = db.query(Test).filter(Test.id == test_id).first()
    if not test:
        raise HTTPException(status_code=404, detail="Test not found")
    ev = db.query(Evidence).filter(Evidence.test_id == test_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence not found")
    scan = db.query(Scan).filter(Scan.id == test.scan_id).first()
    target = db.query(Target).filter(Target.id == scan.target_id).first() if scan else None
    meta = ev.evidence_metadata or {}
    return EvidenceRecord(
        scan_id=test.scan_id,
        test_id=test.id,
        timestamp=ev.created_at,
        target=target.base_url if target else "unknown",
        request=ev.request,
        response=ev.response,
        http_status=ev.http_status,
        headers=ev.headers,
        tool_calls=ev.tool_calls,
        retrieved_documents=ev.retrieved_documents,
        detectors_triggered=ev.detectors_triggered or [],
        expected_behavior=ev.expected_behavior,
        observed_behavior=ev.observed_behavior,
        reproduction_count=meta.get("reproduction_count", test.reproduction_count),
        confidence=meta.get("confidence", test.confidence),
        result=test.result,
    )


@app.get("/scans/{scan_id}/evidence", response_model=list[EvidenceRecord])
async def get_scan_evidence(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    tests = db.query(Test).filter(Test.scan_id == scan_id).all()
    evidences: list[EvidenceRecord] = []
    for t in tests:
        ev = db.query(Evidence).filter(Evidence.test_id == t.id).first()
        if ev:
            meta = ev.evidence_metadata or {}
            target = db.query(Target).filter(Target.id == scan.target_id).first()
            evidences.append(
                EvidenceRecord(
                    scan_id=scan_id,
                    test_id=t.id,
                    timestamp=ev.created_at,
                    target=target.base_url if target else "unknown",
                    request=ev.request,
                    response=ev.response,
                    http_status=ev.http_status,
                    headers=ev.headers,
                    tool_calls=ev.tool_calls,
                    retrieved_documents=ev.retrieved_documents,
                    detectors_triggered=ev.detectors_triggered or [],
                    expected_behavior=ev.expected_behavior,
                    observed_behavior=ev.observed_behavior,
                    reproduction_count=meta.get("reproduction_count", 1),
                    confidence=meta.get("confidence", 0),
                    result=t.result,
                )
            )
    return evidences


@app.get("/attacks", response_model=list[AttackDefinitionSchema])
async def list_attacks(category: str | None = None, db: Session = Depends(get_db)):
    query = db.query(AttackDefinition)
    if category:
        query = query.filter(AttackDefinition.category == category)
    attacks = query.all()
    return [
        AttackDefinitionSchema(
            attack_id=a.attack_id,
            category=a.category,
            name=a.name,
            description=a.description,
            target_types=[TargetType(t) for t in a.target_types],
            preconditions=a.preconditions,
            payload_generator=a.payload_generator,
            execution_strategy=a.execution_strategy,
            expected_secure_behavior=a.expected_secure_behavior,
            vulnerable_behavior=a.vulnerable_behavior,
            evidence_requirements=a.evidence_requirements,
            detectors=a.detectors,
            severity=a.severity,
            remediation=a.remediation,
            references=a.references,
        )
        for a in attacks
    ]


@app.get("/checklist", response_model=list[ChecklistItemRecord])
async def get_checklist(db: Session = Depends(get_db)):
    items = db.query(ChecklistItem).order_by(ChecklistItem.sprint, ChecklistItem.task).all()
    return [
        ChecklistItemRecord(
            id=item.id,
            sprint=item.sprint,
            task=item.task,
            status=item.status,
            tests_exist=item.tests_exist,
            tests_pass=item.tests_pass,
            docs_updated=item.docs_updated,
            acceptance_criteria_met=item.acceptance_criteria_met,
            verified_at=item.verified_at,
        )
        for item in items
    ]


@app.post("/checklist", response_model=ChecklistItemRecord, status_code=status.HTTP_201_CREATED)
async def create_checklist_item(item: ChecklistItemRecord, db: Session = Depends(get_db)):
    db_item = ChecklistItem(
        sprint=item.sprint,
        task=item.task,
        status=item.status,
        tests_exist=item.tests_exist,
        tests_pass=item.tests_pass,
        docs_updated=item.docs_updated,
        acceptance_criteria_met=item.acceptance_criteria_met,
    )
    db.add(db_item)
    db.commit()
    db.refresh(db_item)
    return ChecklistItemRecord(
        id=db_item.id,
        sprint=db_item.sprint,
        task=db_item.task,
        status=db_item.status,
        tests_exist=db_item.tests_exist,
        tests_pass=db_item.tests_pass,
        docs_updated=db_item.docs_updated,
        acceptance_criteria_met=db_item.acceptance_criteria_met,
        verified_at=db_item.verified_at,
    )


@app.get("/protections/checks")
async def get_protection_checks(target_id: int | None = None, db: Session = Depends(get_db)):
    """Blue-team protection checks - static + runtime where available. Never treated as proof alone (spec 26)."""
    from app.database.models import Target as DBTarget

    target_config: dict = {}
    runtime_by_check: dict[str, dict] = {}
    if target_id:
        target = db.query(DBTarget).filter(DBTarget.id == target_id).first()
        if target:
            target_config = target.config or {}
            # Try to get last scan's evidence for runtime
            last_scan = db.query(Scan).filter(Scan.target_id == target_id).order_by(Scan.created_at.desc()).first()
            if last_scan:
                tests = db.query(Test).filter(Test.scan_id == last_scan.id).all()
                for t in tests:
                    ev = db.query(Evidence).filter(Evidence.test_id == t.id).first()
                    if ev:
                        # Map test category to check id
                        mapping = {"LLM08": "tenant_isolation", "LLM06": "tool_allowlist", "LLM02": "secret_handling", "LLM05": "output_validation", "LLM10": "rate_limit", "LLM01": "authorization"}
                        check_id = mapping.get(t.category, "authorization")
                        runtime_by_check[check_id] = {
                            "detectors_triggered": ev.detectors_triggered or [],
                            "http_status": ev.http_status,
                            "observed_behavior": ev.observed_behavior,
                        }
    results = run_all_checks(target_config, runtime_by_check)
    return [
        {
            "check_id": r.check_id,
            "name": r.name,
            "passed": r.passed,
            "static_evidence": r.static_evidence,
            "runtime_evidence": r.runtime_evidence,
            "remediation": r.remediation,
            "severity": r.severity,
            "reason": r.reason,
        }
        for r in results
    ]


@app.get("/attacks/{attack_id}/remediation")
async def get_attack_remediation(attack_id: str, db: Session = Depends(get_db)):
    """Every finding has documented remediation + retest per Sprint 7 acceptance."""
    from app.attacks.registry import registry

    attack = registry.get(attack_id)
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")
    return build_remediation(attack)


# --- Sprint 8 Regression (real) ---
@app.post("/findings/{finding_id}/retest", status_code=status.HTTP_201_CREATED)
async def retest_finding_endpoint(finding_id: int, db: Session = Depends(get_db)):
    """Real retest: new scan for same attack, compare before/after, update regression status, store history."""
    from app.regression.engine import retest_finding

    try:
        retest, finding, scan = retest_finding(finding_id, db)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {
        "retest_id": retest.id,
        "finding_id": finding.id,
        "scan_id": scan.id,
        "result": retest.result.value if hasattr(retest.result, "value") else str(retest.result),
        "regression_status": finding.regression_status.value if hasattr(finding.regression_status, "value") else str(finding.regression_status),
        "notes": retest.notes,
    }


@app.get("/findings/{finding_id}/history")
async def get_finding_history(finding_id: int, db: Session = Depends(get_db)):
    from app.regression.engine import get_regression_history

    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    history = get_regression_history(finding_id, db)
    return [
        {
            "id": r.id,
            "finding_id": r.finding_id,
            "scan_id": r.scan_id,
            "result": r.result.value if hasattr(r.result, "value") else str(r.result),
            "evidence": r.evidence,
            "notes": r.notes,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in history
    ]


@app.get("/findings/{finding_id}/compare")
async def get_finding_compare(finding_id: int, db: Session = Depends(get_db)):
    from app.regression.engine import compare_before_after

    try:
        return compare_before_after(finding_id, db)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/findings/{finding_id}/lifecycle")
async def get_finding_lifecycle(finding_id: int, db: Session = Depends(get_db)):
    from app.regression.engine import finding_lifecycle

    try:
        return finding_lifecycle(finding_id, db)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.patch("/checklist/{item_id}", response_model=ChecklistItemRecord)
async def update_checklist_item(item_id: int, item: ChecklistItemRecord, db: Session = Depends(get_db)):
    db_item = db.query(ChecklistItem).filter(ChecklistItem.id == item_id).first()
    if not db_item:
        raise HTTPException(status_code=404, detail="Checklist item not found")

    db_item.status = item.status
    db_item.tests_exist = item.tests_exist
    db_item.tests_pass = item.tests_pass
    db_item.docs_updated = item.docs_updated
    db_item.acceptance_criteria_met = item.acceptance_criteria_met
    if item.status == "VERIFIED" and not db_item.verified_at:
        db_item.verified_at = datetime.utcnow()

    db.commit()
    db.refresh(db_item)
    return ChecklistItemRecord(
        id=db_item.id,
        sprint=db_item.sprint,
        task=db_item.task,
        status=db_item.status,
        tests_exist=db_item.tests_exist,
        tests_pass=db_item.tests_pass,
        docs_updated=db_item.docs_updated,
        acceptance_criteria_met=db_item.acceptance_criteria_met,
        verified_at=db_item.verified_at,
    )
