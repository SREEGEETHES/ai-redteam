import enum
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy import (
    Enum as SQLEnum,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class ScanStatus(enum.StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class TestResult(enum.StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


class Severity(enum.StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RegressionStatus(enum.StrEnum):
    NOT_TESTED = "NOT_TESTED"
    VERIFIED = "VERIFIED"
    REGRESSION_FAILED = "REGRESSION_FAILED"
    FIX_PENDING = "FIX_PENDING"


class Target(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    target_type = Column(String(50), nullable=False)
    base_url = Column(String(500), nullable=False)
    config = Column(JSON, default={})
    is_authorized = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scans = relationship("Scan", back_populates="target")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=False)
    taxonomy_version = Column(String(50), nullable=False)
    git_commit = Column(String(100), nullable=True)
    configuration = Column(JSON, default={})
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    target = relationship("Target", back_populates="scans")
    tests = relationship("Test", back_populates="scan")
    findings = relationship("Finding", back_populates="scan")


class Test(Base):
    __tablename__ = "tests"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    attack_id = Column(String(100), nullable=False)
    category = Column(String(50), nullable=False)
    name = Column(String(255), nullable=False)
    result = Column(SQLEnum(TestResult), default=TestResult.INCONCLUSIVE)
    severity = Column(SQLEnum(Severity), nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    reproduction_count = Column(Integer, default=1)
    confidence = Column(Integer, default=0)

    scan = relationship("Scan", back_populates="tests")
    evidence = relationship("Evidence", back_populates="test", uselist=False)
    finding = relationship("Finding", back_populates="test", uselist=False)


class Evidence(Base):
    __tablename__ = "evidence"

    id = Column(Integer, primary_key=True, index=True)
    test_id = Column(Integer, ForeignKey("tests.id"), nullable=False, unique=True)
    request = Column(JSON, nullable=True)
    response = Column(JSON, nullable=True)
    http_status = Column(Integer, nullable=True)
    headers = Column(JSON, nullable=True)
    tool_calls = Column(JSON, nullable=True)
    retrieved_documents = Column(JSON, nullable=True)
    detectors_triggered = Column(JSON, nullable=True)
    expected_behavior = Column(Text, nullable=True)
    observed_behavior = Column(Text, nullable=True)
    evidence_metadata = Column(JSON, default={})
    created_at = Column(DateTime, default=datetime.utcnow)

    test = relationship("Test", back_populates="evidence")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    test_id = Column(Integer, ForeignKey("tests.id"), nullable=False, unique=True)
    attack_id = Column(String(100), nullable=False)
    category = Column(String(50), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(SQLEnum(Severity), nullable=False)
    severity_reason = Column(Text, nullable=True)
    root_cause = Column(Text, nullable=True)
    impact = Column(Text, nullable=True)
    protection_control = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    retest_procedure = Column(Text, nullable=True)
    regression_status = Column(SQLEnum(RegressionStatus), default=RegressionStatus.NOT_TESTED)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")
    test = relationship("Test", back_populates="finding")
    retests = relationship("Retest", back_populates="finding")


class Retest(Base):
    __tablename__ = "retests"

    id = Column(Integer, primary_key=True, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    result = Column(SQLEnum(TestResult), default=TestResult.INCONCLUSIVE)
    evidence = Column(JSON, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    finding = relationship("Finding", back_populates="retests")
    scan = relationship("Scan")


class ChecklistItem(Base):
    __tablename__ = "checklist_items"

    id = Column(Integer, primary_key=True, index=True)
    sprint = Column(String(50), nullable=False)
    task = Column(String(500), nullable=False)
    status = Column(String(20), default="TODO")
    tests_exist = Column(Boolean, default=False)
    tests_pass = Column(Boolean, default=False)
    docs_updated = Column(Boolean, default=False)
    acceptance_criteria_met = Column(Boolean, default=False)
    verified_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (Index("ix_sprint_task", "sprint", "task", unique=True),)


class AttackDefinition(Base):
    __tablename__ = "attack_definitions"

    id = Column(Integer, primary_key=True, index=True)
    attack_id = Column(String(100), unique=True, nullable=False)
    category = Column(String(50), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    target_types = Column(JSON, default=[])
    preconditions = Column(JSON, default=[])
    payload_generator = Column(String(255), nullable=True)
    execution_strategy = Column(String(255), nullable=True)
    expected_secure_behavior = Column(Text, nullable=False)
    vulnerable_behavior = Column(Text, nullable=False)
    evidence_requirements = Column(JSON, default=[])
    detectors = Column(JSON, default=[])
    severity = Column(SQLEnum(Severity), default=Severity.MEDIUM)
    remediation = Column(Text, nullable=True)
    references = Column(JSON, default=[])
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
