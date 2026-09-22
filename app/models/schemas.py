from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl


class TargetType(str, Enum):
    LLM = "llm"
    RAG = "rag"
    AGENT = "agent"


class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class TestResult(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RegressionStatus(str, Enum):
    NOT_TESTED = "NOT_TESTED"
    VERIFIED = "VERIFIED"
    REGRESSION_FAILED = "REGRESSION_FAILED"
    FIX_PENDING = "FIX_PENDING"


class TargetConfig(BaseModel):
    name: str
    target_type: TargetType
    base_url: HttpUrl
    config: dict[str, Any] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    auth: dict[str, str] | None = None


class TargetResponse(BaseModel):
    id: int
    name: str
    target_type: TargetType
    base_url: str
    config: dict[str, Any]
    is_authorized: bool
    created_at: datetime


class AttackDefinition(BaseModel):
    attack_id: str
    category: str
    name: str
    description: str
    target_types: list[TargetType]
    preconditions: list[str] = Field(default_factory=list)
    payload_generator: str | None = None
    execution_strategy: str | None = None
    expected_secure_behavior: str
    vulnerable_behavior: str
    evidence_requirements: list[str] = Field(default_factory=list)
    detectors: list[str] = Field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)


class EvidenceRecord(BaseModel):
    scan_id: int
    test_id: int
    timestamp: datetime
    target: str
    request: dict[str, Any] | None = None
    response: dict[str, Any] | None = None
    http_status: int | None = None
    headers: dict[str, str] | None = None
    tool_calls: list[dict[str, Any]] | None = None
    retrieved_documents: list[dict[str, Any]] | None = None
    detectors_triggered: list[str] = Field(default_factory=list)
    expected_behavior: str | None = None
    observed_behavior: str | None = None
    reproduction_count: int = 1
    confidence: int = 0
    result: TestResult = TestResult.INCONCLUSIVE


class TestRecord(BaseModel):
    id: int | None = None
    scan_id: int
    attack_id: str
    category: str
    name: str
    result: TestResult = TestResult.INCONCLUSIVE
    severity: Severity | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    reproduction_count: int = 1
    confidence: int = 0


class FindingRecord(BaseModel):
    id: int | None = None
    scan_id: int
    test_id: int
    attack_id: str
    category: str
    title: str
    description: str
    severity: Severity
    severity_reason: str | None = None
    root_cause: str | None = None
    impact: str | None = None
    protection_control: str | None = None
    remediation: str | None = None
    retest_procedure: str | None = None
    regression_status: RegressionStatus = RegressionStatus.NOT_TESTED


class ScanConfig(BaseModel):
    target_id: int
    attack_ids: list[str] | None = None
    categories: list[str] | None = None
    budget: dict[str, Any] = Field(default_factory=dict)


class ScanRecord(BaseModel):
    id: int | None = None
    target_id: int
    taxonomy_version: str
    git_commit: str | None = None
    configuration: dict[str, Any] = Field(default_factory=dict)
    status: ScanStatus = ScanStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None


class RetestRecord(BaseModel):
    id: int | None = None
    finding_id: int
    scan_id: int
    result: TestResult = TestResult.INCONCLUSIVE
    evidence: dict[str, Any] | None = None
    notes: str | None = None


class ChecklistItemRecord(BaseModel):
    id: int | None = None
    sprint: str
    task: str
    status: Literal["TODO", "IN_PROGRESS", "VERIFIED", "BLOCKED"] = "TODO"
    tests_exist: bool = False
    tests_pass: bool = False
    docs_updated: bool = False
    acceptance_criteria_met: bool = False
    verified_at: datetime | None = None
