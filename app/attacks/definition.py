"""AttackDefinition - core model for Sprint 2."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models.schemas import Severity, TargetType


@dataclass(frozen=True)
class AttackDefinition:
    """Immutable attack definition, mirrors spec 18.

    Attributes are intentionally strict - no LLM opinion alone.
    Every definition declares evidence_requirements and detectors
    that must be satisfied to classify PASS/FAIL.
    """

    id: str  # e.g. LLM01-PI-001
    name: str
    category: str  # LLM01 .. LLM10
    description: str
    target_types: list[TargetType]
    preconditions: list[str] = field(default_factory=list)
    payload_generator: str | None = None  # key into PAYLOAD_REGISTRY
    execution_strategy: str | None = None  # single_shot | multi_turn | etc
    expected_secure_behavior: str = ""
    vulnerable_behavior: str = ""
    evidence_requirements: list[str] = field(default_factory=list)
    detectors: list[str] = field(default_factory=list)  # keys into DETECTOR_REGISTRY
    severity: Severity = Severity.MEDIUM
    severity_reason: str | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    owasp_mapping: list[str] = field(default_factory=list)
    cwe_mapping: list[str] = field(default_factory=list)
    reproduction_count: int = 1  # how many times to repeat for confidence

    def __post_init__(self):
        if not self.id:
            raise ValueError("AttackDefinition.id is required")
        if not self.category:
            raise ValueError("AttackDefinition.category is required")
        if not self.expected_secure_behavior:
            raise ValueError("expected_secure_behavior is required")
        if not self.vulnerable_behavior:
            raise ValueError("vulnerable_behavior is required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_id": self.id,
            "category": self.category,
            "name": self.name,
            "description": self.description,
            "target_types": [t.value for t in self.target_types],
            "preconditions": self.preconditions,
            "payload_generator": self.payload_generator,
            "execution_strategy": self.execution_strategy,
            "expected_secure_behavior": self.expected_secure_behavior,
            "vulnerable_behavior": self.vulnerable_behavior,
            "evidence_requirements": self.evidence_requirements,
            "detectors": self.detectors,
            "severity": self.severity.value,
            "severity_reason": self.severity_reason,
            "remediation": self.remediation,
            "references": self.references,
            "owasp_mapping": self.owasp_mapping,
            "cwe_mapping": self.cwe_mapping,
            "reproduction_count": self.reproduction_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackDefinition:
        return cls(
            id=data["attack_id"] if "attack_id" in data else data["id"],
            name=data["name"],
            category=data["category"],
            description=data["description"],
            target_types=[TargetType(t) for t in data.get("target_types", [])],
            preconditions=data.get("preconditions", []),
            payload_generator=data.get("payload_generator"),
            execution_strategy=data.get("execution_strategy"),
            expected_secure_behavior=data["expected_secure_behavior"],
            vulnerable_behavior=data["vulnerable_behavior"],
            evidence_requirements=data.get("evidence_requirements", []),
            detectors=data.get("detectors", []),
            severity=Severity(data.get("severity", "MEDIUM")),
            severity_reason=data.get("severity_reason"),
            remediation=data.get("remediation"),
            references=data.get("references", []),
            owasp_mapping=data.get("owasp_mapping", []),
            cwe_mapping=data.get("cwe_mapping", []),
            reproduction_count=data.get("reproduction_count", 1),
        )
