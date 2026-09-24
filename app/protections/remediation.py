"""Remediation Engine - Sprint 7.

Every FAIL generates Finding, Root Cause, Impact, Evidence, Recommended Fix, Protection Control, Retest Procedure per spec 27/41.
"""

from __future__ import annotations

from app.attacks.definition import AttackDefinition


def build_remediation(attack: AttackDefinition, evidence: dict | None = None) -> dict[str, str]:
    """Return structured remediation dict for Finding."""
    return {
        "finding": f"{attack.name} ({attack.id})",
        "attack_id": attack.id,
        "category": attack.category,
        "severity": attack.severity.value,
        "severity_reason": attack.severity_reason or f"OWASP {attack.category}",
        "description": attack.description,
        "root_cause": f"Vulnerable behavior: {attack.vulnerable_behavior} | Preconditions: {', '.join(attack.preconditions)}",
        "impact": f"Severity {attack.severity.value}: {attack.severity_reason or attack.description}",
        "evidence": f"Evidence requirements: {', '.join(attack.evidence_requirements)}; detectors: {', '.join(attack.detectors)}",
        "protection_control": attack.remediation or "Apply defense-in-depth controls per OWASP",
        "recommended_fix": attack.remediation or "See OWASP remediation",
        "retest_procedure": f"Re-run attack {attack.id} via payload generator '{attack.payload_generator}' and verify detectors {attack.detectors} not triggered; expect {attack.expected_secure_behavior}",
        "references": "; ".join(attack.references),
        "owasp_mapping": ", ".join(attack.owasp_mapping),
    }


def finding_from_attack(
    attack: AttackDefinition, scan_id: int, test_id: int, evidence: dict | None = None
) -> dict:
    """Helper to create Finding DB dict."""
    rem = build_remediation(attack, evidence)
    return {
        "scan_id": scan_id,
        "test_id": test_id,
        "attack_id": attack.id,
        "category": attack.category,
        "title": attack.name,
        "description": attack.description,
        "severity": attack.severity,
        "severity_reason": rem["severity_reason"],
        "root_cause": rem["root_cause"],
        "impact": rem["impact"],
        "protection_control": rem["protection_control"],
        "remediation": rem["recommended_fix"],
        "retest_procedure": rem["retest_procedure"],
    }
