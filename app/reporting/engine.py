"""Reporting Engine - Sprint 9 Real Implementation.

Generates reproducible JSON/Markdown/HTML reports per spec 41 with:
ID, Title, OWASP Category, Target, Severity, Status, Description, Attack Objective,
Preconditions, Attack Procedure, Observed Behavior, Expected Behavior, Evidence,
Impact, Root Cause, Protection, Retest Procedure, Regression Result, References
plus Executive Summary, Technical Findings, Evidence, Remediation, Retest Status.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.attacks.registry import registry
from app.database.models import Evidence, Finding, Scan, Target, Test


def _scan_summary(scan: Scan, tests: list[Test], findings: list[Finding]) -> dict[str, Any]:
    total = len(tests)
    counts = {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0, "NOT_APPLICABLE": 0, "ERROR": 0}
    severity_counts = {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for t in tests:
        key = t.result.value if hasattr(t.result, "value") else str(t.result)
        counts[key] = counts.get(key, 0) + 1
    for f in findings:
        key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        severity_counts[key] = severity_counts.get(key, 0) + 1

    # Overall verdict per spec: not "secure", but "tested scenarios passed/failed"
    if counts["FAIL"] > 0:
        verdict = f"FAIL: {counts['FAIL']} vulnerability(ies) demonstrated under tested conditions"
    elif counts["PASS"] > 0 and counts["FAIL"] == 0:
        verdict = "PASS: Tested scenarios passed under defined conditions (not a guarantee of overall security)"
    else:
        verdict = "INCONCLUSIVE: Insufficient evidence"

    return {
        "total_tests": total,
        "counts": counts,
        "severity_counts": severity_counts,
        "findings": len(findings),
        "verdict": verdict,
        "taxonomy_version": scan.taxonomy_version,
    }


def generate_json_report(scan_id: int, db: Session) -> dict[str, Any]:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise ValueError(f"Scan {scan_id} not found")
    target = db.query(Target).filter(Target.id == scan.target_id).first()
    tests = db.query(Test).filter(Test.scan_id == scan_id).all()
    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    summary = _scan_summary(scan, tests, findings)

    # Technical findings per spec 41
    technical = []
    for f in findings:
        attack = registry.get(f.attack_id)
        test = db.query(Test).filter(Test.id == f.test_id).first()
        evidence = db.query(Evidence).filter(Evidence.test_id == test.id).first() if test else None
        # Retest history
        from app.database.models import Retest

        history = (
            db.query(Retest)
            .filter(Retest.finding_id == f.id)
            .order_by(Retest.created_at.desc())
            .all()
        )
        technical.append(
            {
                "id": f.attack_id,
                "title": f.title,
                "owasp_category": f.category,
                "target": {
                    "id": target.id if target else None,
                    "name": target.name if target else None,
                    "url": target.base_url if target else None,
                    "type": target.target_type if target else None,
                },
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "severity_reason": f.severity_reason,
                "status": test.result.value
                if test and hasattr(test.result, "value")
                else str(test.result)
                if test
                else None,
                "description": f.description,
                "attack_objective": attack.vulnerable_behavior if attack else None,
                "preconditions": attack.preconditions if attack else None,
                "attack_procedure": f"Payload via {attack.payload_generator} with detectors {attack.detectors}"
                if attack
                else None,
                "observed_behavior": evidence.observed_behavior if evidence else None,
                "expected_behavior": evidence.expected_behavior if evidence else None,
                "evidence": {
                    "request": evidence.request if evidence else None,
                    "response": evidence.response if evidence else None,
                    "http_status": evidence.http_status if evidence else None,
                    "headers": evidence.headers if evidence else None,
                    "tool_calls": evidence.tool_calls if evidence else None,
                    "retrieved_documents": evidence.retrieved_documents if evidence else None,
                    "detectors_triggered": evidence.detectors_triggered if evidence else None,
                    "reproduction_count": test.reproduction_count if test else None,
                    "confidence": test.confidence if test else None,
                    "evidence_hash": evidence.evidence_metadata.get("evidence_hash")
                    if evidence and evidence.evidence_metadata
                    else None,
                }
                if evidence
                else None,
                "impact": f.impact,
                "root_cause": f.root_cause,
                "protection": f.protection_control,
                "remediation": f.remediation,
                "retest_procedure": f.retest_procedure,
                "regression_result": f.regression_status.value
                if hasattr(f.regression_status, "value")
                else str(f.regression_status),
                "retest_history": [
                    {
                        "scan_id": r.scan_id,
                        "result": r.result.value if hasattr(r.result, "value") else str(r.result),
                        "notes": r.notes,
                        "created_at": r.created_at.isoformat() if r.created_at else None,
                    }
                    for r in history
                ],
                "references": attack.references if attack else [],
            }
        )

    # Evidence section: all tests with evidence (including PASS)
    evidence_section = []
    for t in tests:
        ev = db.query(Evidence).filter(Evidence.test_id == t.id).first()
        evidence_section.append(
            {
                "test_id": t.id,
                "attack_id": t.attack_id,
                "category": t.category,
                "name": t.name,
                "result": t.result.value if hasattr(t.result, "value") else str(t.result),
                "severity": t.severity.value
                if t.severity and hasattr(t.severity, "value")
                else str(t.severity)
                if t.severity
                else None,
                "evidence": {
                    "request": ev.request if ev else None,
                    "response": ev.response if ev else None,
                    "http_status": ev.http_status if ev else None,
                    "detectors_triggered": ev.detectors_triggered if ev else None,
                    "reproduction_count": t.reproduction_count,
                    "confidence": t.confidence,
                }
                if ev
                else None,
            }
        )

    # Build report without volatile fields for hash
    report_core = {
        "scan": {
            "id": scan.id,
            "target_id": scan.target_id,
            "target_name": target.name if target else None,
            "target_url": target.base_url if target else None,
            "target_type": target.target_type if target else None,
            "taxonomy_version": scan.taxonomy_version,
            "git_commit": scan.git_commit,
            "configuration": scan.configuration,
            "status": scan.status.value if hasattr(scan.status, "value") else str(scan.status),
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
        },
        "executive_summary": {
            "verdict": summary["verdict"],
            "total_tests": summary["total_tests"],
            "counts": summary["counts"],
            "severity_counts": summary["severity_counts"],
            "findings": summary["findings"],
            "note": "PASS means tested security expectation satisfied for defined scenario; FAIL means attack demonstrated vulnerability; not a guarantee of overall security.",
        },
        "technical_findings": technical,
        "evidence": evidence_section,
        "remediation": [
            {
                "attack_id": f.attack_id,
                "title": f.title,
                "remediation": f.remediation,
                "protection_control": f.protection_control,
                "retest_procedure": f.retest_procedure,
            }
            for f in findings
        ],
        "retest_status": [
            {
                "finding_id": f.id,
                "attack_id": f.attack_id,
                "regression_status": f.regression_status.value
                if hasattr(f.regression_status, "value")
                else str(f.regression_status),
                "history": [
                    {
                        "scan_id": r.scan_id,
                        "result": r.result.value if hasattr(r.result, "value") else str(r.result),
                    }
                    for r in db.query(Retest).filter(Retest.finding_id == f.id).all()
                ],
            }
            for f in findings
        ],
        "report_version": "1.0",
    }
    # Hash for reproducibility (exclude generated_at)
    report_json = json.dumps(report_core, sort_keys=True, default=str)
    report_hash = hashlib.sha256(report_json.encode()).hexdigest()[:16]
    return {
        **report_core,
        "generated_at": datetime.now(UTC).isoformat(),
        "report_hash": report_hash,
    }


def generate_markdown_report(scan_id: int, db: Session) -> str:
    data = generate_json_report(scan_id, db)
    scan = data["scan"]
    exec_sum = data["executive_summary"]

    lines = []
    lines.append(f"# AI Red Team Report — Scan {scan['id']}")
    lines.append("")
    lines.append(
        f"**Target:** {scan['target_name']} ({scan['target_url']}) [{scan['target_type']}]"
    )
    lines.append(f"**Taxonomy:** {scan['taxonomy_version']}")
    lines.append(f"**Status:** {scan['status']}")
    lines.append(f"**Generated:** {data['generated_at']}")
    lines.append(f"**Hash:** `{data['report_hash']}`")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"**Verdict:** {exec_sum['verdict']}")
    lines.append("")
    lines.append(f"- Total tests: {exec_sum['total_tests']}")
    lines.append(f"- Findings: {exec_sum['findings']}")
    lines.append(
        f"- Counts: PASS={exec_sum['counts']['PASS']}, FAIL={exec_sum['counts']['FAIL']}, INCONCLUSIVE={exec_sum['counts']['INCONCLUSIVE']}, ERROR={exec_sum['counts']['ERROR']}"
    )
    lines.append(f"- Severity: {exec_sum['severity_counts']}")
    lines.append("")
    lines.append(f"> {exec_sum['note']}")
    lines.append("")
    lines.append("## Technical Findings")
    lines.append("")
    if not data["technical_findings"]:
        lines.append("_No findings — all tested scenarios passed or were inconclusive._")
    else:
        for f in data["technical_findings"]:
            lines.append(f"### {f['id']} — {f['title']}")
            lines.append(
                f"- **OWASP:** {f['owasp_category']} | **Severity:** {f['severity']} | **Status:** {f['status']}"
            )
            lines.append(f"- **Target:** {f['target']['name']} ({f['target']['url']})")
            lines.append(f"- **Description:** {f['description']}")
            lines.append(f"- **Attack Objective:** {f['attack_objective']}")
            lines.append(f"- **Preconditions:** {f['preconditions']}")
            lines.append(f"- **Attack Procedure:** {f['attack_procedure']}")
            lines.append(f"- **Observed:** {f['observed_behavior']}")
            lines.append(f"- **Expected:** {f['expected_behavior']}")
            lines.append(f"- **Impact:** {f['impact']}")
            lines.append(f"- **Root Cause:** {f['root_cause']}")
            lines.append(f"- **Protection:** {f['protection']}")
            lines.append(f"- **Remediation:** {f['remediation']}")
            lines.append(f"- **Retest:** {f['retest_procedure']}")
            lines.append(f"- **Regression:** {f['regression_result']}")
            if f["retest_history"]:
                lines.append(f"- **Retest History:** {f['retest_history']}")
            lines.append(
                f"- **Evidence:** `detectors={f['evidence']['detectors_triggered']}` `http_status={f['evidence']['http_status']}` `reproduction={f['evidence']['reproduction_count']}`"
            )
            lines.append(f"  - Request: `{f['evidence']['request']}`")
            lines.append(f"  - Response: `{str(f['evidence']['response'])[:200]}`")
            lines.append(f"- **References:** {f['references']}")
            lines.append("")
    lines.append("## Evidence (All Tests)")
    lines.append("")
    for ev in data["evidence"]:
        lines.append(
            f"- **{ev['attack_id']}** {ev['name']} → **{ev['result']}** (confidence {ev['evidence']['confidence'] if ev['evidence'] else 'n/a'}, reproduction {ev['evidence']['reproduction_count'] if ev['evidence'] else 'n/a'})"
        )
    lines.append("")
    lines.append("## Remediation")
    lines.append("")
    for r in data["remediation"]:
        lines.append(
            f"- **{r['attack_id']}** {r['title']}: {r['remediation']} (Protection: {r['protection_control']}) — Retest: {r['retest_procedure']}"
        )
    lines.append("")
    lines.append("## Retest Status")
    lines.append("")
    for rs in data["retest_status"]:
        lines.append(
            f"- **{rs['attack_id']}** → {rs['regression_status']} history: {rs['history']}"
        )
    lines.append("")
    lines.append("---")
    lines.append(
        "*Generated by AI Red Team — reproducible evidence, deterministic detectors, no LLM opinion alone.*"
    )
    return "\n".join(lines)


def generate_html_report(scan_id: int, db: Session) -> str:
    md = generate_markdown_report(scan_id, db)
    # Minimal Markdown to HTML conversion (no external deps for Sprint 9)
    # Escape and wrap
    import html

    escaped = html.escape(md)
    # Simple replacements for headers and lists
    html_body = escaped.replace("\n", "<br>\n")
    # Add basic styling
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset=\"utf-8\">
<title>AI Red Team Report — Scan {scan_id}</title>
<style>
body {{ font-family: sans-serif; margin: 2em; line-height: 1.5; }}
h1 {{ color: #b00; }}
h2 {{ color: #333; border-bottom: 1px solid #ccc; }}
h3 {{ color: #555; }}
code {{ background: #f4f4f4; padding: 2px 4px; }}
pre {{ background: #f4f4f4; padding: 1em; overflow-x: auto; }}
</style>
</head>
<body>
<pre>{html_body}</pre>
</body>
</html>"""


def save_reports(scan_id: int, db: Session, reports_dir: str = "reports") -> dict[str, str]:
    """Save all three formats to files, return paths."""
    import pathlib

    pathlib.Path(reports_dir).mkdir(parents=True, exist_ok=True)
    data = generate_json_report(scan_id, db)
    import json
    import pathlib

    json_path = pathlib.Path(reports_dir) / f"scan-{scan_id}.json"
    md_path = pathlib.Path(reports_dir) / f"scan-{scan_id}.md"
    html_path = pathlib.Path(reports_dir) / f"scan-{scan_id}.html"
    json_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    md_path.write_text(generate_markdown_report(scan_id, db), encoding="utf-8")
    html_path.write_text(generate_html_report(scan_id, db), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path), "html": str(html_path)}
