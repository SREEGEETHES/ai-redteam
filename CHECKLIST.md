# AI Red Team - Project Checklist

## SPRINT 0 — Architecture & Foundation

* [x] Repository structure created
* [x] Python project setup (pyproject.toml)
* [x] FastAPI skeleton
* [x] CLI skeleton
* [x] SQLite setup
* [x] Pydantic models
* [x] Logging system
* [x] Configuration system
* [x] Target authorization guard
* [x] Docker Compose foundation
* [x] Initial tests

## SPRINT 1 — Target Adapters

* [x] REST adapter
* [x] Ollama adapter
* [x] OpenAI-compatible adapter
* [x] RAG adapter
* [x] Agent adapter
* [x] Target configuration
* [x] Health checks
* [x] Baseline requests
* [x] Request/response capture
* [x] Vulnerable labs (LLM, RAG, Agent)
* [x] Secure labs (LLM, RAG, Agent)

## SPRINT 2 — Attack Framework

* [x] AttackDefinition (app/attacks/definition.py - immutable dataclass with strict evidence requirements)
* [x] Attack registry (app/attacks/registry.py - SEED_ATTACKS covering LLM01/02/04/06/07/08 + registry API)
* [x] Payload generator (app/attacks/payloads.py - 11 deterministic generators, no LLM)
* [x] Execution engine (app/attacks/engine.py - baseline→attack→observe→evidence→classify with reproduction & adaptation)
* [x] Result engine (app/attacks/results.py - NO FAKE PASS: FAIL> PASS> INCONCLUSIVE> ERROR, never converts absence to PASS)
* [x] Evidence model (app/evidence/engine.py - immutable EvidenceRecord with request/response/status/tool_calls/docs/detectors/reproduction/confidence)
* [x] Deterministic detectors (app/attacks/detectors.py - 8 detectors: canary/regex/prompt_leak/injection/refusal/tool/cross_tenant/http_error)
* [x] Scan orchestrator (app/core/orchestrator.py - persists Test/Evidence/Finding, handles NOT_APPLICABLE, FAIL/PASS)
* [x] API run endpoints (POST /scans/{id}/run, GET /scans/{id}/tests, GET /tests/{id}/evidence)
* [x] Live lab verification (vulnerable vs secure RAG/LLM/Agent → FAIL→PASS with evidence)

## SPRINT 3 — OWASP LLM Testing

* [x] LLM01 Prompt Injection (LLM01-PI-001 direct injection, detectors: prompt_injection_success/system_prompt_leak/refusal, PASS secure)
* [x] LLM02 Sensitive Information Disclosure (LLM02-SD-001 canary extraction, canary/regex detectors, secret filtering)
* [x] LLM03 Supply Chain Vulnerabilities (LLM03-SC-001 SBOM leak + LLM03-SC-002 vulnerable dependency, detectors: sbom_leak/vulnerable_dependency, labs: SBOM leak vs pinned signed)
* [x] LLM04 Data and Model Poisoning (LLM04-POISON-001 poisoned retrieval, detectors: prompt_injection/canary, labs: poisoned doc)
* [x] LLM05 Improper Output Handling (LLM05-OH-001 SQLi + LLM05-OH-002 XSS/shell, detectors: improper_output_sql_xss/output_handling_safe, labs: raw SQL/HTML vs sanitized)
* [x] LLM06 Excessive Agency (LLM06-AGENT-001 unauthorized tool, detectors: unauthorized_tool_attempt/refusal, labs: allowlist vs destructive)
* [x] LLM07 System Prompt Leakage (LLM07-SPL-001 direct extraction, detectors: system_prompt_leak/refusal)
* [x] LLM08 Vector and Embedding Weaknesses (LLM08-VECT-001 cross-tenant, detector: cross_tenant_retrieval, labs: tenant isolation)
* [x] LLM09 Misinformation (LLM09-MIS-001 fabricated citation + LLM09-MIS-002 ungrounded Atlantis, detectors: fabricated_citation/grounding_ok, labs: grounding refusal)
* [x] LLM10 Unbounded Consumption (LLM10-UC-001 token exhaustion + LLM10-UC-002 concurrency, detectors: unbounded_consumption/consumption_safe, labs: huge output vs 429/limit)
* [x] Each category has ≥1 controlled attack + protection + retest path (OWASP 2026 full coverage, 14 seed attacks, live vuln FAIL→secure PASS verified, 114 tests pass)

## SPRINT 4 — RAG Security

* [x] Vulnerable RAG lab (enhanced: /ingest no quarantine, /document/{id} no ACL, /retrieval/inspect leaks raw metadata/similarity, poisoned doc seeded, context leak via Admin mode)
* [x] Secure RAG lab (enhanced: /ingest provenance+quarantine, /document/{id} ACL 403, /retrieval/inspect filtered, tenant isolation, secret filtering)
* [x] Tenant isolation (LLM08-VECT-001 + tenant_isolation_ok detector, vulnerable FAIL cross_tenant vs secure PASS isolation_ok, live verified)
* [x] Document authorization (RAG-UNAUTH-001 direct ID, vulnerable 200 vs secure 403 ACL, detector: unauthorized_document_access/refusal, live verified)
* [x] Retrieval inspection (RAG-RETRIEVAL-001, vulnerable metadata_leak=true vs secure filtered metadata_leak=false, retrieval_inspection_ok, live verified)
* [x] Poisoned document lab (RAG-POISON-002 ingest quarantine, vulnerable ingested vs secure quarantined, poisoned_ingest detector, live verified)
* [x] Context leakage tests (RAG-CONTEXT-001 indirect injection via retrieved poisoned doc, vulnerable Admin mode vs secure grounding_ok, context_leakage detector, live verified)
* [x] Unauthorized retrieval tests (RAG-UNAUTH-001 + LLM08 cross-tenant, unauthorized_document_access, live vulnerable FAIL→secure PASS, 8 new tests, 122 total, adapter methods: ingest_document/get_document_by_id/retrieval_inspect)

## SPRINT 5 — Agent Security

* [x] Vulnerable agent lab (enhanced: all 8 tools, no auth, no validation, destructive DATABASE DELETED, shell exec, privilege escalation)
* [x] Tool registry (app/tools/registry.py - ToolDefinition, ToolRegistry with allowlist, risk levels, SECURE vs VULNERABLE)
* [x] Tool permission model (app/tools/permissions.py - PermissionModel with least privilege, scoped credentials, approval)
* [x] Tool invocation capture (adapter captures tool/args/auth/result/side_effect/sequence, evidence tool_calls, orchestrator persists)
* [x] Excessive agency tests (AGENT-EXCESS-001 privilege escalation, AGENT-SANDBOX-001 shell, excessive_agency/sandbox_violation detectors)
* [x] Unauthorized tool tests (LLM06-AGENT-001 delete_database, unauthorized_tool_attempt, live FAIL vs PASS)
* [x] Argument validation (app/tools/validator.py - path traversal/SQL/command, AGENT-ARG-001, argument_validation_bypass)
* [x] Human approval gate (app/tools/permissions.py approval_token, AGENT-APPROVAL-001 write without approval, approval_gate_bypass)
* [x] Sandboxed tools (app/tools/sandbox.py - MockFilesystem/MockDatabase/MockHTTP/MockEmail/Sandbox, no real damage, live verified)

## SPRINT 6 — Evidence Engine

* [x] Evidence records (immutable EvidenceRecord with scan_id/test_id/timestamp/target/request/response/status/headers/tool_calls/retrieved_docs/detectors/expected/observed/reproduction/confidence/result + hash 16, evidence_metadata)
* [x] Request capture (attack_id/target_id/target_url/payload/headers/auth context/user session/timestamp/method via capture_request_details)
* [x] Response capture (http_status/headers/body/tool_calls/retrieved_ids/similarity/baseline/timestamp via capture_response_details)
* [x] Tool-call capture (tool/args/auth/result/side_effect/sequence/timestamp via capture_tool_calls_detailed, evidence tool_calls)
* [x] Retrieval evidence (retrieved_ids, documents, metadata, similarity_scores, context, count via capture_retrieval_evidence)
* [x] Deterministic detection (run_detectors pure functions, no LLM, confidence, reproducible, verified via test_deterministic_detection)
* [x] Reproduction tracking (reproduction_count, history, reproducible bool, non-reproducible→INCONCLUSIVE via reproduction_history, engine loop)
* [x] Evidence viewer (API GET /scans/{id}/evidence, GET /tests/{id}/evidence + dashboard/pages Evidence with request/response/tool/retrieval/detectors/reproduction/hash, viewer helpers evidence_viewer_summary, enforce_immutability)

## SPRINT 7 — Protection Engine

* [x] Remediation recommendations (app/protections/remediation.py - build_remediation per Finding, root cause/impact/fix/retest, 14 attacks all have remediation, verified via test_every_attack_has_remediation)
* [x] Security controls (ToolRegistry allowlist, PermissionModel least privilege, validator, sandbox, tenant isolation, rate limit, output validation)
* [x] Protection checks (app/protections/checks.py - 7 checks: authorization, tool_allowlist, rate_limit, output_validation, secret_handling, tenant_isolation, logging_approval, static+runtime, PROTECTION_REGISTRY)
* [x] Authorization checks (authorization middleware/ACL, static allowlist + runtime 403/refusal, vulnerable FAIL vs secure PASS)
* [x] Rate-limit checks (static quota + runtime 429/consumption_safe, vulnerable unbounded vs secure limit)
* [x] Output validation checks (static schema + runtime improper_output_sql_xss vs output_handling_safe)
* [x] Tool allowlist checks (static allowlist <=3 + runtime unauthorized_tool_attempt vs refusal, SECURE 2 vs VULN 8)
* [x] Secret handling checks (static secret_scanning + runtime canary/regex leak vs refusal, vulnerable leak vs secure filtered)

## SPRINT 8 — Regression

* [x] Retest engine (app/regression/engine.py - real retest_finding creates retest scan, runs single attack via orchestrator, compares FAIL→PASS)
* [x] Before/after comparison (compare_before_after returns original_result, latest_retest, evidence, verified bool)
* [x] Regression status (RegressionStatus: NOT_TESTED, VERIFIED, REGRESSION_FAILED, FIX_PENDING per spec 28)
* [x] Finding lifecycle (finding_lifecycle timeline, retest_count, history)
* [x] Fix verification (FAIL→PASS => VERIFIED, FAIL→FAIL => REGRESSION_FAILED, FAIL→INCONCLUSIVE/ERROR => FIX_PENDING, live vuln→secure verified)
* [x] Regression history (get_regression_history, Retest table, API GET /findings/{id}/history/compare/lifecycle, CLI retest group, 6 tests, 167 total, live vulnerable FAIL→secure PASS retest history)

## SPRINT 9 — Reporting

* [x] JSON report (app/reporting/engine.py generate_json_report with scan/target/summary/findings/evidence/remediation/retest + report_hash 16, reproducible)
* [x] Markdown report (generate_markdown_report with Executive Summary, Technical Findings per spec 41, Evidence, Remediation, Retest)
* [x] HTML report (generate_html_report minimal MD→HTML, styled, same content)
* [x] Executive summary (verdict, total/tests counts, severity_counts, note per spec 49)
* [x] Technical findings (per finding: ID, Title, OWASP, Target, Severity, Status, Description, Attack Objective, Preconditions, Procedure, Observed/Expected, Evidence, Impact, Root Cause, Protection, Remediation, Retest, Regression, References)
* [x] Evidence (per test: request/response/status/headers/tool_calls/retrieved_docs/detectors/reproduction/confidence, hash, viewer)
* [x] Remediation (per finding: recommended_fix, protection_control, retest_procedure from registry)
* [x] Retest status (retest_status with regression_status + history, save_reports to reports/scan-{id}.json/md/html, API GET /scans/{id}/report?format=, CLI report group, 8 tests, 175 total, live reproducible hash)

## SPRINT 10 — Streamlit Dashboard

* [x] Dashboard (dashboard/main.py:1 — 13 pages, wide layout, API health)
* [x] Target selector (Targets page with list/health, add, details + protection checks via GET /protections/checks)
* [x] Scan launcher (Scan page with target/category/attack selectors, POST /scans + POST /scans/{id}/run, real API, no CLI)
* [x] Progress (Scan page progress bar per test, bar_chart PASS/FAIL, polling, last_scan_id session)
* [x] PASS/FAIL dashboard (Overview bar_chart counts, Scan progress bar, Findings table)
* [x] Severity dashboard (Overview bar_chart severity_counts, Findings filter)
* [x] Findings (Findings page with scan selector, severity filter, remediation/retest expanders, Retest button POST /findings/{id}/retest)
* [x] Evidence viewer (Evidence page with request/response/tool/retrieval/detectors/reproduction/hash, compare before/after)
* [x] Remediation viewer (Remediation page per finding with root cause/impact/protection/remediation/retest, GET /attacks/{id}/remediation)
* [x] Retest button (Findings + Retest pages, CLI retest group, API retest/history/compare/lifecycle)
* [x] Scan history (Scan History page with all scans, tests, findings, evidence, report buttons JSON/Markdown/HTML via GET /scans/{id}/report)

## SPRINT 11 — CI/CD

* [x] GitHub Actions (`.github/workflows/ci.yml` + `artifacts.yml`)
* [x] Automated tests (lint, typecheck, unit, integration on every PR/push)
* [x] Security regression tests (daily scheduled + PR gate, vulnerable vs secure labs)
* [x] Scanner test suite (183 tests in CI, 183 passed)
* [x] Docker build (multi-stage, Buildx, multi-arch, cache, GHCR push on main)
* [x] Artifact generation (reports JSON/MD/HTML, test results, coverage, SBOM)

## SPRINT 12 — J.A.R.V.I.S. Integration

* [ ] /jarvis ai-redteam scan
* [ ] /jarvis ai-redteam status
* [ ] /jarvis ai-redteam report
* [ ] /jarvis ai-redteam retest
* [ ] /jarvis ai-redteam checklist
* [ ] /jarvis ai-redteam dashboard