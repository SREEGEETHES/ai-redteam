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

* [ ] Vulnerable RAG lab
* [ ] Secure RAG lab
* [ ] Tenant isolation
* [ ] Document authorization
* [ ] Retrieval inspection
* [ ] Poisoned document lab
* [ ] Context leakage tests
* [ ] Unauthorized retrieval tests

## SPRINT 5 — Agent Security

* [ ] Vulnerable agent lab
* [ ] Tool registry
* [ ] Tool permission model
* [ ] Tool invocation capture
* [ ] Excessive agency tests
* [ ] Unauthorized tool tests
* [ ] Argument validation
* [ ] Human approval gate
* [ ] Sandboxed tools

## SPRINT 6 — Evidence Engine

* [ ] Evidence records
* [ ] Request capture
* [ ] Response capture
* [ ] Tool-call capture
* [ ] Retrieval evidence
* [ ] Deterministic detection
* [ ] Reproduction tracking
* [ ] Evidence viewer

## SPRINT 7 — Protection Engine

* [ ] Remediation recommendations
* [ ] Security controls
* [ ] Protection checks
* [ ] Authorization checks
* [ ] Rate-limit checks
* [ ] Output validation checks
* [ ] Tool allowlist checks
* [ ] Secret handling checks

## SPRINT 8 — Regression

* [ ] Retest engine
* [ ] Before/after comparison
* [ ] Regression status
* [ ] Finding lifecycle
* [ ] Fix verification
* [ ] Regression history

## SPRINT 9 — Reporting

* [ ] JSON report
* [ ] Markdown report
* [ ] HTML report
* [ ] Executive summary
* [ ] Technical findings
* [ ] Evidence
* [ ] Remediation
* [ ] Retest status

## SPRINT 10 — Streamlit Dashboard

* [ ] Dashboard
* [ ] Target selector
* [ ] Scan launcher
* [ ] Progress
* [ ] PASS/FAIL dashboard
* [ ] Severity dashboard
* [ ] Findings
* [ ] Evidence viewer
* [ ] Remediation viewer
* [ ] Retest button
* [ ] Scan history

## SPRINT 11 — CI/CD

* [ ] GitHub Actions
* [ ] Automated tests
* [ ] Security regression tests
* [ ] Scanner test suite
* [ ] Docker build
* [ ] Artifact generation

## SPRINT 12 — J.A.R.V.I.S. Integration

* [ ] /jarvis ai-redteam scan
* [ ] /jarvis ai-redteam status
* [ ] /jarvis ai-redteam report
* [ ] /jarvis ai-redteam retest
* [ ] /jarvis ai-redteam checklist
* [ ] /jarvis ai-redteam dashboard