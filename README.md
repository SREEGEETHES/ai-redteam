# AI Red Team

> Break the AI. Prove the vulnerability. Verify the fix.

A production-quality, local-first AI Red Team Security Testing Platform for testing LLM, RAG, and AI-agent applications against controlled adversarial scenarios.

## Features

- **Multi-target support**: LLM APIs, RAG systems, AI Agents
- **OWASP GenAI LLM Top 10 2026** taxonomy alignment
- **Evidence-based testing**: Deterministic evidence collection, not LLM opinions
- **No Fake Pass rule**: PASS requires sufficient evidence of secure behavior
- **Regression testing**: FAIL → PASS verification with history
- **Multiple interfaces**: CLI, REST API, Streamlit Dashboard
- **J.A.R.V.I.S. ready**: Designed for future integration (optional)
- **Safe by default**: Target authorization guards, localhost defaults, sandboxed execution

## Quick Start

### Prerequisites

- Python 3.11+
- Docker (for vulnerable labs)
- Ollama (for local LLM testing)

### Installation

```bash
# Clone and install
git clone <repo>
cd ai-redteam
pip install -e .

# Initialize database
redteam init

# Start API server
redteam serve
```

### Run Vulnerable Labs

```bash
# Start vulnerable RAG lab
docker compose up vulnerable-rag

# In another terminal, scan it
redteam target add vulnerable-rag http://localhost:8003 --type rag
redteam scan start 1
```

### Streamlit Dashboard

```bash
# Start dashboard
docker compose up dashboard
# Or locally
streamlit run dashboard/main.py
```

## Architecture

```
AI RED TEAM PLATFORM
    │
    ├── CLI              # Command-line interface
    ├── REST API         # FastAPI server
    ├── Streamlit        # Web dashboard
    │
    ├── Scan Orchestrator
    │       │
    │       ├── Attack Engine
    │       ├── Evidence Engine
    │       └── Policy Engine
    │
    ├── Target Adapters
    │       ├── REST Adapter
    │       ├── Ollama Adapter
    │       ├── OpenAI Adapter
    │       ├── RAG Adapter
    │       └── Agent Adapter
    │
    ├── Security Analyzer
    │       ├── LLM Target
    │       ├── RAG Target
    │       └── Agent Target
    │
    ├── Report Generator
    ├── Regression Engine
    └── SQLite History
```

## OWASP GenAI LLM Top 10 2026 Coverage

| ID | Category | Status |
|----|----------|--------|
| LLM01 | Prompt Injection | 🚧 |
| LLM02 | Sensitive Information Disclosure | 🚧 |
| LLM03 | Supply Chain Vulnerabilities | 🚧 |
| LLM04 | Data and Model Poisoning | 🚧 |
| LLM05 | Improper Output Handling | 🚧 |
| LLM06 | Excessive Agency | 🚧 |
| LLM07 | System Prompt Leakage | 🚧 |
| LLM08 | Vector and Embedding Weaknesses | 🚧 |
| LLM09 | Misinformation | 🚧 |
| LLM10 | Unbounded Consumption | 🚧 |

## Result Classification

- **PASS**: Tested security expectation satisfied
- **FAIL**: Attack demonstrated vulnerability
- **INCONCLUSIVE**: Insufficient evidence
- **NOT_APPLICABLE**: Test not applicable to target
- **ERROR**: Test execution failed

## Security

- Target authorization required (localhost by default)
- No hardcoded credentials
- Sandboxed agent tool execution
- Rate limits and execution budgets
- Audit logging

## Documentation

- [Architecture](docs/architecture.md)
- [Threat Model](docs/threat-model.md)
- [Attack Methodology](docs/attack-methodology.md)
- [Protection Guide](docs/protection-guide.md)
- [OWASP Mapping](docs/owasp-mapping.md)

## Development

```bash
# Install dev dependencies
pip install -e .[dev]

# Run tests
pytest

# Lint
ruff check .

# Type check
mypy app/
```

## Project Structure

```
ai-red-team/
├── app/
│   ├── api/           # FastAPI REST API
│   ├── cli/           # Click CLI
│   ├── core/          # Config, logging
│   ├── attacks/       # Attack definitions per OWASP category
│   ├── adapters/      # Target adapters
│   ├── analyzers/     # Evidence analysis
│   ├── evidence/      # Evidence models
│   ├── protections/   # Blue-team checks
│   ├── regression/    # Regression testing
│   ├── reporting/     # Report generation
│   ├── database/      # SQLAlchemy models
│   ├── models/        # Pydantic schemas
│   └── security/      # Authorization guards
├── dashboard/         # Streamlit UI
├── config/
│   ├── taxonomies/    # OWASP taxonomy files
│   └── policies/      # Security policies
├── examples/          # Vulnerable/secure labs
├── tests/             # Unit & integration tests
├── docs/              # Documentation
├── docker/            # Dockerfiles
├── CHECKLIST.md       # Sprint checklist
└── pyproject.toml
```

## License

MIT License - See LICENSE file for details.

## Disclaimer

This is an authorized security testing platform. Testing must be limited to:
- localhost
- Developer-owned applications
- Explicitly authorized environments
- Intentionally vulnerable labs
- Test/staging environments with authorization

The platform includes safeguards preventing accidental scanning of unauthorized targets.