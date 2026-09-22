
# AI Red Team Development Rules

This repository is an authorized AI security testing project.

Follow the project's README, architecture documents, threat model, and CHECKLIST.md.

Do not generate the entire project in one step.

Work sprint-by-sprint.

Never mark a checklist item complete unless:
1. The implementation exists.
2. Relevant tests exist.
3. Tests pass.
4. Acceptance criteria are satisfied.
5. Documentation is updated.

Never use real credentials, secrets, customer data, or destructive infrastructure.

All security testing must use:
- localhost
- intentionally vulnerable labs
- developer-owned applications
- explicitly authorized environments

Prefer deterministic security evidence over LLM opinions.

Never claim an application is "secure" merely because tests passed.

Use:
- PASS
- FAIL
- INCONCLUSIVE
- NOT_APPLICABLE
- ERROR

Keep the AI Red Team engine independent from J.A.R.V.I.S.

J.A.R.V.I.S. will be integrated later as an optional interface.

Do not add J.A.R.V.I.S. dependencies during the initial implementation.