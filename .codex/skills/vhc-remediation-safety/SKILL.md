---
name: vhc-remediation-safety
description: Review or change generated remediation artifacts and integrations safely. Use when editing PowerShell fix generation, ticket payloads, Slack webhooks, Salesforce tasks, finding enrichment, or secret/error handling.
---

# VHC Remediation Safety

Use this when findings leave analysis and become artifacts or integrations.

## Rules

- Preserve `-WhatIf` on mutating PowerShell commands.
- Keep `_ps_quote()` injection checks for job/object names; reject control characters.
- Keep ticket payloads limited to High and Medium findings unless explicitly requested.
- Never hardcode credentials; use environment/CLI inputs and redact secrets in errors.
- Validate Slack webhooks as HTTPS `hooks.slack.com/services/` or `hooks.slack-gov.com/services/`.
- Mock Slack and Salesforce in tests; do not use live credentials for normal validation.

## Checks

- PowerShell/artifact scope: `python -m pytest tests/test_vhc_simplifier.py tests/test_windows_server_env.py -v --tb=short`
- Integration error handling: `python -m pytest tests/test_coverage_gaps.py -v --tb=short`
- Syntax: `python -m py_compile vhc_simplifier.py`
