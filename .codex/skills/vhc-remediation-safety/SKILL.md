---
name: vhc-remediation-safety
description: Review or change Veeam remediation enrichment, Markdown, PowerShell, ticket JSON, Slack, Salesforce, and error logging safely. Use for PATTERN_MAP commands or links, VBR 12/13 version semantics, injection, dry-run behavior, redirects, timeouts, partial writes, or secret redaction.
---

# VHC Remediation Safety

Trace the complete trust boundary:
`finding -> PATTERN_MAP -> enrich_findings() -> writer/integration`.
Generated guidance can reach an operator or external system even when this
Python process never executes PowerShell.

## Version and command truth

- The input/result model carries no VBR or VHC version. Do not imply a VBR 13
  command is safe when enrichment only links to archived VBR 12 documentation.
- Validate every `PATTERN_MAP` URL and cmdlet against the matching official
  Veeam user guide and PowerShell reference at edit time.
- Review `Get-VBRBackupSession` by job ID, not merely `-Name <job>`; the current
  reference example resolves a job and filters sessions by `JobId`:
  [Get-VBRBackupSession](https://helpcenter.veeam.com/docs/vbr/powershell/get-vbrbackupsession.html).
- `Set-VBRJobAdvancedStorageOptions` applies to VMware/Hyper-V jobs and encryption
  uses an encryption key. Do not emit it generically for tape, CDP, NAS,
  Kubernetes, or M365 names:
  [Set-VBRJobAdvancedStorageOptions](https://helpcenter.veeam.com/docs/vbr/powershell/set-vbrjobadvancedstorageoptions.html).
- Confirm malware retrieval against
  [Get-VBRMalwareDetectionEvent](https://helpcenter.veeam.com/docs/vbr/powershell/get-vbrmalwaredetectionevent.html).

If job type, version, or key cannot be proven, emit review-only guidance instead
of a misleading executable command.

`fixit.ps1` is a safe-preview artifact for review in a Veeam PowerShell session,
not a standalone or version-aware remediation tool. If a proposed cmdlet does
not support `ShouldProcess`/`-WhatIf`, keep it as a manual comment.

## Artifact rules

- Preserve `_ps_quote()` and refuse ASCII control characters. Test quotes,
  semicolons, pipes, hashes, CR/LF, tabs, and malicious report-derived names.
- Preserve `-WhatIf` on every generated mutating verb. Also validate actual
  cmdlet semantics; `-WhatIf` does not make a wrong command correct.
- Never execute generated mutation commands during validation.
- Keep ticket output limited to High/Medium findings unless explicitly changed.
- Preserve the three artifact names and contracts: `remediation_summary.md`,
  `fixit.ps1`, and `tickets.json`; ticket short descriptions remain capped at
  250 characters.
- Escape or safely delimit report-derived Markdown so findings cannot forge
  headings, links, or code fences.
- Define behavior for existing artifacts when a later run has no findings. Do
  not leave stale files that look like current output without an explicit rule.
- Keep independent writer failures isolated through `_write_artifact()`.

## Integration and logging rules

- Keep Slack restricted to HTTPS `hooks.slack.com/services/` or
  `hooks.slack-gov.com/services/`, with redirects refused and a 10-second timeout
  in both httpx and urllib paths.
- Redact the complete webhook and Salesforce username/password/token from
  `HealthCheckResult.errors`, exceptions, and log records.
- Salesforce has no explicit timeout and may create some tasks before one call
  fails. Treat it as a partial external write: mock it, test the failure result,
  and never use live credentials in routine validation. Do not add retry or
  idempotency machinery without an explicit requirement.
- Keep optional integrations after local artifacts and isolated from the
  ordinary offline path.

## Checks

```powershell
python -m pytest tests/test_vhc_simplifier.py tests/test_windows_server_env.py -v --tb=short
python -m pytest tests/test_coverage_gaps.py tests/test_vbr_server_simulation.py -v --tb=short
python -m py_compile vhc_simplifier.py
python -m ruff check .
python -m ruff format --check .
```

Add focused `capsys`/`caplog` assertions when output or logging changes. Assert
secrets are absent, not only that an error exists.
