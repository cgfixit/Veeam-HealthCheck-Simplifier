---
name: optimize
description: Repo-local optimization workflow for Veeam-HealthCheck-Simplifier. Use for evidence-backed improvements to VHC/VBR input discovery, CSV/JSON loading, analyzers, remediation artifacts, optional integrations, CI, or Python 3.12+ Windows behavior.
---

# Optimize

Run one evidence-backed robustness, correctness, or performance pass on
`vhc_simplifier.py`. Ponytail discipline applies: understand the full path,
reuse existing seams, and make the smallest justified change.

## Evidence boundaries

- The application expects five logical inputs (`jobs`, `sessions`, `security`,
  `repositories`, and `malware`) but emits four analyzer sections; session
  failures are handled inside `analyze_jobs()`.
- `tests/conftest.py` contains simulated VBR 12.3.2 and VBR 13 CSV/JSON shapes.
  These fixtures prove parser behavior, not live VBR, VHC, or Windows Server
  compatibility.
- Require Windows CI or a real Windows reproduction for UNC, long-path, locale,
  and encoding claims. Cross-platform path simulations are not OS validation.
- Treat JSON as this application's alternate/API-shaped input contract. Do not
  claim that the community VHC script emits these JSON fixtures without an
  authentic export or upstream source proving it.
- Treat the 30-day and seven-restore-point thresholds in `CONFIG` as project
  policy unless a version-matched Veeam source establishes a product default.
- The runtime does not detect VBR or VHC version. Generated commands and links
  therefore must not imply version-specific safety that the input cannot prove.

## Authoritative Veeam sources

Verify version-sensitive claims at edit time; do not rely on test prose alone.

- [VeeamHub Health Check](https://github.com/VeeamHub/veeam-healthcheck) for the
  community tool's current support boundary, invocation, and output behavior.
- [VBR 12.3 release information](https://www.veeam.com/kb4696) and the
  [official build table](https://www.veeam.com/kb2680), plus the
  [VBR 12 archived guide](https://helpcenter.veeam.com/archive/backup/120/vsphere/overview.html).
- VBR 12 archived pages for
  [Security & Compliance Analyzer](https://helpcenter.veeam.com/archive/backup/120/vsphere/best_practices_analyzer.html),
  [malware events](https://helpcenter.veeam.com/archive/backup/120/vsphere/malware_detection_view_events.html),
  [job encryption](https://helpcenter.veeam.com/archive/backup/120/vsphere/encryption_job.html),
  [retention](https://helpcenter.veeam.com/archive/backup/120/vsphere/retention_policy.html), and
  [hardened repositories](https://helpcenter.veeam.com/archive/backup/120/vsphere/hardened_repository_about.html).
- Current VBR 13 pages for
  [backup-server requirements](https://helpcenter.veeam.com/docs/vbr/userguide/system_requirements_backup_server.html?ver=13),
  [Security & Compliance Analyzer](https://helpcenter.veeam.com/docs/vbr/userguide/best_practices_analyzer.html?ver=13), and
  [malware detection](https://helpcenter.veeam.com/docs/vbr/userguide/malware_detection.html?ver=13).
- Current PowerShell references for
  [Get-VBRBackupSession](https://helpcenter.veeam.com/docs/vbr/powershell/get-vbrbackupsession.html),
  [Set-VBRJobAdvancedStorageOptions](https://helpcenter.veeam.com/docs/vbr/powershell/set-vbrjobadvancedstorageoptions.html), and
  [Get-VBRMalwareDetectionEvent](https://helpcenter.veeam.com/docs/vbr/powershell/get-vbrmalwaredetectionevent.html).

## Workflow

1. Confirm scope and record the clean baseline:
   - `git status --short --branch`
   - `python -m py_compile vhc_simplifier.py`
   - `python -m pytest tests --cov=vhc_simplifier --cov-report=term-missing`
   - `python -m ruff check .`
   - `python -m ruff format --check .`
2. Trace the affected path and every caller before editing a shared helper:
   `_resolve_input_file()` -> `_safe_load_csv()` / `_safe_load_json()` ->
   `analyze_*()` through `_run_analyzer()` -> `enrich_findings()` -> artifact
   writers through `_write_artifact()` -> optional integrations.
3. Demonstrate one root cause. Prefer, in order:
   - ambiguous hostname-prefixed file selection, partial/corrupt input, encoding,
     or VBR 12/13 schema drift;
   - unknown cells being coerced into noncompliance, silent session exceptions,
     malware substring false positives, or job-type/version semantic drift;
   - stale `PATTERN_MAP` cmdlets or documentation links;
   - stale artifacts, unescaped report-derived Markdown, unsafe PowerShell,
     redirects, timeouts, partial integration writes, or secret-bearing logs;
   - repeated IO or a measured regression on an owned local path;
   - CLI, README, test, dependency, or CI drift that changes operator behavior.
4. Make the smallest root-cause change. Add a focused regression test that
   fails before the fix. Make no code change when evidence does not justify one.
5. Re-run the baseline, then run
   `python vhc_simplifier.py --demo --quiet --no-artifacts`,
   `git diff --check`, and a complete diff review.

For performance work, use fixed local fixtures and compare repeated before/after
medians under the same Python and filesystem conditions. Reuse the existing
100-job and 1,000-malware-event cases before inventing a microbenchmark. Never
benchmark live Slack or Salesforce calls.

## Code and test ownership

- Discovery/loaders: `_resolve_input_file()`, `_candidate_encodings()`,
  `_safe_load_csv()`, `_safe_load_json()`; validate in
  `test_windows_server_env.py`, `test_vbr_server_simulation.py`, and
  `test_coverage_gaps.py`. Probe exact-versus-fuzzy collisions, multiple hosts,
  case variants, and distinct missing/empty/malformed/header-only outcomes.
- Domain behavior: coercers plus the four `analyze_*()` functions; validate core
  semantics in `test_vhc_simplifier.py` and version parity with shared fixtures
  from `tests/conftest.py`. Missing or unparseable values are unknown, not proof
  that retention, encryption, or immutability is noncompliant.
- Remediation: `PATTERN_MAP`, `_ps_quote()`, and the three writers; validate
  actual cmdlet/job-type semantics, not only syntax. Every mutating command must
  keep `-WhatIf`, and malicious names must not inject code.
- Integrations/logging: Salesforce, Slack, `HealthCheckResult.errors`, and CLI
  logging; mock the network and assert secrets are absent from results and logs.
  Slack must retain its 10-second timeout and redirect refusal. Salesforce has
  no explicit timeout and may partially create tasks before an error, so never
  exercise it with live credentials during optimization.

## Rules

- Keep the single-file CLI unless a demonstrated cohesive boundary makes a
  split safer or materially easier to maintain.
- Reuse `_safe_load_csv()`, `_safe_load_json()`, `_str_cell()`, `_to_number()`,
  `_to_bool()`, `_run_analyzer()`, and `_write_artifact()`.
- Preserve strict encoding fallback: UTF-8 BOM, UTF-16 variants, then cp1252;
  reject corrupt NUL-decoded files. Do not restore replacement decoding.
- Guard missing DataFrame columns before access and tolerate unrelated VBR 13
  columns.
- Preserve partial-run behavior, exit codes 0/1/2, Slack redirect refusal and
  10-second timeout, Salesforce/Slack isolation, and PowerShell `-WhatIf`.
- Use `vhc-export-validation` for input changes and
  `vhc-remediation-safety` for outputs or integrations.
