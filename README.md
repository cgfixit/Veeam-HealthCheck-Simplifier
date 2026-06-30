# Veeam Health Check Simplifier

**A security-focused CLI pipeline that ingests [Veeam Health Check](https://vee.am/vhc2) exports from Veeam Backup & Replication (VBR) servers, analyzes them for compliance gaps, and generates safe, reviewable remediation artifacts.**

---

## What is the Veeam Health Check?

The [Veeam Health Check (VHC)](https://vee.am/vhc2) is a PowerShell-based diagnostic script that runs against a Veeam Backup & Replication server on Windows. It exports CSV and JSON files covering:

- **Jobs** — backup job configuration (retention, encryption, schedules)
- **Sessions** — recent job run results (success, failure, warnings)
- **Security Compliance** — best-practice status (MFA, RDP, encryption, immutability)
- **Repositories** — backup storage targets and immutability support
- **Malware Events** — inline scan, YARA rule, and entropy detection results

This project takes those raw exports and transforms them into actionable remediation guidance — no manual spreadsheet review required.

### Supported VBR Versions

| VBR Version | Build | Windows Server | Status |
|---|---|---|---|
| v12.3.2 | 12.3.2.4643 | 2016, 2019, 2022, 2025 | Simulated VHC fixture coverage |
| v13 | 13.0.x fixture target | 2019, 2022, 2025 | Simulated VHC fixture coverage |

---

## How It Works

```
                     ┌─────────────────────────────────┐
                     │  Windows Server with VBR        │
                     │  Run https://vee.am/vhc2        │
                     │  → Exports CSV/JSON files       │
                     └───────────────┬─────────────────┘
                                     │
                                     ▼
                     ┌─────────────────────────────────┐
                     │  vhc_simplifier.py               │
                     │                                   │
                     │  1. Load exports (CSV or JSON)    │
                     │  2. Analyze across 5 domains      │
                     │  3. Enrich with remediation cmds  │
                     │  4. Generate artifacts            │
                     │  5. (Optional) Push to SF/Slack   │
                     └───────────────┬─────────────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    ▼                ▼                ▼
             remediation_      fixit.ps1       tickets.json
             summary.md     (safe -WhatIf)    (ITSM-ready)
```

### Analysis Pipeline

1. **Load** — `_safe_load_csv()` / `_safe_load_json()` with UTF-8 BOM stripping, Windows-oriented encoding fallback, corrupt-decode guards, and empty-file guards
2. **Analyze** — fault-isolated analyzers (`_run_analyzer()` wrapper catches exceptions per-analyzer, never aborts the run):
   - `analyze_jobs()` — retention, encryption, schedule gaps
   - `analyze_sessions()` — recent failures and warnings
   - `analyze_security()` — best-practice compliance status
   - `analyze_repositories()` — immutability support gaps
   - `analyze_malware()` — infected/suspicious scan results
3. **Enrich** — `enrich_findings()` pattern-matches each finding to a PowerShell remediation command with KB article links, applying `_ps_quote()` injection guards
4. **Write** — `_write_artifact()` wrapper isolates IO errors per-file:
   - `remediation_summary.md` — human-readable report with severity, PS snippets, and KB links
   - `fixit.ps1` — executable remediation script (all mutating verbs include `-WhatIf`)
   - `tickets.json` — ITSM-ready payload (High/Medium findings only)
5. **Integrate** (optional) — push findings to Salesforce as Tasks or post a summary to Slack

---

## Features

- **Multi-format input** — CSV (default, from [vee.am/vhc2](https://vee.am/vhc2)) or JSON (VBR REST API exports)
- **Demo mode** — runs instantly with embedded real-world sample data; no input files required
- **Secure PowerShell output** — all mutating commands (`Set-`, `New-`, `Remove-`, etc.) include `-WhatIf` by default
- **PS injection prevention** — object names with control characters are refused, not interpolated
- **Salesforce integration** — creates Tasks on an Account record for High/Medium findings
- **Slack notifications** — posts a severity summary to an incoming webhook
- **Graceful degradation** — missing input files are logged but never fatal; partial runs proceed; individual analyzer failures are recorded and skipped without aborting the run
- **Robust encoding handling** — tolerates UTF-8 BOM (common from Windows PowerShell `Export-Csv`), UTF-16 variants, and Windows code-page fallback while rejecting corrupt NUL-decoded files
- **No secrets in code** — Salesforce credentials resolved from environment variables only

---

## Generated Artifacts

| File | Description |
|---|---|
| `remediation_summary.md` | Human-readable findings with PowerShell snippets and KB links |
| `fixit.ps1` | Safe preview remediation script (`-WhatIf` on all mutating commands) |
| `tickets.json` | ITSM-ready JSON payload (High/Medium findings only) |

---

## Requirements

- Python 3.12+ (tested on 3.12 and 3.13)
- `pandas` (core dependency)
- `simple-salesforce` *(optional — only for `--sf-account-id`)*
- `httpx` *(optional — Slack fallback uses stdlib `urllib` if absent)*
- `pytest`, `pytest-cov` *(dev/testing only)*

```bash
pip install -r requirements.txt
```

---

## Quick Start

```bash
# Demo mode (no files needed — uses embedded sample data)
python vhc_simplifier.py --demo

# Real CSV export from a VBR server (run vee.am/vhc2 on Windows first)
python vhc_simplifier.py --input-dir ./vhc-exports --output-dir ./results

# JSON / VBR REST API export
python vhc_simplifier.py --input-dir ./vhc-json --input-format json

# With Salesforce Task creation
export SF_USERNAME=user@domain.com
export SF_PASSWORD=yourpassword
export SF_TOKEN=yoursecuritytoken
python vhc_simplifier.py --demo --sf-account-id 001XXXXXXXXXXXX

# With Slack notification
python vhc_simplifier.py --input-dir ./vhc-exports \
  --slack-webhook https://hooks.slack.com/services/T00/B00/xxx

# Quiet mode (no console output, just artifacts)
python vhc_simplifier.py --input-dir ./vhc-exports --quiet

# Skip artifact writing (analysis only)
python vhc_simplifier.py --input-dir ./vhc-exports --no-artifacts
```

---

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `--input-dir` | `.` | Directory containing VHC export files |
| `--output-dir` | `.` | Directory for generated artifacts |
| `--input-format` | `csv` | Input format: `csv` or `json` |
| `--demo` | off | Use embedded sample data (no files needed) |
| `--no-artifacts` | off | Skip writing `.md`/`.ps1`/`.json` files |
| `--quiet` | off | Suppress console report |
| `--verbose` | off | Enable verbose/debug logging |
| `--sf-account-id` | — | Salesforce Account ID for Task creation |
| `--sf-username` | — | SF username (prefer `SF_USERNAME` env var) |
| `--sf-password` | — | SF password (prefer `SF_PASSWORD` env var) |
| `--sf-token` | — | SF security token (prefer `SF_TOKEN` env var) |
| `--slack-webhook` | — | Slack incoming webhook URL |

---

## Expected Input Files

These files are produced by running the [Veeam Health Check script](https://vee.am/vhc2) on a Windows Server with VBR installed:

| Data | CSV filename | JSON filename |
|---|---|---|
| Jobs | `localhost_Jobs.csv` | `localhost_Jobs.json` |
| Sessions | `VeeamSessionReport.csv` | `VeeamSessionReport.json` |
| Security | `localhost_SecurityCompliance.csv` | `localhost_SecurityCompliance.json` |
| Repositories | `localhost_Repositories.csv` | `localhost_Repositories.json` |
| Malware | `localhostmalware_events.csv` | `localhostmalware_events.json` |

All files are optional — missing files are logged and skipped without aborting.

---

## Integrations

### Salesforce

Creates Tasks on a Salesforce Account record for High and Medium severity findings. Requires `simple-salesforce` and credentials via environment variables:

```bash
export SF_USERNAME=user@domain.com
export SF_PASSWORD=yourpassword
export SF_TOKEN=yoursecuritytoken
python vhc_simplifier.py --demo --sf-account-id 001XXXXXXXXXXXX
```

### Slack

Posts a severity summary to a Slack incoming webhook. Validates that the webhook URL uses HTTPS and targets `hooks.slack.com` or `hooks.slack-gov.com`:

```bash
python vhc_simplifier.py --demo \
  --slack-webhook https://hooks.slack.com/services/T00/B00/xxx
```

Uses `httpx` if available, falls back to stdlib `urllib`.

---

## Testing

The test suite covers 219 tests across 6 files with 90%+ code coverage:

| Test File | Tests | Coverage |
|---|---|---|
| `test_vhc_simplifier.py` | Core helpers, analyzers, loaders, enrichment, artifact writers, integration runs |
| `test_coverage_gaps.py` | Edge cases: NaN handling, empty DataFrames, encoding, type coercion |
| `test_vbr_server_simulation.py` | VBR v12.3.2 and v13 mock server simulation with realistic export data |
| `test_windows_server_env.py` | Windows paths, encoding (BOM, UTF-16), PowerShell injection, server version matrix |
| `test_mock_veeam_environment.py` | Full mock VBR environments with file-level fault injection |
| `conftest.py` | Shared fixtures with realistic VBR v12 and v13 CSV/JSON export data |

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage reporting
python -m pytest tests/ -v --cov=vhc_simplifier --cov-report=term-missing

# Run VBR server simulation tests only
python -m pytest tests/test_vbr_server_simulation.py -v
```

---

## CI/CD Workflows

Six GitHub Actions workflows run on every push and pull request to `main`:

| Workflow | File | Purpose |
|---|---|---|
| **CI** | `ci.yml` | Lint + test matrix (Python 3.12/3.13 on ubuntu + windows), 80% coverage threshold |
| **Ruff** | `ruff.yml` | Python lint and format checks |
| **Gitleaks** | `gitleaks.yml` | Secret scanning (push, PR, weekly) |
| **DevSkim** | `devskim.yml` | Microsoft security anti-pattern detection (push, PR, weekly) |
| **CodeQL** | `codeql.yml` | GitHub static analysis (push, PR, weekly) |
| **Dependency Review** | `dependency-review.yml` | Supply chain vulnerability checks on PRs |

---

## Architecture

```
Input (CSV / JSON / --demo)
        |
        v
  _safe_load_*()       <- adapter layer (BOM stripping, encoding fallback)
        |
        v
  _run_analyzer()      <- fault isolation wrapper (records errors, never aborts)
        |
        v
  analyze_*()          <- pure functions, domain-scoped (jobs, sessions, security, repos, malware)
        |
        v
  enrich_findings()    <- pattern-matched remediation + PS injection guard (_ps_quote)
        |
        |---> _write_artifact()        <- IO error isolation wrapper
        |         |---> write_markdown()
        |         |---> write_powershell_script()
        |         `---> write_ticket_payload()
        |---> _push_to_salesforce()    (optional)
        `---> _post_slack_summary()    (optional)
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Unhandled exception |
| `2` | Processing errors occurred (check stderr / logs) |

---

## Security Notes

- **Never commit credentials.** Use env vars (`SF_USERNAME`, `SF_PASSWORD`, `SF_TOKEN`) or a secrets manager.
- **Review `-WhatIf` output before removing it.** Validate every command in a non-production environment first.
- **Injection prevention.** Object names with ASCII control characters (`0x00-0x1F`, `0x7F`) are refused from PS command generation entirely.
- **Slack webhook validation.** Only `https://hooks.slack.com/...` and `https://hooks.slack-gov.com/...` URLs are accepted.

---

See [LICENSE.md](LICENSE.md), [CONTRIBUTORS.md](CONTRIBUTORS.md), and [SECURITY.md](SECURITY.md).
