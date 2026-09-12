# CLAUDE.md

Project guidance for Claude Code sessions in `cgfixit/Veeam-HealthCheck-Simplifier`.

## Project Overview

Single-file Python CLI (`vhc_simplifier.py`, v4.1.0) that processes Veeam Health Check exports from VBR servers (v12.3.2 and v13) into remediation artifacts. Input comes from running https://vee.am/vhc2 on Windows Server.

## Commands

```bash
# Install dependencies
pip install -r requirements.txt

# Run demo mode
python vhc_simplifier.py --demo

# Run all tests (260 collected; CI fails under 80% coverage)
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --cov=vhc_simplifier --cov-report=term-missing --cov-fail-under=80

# Lint check
ruff check vhc_simplifier.py tests/

# Format check
ruff format --check vhc_simplifier.py tests/

# Quick syntax validation
python -m py_compile vhc_simplifier.py
```

## Architecture

- **Single-file CLI** — `vhc_simplifier.py` is the entire application. Do not split into a package unless explicitly asked.
- **Fault-isolated analyzers** — each `analyze_*()` function runs inside `_run_analyzer()`, which catches exceptions per-analyzer. A failing analyzer records an error and skips, never aborts the run.
- **Adapters** — `_safe_load_csv()` and `_safe_load_json()` handle encoding quirks (UTF-8 BOM, encoding fallback, strict decode). The rest of the pipeline works on pandas DataFrames.
- **Enrichment** — `enrich_findings()` pattern-matches findings to PowerShell commands. `_ps_quote()` guards against injection. Control characters trigger `REFUSED`.
- **Artifact writers** — `_write_artifact()` wraps each output file write in its own try/except.

## Key Constraints

- **Python 3.12+** — do not use features removed before 3.12 or added after 3.13.
- **Preserve `-WhatIf` defaults** on all mutating PowerShell verbs. Never remove without explicit request.
- **No secrets in code** — Salesforce credentials come from env vars only. Never log or hardcode tokens.
- **Slack webhook validation** — only `https://hooks.slack.com/services/...` and `https://hooks.slack-gov.com/services/...` are accepted.
- **Analyzer signatures** — analyzers take DataFrames directly: `analyze_jobs(jobs_df, sessions_df)`, `analyze_security(sec_df)`, `analyze_repositories(repo_df)`, `analyze_malware(malware_df)`. They do NOT take a `result` parameter.
- **Encoding robustness** — CSV loading tries `_candidate_encodings` with `encoding_errors="strict"` and rejects NUL-decoded files. `_read_text()` strips a UTF-8 BOM (`\ufeff`) before JSON parse.

## Test Structure

Tests live in `tests/` with shared fixtures in `conftest.py`. The conftest provides realistic VBR v12.3.2 and v13 export data via fixtures (`vbr_v12_csv_dir`, `vbr_v13_csv_dir`, etc.).

| File | Purpose |
|---|---|
| `test_vhc_simplifier.py` | Core unit tests for helpers, analyzers, loaders, enrichment, artifact writers |
| `test_coverage_gaps.py` | Edge cases: NaN, empty DataFrames, encoding, type coercion |
| `test_vbr_server_simulation.py` | VBR v12/v13 mock server simulation with realistic exports |
| `test_windows_server_env.py` | Windows paths, encoding, PS injection, server version matrix |
| `test_mock_veeam_environment.py` | Full mock VBR environments, file-level fault injection |
| `conftest.py` | Shared fixtures with VBR v12 and v13 CSV/JSON data |

## CI Workflows

Seven GitHub Actions workflows in `.github/workflows/`:
- `ci.yml` — lint + test matrix (Python 3.12/3.13, ubuntu/windows), 80% coverage threshold, Docker smoke
- `ruff.yml` — Ruff lint + format
- `gitleaks.yml` — secret scanning
- `devskim.yml` — Microsoft security linting (tests/ excluded via `ignore-globs`)
- `codeql.yml` — GitHub static analysis
- `dependency-review.yml` — supply chain checks (pull requests only)
- `trivy.yml` — filesystem + Docker image vulnerability scanning

## Style

- Use `ruff` for linting and formatting. Config lives in `pyproject.toml` (`target-version = "py312"`, `line-length = 110`).
- Minimal comments. The code should be self-documenting.
- Prefer stdlib and existing dependencies over adding packages.
- Keep changes in the fewest files possible.
