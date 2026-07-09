---
name: optimize
description: Repo-local optimization and robustness checklist for Veeam-HealthCheck-Simplifier. Use when asked to optimize, harden, or improve CI/test coverage for VHC CSV/JSON loading, analyzer fault isolation, generated artifacts, or Python 3.12+ Windows compatibility.
---

# Optimize

Use this for small robustness and performance passes on `vhc_simplifier.py`.

## Rules

- Keep the single-file CLI unless the user explicitly asks for structure.
- Reuse `_safe_load_csv()`, `_safe_load_json()`, `_str_cell()`, `_to_number()`, `_to_bool()`, `_run_analyzer()`, and `_write_artifact()`.
- Preserve strict encoding fallback behavior: UTF-8 BOM, UTF-16 variants, then Windows code page fallback; reject corrupt NUL-decoded files.
- Guard missing DataFrame columns before access.
- Keep optional Slack and Salesforce paths isolated from the default local path.
- Preserve `-WhatIf` on generated PowerShell mutating commands.

## Checks

- Python syntax: `python -m py_compile vhc_simplifier.py`
- Behavior: `python -m pytest tests/ -v`
- CI parity: `ruff check vhc_simplifier.py tests/` and `ruff format --check vhc_simplifier.py tests/`

## Notes

- This replaces the older Claude optimize notes. Do not reintroduce `encoding_errors="replace"` as the default CSV path; current behavior is strict fallback plus corrupt-decode guards.
