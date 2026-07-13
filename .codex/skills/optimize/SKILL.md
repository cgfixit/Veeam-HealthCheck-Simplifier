---
name: optimize
description: Repo-local optimization and robustness checklist for Veeam-HealthCheck-Simplifier. Use when asked to optimize, harden, or improve CI/test coverage for VHC CSV/JSON loading, analyzer fault isolation, generated artifacts, or Python 3.12+ Windows compatibility.
---

# Optimize

Use this for one evidence-backed robustness or performance pass on
`vhc_simplifier.py`.

## Workflow

1. Record the baseline and confirm the worktree contains no unrelated changes:
   - `git status --short --branch`
   - `python -m py_compile vhc_simplifier.py`
   - `python -m pytest tests/ -v --cov=vhc_simplifier --cov-fail-under=80`
   - `ruff check vhc_simplifier.py tests/`
   - `ruff format --check vhc_simplifier.py tests/`
2. Trace the affected path end to end: input discovery, loading, analysis,
   enrichment, artifact writing, and optional integrations. Search every caller
   before editing a shared helper.
3. Pick one demonstrated issue. Prefer incorrect edge-case behavior, repeated
   IO, an unisolated failure, or CI/runtime drift over speculative cleanup.
4. Make the smallest root-cause change. Add one focused regression test when
   behavior changes; make no code change when the evidence does not justify one.
   For integration failures, assert credential-shaped inputs are absent from
   errors and logs instead of checking only that an error exists.
5. Run `ruff format` on touched Python files, re-run the baseline checks and
   `python vhc_simplifier.py --demo --quiet --no-artifacts`, then review
   `git diff --check` and the complete diff.

For performance claims, compare the same deterministic local command before and
after. Do not benchmark live Slack or Salesforce calls.

## Rules

- Keep the single-file CLI unless the user explicitly asks for structure.
- Reuse `_safe_load_csv()`, `_safe_load_json()`, `_str_cell()`, `_to_number()`, `_to_bool()`, `_run_analyzer()`, and `_write_artifact()`.
- Preserve strict encoding fallback behavior: UTF-8 BOM, UTF-16 variants, then Windows code page fallback; reject corrupt NUL-decoded files.
- Guard missing DataFrame columns before access.
- Keep optional Slack and Salesforce paths isolated from the default local path.
- Preserve `-WhatIf` on generated PowerShell mutating commands.
- Use `vhc-export-validation` for loader/export changes and
  `vhc-remediation-safety` for generated artifacts or integrations.

## Notes

- This replaces the older Claude optimize notes. Do not reintroduce `encoding_errors="replace"` as the default CSV path; current behavior is strict fallback plus corrupt-decode guards.
