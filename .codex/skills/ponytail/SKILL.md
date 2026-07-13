---
name: ponytail
description: Apply the smallest safe repo-specific change in Veeam-HealthCheck-Simplifier. Use for minimal root-cause fixes that reuse the single-file pipeline, existing pandas/stdlib boundaries, VHC/VBR fixtures, analyzer isolation, safe artifacts, and optional integration controls without speculative dependencies or architecture.
---

# Repo Ponytail

Read the affected path end to end, then stop at the first existing seam that
holds.

## Reuse ladder

1. Delete stale guidance, duplication, or a dead branch before adding code.
2. Reuse discovery/loaders: `_resolve_input_file()`, `_safe_load_csv()`, and
   `_safe_load_json()`.
3. Reuse cell helpers: `_str_cell()`, `_to_number()`, and `_to_bool()`; do not
   duplicate NaN/blank handling inside analyzers.
4. Reuse `_run_analyzer()` and `_write_artifact()` for failure isolation.
5. Extend `PATTERN_MAP` or an existing writer only after verifying Veeam command
   and version semantics.
6. Use stdlib or installed pandas before adding a dependency.

## Non-negotiable behavior

- Keep the single-file CLI unless one proven cohesive split is smaller and safer.
- Preserve five-input partial runs, four output sections, result dict keys, and
  exit codes 0/1/2.
- Preserve strict encoding fallback and corrupt NUL rejection.
- Preserve PowerShell quoting and `-WhatIf`, Slack host/redirect/timeout rules,
  integration redaction, and offline default behavior.
- Reuse `tests/conftest.py`; do not add another VBR fixture matrix.
- Route loader/discovery changes through `vhc-export-validation` and
  enrichment/artifact/integration changes through `vhc-remediation-safety`.
- Route module ownership or logging changes through `refactor`, and measured
  local hot-path work through `optimize`.
- Do not add speculative VBR-version detection, hooks, integrations, module
  layers, or dependencies.

## Check

Leave one focused regression test for nontrivial behavior. Run its owning file,
then the full suite only when shared code changed:

```powershell
python -m py_compile vhc_simplifier.py
python -m pytest tests -v
python -m ruff check .
python -m ruff format --check .
```

A no-op is correct when the existing seam already handles the request.
