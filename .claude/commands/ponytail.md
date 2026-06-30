Use the laziest correct path for changes to this repository.

## Rules

- Reuse existing helpers in `vhc_simplifier.py` before adding new ones.
- Keep changes in the fewest files possible.
- Do not add dependencies for formatting, CLI parsing, HTTP calls, or data handling already covered by stdlib or current requirements.
- Preserve `-WhatIf` defaults and secret-safe behavior in all PowerShell output.
- When logic changes, run: `python -m py_compile vhc_simplifier.py` and `python -m pytest tests/ -v`.
- Prefer `_safe_load_csv()` / `_safe_load_json()` for any new data loading — they handle encoding edge cases.

## Bias

- Single-file CLI is the default. Do not introduce a package layout.
- Small root-cause fixes beat broad rewrites.
- If a feature sounds speculative, do not scaffold for it.
- Three similar lines > a premature abstraction.
- Fix the bug, not the neighborhood.
