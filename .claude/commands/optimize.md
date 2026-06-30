Apply performance and robustness optimizations to the VHC pipeline.

## Encoding & Data Robustness

- Always use `encoding_errors="replace"` when calling `pd.read_csv()`.
- Strip UTF-8 BOM from JSON before parsing with `.lstrip("﻿")`.
- Guard against missing DataFrame columns before accessing them.
- Use `_str_cell()`, `_to_number()`, `_to_bool()` for type-safe cell access.

## Fault Isolation

- Wrap new analyzers in `_run_analyzer()` — it catches exceptions and records errors without aborting.
- Wrap new file writes in `_write_artifact()` — same pattern for IO errors.
- Never let a single failing component abort the entire run.

## Test Coverage

- Target 80%+ coverage (enforced by CI). Current: 90%+.
- Use `conftest.py` fixtures (`vbr_v12_csv_dir`, `vbr_v13_csv_dir`, etc.) for realistic test data.
- Test both CSV and JSON input paths.
- Test encoding edge cases: BOM, UTF-16, Latin-1 characters, empty files.
- Test PowerShell injection: control characters, semicolons, pipes, newlines.
- Analyzer signatures: `analyze_jobs(jobs_df, sessions_df)`, `analyze_security(sec_df)`, etc. — no `result` parameter.

## CI Pipeline

- Python 3.12 and 3.13 matrix on ubuntu-latest and windows-latest.
- Ruff lint + format checks must pass.
- Run `ruff check --fix` and `ruff format` before committing.

## Checklist

After running this skill, verify:
1. `python -m py_compile vhc_simplifier.py` passes
2. `python -m pytest tests/ -v --cov=vhc_simplifier --cov-fail-under=80` passes
3. `ruff check vhc_simplifier.py tests/` is clean
4. `ruff format --check vhc_simplifier.py tests/` is clean
