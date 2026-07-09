---
name: vhc-export-validation
description: Validate Veeam Health Check CSV/JSON export compatibility for this repo. Use when changing VHC input filenames, CSV/JSON loaders, Windows encodings, VBR v12.3.2/v13 fixture behavior, or tests that prove real export handling.
---

# VHC Export Validation

Use this when touching input discovery or parsing.

## Flow

1. Check filename resolution in `_resolve_input_file()` before adding special cases.
2. Keep loaders centralized in `_safe_load_csv()` and `_safe_load_json()`.
3. Cover both fixture generations: `vbr_v12_*` and `vbr_v13_*` from `tests/conftest.py`.
4. Include Windows export edge cases when relevant: UTF-8 BOM, UTF-16, cp1252, CRLF, empty/header-only files, hostname-prefixed files.

## Checks

- Narrow: `python -m pytest tests/test_windows_server_env.py tests/test_vbr_server_simulation.py -v --tb=short`
- Loader-only edits: also run `python -m pytest tests/test_vhc_simplifier.py -v --tb=short`
- Always: `python -m py_compile vhc_simplifier.py`

## Boundaries

- Do not claim live VBR support is fully proven from fixtures alone.
- If real `vee.am/vhc2` exports are unavailable, state that validation is fixture/simulation coverage only.
