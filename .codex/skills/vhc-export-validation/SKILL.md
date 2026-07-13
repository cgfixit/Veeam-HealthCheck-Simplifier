---
name: vhc-export-validation
description: Validate this repo's Veeam Health Check input contract. Use when changing VHC/VBR file discovery, CSV or API-shaped JSON loading, Windows encodings and paths, five expected datasets, VBR 12/13 simulated schemas, unknown cells, or claims about real export compatibility.
---

# VHC Export Validation

Trace `_resolve_input_file()` -> `_safe_load_csv()` / `_safe_load_json()` ->
the owning analyzer. Keep discovery and decoding centralized.

## Input contract

| Key | Default basename | Owning analysis |
|---|---|---|
| `jobs` | `localhost_Jobs` | `analyze_jobs()` |
| `sessions` | `VeeamSessionReport` | `analyze_jobs()` |
| `security` | `localhost_SecurityCompliance` | `analyze_security()` |
| `repositories` | `localhost_Repositories` | `analyze_repositories()` |
| `malware` | `localhostmalware_events` | `analyze_malware()` |

The resolver accepts hostname-prefixed variants. Preserve exact-name priority.
If multiple fuzzy candidates can represent different VBR hosts or runs, do not
silently broaden the matcher or depend on alphabetical selection; make the
ambiguity explicit and test it.

## Provenance boundaries

- The community [Veeam Health Check](https://github.com/VeeamHub/veeam-healthcheck)
  is the upstream source for current invocation and output claims.
- Treat CSV as the VHC-shaped input exercised by this repo. Treat JSON as the
  application's alternate/API-shaped record contract; do not call it VHC output
  without an authentic export or upstream evidence.
- `tests/conftest.py` is the canonical synthetic VBR 12/13 fixture source.
  Do not add another version matrix or claim those fixtures prove a live build,
  VHC release, Windows Server version, UNC share, or MAX_PATH behavior.
- Confirm version and build claims with the
  [official VBR build table](https://www.veeam.com/kb2680) and current or archived
  Veeam documentation.

## Required cases

Cover only cases owned by the change:

- exact and hostname-prefixed names, case variants, multiple candidates, and
  exact-versus-fuzzy collisions;
- missing directory/file, zero bytes, header-only/no rows, malformed CSV/JSON,
  corrupt binary input, partial export sets, and extra/unknown columns;
- UTF-8 BOM, UTF-16/LE/BE, cp1252, CRLF, spaces, and non-ASCII object names;
- JSON list records and supported `data`, `value`, `items`, `results`, and nested
  `result` wrappers;
- VBR 12/13 schema drift using shared fixtures, with unrelated added columns
  tolerated;
- missing, NaN, blank, or unparseable cells preserved as unknown rather than
  automatically converted into a compliance failure.

For malformed or unsupported inputs, assert the exact expected
`HealthCheckResult.errors` entry; do not accept a test that passes whether rows
were loaded, dropped, or errored.

Require Windows CI or a real Windows reproduction for Windows-specific claims.
Cross-platform pathlib tests remain simulations.

## Checks

```powershell
python -m pytest tests/test_windows_server_env.py tests/test_vbr_server_simulation.py -v --tb=short
python -m pytest tests/test_vhc_simplifier.py tests/test_coverage_gaps.py -v --tb=short
python -m py_compile vhc_simplifier.py
python -m ruff check .
python -m ruff format --check .
```

Use the narrowest owning files first, then the full suite for shared loader or
resolver changes. State explicitly when no sanitized real export was available.
