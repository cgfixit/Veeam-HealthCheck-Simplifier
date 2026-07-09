# VHC Export Validation

Use `.codex/skills/vhc-export-validation/SKILL.md` as the source of truth for
VHC CSV/JSON input discovery and encoding checks.

When the user changes input loading, file discovery, or export compatibility:

- run `python -m pytest tests/test_windows_server_env.py tests/test_vbr_server_simulation.py -v --tb=short`
- add `python -m pytest tests/test_vhc_simplifier.py -v --tb=short` when loader behavior changed
- always run `python -m py_compile vhc_simplifier.py`
