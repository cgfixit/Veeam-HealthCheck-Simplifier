# VHC Export Validation

Use `.codex/skills/vhc-export-validation/SKILL.md` as the source of truth.

When changing input discovery or parsing:

- keep loader logic in `_safe_load_csv()` and `_safe_load_json()`
- cover both `vbr_v12_*` and `vbr_v13_*` fixtures
- validate with `python -m py_compile vhc_simplifier.py`
- run targeted tests for Windows export and loader behavior
