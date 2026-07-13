# Refactor

Use `.codex/skills/refactor/SKILL.md` as the source of truth.

When the user asks for refactor work:

- keep progress in the OS temporary directory as `refactor-<repo>.md`
- preserve the existing loader -> analyzer -> enrichment -> writer -> integration
  ownership flow and the `run_healthcheck()`/exit-code contracts
- use `tests/conftest.py` as the canonical VBR 12/13 fixture source
- treat logging configuration as a CLI concern and test stdout, stderr, and
  secret redaction explicitly
- measure fixed deterministic local paths, not live integrations or arbitrary
  pandas startup targets
- make one targeted change per loop
- validate with `python -m py_compile vhc_simplifier.py`
- run targeted or full `pytest` coverage based on scope
