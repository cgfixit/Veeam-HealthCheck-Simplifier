# Refactor

Use `.codex/skills/refactor/SKILL.md` as the source of truth.

When the user asks for refactor work:

- keep progress in `/tmp/refactor-${PROJNAME}.md`
- measure deterministic local paths, not live integrations
- make one targeted change per loop
- validate with `python -m py_compile vhc_simplifier.py`
- run targeted or full `pytest` coverage based on scope
