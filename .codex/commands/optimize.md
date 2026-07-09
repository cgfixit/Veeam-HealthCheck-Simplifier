# Optimize

Use `.codex/skills/optimize/SKILL.md` as the source of truth.

When asked to optimize this repo:

- keep the single-file CLI unless structure is explicitly requested
- reuse existing helpers in `vhc_simplifier.py`
- validate with `python -m py_compile vhc_simplifier.py`
- run `python -m pytest tests/ -v` when behavior changes
- use Ruff checks for CI parity when the diff touches Python behavior broadly
