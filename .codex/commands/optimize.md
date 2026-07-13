# Optimize

Use `.codex/skills/optimize/SKILL.md` as the source of truth.

When asked to optimize this repo:

- record the baseline and reject unrelated worktree changes before editing
- trace discovery, loading, analysis, enrichment, artifacts, and integrations
- search every caller before changing a shared helper
- fix one demonstrated root cause with the smallest diff and one focused test;
  integration error tests must prove secrets are absent
- format touched Python files, then rerun the full baseline, demo, and diff review
- report a no-op when no evidence-backed optimization remains
