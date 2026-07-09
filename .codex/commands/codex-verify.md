# Codex Verify

Use `.codex/skills/codex-verify/SKILL.md` as the source of truth.

When onboarding or checking setup drift:

- verify local repo context with `git status --short --branch` and `git remote -v`
- verify `.codex/`, `AGENTS.md`, and `.codex/README.md` are aligned
- prefer GitHub connector reads for repo permissions
- treat local `gh` as untrusted until it proves real auth output
- inspect `.github/workflows/` directly for permission and pinning drift
