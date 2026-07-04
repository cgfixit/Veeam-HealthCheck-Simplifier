# Codex Setup

This repository includes local Codex guidance.

- `AGENTS.md` holds repo-specific commands, constraints, and validation rules.
- `.codex/skills/ponytail/SKILL.md` adds a repo-local minimal-change skill.
- `.codex/skills/refactor/SKILL.md` adds the iterative architecture and speed refactor loop.

Keep the CyClaw-style split:

- `AGENTS.md` for repo facts and non-negotiable rules
- `.codex/` for reusable Codex skills and small playbooks

Codex optimization bias:

- Prefer measurable CLI and helper hot paths, repeated file/encoding work, single-file choke points, test/runtime drift, and code deletion over broad rewrite ideas.
- Try to find different issues than a generic Claude-style optimizer would repeat: cold import/startup cost, redundant artifact generation steps, duplicate encoding/validation logic, and optional-integration behavior that escaped focused tests.

Keep this folder small. Add new Codex files only when they encode real repo behavior.
