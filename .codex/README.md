# Codex Setup

This repository includes local Codex guidance.

- `AGENTS.md` holds repo-specific commands, constraints, and validation rules.
- `.codex/commands/` holds lightweight compatibility wrappers; skills remain the source of truth.
- `.codex/skills/ponytail/SKILL.md` adds a repo-local minimal-change skill.
- `.codex/skills/optimize/SKILL.md` owns evidence-based VHC/VBR robustness and performance work.
- `.codex/skills/codex-verify/SKILL.md` checks repo-local Codex discoverability plus GitHub and workflow setup drift.
- `.codex/skills/refactor/SKILL.md` owns architecture, test consolidation, logging, and measured refactor work.
- `.codex/skills/vhc-export-validation/SKILL.md` covers VHC CSV/JSON filename, encoding, and v12/v13 fixture validation work.
- `.codex/skills/vhc-remediation-safety/SKILL.md` covers generated PowerShell, tickets, Slack, Salesforce, and secret-safe behavior.

Keep the guidance split:

- `AGENTS.md` for repo facts and non-negotiable rules
- `.codex/` for reusable Codex skills and small playbooks

Codex optimization bias:

- Prefer measurable CLI and helper hot paths, repeated file/encoding work, single-file choke points, test/runtime drift, and code deletion over broad rewrite ideas.
- Try to find different issues than a generic Claude-style optimizer would repeat: cold import/startup cost, redundant artifact generation steps, duplicate encoding/validation logic, and optional-integration behavior that escaped focused tests.
- Treat the Codex skills as authoritative for Codex. Do not import stale Claude
  guidance such as replacement decoding.

Keep this folder small. Add new Codex files only when they encode real repo behavior.

The compatibility command notes mirror the skills one-for-one. They are
interactive workflow entrypoints, not lifecycle hooks:

- `optimize`
- `refactor`
- `codex-verify`
- `vhc-export-validation`
- `vhc-remediation-safety`
- `ponytail`

Do not consolidate these interactive, networked, or mutating workflows into
hooks. A future hook is justified only for a narrow, deterministic,
non-mutating lifecycle check with a proven trigger and bounded runtime. Keep
review, optimize, refactor, and publish work user-invoked; keep wrappers thin
and skills authoritative.
