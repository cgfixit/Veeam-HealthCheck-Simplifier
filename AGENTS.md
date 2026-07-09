# AGENTS.md

Repository guidance for Codex in `cgfixit/Veeam-HealthCheck-Simplifier`.

## Scope

- This repo is a single-file Python CLI centered on `vhc_simplifier.py`.
- Tests live under `tests/`.
- There is no package layout, build backend, or lockfile. Keep changes minimal and local.
- `.codex/commands/` is the repo-local command discovery surface for Codex.
- Use `.codex/skills/refactor/SKILL.md` when asked to run an iterative architecture or speed refactor loop.
- Use `.codex/skills/optimize/SKILL.md` for robustness, loader, CI, and Python 3.12+ Windows compatibility optimization.
- Use `.codex/skills/codex-verify/SKILL.md` after clone, before publish, or when checking GitHub/CI/Codex setup drift.
- Use `.codex/skills/vhc-export-validation/SKILL.md` when changing VHC CSV/JSON input discovery, encodings, or VBR v12/v13 fixture behavior.
- Use `.codex/skills/vhc-remediation-safety/SKILL.md` when changing generated PowerShell, ticket payloads, Slack, Salesforce, or secret/error handling.
- Layer the global `ponytail` and `karpathy-guidelines` skills on top of the repo-local skill when the task is coding-heavy or review-heavy.
- Use `rtk-exe` only for tasks that explicitly depend on local `rtk.exe`; do not assume it exists on PATH.

## Commands

- Install deps: `python -m pip install -r requirements.txt`
- Run demo: `python vhc_simplifier.py --demo`
- Run tests: `python -m pytest tests/ -v`
- Narrow validation: `python -m py_compile vhc_simplifier.py`

## Repo Facts

- Target Python is 3.12+ per README and file header.
- Main outputs are `remediation_summary.md`, `fixit.ps1`, and `tickets.json`.
- Optional integrations are Salesforce and Slack. Never hardcode or log secrets.
- PowerShell output is intentionally safety-biased with `-WhatIf` defaults. Do not remove that without an explicit request.
- The current repo-local Codex structure follows the CyClaw split: `AGENTS.md` for repo facts, `.codex/` for reusable Codex workflows.
- `.claude/Skills` and `.claude/commands` have Codex equivalents under `.codex/skills`; keep Codex copies authoritative if the Claude notes are stale.
- Local `gh` may be a shim in this environment. Prefer GitHub connector reads for repo and PR metadata unless `gh auth status` proves the CLI path is real and authenticated.

## Change Rules

- Preserve the single-file CLI structure unless a refactor is explicitly requested.
- Prefer stdlib and existing dependencies over adding packages.
- Keep analyzer logic pure where practical; isolate IO and external integrations.
- Treat credential handling, webhook posting, and generated PowerShell as high-risk paths.
- For mutating behavior, preserve dry-run or safe-preview semantics.
- When editing README or positioning copy, separate repo-backed facts, measured runtime results, market signals, and inference. Do not claim PMF or operational savings without evidence.

## Validation Expectations

- After editing Python, run `python -m py_compile vhc_simplifier.py`.
- Run `python -m pytest tests/ -v` when the change affects behavior.
- If optional integrations are touched, state what could not be verified without live credentials.
