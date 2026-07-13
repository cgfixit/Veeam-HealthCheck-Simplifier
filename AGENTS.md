# AGENTS.md

Repository guidance for Codex in `cgfixit/Veeam-HealthCheck-Simplifier`.

## Scope

- This repo is a single-file Python CLI centered on `vhc_simplifier.py`.
- Tests live under `tests/`.
- Packaging uses the `setuptools.build_meta` backend for the single `vhc_simplifier` module; there is no package directory or lockfile.
- `.codex/skills/` contains the authoritative repo workflows.
- `.agents/skills/` contains namespaced Codex discovery entrypoints that route
  to the authoritative `.codex/skills/` files; do not duplicate procedures.
- `.codex/commands/` contains lightweight compatibility wrappers. Do not turn
  interactive, networked, or mutating workflows into lifecycle hooks; reserve
  hooks for narrow, deterministic, non-mutating checks with a proven trigger.
- Use `.codex/skills/refactor/SKILL.md` when asked to run an iterative architecture or speed refactor loop.
- Use `.codex/skills/optimize/SKILL.md` for robustness, loader, CI, and Python 3.12+ Windows compatibility optimization.
- Use `.codex/skills/codex-verify/SKILL.md` after clone, before publish, or when checking GitHub/CI/Codex setup drift.
- Use `.codex/skills/vhc-export-validation/SKILL.md` when changing VHC CSV/JSON input discovery, encodings, or VBR v12/v13 fixture behavior.
- Use `.codex/skills/vhc-remediation-safety/SKILL.md` when changing generated PowerShell, ticket payloads, Slack, Salesforce, or secret/error handling.
- Use `.codex/skills/ponytail/SKILL.md` for minimum-diff changes.

## Commands

- Install deps: `python -m pip install -r requirements.txt`
- Run demo: `python vhc_simplifier.py --demo`
- Run tests: `python -m pytest tests/ -v`
- Narrow validation: `python -m py_compile vhc_simplifier.py`

## Repo Facts

- Target Python is 3.12+ per README and file header.
- The parser has five logical input basenames and four analyzer sections;
  sessions are analyzed inside `analyze_jobs()`.
- VBR 12/13 and Windows Server fixtures are simulations. Do not claim live
  product support without authentic exports or authoritative Veeam evidence.
- Main outputs are `remediation_summary.md`, `fixit.ps1`, and `tickets.json`.
- Optional integrations are Salesforce and Slack. Never hardcode or log secrets.
- PowerShell output is intentionally safety-biased with `-WhatIf` defaults. Do not remove that without an explicit request.
- `AGENTS.md` owns repo facts; `.codex/skills/` owns reusable workflows. Keep
  Codex guidance authoritative if Claude notes are stale.

## Change Rules

- Preserve the single-file CLI structure unless a refactor is explicitly requested.
- Prefer stdlib and existing dependencies over adding packages.
- Keep analyzer logic pure where practical; isolate IO and external integrations.
- Keep `run_healthcheck()` as the orchestrator and `main()` as the CLI/logging
  boundary; importing the module must not configure process-global logging.
- Treat credential handling, webhook posting, and generated PowerShell as high-risk paths.
- For mutating behavior, preserve dry-run or safe-preview semantics.
- When editing README or positioning copy, separate repo-backed facts, measured runtime results, market signals, and inference. Do not claim PMF or operational savings without evidence.

## Validation Expectations

- After editing Python, run `python -m py_compile vhc_simplifier.py`.
- Run `python -m pytest tests/ -v` when the change affects behavior.
- Run `python -m ruff check .` and `python -m ruff format --check .` after
  Python changes.
- If optional integrations are touched, state what could not be verified without live credentials.
