---
name: refactor
description: Iterative, evidence-backed refactor workflow for Veeam-HealthCheck-Simplifier. Use for single-file architecture cleanup, test consolidation, logging ownership, duplication removal, or measured local performance work.
---

# Refactor

Use Ponytail discipline: read the real path first, delete duplication before
adding layers, and keep one independently reviewable change per loop. The
single-file CLI remains the default architecture.

## Architecture contract

Preserve this ownership flow unless a failing test or measurement proves a
different boundary is needed:

1. Runtime/config: imports, optional dependency probes, `HealthCheckConfig`, and
   `HealthCheckResult`.
2. Input adapter: `_resolve_input_file()` -> encoding/text helpers ->
   `_safe_load_csv()` / `_safe_load_json()`.
3. Domain analysis: coercion helpers and four analyzers, dispatched through
   `_run_analyzer()` so one failed section cannot abort the run.
4. Policy/enrichment: `PATTERN_MAP`, `_MUTATING_VERBS`, `_ps_quote()`, and
   `enrich_findings()`.
5. Output adapters: three writers dispatched independently through
   `_write_artifact()`.
6. External adapters: opt-in Salesforce and Slack paths, including validation,
   timeout, redirect refusal, and redaction.
7. Orchestration/presentation: `run_healthcheck()` returns the existing dict
   contract; `main()` owns CLI parsing, process logging, and exit codes 0/1/2.

Do not create service/repository/controller classes around seams that already
exist. Split the module only when a cohesive boundary has multiple owners or
cannot be tested safely in place, and record why a helper extraction is
insufficient.

## Test ownership

- `tests/conftest.py`: canonical reusable simulated VBR 12/13 CSV/JSON fixtures.
- `test_vhc_simplifier.py`: core helpers, analyzers, loaders, enrichment,
  writers, resilience wrappers, demo flow, and Slack redirect behavior.
- `test_coverage_gaps.py`: rare branches, malformed shapes, serialization,
  writer failures, and integration adapters.
- `test_vbr_server_simulation.py`: shared-fixture version parity, partial and
  corrupt inputs, analyzer/artifact isolation, and end-to-end sections.
- `test_windows_server_env.py`: Windows paths/encodings, PowerShell safety,
  larger inputs, CLI logging, and exit codes.
- `test_mock_veeam_environment.py`: overlapping self-contained simulations;
  consolidate only as a separate deletion-focused change with no lost behavior
  or coverage.

Extend the owning file and reuse `conftest.py`; do not add a third VBR fixture
matrix. Replace tautological assertions with an expected result or error.
Always label these inputs as simulations, not proof of live product support.

## Logging refactor contract

The justified logging seam is the CLI boundary:

- module scope should create only a named logger, not configure the process root
  logger as an import side effect;
- `main()` should configure CLI handlers and levels once;
- define whether `--quiet` suppresses only the human report or also routine log
  records before changing behavior;
- keep the human report on stdout and diagnostics on stderr without duplicates;
- treat `HealthCheckResult.errors` as the programmatic error contract;
- redact credential and webhook values from both result errors and log records;
- cover changes with focused `caplog` and `capsys` tests, not a logging framework.

## Loop

1. Create `$env:TEMP\refactor-Veeam-HealthCheck-Simplifier.md` only when a
   multi-step loop starts. Record UTC time, target, baseline, and progress.
2. Establish a clean baseline with syntax, full tests/coverage, Ruff, and the
   deterministic demo command from the optimize skill.
3. Pick one demonstrated ownership, duplication, test, logging, or performance
   defect. Search all callers and tests.
4. Apply the smallest change. Preserve public dict keys, artifacts, partial-run
   behavior, safety controls, and exit codes unless the task explicitly changes
   their contract.
5. Run the owning tests, then the full baseline when behavior or shared code
   changed. Review the entire diff in REVIEW mode.
6. If performance is the target, compare at least five fixed-fixture runs before
   and after and report the median. Do not impose an arbitrary startup target on
   pandas import or filesystem IO.
7. Commit only when the user requested repository mutation or the active
   workflow explicitly includes commits. Update the tracker with checks,
   measurements, review outcome, and commit hash.

## Stop criteria

Stop when the touched path has one obvious owner, duplication is reduced rather
than relocated, targeted and full required checks pass, no correctness issue
remains in the diff, and any performance claim has reproducible before/after
evidence. A no-op is correct when the evidence does not justify a refactor.
