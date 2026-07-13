---
name: refactor
description: >-
  Iterative architecture and speed refactor loop for
  Veeam-HealthCheck-Simplifier. Use when asked to refactor structure, clean up
  the single-file CLI, or run a measured optimization loop with verification,
  review, commits, and tracker updates.
---

# Refactor

Use this skill for `Veeam-HealthCheck-Simplifier` when the user asks for a
refactor or performance work.

This is a Codex-native loop with Ponytail always on: keep the single-file CLI
unless there is a concrete structural reason to split it, reuse existing
helpers, and delete duplication before adding new layers.

## Rules

- Keep progress in the OS temporary directory as `refactor-<repo>.md`.
- Use deterministic local paths such as `--demo` or targeted tests, not live
  Salesforce or Slack calls.
- One targeted change per loop.
- After each significant step: measure, test, autoreview, commit, update the
  tracker.

## Setup

Create the tracker only when the loop starts, using this template:

```md
# Refactor Loop - <repo>
Started: <UTC timestamp>
Target: cleaner CLI structure and deterministic local paths under 50 ms where feasible
## Goals
- Clean, understandable single-file architecture
- No duplicated encoding, enrichment, or artifact logic
- Deterministic local hot paths measured after each change
- Ponytail defaults: delete, simplify, reuse
## Baseline
(record first measurements before editing)
## Progress
```

## Measurement Protocol

This repo is a CLI, not a web app. Measure deterministic local commands and
helpers instead of pretending HTTP pages exist.

Keep measurement conditions fixed:

- same Python version
- same `--demo` or fixture inputs
- no live network integrations
- five runs per measurement
- median, not mean

Suggested baseline set:

```bash
python -m py_compile vhc_simplifier.py
python vhc_simplifier.py --demo --quiet --no-artifacts
python -m pytest tests/test_vhc_simplifier.py -q
python -c "import time; t=time.perf_counter(); import vhc_simplifier; print(int((time.perf_counter()-t)*1000))"
```

If the step targets a different path, switch to the matching targeted test or
helper probe and record why.

Pass/fail gate:

- The targeted owned paths should improve and trend toward sub-50 ms medians
  where feasible.
- If interpreter startup or unavoidable file I/O is the remaining floor,
  document that ceiling in the tracker.

## Loop

1. Assess
   - Look for god-function sprawl, mixed IO/business logic, repeated encoding
     or enrichment work, duplicate artifact handling, or optional-integration
     code leaking into the ordinary path.
2. Pick one change
   - Prefer deleting dead branches, extracting one bounded helper, reducing
     repeated file/JSON/markdown work, or tightening the ordinary `--demo` path.
3. Execute
   - Keep the diff focused.
4. Measure
   - Re-run the same measurement set.
5. Live-test correctness
   - `python -m py_compile vhc_simplifier.py`
   - `python -m pytest tests/ -v` when behavior changed
   - targeted test files when the scope is narrower
6. Autoreview
   - Review the diff in REVIEW MODE.
   - Prioritize findings broad optimizer passes often miss here:
     - cold import/startup cost
     - repeated artifact generation steps
     - duplicated encoding and validation logic
     - optional integration code slowing the default path
     - code that should be deleted instead of abstracted
7. Commit
   - `git add -p`
   - `git commit -m "refactor: <what changed and why>"`
   - Use `perf:` when the step is mainly a measured speed gain.
8. Update tracker
   - Record target, change, measurements, tests, autoreview outcome, commit hash

## Stop Criteria

Stop when all are true:

- The path you touched has one obvious owner.
- IO, enrichment, and artifact generation are not unnecessarily tangled.
- Targeted checks pass.
- Latest autoreview finds no correctness issues worth fixing first.
- Deterministic owned hot paths are under 50 ms for two consecutive five-run
  measurement rounds, or a documented runtime floor is the only remaining limit.

Append:

```md
## Final State
Completed: <timestamp>
Summary: <what improved>
Ceilings: <anything still above target and why>
```
