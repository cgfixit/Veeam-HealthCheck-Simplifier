---
name: codex-verify
description: Verify the Veeam-HealthCheck-Simplifier Codex setup after clone, before publish, or when local skill discovery, GitHub authentication, Actions, branch state, repo guidance, or VHC/VBR facts may have drifted.
---

# Codex Verify

Prove each layer separately. A valid file tree does not prove Codex discovery,
GitHub write access, branch policy, or passing Actions.

## 1. Repository state

```powershell
git status --short --branch
git remote -v
git fetch origin main
git rev-parse HEAD
git rev-parse origin/main
git rev-list --left-right --count HEAD...origin/main
```

Record whether the checkout is clean, ahead, behind, detached, or contains
unrelated work. Do not call a local commit remote until its SHA is visible on
GitHub.

## 2. Codex wiring

Verify all six source skills and six thin compatibility wrappers exist:

```powershell
Get-ChildItem .codex\skills -Directory
Get-ChildItem .codex\commands -File -Filter *.md |
    Where-Object Name -ne README.md
rg -n "^name:|^description:" .codex\skills
Get-Content AGENTS.md
Get-Content .codex\README.md
```

Requirements:

- each skill folder contains one valid `SKILL.md` with a unique lowercase name;
- wrappers point to the matching skill and do not duplicate its procedure;
- `AGENTS.md` contains repo facts, while personal tone and generic safety stay
  in account settings;
- commands remain interactive wrappers, not lifecycle hooks;
- repo-local and user-scope skills do not silently shadow different same-name
  skills. Resolve `$CODEX_HOME` (or `$HOME\.codex`) and inspect its `skills` and
  `commands` directories before installing. Never overwrite an unrelated skill.

Use collision-free account aliases for this repo when needed:
`vhc-codex-verify`, `vhc-optimize`, `vhc-refactor`, and `vhc-ponytail`;
`vhc-export-validation` and `vhc-remediation-safety` are already namespaced.

After installing or changing user-scope skills, restart Codex and verify the
expected entries in the skill/slash picker. Filesystem presence alone is not a
discovery test.

## 3. GitHub and Actions

1. Prefer the GitHub connector for authenticated profile, repository metadata,
   collaborator permission, default branch, PR, and Actions reads.
2. Treat `gh` as untrusted until resolving every candidate and receiving real
   auth output:

```powershell
Get-Command gh -All
gh auth status
```

If the first `gh` is a shim, invoke the real binary explicitly. Keep connector
permissions and CLI token scopes as separate evidence.

3. Inspect `.github/workflows/` directly for workflow count, triggers, root/job
   permissions, duplicate coverage, and floating third-party action refs.
4. Query classic branch protection and repository rulesets separately. A 404
   from the classic endpoint is not evidence that no ruleset applies.
5. After a push, identify runs for the exact commit and wait for every required
   workflow to reach a terminal state.

## 4. Repo-truth drift

Search current docs and tests for stale claims before publishing guidance:

```powershell
rg -n 'encoding_errors="replace"|analyze_sessions|--verbose|219 tests|Six workflows|HTML/JSON|12\.3\.2\.4643' README.md SECURITY.md CLAUDE.md .claude tests .codex AGENTS.md
```

Verify against current code rather than replacing numbers mechanically:

- `pyproject.toml` owns Python/package/test configuration;
- `EXPECTED_BASENAMES` has five inputs; `run_healthcheck()` emits four sections;
- sessions are analyzed inside `analyze_jobs()`;
- synthetic VBR/Windows fixtures are not live compatibility evidence;
- count tests with `python -m pytest --collect-only -q` and workflows from the
  filesystem.

## 5. Validation

Run the six skill validators when the account's `skill-creator` helper is
available, then:

```powershell
python -m py_compile vhc_simplifier.py
python -m pytest tests --cov=vhc_simplifier --cov-report=term-missing
python -m ruff check .
python -m ruff format --check .
python vhc_simplifier.py --demo --quiet --no-artifacts
git diff --check
```

Report exact pass/fail evidence and anything that required live credentials or
an authentic VHC export and therefore remains unverified.
