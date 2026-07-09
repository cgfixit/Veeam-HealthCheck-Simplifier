---
name: codex-verify
description: Verify repo-local Codex discoverability and the trustworthy GitHub and workflow inspection path for Veeam-HealthCheck-Simplifier after clone, before publish, or when setup drift is suspected.
---

# Codex Verify

Use this after cloning the repo, before publishing `.codex/` changes, or when a
GitHub or CI setup claim needs evidence.

## Steps

1. Verify local repo context:

```powershell
git status --short --branch
git remote -v
```

2. Verify the Codex surface exists and is discoverable:

```powershell
Get-ChildItem .codex -Recurse
Get-Content AGENTS.md
Get-Content .codex\README.md
```

3. Prefer GitHub connector reads for repo metadata and permissions.
4. Treat local `gh` as untrusted until `gh auth status` returns real output.
5. Inspect workflow drift directly from `.github/workflows/`:
   - root `permissions:` blocks
   - SHA-pinned external actions where the repo claims hardening
   - duplicate or stale workflow coverage

## Guardrails

- Do not claim GitHub Actions or PR write access from a blank or shim `gh`.
- Report connector-verified repo permissions separately from local CLI auth.
- Call out floating GitHub Action refs explicitly instead of pretending the repo
  is fully pinned.
- If `rtk.exe` is not on PATH, stop there for RTK-specific work; do not invent a
  repo routine around a missing binary.
