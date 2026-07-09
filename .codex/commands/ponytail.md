# Ponytail

Use `.codex/skills/ponytail/SKILL.md` as the repo-local source of truth and
layer the global `ponytail` plugin when available.

When the user asks for the simplest safe change:

- prefer the fewest-file root-cause fix
- reuse existing helpers before adding new ones
- avoid new dependencies
- keep `-WhatIf` and secret-safe behavior intact
