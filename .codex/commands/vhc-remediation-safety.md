# VHC Remediation Safety

Use `.codex/skills/vhc-remediation-safety/SKILL.md` as the source of truth.

When editing generated artifacts or integrations:

- preserve `-WhatIf` on mutating PowerShell output
- do not echo secrets or webhook URLs back in errors
- keep Slack and Salesforce validation strict
- validate with targeted tests plus `python -m py_compile vhc_simplifier.py`
