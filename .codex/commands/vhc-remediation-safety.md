# VHC Remediation Safety

Use `.codex/skills/vhc-remediation-safety/SKILL.md` as the source of truth for
generated PowerShell, tickets, Slack, Salesforce, and secret-safe behavior.

When the user changes findings that become artifacts or integrations:

- run `python -m pytest tests/test_vhc_simplifier.py tests/test_windows_server_env.py -v --tb=short`
- run `python -m pytest tests/test_coverage_gaps.py -v --tb=short` for integration error handling
- always run `python -m py_compile vhc_simplifier.py`
