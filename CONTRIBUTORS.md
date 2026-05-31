# Contributors

Thank you to everyone who has contributed to Veeam-HealthCheck-Simplifier.

---

## Core Author

| Name | GitHub | Role |
|---|---|---|
| Christopher Grady | [@CGFixIT](https://github.com/CGFixIT) | Creator, maintainer |

---

## How to Contribute

1. Fork the repo and create a feature branch off `main`
2. Make your changes with clear, focused commits
3. Ensure `python vhc_simplifier.py --demo` runs cleanly on Python 3.12+
4. Open a pull request with a description of what changed and why

### Contribution Areas

- **New analyzers** — additional `analyze_*()` functions for new VHC data sections
- **New output targets** — Jira, ServiceNow, Teams webhook, etc.
- **Pattern map expansions** — new remediation entries in `PATTERN_MAP`
- **JSON schema mappings** — field name normalization for VBR REST API responses
- **Tests** — pytest coverage for core analysis and enrichment logic

### Code Style

- Python 3.12+ only; type hints required on all public functions
- New side-effect integrations go in isolated `_push_*` / `_post_*` functions
- Failures in optional integrations append to `result.errors` and never raise
- No secrets, credentials, or customer data in commits

---

*To be listed here, open a PR. All merged contributors will be added.*
