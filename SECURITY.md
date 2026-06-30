# Security Policy

## Supported Versions

This project is a single-script utility (`vhc_simplifier.py`) and does not follow a versioned release cycle. Security fixes are applied to the **latest commit on `main`** only.

| State               | Supported          |
| ------------------- | ------------------ |
| Latest (`main`)     | :white_check_mark: |
| Any prior commit    | :x:                |

> **Recommendation:** Always pull the latest version from `main` before running in production environments.

---

## Scope

This tool parses and summarizes Veeam Health Check HTML/JSON reports. Security considerations relevant to this project include:

- **Path traversal / arbitrary file read** — malicious input file paths passed to the script
- **Unsafe deserialization** — processing of crafted/malformed Veeam report files
- **Credential exposure** — accidental logging or surfacing of sensitive data present in Veeam reports (e.g., repository names, job credentials, server hostnames)
- **Dependency vulnerabilities** — issues in packages listed in `requirements.txt`
- **Code injection** — any vector allowing execution of unintended code via report content

Out of scope: vulnerabilities in Veeam Backup & Replication itself, or issues requiring physical/administrative access to the host running this script.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues privately via one of the following:

- **Email:** [security@cgfixit.com](mailto:contact@cgfixit.com)
- **Web:** [https://cgfixit.com](https://cgfixit.com) (use the contact form and mark subject as `[SECURITY]`)

### What to Include

To help triage effectively, please provide:

1. A clear description of the vulnerability and its potential impact
2. Steps to reproduce (include a sanitized/minimal sample report file if applicable)
3. The environment details (OS, Python version, relevant dependencies from `requirements.txt`)
4. Any suggested remediation, if you have one

### Response Timeline

| Milestone                        | Target Timeframe     |
| -------------------------------- | -------------------- |
| Acknowledgment of report         | Within **48 hours**  |
| Initial triage / severity rating | Within **5 days**    |
| Fix or mitigation published      | Within **14 days**   |
| Public disclosure (if warranted) | After fix is live    |

These are best-effort targets for a solo-maintained open-source project. Complex issues may take longer; you will be kept informed.

### Outcome

- **Accepted vulnerabilities** will receive a fix on `main` and a note in the commit message referencing the report (reporter credited by name/handle if desired).
- **Declined reports** will receive a clear explanation of why the finding is out of scope or not actionable.

---

## Dependency Security

Dependencies are tracked in [`requirements.txt`](./requirements.txt). It is recommended to:

```bash
pip install --upgrade -r requirements.txt
pip-audit -r requirements.txt   # requires pip-audit
```

Report any known CVEs in listed packages using the process above.

---

## Service Account & MFA Considerations

This tool is designed to run unattended (cron, Windows Task Scheduler, CI pipeline), which means any credentials it uses — VBR REST API access (if an operator scripts JSON exports instead of running the VHC PowerShell script interactively), Salesforce (`SF_USERNAME`/`SF_PASSWORD`/`SF_TOKEN`), and Slack — must be non-interactive. MFA-enforcing Conditional Access policies are built around interactive logins, so "just enable MFA on the automation account like everyone else" does not work and routinely causes outages or pushes admins toward insecure workarounds (org-wide MFA exemptions, permanently-exempted accounts with no compensating controls).

- **Use a dedicated automation identity per integration.** Never reuse a human admin's MFA-enrolled account for `SF_USERNAME`/`SF_PASSWORD`/`SF_TOKEN` or for any VBR API credential this tool consumes. A shared human account ties the automation's uptime to that person's MFA state, password rotations, and offboarding.
- **Prefer auth methods built for automation over disabling MFA:**
  - **Salesforce** — where the org's setup allows it, prefer a Connected App using OAuth (JWT bearer flow) over the username + password + security-token combo. If the `SF_USERNAME`/`SF_PASSWORD`/`SF_TOKEN` env vars must be used (as this tool currently supports), scope that profile to the minimum permission needed — creating Tasks on the target Account only.
  - **VBR REST API** — if scripting JSON exports against the API rather than running the VHC PowerShell script by hand, use a scoped, role-restricted service account rather than domain admin credentials.
  - **Slack** — incoming webhooks (what this tool uses) are already non-interactive by design and need no MFA at all; this is the "already solved" case. Contrast with a Slack bot user token tied to a human's app install, which reintroduces the same MFA/Conditional-Access problem.
- **If an MFA/Conditional Access exemption is genuinely unavoidable** for some account in this chain, treat it as a high-risk exception and compensate:
  - Scope the exemption as tightly as possible (named locations, source IP/CIDR allow-listing, device compliance requirements).
  - Apply least-privilege RBAC — read-only or report-only roles wherever the integration allows it.
  - Rotate the credential on a fixed schedule, and immediately on staff turnover.
  - Turn on sign-in/audit-log alerting specifically for that account — the MFA exemption removes a detection layer the account would otherwise have.
  - Never reuse that exempted account for interactive/human login.

As with all credentials used by this tool, service account secrets must only come from environment variables or a secrets manager — never hardcoded, committed, or logged. See `_redact()` in `vhc_simplifier.py`, which strips Salesforce credentials out of error messages before they reach logs or `result.errors`.

---

## Disclosure Policy

This project follows **responsible disclosure**. Public details of a confirmed vulnerability will not be released until a fix is available or a reasonable remediation window (14 days) has passed without resolution, whichever comes first.
