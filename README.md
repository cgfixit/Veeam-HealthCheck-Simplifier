# Veeam Health Check Simplifier

**v4.2.0** — a security-focused VBR pipeline that ingests [Veeam Health Check](https://vee.am/vhc2) exports from Veeam Backup & Replication (VBR) servers, analyzes them for optimizations, fixes, security hardening, compliance gaps, and generates safe, reviewable remediation artifacts.

---

## What is the Veeam Health Check?

The [Veeam Health Check (VHC)](https://github.com/VeeamHub/veeam-healthcheck) is a free, community-supported VeeamHub tool: a Windows .NET application whose collectors run Veeam PowerShell cmdlets against a Veeam Backup & Replication server. It writes CSV files (by default under `C:\temp\vHC\Original\VBR\<server>\<timestamp>\`) covering:

- **Jobs** — backup job configuration (retention, encryption, schedules)
- **Sessions** — recent job run results (success, failure, warnings)
- **Security Compliance** — best-practice status (MFA, RDP, encryption, immutability)
- **Repositories** — backup storage targets and immutability support
- **Malware Events** — inline scan, YARA rule, and entropy detection results

This project takes those raw exports and transforms them into actionable remediation guidance — no manual spreadsheet review required. JSON input is an alternate, API-shaped record format (for example VBR REST API output), not something VHC itself writes.

### Supported VBR Versions

| VBR Version | Build | Windows Server | Status |
|---|---|---|---|
| v12.3.2 | 12.3.2.x fixture target (latest: 12.3.2.4934, P4) | 2016, 2019, 2022, 2025 | Simulated VHC fixture coverage |
| v13 | 13.x fixture target (latest: 13.1.2.57) | 2019, 2022, 2025 | Simulated VHC fixture coverage |

Latest builds per Veeam's [build table (KB2680)](https://www.veeam.com/kb2680), checked 2026-11-14. The
fixtures are simulations and are not tied to a specific build.

File names and the analyzed columns were cross-checked against the upstream VHC collector
source and its VBR v13 golden-baseline CSVs (VeeamHub/veeam-healthcheck `d403bea`, 2026-11-02).
That is upstream evidence about the export format, not a test against a live VBR server.

---

## How It Works

```
                     ┌─────────────────────────────────┐
                     │  Windows Server with VBR        │
                     │  Run https://vee.am/vhc2        │
                     │  → Exports CSV/JSON files       │
                     └───────────────┬─────────────────┘
                                     │
                                     ▼
                     ┌─────────────────────────────────┐
                     │  vhc_simplifier.py               │
                     │                                   │
                     │  1. Load exports (CSV or JSON)    │
                     │  2. Analyze 4 sections (5 inputs) │
                     │  3. Enrich with remediation cmds  │
                     │  4. Generate artifacts            │
                     │  5. (Optional) Push to SF/Slack   │
                     └───────────────┬─────────────────┘
                                     │
                    ┌────────────────┼────────────────┐
                    ▼                ▼                ▼
             remediation_      fixit.ps1       tickets.json
             summary.md     (safe -WhatIf)    (ITSM-ready)
```

### Analysis Pipeline

1. **Load** — `_safe_load_csv()` / `_safe_load_json()` with UTF-8 BOM stripping, Windows-oriented encoding fallback, corrupt-decode guards, and empty-file guards
2. **Analyze** — four fault-isolated analyzers (`_run_analyzer()` wrapper catches exceptions per-analyzer, never aborts the run):
   - `analyze_jobs(jobs_df, sessions_df)` — retention, encryption, and recent session failures (there is no separate `analyze_sessions()`)
   - `analyze_security()` — best-practice compliance status
   - `analyze_repositories()` — immutability support gaps
   - `analyze_malware()` — infected/suspicious events, read from `Status` (Veeam documents it as the event severity) or from `Type` (where VHC's own v13 baselines carry the verdict), unless `Status` is `Clean`
3. **Enrich** — `enrich_findings()` pattern-matches each finding to a PowerShell remediation command with KB article links, applying `_ps_quote()` injection guards
4. **Write** — `_write_artifact()` wrapper isolates IO errors per-file:
   - `remediation_summary.md` — human-readable report with severity, PS snippets, and KB links
   - `fixit.ps1` — executable remediation script (all mutating verbs include `-WhatIf`)
   - `tickets.json` — ITSM-ready payload (High/Medium findings only)
5. **Integrate** (optional) — push findings to Salesforce as Tasks or post a summary to Slack

---

## Features

- **Multi-format input** — CSV (default, from [vee.am/vhc2](https://vee.am/vhc2)) or JSON (VBR REST API exports)
- **Demo mode** — runs instantly with embedded sample data; no input files required
- **Secure PowerShell output** — mutating cmdlets (`Set-`, `New-`, `Remove-`, etc.) include `-WhatIf` by default; several remediations (storage encryption, retention, immutability) are review-only comments, not mutating cmdlets
- **PS injection prevention** — object names with control characters are refused, not interpolated
- **Salesforce integration** — creates Tasks on an Account record for High/Medium findings
- **Slack notifications** — posts a severity summary to an incoming webhook
- **Graceful degradation** — missing input files are logged but never fatal; partial runs proceed; individual analyzer failures are recorded and skipped without aborting the run
- **Robust encoding handling** — tolerates UTF-8 BOM (common from Windows PowerShell `Export-Csv`), UTF-16 variants, and Windows code-page fallback while rejecting corrupt NUL-decoded files
- **No secrets in code** — Salesforce credentials resolved from environment variables only

---

## Generated Artifacts

| File | Description |
|---|---|
| `remediation_summary.md` | Human-readable findings with PowerShell snippets and KB links |
| `fixit.ps1` | Safe preview remediation script (`-WhatIf` on all mutating commands) |
| `tickets.json` | ITSM-ready JSON payload (High/Medium findings only) |

---

## Installation

Pick the option that matches where the exports are:

| Where you run it | Install | Needs Python |
|---|---|---|
| Windows Server / admin workstation, no Python allowed | Windows bundle zip from [Releases](https://github.com/cgfixit/Veeam-HealthCheck-Simplifier/releases) | No |
| Any machine with Python 3.12+ | Release wheel via `pipx` / `uv tool`, or `pip` with `constraints.txt` | Yes |
| Linux automation host / scheduled runs | Container image (`ghcr.io`) or `docker compose` | No (Docker) |
| Development | Clone + `pip install -r requirements.txt` | Yes |

**Windows bundle (no Python).** Download `vhc-simplifier-<version>-windows-x64.zip`, check it against
`SHA256SUMS` (and optionally `gh attestation verify <zip> --repo cgfixit/Veeam-HealthCheck-Simplifier`),
unzip, and run `vhc-simplifier\vhc-simplifier.exe --input-dir C:\temp\vHC\Original\VBR\<server>\<timestamp>`.
It is a PyInstaller one-folder build with its own CPython, pandas, and numpy, plus their license notices in
`licenses\`. It includes the core CLI and Slack posting (stdlib `urllib`); Salesforce Task creation needs the
`salesforce` extra from a Python install. The executable is not code-signed, so SmartScreen or application
control policies may require an allow rule.

**Wheel.** `pipx install vhc_simplifier-<version>-py3-none-any.whl` (or `uv tool install <wheel>`) puts
`vhc-simplifier` on your PATH. For the exact tested dependency versions, install into a venv with the
constraints file: `pip install -c constraints.txt vhc_simplifier-<version>-py3-none-any.whl`.

### Dependency layout

| File | Role |
|---|---|
| `pyproject.toml` | Source of truth: runtime dependency ranges, extras, release tooling group, version (read from `vhc_simplifier.__version__`) |
| `constraints.txt` | Exact pins for every package on Python 3.12+ and all platforms, generated by `uv pip compile --universal`; used by CI, the Dockerfile, and the release build |
| `requirements.txt` | Development shortcut: `-c constraints.txt` plus an editable install with all extras |

| Extra / group | Adds |
|---|---|
| *(core)* | `pandas` |
| `salesforce` | `simple-salesforce` *(only for `--sf-account-id`)* |
| `slack` | `httpx` *(optional — Slack falls back to stdlib `urllib`)* |
| `integrations` | both of the above |
| `container` | `cronsim`, used only by `docker_entrypoint.py` |
| `dev` | `container` + `pytest`, `pytest-cov`, `ruff` |
| `release` *(PEP 735 group)* | `build`, `setuptools`, `pyinstaller` |

```bash
# Development checkout: package (editable) + all extras, pinned
pip install -r requirements.txt

# Only what you need, still pinned
pip install -c constraints.txt ".[salesforce]"

# Regenerate pins after changing pyproject.toml (Dependabot also updates them weekly)
uv pip compile pyproject.toml --all-extras --group pyproject.toml:release --universal \
  --python-version 3.12 -o constraints.txt
```

Python 3.12+ is required (CI tests 3.12, 3.13, and 3.14; the container image uses 3.14).

---

## Quick Start

```bash
# Demo mode (no files needed — uses embedded sample data)
python vhc_simplifier.py --demo        # or: vhc-simplifier --demo  (after installing)

# Show the installed version
python vhc_simplifier.py --version

# Real CSV export from a VBR server (run vee.am/vhc2 on Windows first)
python vhc_simplifier.py --input-dir ./vhc-exports --output-dir ./results

# JSON / VBR REST API export
python vhc_simplifier.py --input-dir ./vhc-json --input-format json

# With Salesforce Task creation
export SF_USERNAME=user@domain.com
export SF_PASSWORD=yourpassword
export SF_TOKEN=yoursecuritytoken
python vhc_simplifier.py --demo --sf-account-id 001XXXXXXXXXXXX

# With Slack notification
python vhc_simplifier.py --input-dir ./vhc-exports \
  --slack-webhook https://hooks.slack.com/services/T00/B00/xxx

# Quiet mode (no console output, just artifacts)
python vhc_simplifier.py --input-dir ./vhc-exports --quiet

# Skip artifact writing (analysis only)
python vhc_simplifier.py --input-dir ./vhc-exports --no-artifacts
```

---

## Running in Docker

```bash
# Build the image (or pull a release: docker pull ghcr.io/cgfixit/veeam-healthcheck-simplifier:<version>)
docker build -t vhc-simplifier .

# Behind a TLS-inspecting proxy, pass its CA as a build secret (never stored in a layer)
docker build --secret id=pip_ca,src=corp-ca.pem -t vhc-simplifier .

# Run once (demo mode, console report only)
docker run --rm vhc-simplifier --demo --no-artifacts

# Run once against real exports
docker run --rm \
  -v $(pwd)/vhc-exports:/app/input:ro \
  -v $(pwd)/output:/app/output \
  vhc-simplifier --input-dir /app/input --output-dir /app/output
```

For recurring runs, set the `CRON_SCHEDULE` env var (standard 5-field cron syntax) and the
container stays running under a small Python scheduler using `cronsim`, re-invoking the CLI
with the exact arguments you pass on each scheduled tick. No BusyBox or OS cron package is installed:

```bash
docker run -d --name vhc-simplifier \
  --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --tmpfs /tmp \
  -e CRON_SCHEDULE="0 6 * * *" \
  -v $(pwd)/vhc-exports:/app/input:ro \
  -v $(pwd)/output:/app/output \
  vhc-simplifier --input-dir /app/input --output-dir /app/output
```

The container runs as the non-root `vhc` user (UID 1000) in both modes; the installed application
code is root-owned and read-only to it. The scheduler writes no crontab,
PID file, or spool; only the output mount and temporary scratch space need to be writable.
Ensure the output mount is writable by UID 1000. With no arguments the image runs the demo and
writes artifacts to `/app/output`. With `CRON_SCHEDULE` unset or
empty, the entrypoint replaces itself with the CLI and preserves its exit status.

Scheduling accepts five fields with lists, ranges, steps, and month/weekday names. Invalid
expressions, newlines, six-field schedules, and macros such as `@daily` fail at startup with
status 2. Times use `/etc/localtime` (UTC in the image), or an IANA `TZ` such as
`America/New_York`. `cronsim` handles DST using that timezone. Runs never overlap; missed
ticks during downtime or a long run are skipped. A failed run is logged and the next run
still occurs. Container termination forwards the signal to the active CLI and waits for it;
Docker's stop timeout still bounds shutdown.

Day-of-month and day-of-week follow Debian/Vixie cron semantics: if either starts with `*`,
both must match; otherwise either may match. This differs from BusyBox for expressions such
as `0 0 */2 * MON` (now odd calendar days that are Mondays, rather than odd days or Mondays).
Review existing expressions that combine both day fields when upgrading.

The Python runner uses a cron parser with no transitive dependencies, avoiding a custom cron grammar.
Debian `cron` adds daemon/spool and privilege assumptions; Supercronic is container-friendly
but adds an architecture-specific native binary. The application itself remains a single-file
CLI and does not require `cronsim` unless installed with the `container` or `dev` extra.

The base image is pinned by digest and checked weekly by Dependabot. Trivy retains full
SARIF reports, including unfixed upstream findings, and separately fails CI on fixable
HIGH/CRITICAL vulnerabilities. The `Trivy (filesystem)` and `Trivy (container image)` checks
must be required in branch rules to prevent merging a failing change. Unfixed findings still
need monitoring; a passing gate does not mean the image has no vulnerabilities. The
[BusyBox alert](https://security-tracker.debian.org/tracker/CVE-2026-90954) concerns `.deb`
extraction, which the application does not invoke; removing the package
removes that dependency exposure without claiming a demonstrated application exploit. Containers
still share the host kernel. Keep the Compose restrictions and use a dedicated VM when a
separate kernel is required. The image retains its shell and OS libraries, but removes the unused
`infocmp` executable and strips set-user-ID/set-group-ID permissions from regular files. The
application does not need privileged login, password-changing, or mount tools. Custom image
builds that install additional packages should repeat this hardening after installation.
The image installs the package itself (`pyproject.toml` with the `container` extra) using the
pins in `constraints.txt` for both runtime and build dependencies, the same pins CI and the
release use; pip is then removed, including its unused vendored packages. To add optional
integrations in a custom image, change `"/tmp/src[container]"` to, for example,
`"/tmp/src[container,salesforce]"`; package installation is not part of container startup.

### Remaining container HIGH findings

Assessment of the Python 3.14 slim image based on Debian trixie, 2026-10-19. Trivy reports
44 HIGH package findings for eight distinct CVEs. The scanner maps Debian source packages
to multiple binary packages; that does not prove the affected program is installed or called.
No application input-to-vulnerable-operation path was found: CSV/JSON handling and artifact
writes use Python, and the scheduler launches only the fixed Python CLI without a shell.

| CVE | Affected operation | Reachability and action |
| --- | --- | --- |
| [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | `infocmp` terminal-data analysis | Previously installed but never called by the application. Remove the executable; retain ncurses libraries needed by other base-image components. This removes the affected tool, not the source-package version finding. |
| [CVE-2026-16742](https://github.com/systemd/systemd/security/advisories/GHSA-jm29-p7hh-vjhv) | `systemd-homed` identity authentication | The image has systemd libraries, but neither homed/homework nor a homed-managed user. No affected authentication path. |
| [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369) | Privileged pathname-based libacl operations | No ACL API/utility caller in the application. Ordinary CSV/JSON/demo execution does not load libacl; running non-root also removes the privileged-caller precondition. Retain the library for OS dependencies. |
| [CVE-2026-76642](https://github.com/util-linux/util-linux/security/advisories/GHSA-m25x-3hj9-m26f) | Failed mount helper followed by privileged post-hooks | No application mount calls or fstab entries. Remove set-ID permissions, including from mount; keep Compose's capability drop and no-new-privileges. Host-created Docker volumes do not call the image's mount utility. |
| [CVE-2026-78408](https://github.com/util-linux/util-linux/security/advisories/GHSA-55fx-f4gg-cfhj) | Privileged `nsenter --join-cgroup` leaks an open cgroup descriptor | The application never invokes nsenter. An affected **host** nsenter can still pass authority through an inherited descriptor even to a process with zero capabilities. Patch the host tool or avoid this option; image permissions cannot repair that host path. |
| [CVE-2026-78409](https://github.com/util-linux/util-linux/security/advisories/GHSA-8f2p-47x3-43mv) | `X-mount.subdir` path resolution | No authorized fstab mount configuration or application mount calls. Set-ID removal and Compose restrictions prevent the ordinary privileged mount path. |
| [CVE-2026-78410](https://github.com/util-linux/util-linux/security/advisories/GHSA-rh77-686x-2f2m) | Restricted SUID bind-mount source race | No fstab entries or mount caller; mount no longer has its SUID bit. Preserve the Compose restrictions. |
| [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) | Perl `Archive::Tar` allocation from a crafted tar header | `perl-base` is installed, but `Archive::Tar` is absent and the application never invokes Perl. No affected archive reader. |

The container regressions check these runtime assumptions alongside scheduled/ordinary artifact
generation and shutdown. The CSV/JSON/demo probe records subprocess launches and checks loaded
libraries; it is evidence for those paths, not an exhaustive proof for arbitrary custom code.
Reassess if custom images add services, modules, privileged operations, or host namespace access.
`docker run` alone does not apply Compose's runtime restrictions.

Debian trixie has no fixed package versions for these findings at the assessment date. Keep the
full Trivy reports visible: removing `infocmp` and stripping set-ID permissions do not change
the package-version results. Do not purge Essential packages, replace trixie libraries with
testing/unstable packages, or suppress CVEs solely to lower the count. Track stable updates;
the libacl fix changes its ABI and Debian has deferred the Perl update pending regressions.

---

## CLI Reference

| Flag | Default | Description |
|---|---|---|
| `--input-dir` | `.` | Directory containing VHC export files |
| `--output-dir` | `.` | Directory for generated artifacts |
| `--input-format` | `csv` | Input format: `csv` or `json` |
| `--version` | — | Print `vhc-simplifier <version>` and exit |
| `--demo` | off | Use embedded sample data (no files needed) |
| `--no-artifacts` | off | Skip writing `.md`/`.ps1`/`.json` files |
| `--quiet` | off | Suppress the default console report (`run_healthcheck(verbose=)` is the Python API; there is no `--verbose` flag) |
| `--sf-account-id` | — | Salesforce Account ID for Task creation |
| `--sf-username` | — | SF username (prefer `SF_USERNAME` env var) |
| `--sf-password` | — | SF password (prefer `SF_PASSWORD` env var) |
| `--sf-token` | — | SF security token (prefer `SF_TOKEN` env var) |
| `--log-file` | — | Also append log records, including data-quality warnings, to this file (UTF-8) |
| `--slack-webhook` | `VHC_SLACK_WEBHOOK` env | Slack incoming webhook URL (prefer the env var; the URL is a secret) |

---

## Expected Input Files

These files are produced by running [Veeam Health Check](https://github.com/VeeamHub/veeam-healthcheck) on a Windows Server with VBR installed. VHC prefixes most files with the VBR server name it collected from (`localhost` for a local run); `VeeamSessionReport.csv` has no prefix:

| Data | CSV filename | JSON filename |
|---|---|---|
| Jobs | `localhost_Jobs.csv` | `localhost_Jobs.json` |
| Sessions | `VeeamSessionReport.csv` | `VeeamSessionReport.json` |
| Security | `localhost_SecurityCompliance.csv` | `localhost_SecurityCompliance.json` |
| Repositories | `localhost_Repositories.csv` | `localhost_Repositories.json` |
| Malware | `localhost_malware_events.csv` | `localhost_malware_events.json` |

All files are optional — missing files are logged and skipped without aborting. Hostname-prefixed variants (for example `VBR01_Jobs.csv` or `vbr01.lab.local_malware_events.csv`) are discovered, as is the older `localhostmalware_events.csv` spelling. Point `--input-dir` at one server's timestamp folder so exports from different servers are never mixed.

---

## Integrations

### Salesforce

Creates Tasks on a Salesforce Account record for High and Medium severity findings. Requires `simple-salesforce` and credentials via environment variables:

```bash
export SF_USERNAME=user@domain.com
export SF_PASSWORD=yourpassword
export SF_TOKEN=yoursecuritytoken
python vhc_simplifier.py --demo --sf-account-id 001XXXXXXXXXXXX
```

### Slack

Posts a severity summary to a Slack incoming webhook. Accepts only `https://hooks.slack.com/services/...` and `https://hooks.slack-gov.com/services/...`:

```bash
python vhc_simplifier.py --demo \
  --slack-webhook https://hooks.slack.com/services/T00/B00/xxx
```

Uses `httpx` if available, falls back to stdlib `urllib`.

---

## Docker Compose

A `docker-compose.yml` is provided to build and run the CLI in a container without installing Python or dependencies locally.

```bash
mkdir -p vhc-exports output
# copy your VHC export files into ./vhc-exports
docker compose up --build

# Scheduled: keep the container running and restart it with the Docker daemon
CRON_SCHEDULE="0 6 * * *" VHC_TZ=America/New_York VHC_RESTART=unless-stopped docker compose up -d --build
```

This mounts `./vhc-exports` read-only to `/app/input` and `./output` read-write to `/app/output`, and runs `vhc-simplifier --input-dir /app/input --output-dir /app/output --quiet`. The restart policy is `no` unless `VHC_RESTART` is set: restarting a one-shot run would repeat it in a loop (re-posting Slack summaries and creating duplicate Salesforce Tasks), so only set it together with `CRON_SCHEDULE`. Override the default command for other flags, e.g. Salesforce or Slack integration:

```bash
VHC_SLACK_WEBHOOK=https://hooks.slack.com/services/T00/B00/xxx \
docker compose run --rm vhc-simplifier \
  --input-dir /app/input --output-dir /app/output \
  --sf-account-id 001XXXXXXXXXXXX
```

Salesforce credentials (`SF_USERNAME`, `SF_PASSWORD`, `SF_TOKEN`) and `VHC_SLACK_WEBHOOK` are passed through from the host environment or a `.env` file — never bake them into the image. The image installs the package with the `container` extra only: Slack posting uses stdlib `urllib` when `httpx` is absent, and Salesforce Task creation needs the `salesforce` extra, which is not in the image. Behind a TLS-inspecting proxy, build first with `docker build --secret id=pip_ca,src=corp-ca.pem -t vhc-simplifier:local .`, then run `docker compose up` without `--build`. Neither `./vhc-exports` nor `./output` should ever be committed; both are covered by `.gitignore`.

---

## Testing

The test suite collects **313** tests across 8 modules plus shared fixtures in `conftest.py` (CI `--cov-fail-under=80`). The 5 tests in `test_container.py` run only against a built image (`VHC_TEST_IMAGE`); CI's Docker job and the release workflow run them:

| Test File | Purpose |
|---|---|
| `test_vhc_simplifier.py` | Core helpers, analyzers, loaders, enrichment, artifact writers, integration runs |
| `test_coverage_gaps.py` | Edge cases: NaN handling, empty DataFrames, encoding, type coercion |
| `test_vbr_server_simulation.py` | VBR v12.3.2 and v13 mock server simulation with realistic export data |
| `test_windows_server_env.py` | Windows paths, encoding (BOM, UTF-16), PowerShell injection, server version matrix |
| `test_mock_veeam_environment.py` | Full mock VBR environments with file-level fault injection |
| `test_docker_entrypoint.py` | Container scheduler: cron parsing, DST, signal forwarding, exit codes (no Docker needed) |
| `test_container.py` | Built-image checks: non-root, read-only rootfs, capabilities, CVE boundaries, scheduled runs |
| `test_pyproject_metadata.py` | Packaging metadata: SPDX license, single-sourced version, every dependency pinned in `constraints.txt` |
| `conftest.py` | Shared fixtures with realistic VBR v12 and v13 CSV/JSON export data |

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage reporting
python -m pytest tests/ -v --cov=vhc_simplifier --cov-report=term-missing

# Run VBR server simulation tests only
python -m pytest tests/test_vbr_server_simulation.py -v

# Container checks against a locally built image
docker build -t vhc-simplifier:ci . && VHC_TEST_IMAGE=vhc-simplifier:ci python tests/test_container.py
```

---

## CI/CD Workflows

Eight GitHub Actions workflows live in `.github/workflows/`. CI, Ruff, Gitleaks, DevSkim, CodeQL, and Trivy run on push and pull request to `main` (Gitleaks, DevSkim, CodeQL, and Trivy also run weekly). Dependency Review runs on pull requests only. Release builds on pull requests that touch packaging and publishes on `v*.*.*` tags.

| Workflow | File | Purpose |
|---|---|---|
| **CI** | `ci.yml` | Lint + test matrix (Python 3.12/3.13/3.14 on ubuntu + windows) installed from `constraints.txt`, 80% coverage threshold, CLI exit-code checks, scheduled/standard Docker checks under non-root and read-only restrictions |
| **Ruff** | `ruff.yml` | Python lint and format checks |
| **Gitleaks** | `gitleaks.yml` | Secret scanning (push, PR, weekly) |
| **DevSkim** | `devskim.yml` | Microsoft security anti-pattern detection (push, PR, weekly) |
| **CodeQL** | `codeql.yml` | GitHub static analysis (push, PR, weekly) |
| **Dependency Review** | `dependency-review.yml` | Supply chain vulnerability checks on PRs |
| **Trivy** | `trivy.yml` | Filesystem + image scans; full SARIF reports and a fixable HIGH/CRITICAL gate (push, PR, weekly) |
| **Release** | `release.yml` | Wheel + sdist, Windows PyInstaller bundle, and image, each smoke-tested; on tags: draft GitHub Release with `SHA256SUMS`, build provenance attestations, and a `ghcr.io` push |

### Cutting a release

1. Bump `__version__` in `vhc_simplifier.py` (the only place the version lives) and merge to `main`.
2. Tag the merge commit: `git tag v<version> && git push origin v<version>`. The workflow fails if the
   tag does not match `__version__`.
3. Review the draft release the workflow creates, then publish it. The image is pushed to
   `ghcr.io/cgfixit/veeam-healthcheck-simplifier:<version>` (and `:latest` for non-prerelease tags);
   a new GHCR package may need its visibility set to public once in the package settings.

---

## Deployment

Deployment options:

- **Release downloads** — the Windows bundle or the wheel; see [Installation](#installation).
- **Docker** — build and run via the included `Dockerfile`, or pull the release image from `ghcr.io`.
- **Host-native (systemd)** — for operators who don't want Docker, `deploy/`
  provides a `oneshot` systemd service, a daily calendar timer, and a
  `logrotate` config for the log output. See [`deploy/README.md`](deploy/README.md)
  for install instructions.

---

## Architecture

```
Input (CSV / JSON / --demo)
        |
        v
  _safe_load_*()       <- adapter layer (BOM stripping, encoding fallback)
        |
        v
  _run_analyzer()      <- fault isolation wrapper (records errors, never aborts)
        |
        v
  analyze_*()          <- four pure functions (jobs+sessions, security, repos, malware)
        |
        v
  enrich_findings()    <- pattern-matched remediation + PS injection guard (_ps_quote)
        |
        |---> _write_artifact()        <- IO error isolation wrapper
        |         |---> write_markdown()
        |         |---> write_powershell_script()
        |         `---> write_ticket_payload()
        |---> _push_to_salesforce()    (optional)
        `---> _post_slack_summary()    (optional)
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Unhandled exception |
| `2` | Processing errors occurred: missing/unreadable inputs, missing expected columns, analyzer, write, or integration failures (check the console report and `remediation_summary.md`) |

---

## Security Notes

- **Never commit credentials.** Use env vars (`SF_USERNAME`, `SF_PASSWORD`, `SF_TOKEN`) or a secrets manager.
- **Review `-WhatIf` output before removing it.** Validate every command in a non-production environment first.
- **Injection prevention.** Object names with control characters (`0x00-0x1F`, `0x7F-0x9F`, `U+2028/2029`) are refused from PS command generation entirely. PowerShell also treats Unicode quotes (`U+2018-U+201B`) as single quotes, so they are doubled along with `'`. Report-derived text is Markdown-escaped and collapsed to one line in `remediation_summary.md`, `fixit.ps1` comments, and the console.
- **Input validation.** Files over 256 MiB, non-regular files, and unreadable paths are skipped with an error. Missing expected columns, header-only files, ambiguous hostname-prefixed matches, and blank/unrecognized cells that are treated as non-compliant (fail-closed) are reported under *Errors* / *Data quality warnings* in the console and in a *Data Quality / Coverage* section of `remediation_summary.md`. Header names are matched case-, space-, and underscore-insensitively.
- **Fail-closed findings are traceable.** A finding raised only because a cell was blank or unrecognized ends with `[unverified: blank/unrecognized <Column>]`. The tag carries into every artifact and the Salesforce Task description. Each data-quality warning is also logged as `WARNING | Data quality: ...`; use `--log-file` to keep a persistent record.
- **Clean runs still write artifacts.** A run with zero findings overwrites `remediation_summary.md`, `fixit.ps1`, and `tickets.json` so stale output from a previous run never looks current.
- **Salesforce.** The account ID must be a 15- or 18-character alphanumeric ID. Task creation failures are counted per task (partial writes are reported, not hidden). Passing `--sf-password`/`--sf-token` on the command line logs a warning.
- **Slack webhook validation.** Only `https://hooks.slack.com/...` and `https://hooks.slack-gov.com/...` URLs are accepted.
- **Release integrity.** Each release lists `SHA256SUMS`, and the wheel, sdist, Windows zip, and container image carry GitHub build provenance attestations (`gh attestation verify <file> --repo cgfixit/Veeam-HealthCheck-Simplifier`). The Windows executable is unsigned.
- **Service accounts & MFA.** Automation accounts used by this tool (Salesforce, Slack, and any scripted VBR REST API access) can't complete interactive MFA challenges — see [SECURITY.md](SECURITY.md#service-account--mfa-considerations) for guidance on scoping non-interactive credentials safely.

---

See [LICENSE.md](LICENSE.md), [CONTRIBUTORS.md](CONTRIBUTORS.md), and [SECURITY.md](SECURITY.md).
