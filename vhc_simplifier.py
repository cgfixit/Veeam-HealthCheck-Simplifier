#!/usr/bin/env python3
"""
Veeam Health Check Simplifier - v4.1 (demo-ready)

CSV (default) or JSON input. Graceful when files are missing.
--demo mode uses embedded sample data from real VHC exports.

Requires Python 3.12+  (tested on 3.12 and 3.13)

python vhc_simplifier.py --demo
python vhc_simplifier.py --demo --sf-account-id 001...   # credential error expected without creds
"""

from __future__ import annotations

import argparse
import io
import json
import logging
import os
import pathlib
import re
import sys
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("vhc_simplifier")

try:
    from simple_salesforce import Salesforce

    HAS_SF = True
except ImportError:
    HAS_SF = False

try:
    import httpx

    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


# ------------------------------------
# Embedded demo data
# ------------------------------------

EMBEDDED_JOBS = """Name,RetentionCount,RetainDaysToKeep,StgEncryptionEnabled
"VMware - Windows/Linux/Solaris",7,30,False
"Hyper-V - Windows / Linux",14,14,True
"""

EMBEDDED_REPOS = """Name,IsImmutabilitySupported
"Pure //x",False
"Exagrid",True
"""

EMBEDDED_SECURITY = """Best Practice,Status
"Remote desktop protocol is disabled","Not Implemented"
"MFA is enabled","Not Implemented"
"Backup jobs to cloud repositories is encrypted","Passed"
"""

EMBEDDED_MALWARE = """ObjectName,Status,DetectionTime
"YARA","Infected","2025-04-28 16:37:01"
"PortScan","Infected","2025-04-28 16:36:43"
"MALWARE","Suspicious","2025-05-21 17:19:49"
"""

EMBEDDED_SESSIONS = """JobName,Status
"VMware - Windows/Linux/Solaris",Failed
"""


@dataclass(frozen=True)
class HealthCheckConfig:
    recommended_retention_days: int = 30
    recommended_min_retention_count: int = 7


CONFIG = HealthCheckConfig()

EXPECTED_BASENAMES: dict[str, str] = {
    "jobs": "localhost_Jobs",
    "sessions": "VeeamSessionReport",
    "security": "localhost_SecurityCompliance",
    "repositories": "localhost_Repositories",
    "malware": "localhostmalware_events",
}

_TEXT_ENCODINGS = ("utf-8-sig", "utf-16", "utf-16-le", "utf-16-be", "cp1252")
_PS_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_NUMBER_RE = re.compile(r"-?\d+(?:\.\d+)?")


def _ps_quote(s: str) -> str | None:
    if not isinstance(s, str):
        s = str(s)
    if _PS_CONTROL_CHARS.search(s):
        return None
    return "'" + s.replace("'", "''") + "'"


def _find_unquoted_hash(cmd: str) -> int | None:
    i, n = 0, len(cmd)
    in_quote = False
    while i < n:
        ch = cmd[i]
        if ch == "'":
            if in_quote and i + 1 < n and cmd[i + 1] == "'":
                i += 2
                continue
            in_quote = not in_quote
        elif ch == "#" and not in_quote:
            return i
        i += 1
    return None


@dataclass
class HealthCheckResult:
    findings: list[str] = field(default_factory=list)
    enriched: list[dict[str, Any]] = field(default_factory=list)
    artifacts: dict[str, pathlib.Path] = field(default_factory=dict)
    missing_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    sections: dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": self.findings,
            "enriched": self.enriched,
            "artifacts": {k: str(v) for k, v in self.artifacts.items()},
            "missing_files": self.missing_files,
            "errors": self.errors,
            "sections": self.sections,
        }


def _clean_columns(df: pd.DataFrame) -> pd.DataFrame:
    df = df.rename(columns=lambda c: str(c).lstrip("\ufeff").strip())
    if any("\x00" in str(c) for c in df.columns):
        raise UnicodeError("decoded columns contain NUL bytes")
    return df


def _candidate_encodings(path: pathlib.Path) -> tuple[str, ...]:
    sample = path.read_bytes()[:4096]
    if b"\x00" in sample:
        return ("utf-16", "utf-16-le", "utf-16-be", "utf-8-sig", "cp1252")
    return _TEXT_ENCODINGS


def _read_text(path: pathlib.Path) -> str:
    last_exc: Exception | None = None
    for encoding in _candidate_encodings(path):
        try:
            text = path.read_text(encoding=encoding)
            if "\x00" in text:
                raise UnicodeError("decoded text contains NUL bytes")
            return text.lstrip("\ufeff")
        except UnicodeError as exc:
            last_exc = exc
    if last_exc is not None:
        raise last_exc
    return path.read_text(encoding="utf-8-sig").lstrip("\ufeff")


def _json_records(data: Any) -> Any:
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return None
    for key in ("data", "value", "items", "results"):
        value = data.get(key)
        if isinstance(value, list):
            return value
    result = data.get("result")
    nested = _json_records(result) if isinstance(result, dict) else None
    return nested if nested is not None else [data]


def _resolve_input_file(input_dir: pathlib.Path, key: str, base: str, input_format: str) -> pathlib.Path:
    exact = input_dir / f"{base}.{input_format}"
    if exact.exists() or not input_dir.is_dir():
        return exact

    suffix = f".{input_format}".lower()
    candidates: list[pathlib.Path] = []
    for path in input_dir.iterdir():
        if not path.is_file() or path.suffix.lower() != suffix:
            continue
        stem = path.stem.lower()
        if key == "jobs" and (stem == "jobs" or stem.endswith("_jobs")):
            candidates.append(path)
        elif key == "sessions" and stem.endswith("sessionreport"):
            candidates.append(path)
        elif key == "security" and (stem == "securitycompliance" or stem.endswith("_securitycompliance")):
            candidates.append(path)
        elif key == "repositories" and (stem == "repositories" or stem.endswith("_repositories")):
            candidates.append(path)
        elif key == "malware" and stem.endswith("malware_events"):
            candidates.append(path)
    return sorted(candidates, key=lambda p: p.name.lower())[0] if candidates else exact


def _safe_load_csv(path: pathlib.Path, result: HealthCheckResult) -> pd.DataFrame | None:
    if not path.exists():
        result.missing_files.append(path.name)
        return None
    if path.stat().st_size == 0:
        result.errors.append(f"{path.name}: empty")
        return None

    last_exc: Exception | None = None
    for encoding in _candidate_encodings(path):
        try:
            df = pd.read_csv(path, encoding=encoding, encoding_errors="strict")
            df = _clean_columns(df)
            return None if df.empty else df
        except Exception as exc:
            last_exc = exc
    if last_exc is not None:
        result.errors.append(f"{path.name}: {type(last_exc).__name__}: {last_exc}")
    return None


def _safe_load_json(path: pathlib.Path, result: HealthCheckResult) -> pd.DataFrame | None:
    if not path.exists():
        result.missing_files.append(path.name)
        return None
    try:
        raw = _read_text(path)
        raw = raw.lstrip("﻿")
        data = json.loads(raw)
        records = _json_records(data)
        if records is None:
            result.errors.append(f"{path.name}: bad JSON structure")
            return None
        df = _clean_columns(pd.DataFrame(records))
        return df if not df.empty else None
    except Exception as e:
        result.errors.append(f"{path.name}: {type(e).__name__}: {e}")
        return None


def _load_embedded() -> dict[str, pd.DataFrame | None]:
    return {
        "jobs": pd.read_csv(io.StringIO(EMBEDDED_JOBS)),
        "sessions": pd.read_csv(io.StringIO(EMBEDDED_SESSIONS)),
        "security": pd.read_csv(io.StringIO(EMBEDDED_SECURITY)),
        "repositories": pd.read_csv(io.StringIO(EMBEDDED_REPOS)),
        "malware": pd.read_csv(io.StringIO(EMBEDDED_MALWARE)),
    }


def _to_number(value: Any, default: float = 0.0) -> float:
    """Coerce a CSV/JSON cell to a number, tolerating None, NaN and bad strings.

    Returns ``default`` for missing or unparseable values so comparisons in the
    analyzers never raise ``TypeError`` on mixed-type data.
    """
    if value is None:
        return default
    try:
        if pd.isna(value):
            return default
    except (TypeError, ValueError):
        pass
    if isinstance(value, str):
        cleaned = value.strip().replace(",", "")
        match = _NUMBER_RE.search(cleaned)
        if match:
            try:
                return float(match.group(0))
            except ValueError:
                return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_bool(value: Any, default: bool = False) -> bool:
    """Coerce a CSV/JSON cell to a bool.

    pandas reads empty cells as ``NaN`` (which is truthy), so ``not value`` is an
    unreliable test. This treats missing/unparseable values as ``default`` and
    recognizes common truthy string spellings.
    """
    if isinstance(value, bool):
        return value
    try:
        if pd.isna(value):
            return default
    except (TypeError, ValueError):
        pass
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in (
            "true",
            "1",
            "yes",
            "y",
            "t",
            "enabled",
            "enable",
            "supported",
        ):
            return True
        if normalized in (
            "false",
            "0",
            "no",
            "n",
            "f",
            "disabled",
            "disable",
            "unsupported",
            "not supported",
        ):
            return False
    return default


def _str_cell(value: Any, default: str = "<unknown>") -> str:
    """Return a cell value as a non-NaN string, using default for missing/NaN."""
    if value is None:
        return default
    try:
        if pd.isna(value):
            return default
    except (TypeError, ValueError):
        pass
    s = str(value).strip()
    return s if s else default


def _row_name(row: Any, default: str = "<unknown>") -> str:
    """Return the Name cell as a non-NaN string, falling back to default."""
    return _str_cell(row.get("Name"), default)


def analyze_jobs(jobs_df, sessions_df):
    findings: list[str] = []
    if jobs_df is not None:
        for _, row in jobs_df.iterrows():
            name = _row_name(row)
            if _to_number(row.get("RetentionCount")) < CONFIG.recommended_min_retention_count:
                findings.append(f"Job '{name}' has low retention count.")
            if _to_number(row.get("RetainDaysToKeep")) < CONFIG.recommended_retention_days:
                findings.append(f"Job '{name}' keeps restore points < recommended.")
            if not _to_bool(row.get("StgEncryptionEnabled")):
                findings.append(f"Job '{name}' missing storage encryption.")
    if sessions_df is not None:
        try:
            if "Status" not in sessions_df.columns or "JobName" not in sessions_df.columns:
                return findings
            failed = sessions_df[sessions_df["Status"].astype(str).str.strip().str.casefold() == "failed"]
            for job in failed["JobName"].dropna().unique():
                findings.append(f"Recent job session failure: '{_str_cell(job)}'.")
        except Exception:
            pass
    return findings


def analyze_security(sec_df):
    findings: list[str] = []
    if sec_df is None:
        return findings
    if "Best Practice" not in sec_df.columns or "Status" not in sec_df.columns:
        return findings
    for _, row in sec_df.iterrows():
        bp = row.get("Best Practice", "")
        status = row.get("Status", "")
        if pd.isna(bp) or str(bp).strip() == "":
            continue
        try:
            if pd.isna(status):
                continue
        except (TypeError, ValueError):
            pass
        normalized_status = str(status).strip()
        if normalized_status == "":
            continue
        if normalized_status.casefold() not in ("passed", "unable to detect"):
            findings.append(f"Security Best Practice NOT implemented: {bp} ({normalized_status})")
    return findings


def analyze_repositories(repo_df):
    findings: list[str] = []
    if repo_df is None:
        return findings
    if "IsImmutabilitySupported" not in repo_df.columns:
        return findings
    for _, row in repo_df.iterrows():
        name = _row_name(row)
        if not _to_bool(row.get("IsImmutabilitySupported")):
            findings.append(f"Repository '{name}' does not support immutability.")
    return findings


def analyze_malware(malware_df):
    findings: list[str] = []
    if malware_df is None:
        return findings
    if "Status" not in malware_df.columns:
        return findings
    mask = (
        malware_df["Status"]
        .astype(str)
        .str.lower()
        .str.contains(r"infected|suspicious", na=False, regex=True)
    )
    for _, row in malware_df[mask].iterrows():
        findings.append(
            f"Malware event: {_str_cell(row.get('ObjectName'))} - "
            f"{_str_cell(row.get('Status'))} at {_str_cell(row.get('DetectionTime'))}"
        )
    return findings


PATTERN_MAP = {
    r"Job '(.+?)' missing storage encryption": {
        "severity": "High",
        "category": "Job",
        "explain": "Enable at-rest encryption to protect backup data.",
        "cmd": "Set-VBRJobAdvancedStorageOptions -Job (Get-VBRJob -Name {0}) -EnableEncryption $true",
        "kb": "https://helpcenter.veeam.com/docs/backup/vbr/encryption.html",
    },
    r"Job '(.+?)' has low retention count": {
        "severity": "Medium",
        "category": "Job",
        "explain": "Increase restore-point retention.",
        "cmd": "# Set via VBR Console: Job Properties > Storage > Restore points to keep on disk",
        "kb": "https://helpcenter.veeam.com/docs/backup/vbr/retention_policy.html",
    },
    r"Job '(.+?)' keeps restore points < recommended": {
        "severity": "Medium",
        "category": "Job",
        "explain": "Extend RetainDaysToKeep.",
        "cmd": "# Set via VBR Console: Job Properties > Storage > Retention Policy (GFS days)",
        "kb": "https://helpcenter.veeam.com/docs/backup/vbr/retention_policy.html",
    },
    r"Repository '(.+?)' does not support immutability": {
        "severity": "High",
        "category": "Repository",
        "explain": "Migrate to Hardened Linux Repository for ransomware resilience.",
        "cmd": "# Manual: Configure Hardened Linux Repository (see VBR v11+ docs)",
        "kb": "https://helpcenter.veeam.com/docs/backup/vbr/hardened_repository.html",
    },
    r"Recent job session failure: '(.+?)'": {
        "severity": "High",
        "category": "Job",
        "explain": "Investigate last sessions for root cause.",
        "cmd": "Get-VBRBackupSession -Name {0} | Sort-Object EndTime -Descending | Select-Object -First 5",
        "kb": "https://www.veeam.com/kb",
    },
    r"Security Best Practice NOT implemented: (.+?) \(": {
        "severity": "High",
        "category": "Security",
        "explain": "Apply missing security control per Veeam Hardening Guide.",
        "cmd": "# See Veeam Hardening Guide for implementation steps",
        "kb": "https://bp.veeam.com/security/Design-and-implementation/Hardening/",
    },
    r"Malware event: (.+?) - ": {
        "severity": "High",
        "category": "Malware",
        "explain": "Triage immediately - isolate affected systems.",
        "cmd": "Get-VBRMalwareEvent | Sort-Object DetectionTime -Descending | Select-Object -First 10",
        "kb": "https://helpcenter.veeam.com/docs/backup/vsphere/malware_detection.html",
    },
}

_MUTATING_VERBS = ("Set-", "Convert-", "Remove-", "New-", "Add-")


def enrich_findings(raw: list[str]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in raw:
        matched = False
        for pattern, meta in PATTERN_MAP.items():
            m = re.search(pattern, line, flags=re.IGNORECASE)
            if not m:
                continue
            obj = m.group(1) if m.groups() else ""
            dedup_key = f"{meta['severity']}|{meta['category']}|{obj}"
            if dedup_key in seen:
                matched = True
                break
            seen.add(dedup_key)
            cmd_template = meta["cmd"]
            if "{0}" in cmd_template:
                quoted = _ps_quote(obj)
                cmd_out = (
                    f"# REFUSED: control chars in object name: {obj!r}"
                    if quoted is None
                    else cmd_template.format(quoted)
                )
            else:
                cmd_out = cmd_template
            enriched.append(
                {
                    "raw": line,
                    "object": obj,
                    "severity": meta["severity"],
                    "category": meta["category"],
                    "explain": meta["explain"],
                    "kb": meta["kb"],
                    "cmd": cmd_out,
                }
            )
            matched = True
            break
        if not matched:
            enriched.append(
                {
                    "raw": line,
                    "object": "",
                    "severity": "Info",
                    "category": "General",
                    "explain": "No predefined remediation - review manually.",
                    "kb": "",
                    "cmd": "",
                }
            )
    return enriched


def write_markdown(enriched, sections, out_path):
    lines = [
        "# Veeam Health Check Remediation Summary",
        f"*Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}*",
        "",
        "## Section Summary",
    ]
    for s, items in sections.items():
        lines.append(f"- **{s}**: {len(items)} finding(s)")
    lines += ["", "## Detailed Findings"]
    for it in enriched:
        lines += [
            f"### {it['severity']} - {it['category']}",
            f"**Finding:** {it['raw']}",
            f"**Impact:** {it['explain']}",
        ]
        if it["cmd"]:
            lines += ["", "```powershell", it["cmd"], "```"]
        if it["kb"]:
            lines.append(f"[KB / Docs]({it['kb']})")
        lines.append("---")
    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


def write_powershell_script(enriched, out_path):
    lines = [
        "# Auto-generated Veeam remediation script (SAFE PREVIEW)",
        "# WARNING: All mutating commands include -WhatIf.",
        "# Remove -WhatIf only after validating in a non-production environment.",
        f"# Generated: {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}",
        "",
    ]
    for it in enriched:
        cmd = it.get("cmd", "")
        if not cmd:
            continue
        if cmd.lstrip().startswith(_MUTATING_VERBS) and "-WhatIf" not in cmd:
            h = _find_unquoted_hash(cmd)
            cmd = f"{cmd[:h].rstrip()} -WhatIf  {cmd[h:]}" if h is not None else f"{cmd} -WhatIf"
        lines += [f"# {it['raw'].replace(chr(13), ' ').replace(chr(10), ' ')}", cmd, ""]
    out_path.write_text("\n".join(lines), encoding="utf-8")
    return out_path


def write_ticket_payload(enriched, out_path):
    payload = [
        {
            "short_description": e["raw"][:250],
            "severity": e["severity"],
            "category": e["category"],
            "cmd": e["cmd"],
            "kb": e["kb"],
        }
        for e in enriched
        if e["severity"] in ("High", "Medium")
    ]
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


def _push_to_salesforce(enriched, sf_account_id, result, username=None, password=None, token=None):
    username = username or os.getenv("SF_USERNAME")
    password = password or os.getenv("SF_PASSWORD")
    token = token or os.getenv("SF_TOKEN")
    if not all([username, password, token]):
        result.errors.append(
            "Salesforce credentials missing. Set SF_USERNAME/SF_PASSWORD/SF_TOKEN env vars "
            "or use --sf-username/--sf-password/--sf-token"
        )
        return
    if not HAS_SF:
        result.errors.append("pip install simple-salesforce")
        return
    try:
        sf = Salesforce(username=username, password=password, security_token=token)
        for e in enriched:
            if e["severity"] not in ("High", "Medium"):
                continue
            sf.Task.create(
                {
                    "Subject": e["raw"][:80],
                    "Description": f"{e['cmd']}\n\nKB: {e['kb']}",
                    "Priority": "High" if e["severity"] == "High" else "Normal",
                    "Status": "Not Started",
                    "WhatId": sf_account_id,
                }
            )
        logger.info("Salesforce push complete")
    except Exception as exc:
        result.errors.append(f"Salesforce error: {_redact(str(exc), username, password, token)}")


def _validate_slack_webhook(url: str) -> bool:
    """Reject obviously invalid Slack webhook URLs before attempting network calls."""
    if not isinstance(url, str):
        return False
    return url.startswith("https://hooks.slack.com/services/") or url.startswith(
        "https://hooks.slack-gov.com/services/"
    )


def _redact(text: str, *secrets: str | None) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def _post_slack_summary(enriched, webhook, result):
    high = sum(1 for e in enriched if e.get("severity") == "High")
    med = sum(1 for e in enriched if e.get("severity") == "Medium")
    message = f"VHC complete - {high} High, {med} Medium findings."
    payload = json.dumps({"text": message}).encode()
    try:
        if HAS_HTTPX:
            response = httpx.post(webhook, json={"text": message}, timeout=10)
            response.raise_for_status()
        else:
            req = urllib.request.Request(webhook, data=payload, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as response:
                status = getattr(response, "status", 200)
                if isinstance(status, int) and status >= 400:
                    raise RuntimeError(f"Slack returned HTTP {status}")
        logger.info("Slack posted")
    except Exception as exc:
        result.errors.append(f"Slack error: {exc}")


def _print_console_report(result: HealthCheckResult) -> None:
    print("\n# Veeam Health Check Summary (v4.1)\n")
    for section, items in result.sections.items():
        print(f"## {section}")
        for f in items or []:
            print(f"- {f}")
        print()
    if result.missing_files:
        print("## Missing files (graceful):")
        for f in result.missing_files:
            print(f"- {f}")
        print()
    if result.errors:
        print("## Errors / Warnings:")
        for e in result.errors:
            print(f"- {e}")
        print()
    if result.artifacts:
        print("## Artifacts written:")
        for k, v in result.artifacts.items():
            print(f"- {k}: {v}")


def _run_analyzer(name: str, func, result: HealthCheckResult, *args) -> list[str]:
    """Run an analyzer, isolating failures so one bad section can't abort the run."""
    try:
        return func(*args)
    except Exception as e:
        msg = f"{name} analysis failed: {type(e).__name__}: {e}"
        result.errors.append(msg)
        logger.exception(msg)
        return []


def _write_artifact(result: HealthCheckResult, key: str, func, *args) -> None:
    """Write an artifact, recording IO/serialization failures instead of crashing."""
    try:
        result.artifacts[key] = func(*args)
    except Exception as e:
        msg = f"Failed to write {key} artifact: {type(e).__name__}: {e}"
        result.errors.append(msg)
        logger.exception(msg)


def run_healthcheck(
    input_dir: str | pathlib.Path = ".",
    output_dir: str | pathlib.Path = ".",
    write_artifacts: bool = True,
    verbose: bool = True,
    input_format: str = "csv",
    demo: bool = False,
    sf_account_id: str | None = None,
    slack_webhook: str | None = None,
    sf_username: str | None = None,
    sf_password: str | None = None,
    sf_token: str | None = None,
) -> dict[str, Any]:
    input_dir = pathlib.Path(input_dir)
    output_dir = pathlib.Path(output_dir)
    result = HealthCheckResult()

    if write_artifacts:
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            msg = f"Cannot create output dir {output_dir}: {type(e).__name__}: {e}"
            result.errors.append(msg)
            logger.error(msg)
            write_artifacts = False

    if input_format not in ("csv", "json"):
        msg = f"Unsupported input format: {input_format!r}. Must be 'csv' or 'json'."
        result.errors.append(msg)
        logger.error(msg)
        return result.to_dict()

    if demo:
        logger.info("Running in --demo mode with embedded sample data")
        try:
            dfs = _load_embedded()
        except Exception as e:
            msg = f"Failed to load embedded demo data: {type(e).__name__}: {e}"
            result.errors.append(msg)
            logger.exception(msg)
            dfs = {}
    else:
        loader = _safe_load_json if input_format == "json" else _safe_load_csv
        dfs = {}
        for key, base in EXPECTED_BASENAMES.items():
            path = _resolve_input_file(input_dir, key, base, input_format)
            dfs[key] = loader(path, result)

    missing = [k for k, v in dfs.items() if v is None]
    if missing and not demo:
        msg = f"Graceful partial run - missing files: {', '.join(missing)}. Continuing with available data."
        result.errors.append(msg)
        logger.warning(msg)

    sections = {
        "Backup Jobs": _run_analyzer(
            "Backup Jobs", analyze_jobs, result, dfs.get("jobs"), dfs.get("sessions")
        ),
        "Security & Compliance": _run_analyzer(
            "Security & Compliance", analyze_security, result, dfs.get("security")
        ),
        "Repositories": _run_analyzer("Repositories", analyze_repositories, result, dfs.get("repositories")),
        "Malware Events": _run_analyzer("Malware Events", analyze_malware, result, dfs.get("malware")),
    }
    all_findings = [f for fl in sections.values() for f in fl]
    result.findings = all_findings
    result.sections = sections
    result.enriched = _run_analyzer("Enrichment", enrich_findings, result, all_findings)

    if write_artifacts and all_findings:
        _write_artifact(
            result,
            "markdown",
            write_markdown,
            result.enriched,
            sections,
            output_dir / "remediation_summary.md",
        )
        _write_artifact(
            result,
            "powershell",
            write_powershell_script,
            result.enriched,
            output_dir / "fixit.ps1",
        )
        _write_artifact(
            result,
            "tickets",
            write_ticket_payload,
            result.enriched,
            output_dir / "tickets.json",
        )

    if sf_account_id and result.enriched:
        _push_to_salesforce(result.enriched, sf_account_id, result, sf_username, sf_password, sf_token)
    if slack_webhook and result.enriched:
        if _validate_slack_webhook(slack_webhook):
            _post_slack_summary(result.enriched, slack_webhook, result)
        else:
            result.errors.append(f"Invalid Slack webhook URL: {slack_webhook!r}")
    if verbose:
        _print_console_report(result)
    return result.to_dict()


def main() -> int:
    p = argparse.ArgumentParser(
        description="Veeam Health Check Simplifier v4.1 - CSV/JSON + demo + graceful degradation"
    )
    p.add_argument("--input-dir", default=".", help="Directory with CSV/JSON files")
    p.add_argument("--output-dir", default=".", help="Where to write artifacts")
    p.add_argument("--input-format", choices=["csv", "json"], default="csv")
    p.add_argument("--demo", action="store_true", help="Use embedded sample data (no files needed)")
    p.add_argument("--no-artifacts", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--sf-account-id", default=None)
    p.add_argument("--sf-username", default=None)
    p.add_argument("--sf-password", default=None)
    p.add_argument("--sf-token", default=None)
    p.add_argument("--slack-webhook", default=None)
    args = p.parse_args()
    try:
        result = run_healthcheck(
            input_dir=args.input_dir,
            output_dir=args.output_dir,
            write_artifacts=not args.no_artifacts,
            verbose=not args.quiet,
            input_format=args.input_format,
            demo=args.demo,
            sf_account_id=args.sf_account_id,
            slack_webhook=args.slack_webhook,
            sf_username=args.sf_username,
            sf_password=args.sf_password,
            sf_token=args.sf_token,
        )
    except Exception as exc:
        logger.critical("Unhandled error in run_healthcheck: %s", exc, exc_info=True)
        return 1
    return 2 if result.get("errors") else 0


if __name__ == "__main__":
    sys.exit(main())
