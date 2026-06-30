"""Unit and integration tests for vhc_simplifier.

Run with:  python -m pytest tests/ -v
"""

from __future__ import annotations

import json
import pathlib
import sys

import pandas as pd
import pytest

# Make the top-level module importable when tests are run from anywhere.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import vhc_simplifier as vhc  # noqa: E402


# ------------------------------------
# Type-coercion helpers
# ------------------------------------


@pytest.mark.parametrize(
    "value, expected",
    [
        (7, 7.0),
        ("7", 7.0),
        (3.5, 3.5),
        (None, 0.0),
        (float("nan"), 0.0),
        ("not-a-number", 0.0),
        ("", 0.0),
    ],
)
def test_to_number_coercion(value, expected):
    assert vhc._to_number(value) == expected


def test_to_number_respects_default():
    assert vhc._to_number(None, default=30) == 30
    assert vhc._to_number("garbage", default=99) == 99


@pytest.mark.parametrize(
    "value, expected",
    [
        (True, True),
        (False, False),
        ("True", True),
        ("false", False),
        ("yes", True),
        ("n", False),
        (1, True),
        (0, False),
        (None, False),
        (float("nan"), False),
        ("", False),
    ],
)
def test_to_bool_coercion(value, expected):
    assert vhc._to_bool(value) is expected


# ------------------------------------
# PowerShell quoting / injection safety
# ------------------------------------


def test_ps_quote_escapes_single_quotes():
    assert vhc._ps_quote("O'Brien") == "'O''Brien'"


def test_ps_quote_refuses_control_chars():
    assert vhc._ps_quote("evil\x00name") is None
    assert vhc._ps_quote("line\nbreak") is None


def test_find_unquoted_hash_ignores_quoted_hash():
    assert vhc._find_unquoted_hash("Get-Thing 'a#b'") is None
    assert vhc._find_unquoted_hash("Get-Thing # comment") == 10


# ------------------------------------
# Analyzers
# ------------------------------------


def test_analyze_jobs_flags_low_retention_and_encryption():
    jobs = pd.DataFrame(
        [
            {
                "Name": "Job1",
                "RetentionCount": 3,
                "RetainDaysToKeep": 5,
                "StgEncryptionEnabled": False,
            }
        ]
    )
    vhc.HealthCheckResult()
    findings = vhc.analyze_jobs(jobs, None)
    assert any("low retention count" in f for f in findings)
    assert any("restore points < recommended" in f for f in findings)
    assert any("missing storage encryption" in f for f in findings)


def test_analyze_jobs_handles_string_and_missing_values():
    """Non-numeric / missing cells must not raise (the old code did)."""
    jobs = pd.DataFrame(
        [
            {
                "Name": "Bad",
                "RetentionCount": "lots",
                "RetainDaysToKeep": None,
                "StgEncryptionEnabled": None,
            }
        ]
    )
    vhc.HealthCheckResult()
    findings = vhc.analyze_jobs(jobs, None)  # must not raise
    assert any("low retention count" in f for f in findings)
    assert any("missing storage encryption" in f for f in findings)


def test_analyze_jobs_compliant_job_has_no_findings():
    jobs = pd.DataFrame(
        [
            {
                "Name": "Good",
                "RetentionCount": 30,
                "RetainDaysToKeep": 30,
                "StgEncryptionEnabled": True,
            }
        ]
    )
    vhc.HealthCheckResult()
    assert vhc.analyze_jobs(jobs, None) == []


def test_analyze_jobs_detects_failed_sessions():
    sessions = pd.DataFrame([{"JobName": "JobX", "Status": "Failed"}])
    vhc.HealthCheckResult()
    findings = vhc.analyze_jobs(None, sessions)
    assert any("JobX" in f for f in findings)


def test_analyze_security_skips_passed_and_blank():
    sec = pd.DataFrame(
        [
            {"Best Practice": "MFA is enabled", "Status": "Not Implemented"},
            {"Best Practice": "Cloud encrypted", "Status": "Passed"},
            {"Best Practice": "", "Status": "Not Implemented"},
        ]
    )
    vhc.HealthCheckResult()
    findings = vhc.analyze_security(sec)
    assert len(findings) == 1
    assert "MFA is enabled" in findings[0]


def test_analyze_repositories_flags_non_immutable():
    repos = pd.DataFrame([{"Name": "Pure", "IsImmutabilitySupported": False}])
    vhc.HealthCheckResult()
    findings = vhc.analyze_repositories(repos)
    assert any("does not support immutability" in f for f in findings)


def test_analyze_malware_flags_infected_and_handles_missing_column():
    malware = pd.DataFrame(
        [{"ObjectName": "YARA", "Status": "Infected", "DetectionTime": "now"}]
    )
    vhc.HealthCheckResult()
    assert len(vhc.analyze_malware(malware)) == 1
    # Missing 'Status' column must be tolerated.
    assert vhc.analyze_malware(pd.DataFrame([{"ObjectName": "x"}])) == []


def test_analyzers_return_empty_for_none():
    vhc.HealthCheckResult()
    assert vhc.analyze_security(None) == []
    assert vhc.analyze_repositories(None) == []
    assert vhc.analyze_malware(None) == []


# ------------------------------------
# Loaders / exception handling
# ------------------------------------


def test_safe_load_csv_missing_file(tmp_path):
    result = vhc.HealthCheckResult()
    assert vhc._safe_load_csv(tmp_path / "nope.csv", result) is None
    assert "nope.csv" in result.missing_files


def test_safe_load_csv_empty_file(tmp_path):
    p = tmp_path / "empty.csv"
    p.write_text("")
    result = vhc.HealthCheckResult()
    assert vhc._safe_load_csv(p, result) is None
    assert any("empty" in e for e in result.errors)


def test_safe_load_json_bad_structure(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps("just a string"))
    result = vhc.HealthCheckResult()
    assert vhc._safe_load_json(p, result) is None
    assert any("bad JSON structure" in e for e in result.errors)


def test_safe_load_json_malformed(tmp_path):
    p = tmp_path / "broken.json"
    p.write_text("{not valid json")
    result = vhc.HealthCheckResult()
    assert vhc._safe_load_json(p, result) is None
    assert result.errors


# ------------------------------------
# Enrichment
# ------------------------------------


def test_enrich_findings_maps_severity_and_dedupes():
    raw = [
        "Job 'Alpha' missing storage encryption.",
        "Job 'Alpha' missing storage encryption.",  # duplicate -> collapsed
    ]
    enriched = vhc.enrich_findings(raw)
    assert len(enriched) == 1
    assert enriched[0]["severity"] == "High"
    assert "Alpha" in enriched[0]["cmd"]


def test_enrich_findings_unknown_line_is_info():
    enriched = vhc.enrich_findings(["totally unrecognized finding"])
    assert enriched[0]["severity"] == "Info"
    assert enriched[0]["cmd"] == ""


def test_enrich_findings_refuses_injection_in_object_name():
    enriched = vhc.enrich_findings(["Job 'evil\x00name' missing storage encryption."])
    assert enriched[0]["cmd"].startswith("# REFUSED")


# ------------------------------------
# Artifact writers
# ------------------------------------


def test_write_powershell_adds_whatif_to_mutating(tmp_path):
    enriched = vhc.enrich_findings(["Job 'Alpha' missing storage encryption."])
    out = vhc.write_powershell_script(enriched, tmp_path / "fixit.ps1")
    text = out.read_text()
    assert "-WhatIf" in text


def test_write_ticket_payload_only_high_medium(tmp_path):
    enriched = vhc.enrich_findings(
        ["Job 'Alpha' missing storage encryption.", "unknown info-level line"]
    )
    out = vhc.write_ticket_payload(enriched, tmp_path / "tickets.json")
    payload = json.loads(out.read_text())
    assert len(payload) == 1
    assert payload[0]["severity"] == "High"


def test_write_markdown_creates_file(tmp_path):
    enriched = vhc.enrich_findings(["Job 'Alpha' missing storage encryption."])
    sections = {"Backup Jobs": ["Job 'Alpha' missing storage encryption."]}
    out = vhc.write_markdown(enriched, sections, tmp_path / "summary.md")
    assert out.exists()
    assert "Remediation Summary" in out.read_text()


# ------------------------------------
# Resilience wrappers in run_healthcheck
# ------------------------------------


def test_run_analyzer_isolates_failures():
    result = vhc.HealthCheckResult()

    def boom(_):
        raise ValueError("kaboom")

    assert vhc._run_analyzer("Boom", boom, result, None) == []
    assert any("Boom analysis failed" in e for e in result.errors)


def test_write_artifact_records_failure():
    result = vhc.HealthCheckResult()

    def boom(_):
        raise OSError("disk full")

    vhc._write_artifact(result, "markdown", boom, "x")
    assert "markdown" not in result.artifacts
    assert any("Failed to write markdown artifact" in e for e in result.errors)


# ------------------------------------
# Integration: full run
# ------------------------------------


def test_run_healthcheck_demo_end_to_end(tmp_path):
    out = vhc.run_healthcheck(
        output_dir=str(tmp_path), demo=True, verbose=False, write_artifacts=True
    )
    assert out["findings"], "demo data should yield findings"
    # Demo embeds malware + missing MFA + non-immutable repo + failed session.
    assert any("Malware" in f for f in out["findings"])
    assert (tmp_path / "remediation_summary.md").exists()
    assert (tmp_path / "fixit.ps1").exists()
    assert (tmp_path / "tickets.json").exists()


def test_run_healthcheck_missing_files_graceful(tmp_path):
    out = vhc.run_healthcheck(
        input_dir=str(tmp_path / "does-not-exist"),
        output_dir=str(tmp_path),
        demo=False,
        verbose=False,
        write_artifacts=True,
    )
    assert out["missing_files"], "should record missing input files"
    assert any("Graceful partial run" in e for e in out["errors"])


def test_run_healthcheck_no_artifacts_flag(tmp_path):
    out = vhc.run_healthcheck(
        output_dir=str(tmp_path), demo=True, verbose=False, write_artifacts=False
    )
    assert out["artifacts"] == {}
    assert not (tmp_path / "remediation_summary.md").exists()


def test_run_healthcheck_reads_csv_input(tmp_path):
    (tmp_path / "localhost_Jobs.csv").write_text(vhc.EMBEDDED_JOBS)
    out = vhc.run_healthcheck(
        input_dir=str(tmp_path),
        output_dir=str(tmp_path),
        demo=False,
        verbose=False,
        write_artifacts=False,
    )
    assert any(
        "retention" in f.lower() or "encryption" in f.lower() for f in out["findings"]
    )
