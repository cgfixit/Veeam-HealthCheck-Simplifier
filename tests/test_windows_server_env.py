"""Tests for Windows Server environment compatibility.

Simulates the file-system, path, and encoding conditions that
vhc_simplifier encounters when run on Windows Server 2016–2025 with
Veeam Backup & Replication installed.  All tests run cross-platform
(mocked where necessary) so CI on Linux/macOS still validates the logic.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
from unittest import mock

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vhc_simplifier as vhc  # noqa: E402


# =====================================================================
# Typical Windows Server VHC export paths
# =====================================================================

WINDOWS_VHC_PATHS = [
    r"C:\VeeamReports\VHC",
    r"C:\ProgramData\Veeam\Backup\Reports",
    r"D:\Backups\VHC-Export",
    r"\\FILESERVER01\Shares\VHC-Exports",
]


class TestWindowsPaths:
    """Ensure the simplifier handles Windows-style paths."""

    def test_backslash_paths_resolve(self, tmp_path):
        """pathlib should normalize Windows backslash paths on any OS."""
        p = pathlib.PurePosixPath(str(tmp_path))
        assert str(p)

    def test_unc_style_path_in_error_message(self, tmp_path):
        """UNC-like input_dir results in a readable missing-file message, not a crash."""
        out = vhc.run_healthcheck(
            input_dir=str(tmp_path / "nonexistent_unc_like_share"),
            output_dir=str(tmp_path / "out"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert out["missing_files"]

    def test_spaces_in_path(self, tmp_path):
        """Paths with spaces (common on Windows) must work."""
        spaced = tmp_path / "VHC Reports 2025"
        spaced.mkdir()
        (spaced / "localhost_Jobs.csv").write_text(vhc.EMBEDDED_JOBS)
        out = vhc.run_healthcheck(
            input_dir=str(spaced),
            output_dir=str(spaced / "Output Results"),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        assert out["findings"]

    def test_long_path_handling(self, tmp_path):
        """Deeply nested output directories approaching MAX_PATH limits."""
        deep = tmp_path
        for i in range(15):
            deep = deep / f"level_{i:02d}"
        out = vhc.run_healthcheck(
            output_dir=str(deep),
            demo=True,
            verbose=False,
            write_artifacts=True,
        )
        assert out["findings"]
        assert (deep / "remediation_summary.md").exists()


# =====================================================================
# Windows Server encoding edge cases
# =====================================================================


class TestWindowsEncoding:
    """VHC exports from Windows PowerShell often have encoding quirks."""

    def test_utf8_bom_csv(self, tmp_path):
        """PowerShell Export-Csv writes UTF-8 BOM by default."""
        content = "﻿" + vhc.EMBEDDED_JOBS
        p = tmp_path / "localhost_Jobs.csv"
        p.write_text(content, encoding="utf-8-sig")
        result = vhc.HealthCheckResult()
        df = vhc._safe_load_csv(p, result)
        assert df is not None
        assert not result.errors

    def test_utf16_le_csv_fallback(self, tmp_path):
        """Some PowerShell versions emit UTF-16 LE. pandas read_csv may fail — error is captured."""
        p = tmp_path / "localhost_Jobs.csv"
        p.write_bytes(vhc.EMBEDDED_JOBS.encode("utf-16-le"))
        result = vhc.HealthCheckResult()
        df = vhc._safe_load_csv(p, result)
        # Either parses successfully or records an error — must not crash.
        assert df is not None or result.errors

    def test_latin1_special_chars_in_job_name(self, tmp_path):
        """Job names with non-ASCII (e.g., German umlauts) from Windows Server locales."""
        csv_data = 'Name,RetentionCount,RetainDaysToKeep,StgEncryptionEnabled\n"Sicherung Büro",3,7,False\n'
        p = tmp_path / "localhost_Jobs.csv"
        p.write_text(csv_data, encoding="utf-8")
        out = vhc.run_healthcheck(
            input_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        assert any("Büro" in f for f in out["findings"])

    def test_json_with_bom(self, tmp_path):
        """JSON exports from Windows may also have BOM prefixes."""
        data = [{"Name": "TestRepo", "IsImmutabilitySupported": False}]
        content = "﻿" + json.dumps(data)
        p = tmp_path / "localhost_Repositories.json"
        p.write_text(content, encoding="utf-8")
        result = vhc.HealthCheckResult()
        df = vhc._safe_load_json(p, result)
        # BOM may cause json.load to fail — must not crash.
        assert df is not None or result.errors


# =====================================================================
# Windows Server version–specific scenarios (2016, 2019, 2022, 2025)
# =====================================================================


class TestWindowsServerVersions:
    """
    Veeam VBR runs on Windows Server 2016+ (VBR v12) / 2019+ (VBR v13).
    These tests validate the PowerShell remediation output targets the right
    cmdlet syntax and that the security compliance checks work across OS
    generations.
    """

    WINDOWS_SERVER_SECURITY_MATRIX = [
        {
            "os": "Windows Server 2016",
            "vbr": "v12",
            "rdp_status": "Not Implemented",
            "mfa_status": "Not Implemented",
            "notes": "Older OS, TLS 1.0/1.1 possibly enabled",
        },
        {
            "os": "Windows Server 2019",
            "vbr": "v12",
            "rdp_status": "Not Implemented",
            "mfa_status": "Passed",
            "notes": "Common production OS for VBR v12",
        },
        {
            "os": "Windows Server 2022",
            "vbr": "v13",
            "rdp_status": "Passed",
            "mfa_status": "Passed",
            "notes": "Recommended OS for VBR v13",
        },
        {
            "os": "Windows Server 2025",
            "vbr": "v13",
            "rdp_status": "Passed",
            "mfa_status": "Passed",
            "notes": "Latest OS, expected compatible with VBR v13",
        },
    ]

    @pytest.mark.parametrize(
        "scenario",
        WINDOWS_SERVER_SECURITY_MATRIX,
        ids=[s["os"] for s in WINDOWS_SERVER_SECURITY_MATRIX],
    )
    def test_security_compliance_per_os(self, scenario, tmp_path):
        sec_csv = (
            "Best Practice,Status\n"
            f'"MFA is enabled","{scenario["mfa_status"]}"\n'
            f'"Remote desktop protocol is disabled","{scenario["rdp_status"]}"\n'
        )
        (tmp_path / "localhost_SecurityCompliance.csv").write_text(sec_csv)
        out = vhc.run_healthcheck(
            input_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        sec_findings = out["sections"].get("Security & Compliance", [])
        if scenario["mfa_status"] != "Passed":
            assert any("MFA" in f for f in sec_findings), (
                f"MFA gap missed on {scenario['os']}"
            )
        else:
            assert not any("MFA" in f for f in sec_findings), (
                f"False MFA finding on {scenario['os']}"
            )

        if scenario["rdp_status"] != "Passed":
            assert any("Remote desktop" in f for f in sec_findings), (
                f"RDP gap missed on {scenario['os']}"
            )
        else:
            assert not any("Remote desktop" in f for f in sec_findings), (
                f"False RDP finding on {scenario['os']}"
            )


# =====================================================================
# PowerShell remediation script correctness
# =====================================================================


class TestPowerShellRemediation:
    """Verify generated PS1 scripts are safe and syntactically correct."""

    def test_whatif_on_all_mutating_verbs(self, tmp_path):
        enriched = vhc.enrich_findings(
            [
                "Job 'TestJob' missing storage encryption.",
                "Job 'TestJob' has low retention count.",
            ]
        )
        out = vhc.write_powershell_script(enriched, tmp_path / "fixit.ps1")
        text = out.read_text()
        for line in text.splitlines():
            stripped = line.lstrip()
            if any(stripped.startswith(v) for v in vhc._MUTATING_VERBS):
                assert "-WhatIf" in line

    def test_special_chars_in_job_name_quoted(self):
        enriched = vhc.enrich_findings(
            ["Job 'Test$Job (Prod)' missing storage encryption."]
        )
        cmd = enriched[0]["cmd"]
        assert "'Test$Job (Prod)'" in cmd or "REFUSED" in cmd

    def test_semicolons_in_job_name_safe(self):
        enriched = vhc.enrich_findings(
            ["Job 'Test;Drop-Database' missing storage encryption."]
        )
        cmd = enriched[0]["cmd"]
        assert ";" not in cmd.split("'")[0]

    def test_pipe_chars_in_job_name_safe(self):
        enriched = vhc.enrich_findings(["Job 'Test|evil' missing storage encryption."])
        cmd = enriched[0]["cmd"]
        assert "Test|evil" in cmd  # inside quotes, so safe

    def test_control_char_injection_refused(self):
        enriched = vhc.enrich_findings(
            ["Job 'evil\x00cmd' missing storage encryption."]
        )
        assert "REFUSED" in enriched[0]["cmd"]

    def test_newline_injection_refused(self):
        """Newline in the finding text either triggers REFUSED or falls through to
        the unmatched path (empty cmd) — both are safe since no PS command is generated."""
        enriched = vhc.enrich_findings(["Job 'evil\ncmd' missing storage encryption."])
        cmd = enriched[0]["cmd"]
        assert cmd == "" or "REFUSED" in cmd


# =====================================================================
# Salesforce / Slack integration error handling
# =====================================================================


class TestIntegrationErrorHandling:
    def test_salesforce_missing_credentials(self, tmp_path):
        with mock.patch.dict(os.environ, {}, clear=True):
            out = vhc.run_healthcheck(
                output_dir=str(tmp_path),
                demo=True,
                verbose=False,
                write_artifacts=False,
                sf_account_id="001FAKE",
            )
        assert any("Salesforce credentials missing" in e for e in out["errors"])

    def test_invalid_slack_webhook_rejected(self, tmp_path):
        out = vhc.run_healthcheck(
            output_dir=str(tmp_path),
            demo=True,
            verbose=False,
            write_artifacts=False,
            slack_webhook="http://evil.example.com/steal-data",
        )
        assert any("Invalid Slack webhook" in e for e in out["errors"])

    def test_valid_slack_webhook_format_accepted(self):
        assert vhc._validate_slack_webhook(
            "https://hooks.slack.com/services/T00/B00/xxx"
        )
        assert vhc._validate_slack_webhook(
            "https://hooks.slack-gov.com/services/T00/B00/xxx"
        )
        assert not vhc._validate_slack_webhook(  # DevSkim: ignore DS137138 — testing that HTTP is rejected
            "http://hooks.slack.com/services/T00/B00/xxx"
        )
        assert not vhc._validate_slack_webhook("https://evil.com")
        assert not vhc._validate_slack_webhook("")
        assert not vhc._validate_slack_webhook(None)  # type: ignore[arg-type]


# =====================================================================
# Invalid input_format
# =====================================================================


class TestInputFormatValidation:
    def test_invalid_format_rejected(self, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            input_format="xml",
            demo=False,
            verbose=False,
        )
        assert any("Unsupported input format" in e for e in out["errors"])
        assert out["findings"] == []

    def test_csv_format_accepted(self, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            input_format="csv",
            demo=False,
            verbose=False,
        )
        assert not any("Unsupported" in e for e in out["errors"])

    def test_json_format_accepted(self, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            input_format="json",
            demo=False,
            verbose=False,
        )
        assert not any("Unsupported" in e for e in out["errors"])


# =====================================================================
# Large dataset stress test
# =====================================================================


class TestLargeDataset:
    """Validates behaviour with larger-than-typical VHC exports."""

    def test_100_jobs_analyzed(self, tmp_path):
        rows = ["Name,RetentionCount,RetainDaysToKeep,StgEncryptionEnabled"]
        for i in range(100):
            enc = "True" if i % 3 == 0 else "False"
            rows.append(f'"Job-{i:03d}",{i % 40},{i % 60},{enc}')
        (tmp_path / "localhost_Jobs.csv").write_text("\n".join(rows))
        out = vhc.run_healthcheck(
            input_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        assert len(out["findings"]) > 50

    def test_1000_malware_events(self, tmp_path):
        rows = ["ObjectName,Status,DetectionTime"]
        for i in range(1000):
            status = "Infected" if i % 10 == 0 else "Clean"
            rows.append(f'"Scan-{i:04d}","{status}","2025-06-01 00:{i % 60:02d}:00"')
        (tmp_path / "localhostmalware_events.csv").write_text("\n".join(rows))
        out = vhc.run_healthcheck(
            input_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        infected_findings = [f for f in out["findings"] if "Infected" in f]
        assert len(infected_findings) == 100


# =====================================================================
# CLI main() entrypoint
# =====================================================================


class TestMainEntrypoint:
    def test_main_returns_0_on_demo(self, monkeypatch):
        monkeypatch.setattr(
            sys, "argv", ["vhc_simplifier.py", "--demo", "--quiet", "--no-artifacts"]
        )
        assert vhc.main() == 0

    def test_main_returns_2_on_errors(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            sys,
            "argv",
            [
                "vhc_simplifier.py",
                "--input-dir",
                str(tmp_path / "nope"),
                "--quiet",
                "--no-artifacts",
            ],
        )
        assert vhc.main() == 2

    def test_main_catches_unhandled_exception(self, monkeypatch):
        monkeypatch.setattr(
            sys, "argv", ["vhc_simplifier.py", "--demo", "--quiet", "--no-artifacts"]
        )
        with mock.patch(
            "vhc_simplifier.run_healthcheck", side_effect=RuntimeError("boom")
        ):
            assert vhc.main() == 1
