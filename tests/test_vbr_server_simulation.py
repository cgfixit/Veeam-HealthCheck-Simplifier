"""VBR server simulation tests for v12.3.2 and v13.

Uses the shared conftest.py fixtures to simulate realistic VBR health-check
exports (CSV and JSON) as produced by https://vee.am/vhc2 on Windows Server
hosts running Veeam Backup & Replication v12.3.2 (build 12.3.2.4643)
and v13 (latest).

These tests validate the full analysis pipeline — loader → analyzer →
enrichment → artifact generation — against each version's export schema
and quirks.
"""

from __future__ import annotations

import json
import pathlib
import sys
from unittest import mock

import pandas as pd

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vhc_simplifier as vhc  # noqa: E402

# =====================================================================
# VBR v12.3.2 — full pipeline (CSV)
# =====================================================================


class TestVBRv12SimulationCSV:
    """Simulate running VHC on a VBR v12.3.2 server with CSV exports."""

    def test_full_pipeline_produces_findings(self, vbr_v12_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        assert out["findings"], "v12 data must produce findings"

    def test_all_sections_populated(self, vbr_v12_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        for section in (
            "Backup Jobs",
            "Security & Compliance",
            "Repositories",
            "Malware Events",
        ):
            assert section in out["sections"], f"Missing section: {section}"

    def test_unencrypted_jobs_flagged(self, vbr_v12_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert any("SQL-Cluster-PROD" in f and "encryption" in f for f in out["findings"])
        assert any("FileServer-Weekly-GFS" in f and "encryption" in f for f in out["findings"])

    def test_low_retention_detected(self, vbr_v12_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert any("FileServer-Weekly-GFS" in f and "low retention" in f for f in out["findings"])
        assert any("Tape Archive - Monthly" in f and "low retention" in f for f in out["findings"])

    def test_failed_sessions_detected(self, vbr_v12_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert any("SQL-Cluster-PROD" in f and "failure" in f for f in out["findings"])
        assert any("Tape Archive - Monthly" in f and "failure" in f for f in out["findings"])
        assert any("Exchange-DAG-Backup" in f and "failure" in f for f in out["findings"])

    def test_security_gaps_identified(self, vbr_v12_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        sec = out["sections"]["Security & Compliance"]
        assert any("MFA" in f for f in sec)
        assert any("Remote desktop" in f for f in sec)
        assert any("Linux hardened" in f for f in sec)
        assert any("Immutability" in f for f in sec)

    def test_immutability_findings(self, vbr_v12_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        repo_findings = out["sections"]["Repositories"]
        assert any("Default Backup Repository" in f for f in repo_findings)
        assert any("NAS Share" in f for f in repo_findings)
        assert not any("Hardened Linux" in f for f in repo_findings)
        assert not any("S3 Object Lock" in f for f in repo_findings)

    def test_malware_events_flagged(self, vbr_v12_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        malware = out["sections"]["Malware Events"]
        assert any("YARA" in f and "Infected" in f for f in malware)
        assert any("PortScan" in f and "Infected" in f for f in malware)
        assert any("Entropy" in f and "Suspicious" in f for f in malware)
        assert len(malware) == 3

    def test_clean_events_not_flagged(self, vbr_v12_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        malware = out["sections"]["Malware Events"]
        assert not any("InlineScan" in f for f in malware)

    def test_compliant_jobs_not_flagged(self, vbr_v12_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        jobs = out["sections"]["Backup Jobs"]
        assert not any(
            "DC01 - Domain Controllers" in f and ("encryption" in f or "low retention" in f) for f in jobs
        )
        assert not any(
            "Oracle-DB-Critical" in f and ("encryption" in f or "low retention" in f) for f in jobs
        )

    def test_artifacts_generated(self, vbr_v12_csv_dir, tmp_path):
        vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        assert (tmp_path / "remediation_summary.md").exists()
        assert (tmp_path / "fixit.ps1").exists()
        assert (tmp_path / "tickets.json").exists()

    def test_enriched_has_all_severities(self, vbr_v12_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        severities = {e["severity"] for e in out["enriched"]}
        assert "High" in severities
        assert "Medium" in severities

    def test_powershell_contains_veeam_cmdlets(self, vbr_v12_csv_dir, tmp_path):
        vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        ps_text = (tmp_path / "fixit.ps1").read_text()
        assert "Set-VBRJobAdvancedStorageOptions" in ps_text or "Get-VBRBackupSession" in ps_text

    def test_no_errors_on_clean_data(self, vbr_v12_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        assert not out["errors"]
        assert not out["missing_files"]


# =====================================================================
# VBR v12.3.2 — JSON format
# =====================================================================


class TestVBRv12SimulationJSON:
    """Same v12 data loaded as JSON — matches what VHC produces with ConvertTo-Json."""

    def test_json_pipeline_produces_findings(self, vbr_v12_json_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_json_dir),
            output_dir=str(tmp_path),
            input_format="json",
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        assert out["findings"]

    def test_json_csv_parity(self, vbr_v12_csv_dir, vbr_v12_json_dir, tmp_path):
        """CSV and JSON loaders must produce the same findings for identical data."""
        csv_out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path / "csv_out"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        json_out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_json_dir),
            output_dir=str(tmp_path / "json_out"),
            input_format="json",
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert sorted(csv_out["findings"]) == sorted(json_out["findings"])

    def test_json_no_errors(self, vbr_v12_json_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_json_dir),
            output_dir=str(tmp_path),
            input_format="json",
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert not out["errors"]


# =====================================================================
# VBR v13 — full pipeline (CSV)
# =====================================================================


class TestVBRv13SimulationCSV:
    """Simulate running VHC on a VBR v13 server with CSV exports."""

    def test_full_pipeline_produces_findings(self, vbr_v13_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        assert out["findings"]

    def test_extra_columns_tolerated(self, vbr_v13_csv_dir, tmp_path):
        """v13 adds ObjectStorageTier, BackupCopyEnabled, etc. — must not crash."""
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert not out["errors"]

    def test_v13_specific_security_findings(self, vbr_v13_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        sec = out["sections"]["Security & Compliance"]
        assert any("Four-eyes" in f for f in sec)
        assert any("gMSA" in f for f in sec)

    def test_v13_kubernetes_job_analyzed(self, vbr_v13_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        jobs = out["sections"]["Backup Jobs"]
        assert not any("Kubernetes-Cluster-01" in f and "encryption" in f for f in jobs), (
            "K8s job has encryption enabled — should not be flagged"
        )

    def test_v13_m365_job_analyzed(self, vbr_v13_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        jobs = out["sections"]["Backup Jobs"]
        assert not any("M365-Exchange-Online" in f and "encryption" in f for f in jobs), (
            "M365 job has encryption — should not be flagged"
        )

    def test_v13_cdp_job_zero_retention(self, vbr_v13_csv_dir, tmp_path):
        """CDP jobs have 0 retention (continuous) — flagged as low retention."""
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        jobs = out["sections"]["Backup Jobs"]
        assert any("CDP-VMware-Critical" in f and "low retention" in f for f in jobs)

    def test_v13_failed_sessions_with_retries(self, vbr_v13_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert any("SQL-Cluster-PROD" in f and "failure" in f for f in out["findings"])
        assert any("NAS-SMB-DFS" in f and "failure" in f for f in out["findings"])
        assert any("Azure-VM-Backup" in f and "failure" in f for f in out["findings"])

    def test_v13_ml_malware_detection(self, vbr_v13_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        malware = out["sections"]["Malware Events"]
        assert any("AI-Anomaly" in f and "Suspicious" in f for f in malware)
        assert any("Entropy" in f and "Suspicious" in f for f in malware)

    def test_v13_azure_blob_immutable_not_flagged(self, vbr_v13_csv_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        repos = out["sections"]["Repositories"]
        assert not any("Azure Blob Immutable" in f for f in repos)
        assert not any("MinIO Immutable" in f for f in repos)

    def test_v13_artifacts_generated(self, vbr_v13_csv_dir, tmp_path):
        vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        assert (tmp_path / "remediation_summary.md").exists()
        assert (tmp_path / "fixit.ps1").exists()
        assert (tmp_path / "tickets.json").exists()

    def test_v13_ticket_payload_correct(self, vbr_v13_csv_dir, tmp_path):
        vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        payload = json.loads((tmp_path / "tickets.json").read_text())
        assert all(t["severity"] in ("High", "Medium") for t in payload)
        assert all("short_description" in t for t in payload)


# =====================================================================
# VBR v13 — JSON format
# =====================================================================


class TestVBRv13SimulationJSON:
    def test_json_pipeline_produces_findings(self, vbr_v13_json_dir, tmp_path):
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v13_json_dir),
            output_dir=str(tmp_path),
            input_format="json",
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        assert out["findings"]

    def test_json_csv_parity(self, vbr_v13_csv_dir, vbr_v13_json_dir, tmp_path):
        csv_out = vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path / "csv_out"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        json_out = vhc.run_healthcheck(
            input_dir=str(vbr_v13_json_dir),
            output_dir=str(tmp_path / "json_out"),
            input_format="json",
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert sorted(csv_out["findings"]) == sorted(json_out["findings"])


# =====================================================================
# Cross-version comparison
# =====================================================================


class TestCrossVersionComparison:
    """Compare v12 and v13 pipeline behavior to catch regressions."""

    def test_v12_v13_both_produce_findings(self, vbr_v12_csv_dir, vbr_v13_csv_dir, tmp_path):
        v12 = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path / "v12"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        v13 = vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path / "v13"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert v12["findings"]
        assert v13["findings"]

    def test_v12_v13_same_section_keys(self, vbr_v12_csv_dir, vbr_v13_csv_dir, tmp_path):
        v12 = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path / "v12"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        v13 = vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path / "v13"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert set(v12["sections"].keys()) == set(v13["sections"].keys())

    def test_v13_has_more_security_findings(self, vbr_v12_csv_dir, vbr_v13_csv_dir, tmp_path):
        """v13 adds Four-eyes and gMSA checks — should have more security findings."""
        v12 = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path / "v12"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        v13 = vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path / "v13"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        v12_sec = len(v12["sections"]["Security & Compliance"])
        v13_sec = len(v13["sections"]["Security & Compliance"])
        assert v13_sec >= v12_sec

    def test_neither_version_has_errors(self, vbr_v12_csv_dir, vbr_v13_csv_dir, tmp_path):
        for label, d in [("v12", vbr_v12_csv_dir), ("v13", vbr_v13_csv_dir)]:
            out = vhc.run_healthcheck(
                input_dir=str(d),
                output_dir=str(tmp_path / label),
                demo=False,
                verbose=False,
                write_artifacts=True,
            )
            assert not out["errors"], f"{label} produced unexpected errors: {out['errors']}"
            assert not out["missing_files"], f"{label} had missing files: {out['missing_files']}"


# =====================================================================
# Edge cases: partial / corrupted VBR exports
# =====================================================================


class TestPartialExports:
    """Simulate common real-world export failures."""

    def test_only_jobs_file_present(self, vbr_v12_csv_dir, tmp_path):
        """VHC sometimes fails mid-export — only some files are written."""
        partial = tmp_path / "partial"
        partial.mkdir()
        import shutil

        shutil.copy(vbr_v12_csv_dir / "localhost_Jobs.csv", partial / "localhost_Jobs.csv")
        out = vhc.run_healthcheck(
            input_dir=str(partial),
            output_dir=str(tmp_path / "out"),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        assert out["findings"], "job findings should still work"
        assert len(out["missing_files"]) == 4

    def test_empty_csv_files(self, tmp_path):
        """All expected files present but empty (0 bytes)."""
        d = tmp_path / "empty"
        d.mkdir()
        for base in vhc.EXPECTED_BASENAMES.values():
            (d / f"{base}.csv").write_text("")
        out = vhc.run_healthcheck(
            input_dir=str(d),
            output_dir=str(tmp_path / "out"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert any("empty" in e for e in out["errors"])

    def test_header_only_csv_files(self, tmp_path):
        """Files with headers but no data rows — should produce zero findings."""
        d = tmp_path / "headers"
        d.mkdir()
        (d / "localhost_Jobs.csv").write_text("Name,RetentionCount,RetainDaysToKeep,StgEncryptionEnabled\n")
        (d / "VeeamSessionReport.csv").write_text("JobName,Status\n")
        (d / "localhost_SecurityCompliance.csv").write_text("Best Practice,Status\n")
        (d / "localhost_Repositories.csv").write_text("Name,IsImmutabilitySupported\n")
        (d / "localhostmalware_events.csv").write_text("ObjectName,Status,DetectionTime\n")
        out = vhc.run_healthcheck(
            input_dir=str(d),
            output_dir=str(tmp_path / "out"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert out["findings"] == []

    def test_corrupted_csv_file(self, tmp_path):
        """One file is binary garbage — others should still be processed."""
        d = tmp_path / "corrupt"
        d.mkdir()
        (d / "localhost_Jobs.csv").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        (d / "localhost_Repositories.csv").write_text('Name,IsImmutabilitySupported\n"TestRepo",False\n')
        out = vhc.run_healthcheck(
            input_dir=str(d),
            output_dir=str(tmp_path / "out"),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        assert any("TestRepo" in f for f in out["findings"])
        assert out["errors"] or out["missing_files"]

    def test_json_with_extra_nesting(self, tmp_path):
        """JSON export with unexpected extra nesting level."""
        d = tmp_path / "nested"
        d.mkdir()
        data = {"data": [{"Name": "Repo1", "IsImmutabilitySupported": False}]}
        wrapped = {"result": data}
        (d / "localhost_Repositories.json").write_text(json.dumps(wrapped))
        result = vhc.HealthCheckResult()
        df = vhc._safe_load_json(d / "localhost_Repositories.json", result)
        assert df is not None or not result.errors


# =====================================================================
# Encoding edge cases specific to VHC exports
# =====================================================================


class TestVHCEncodingEdgeCases:
    def test_utf8_bom_in_all_csvs(self, vbr_v12_csv_dir, tmp_path):
        """PowerShell Export-Csv often writes UTF-8 BOM — must not break any file."""
        for csv_file in vbr_v12_csv_dir.glob("*.csv"):
            content = csv_file.read_text(encoding="utf-8")
            csv_file.write_text("﻿" + content, encoding="utf-8-sig")
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert out["findings"], "BOM-prefixed files should still produce findings"

    def test_crlf_line_endings(self, vbr_v13_csv_dir, tmp_path):
        """Windows CRLF line endings in all export files."""
        for csv_file in vbr_v13_csv_dir.glob("*.csv"):
            content = csv_file.read_text()
            csv_file.write_text(content.replace("\n", "\r\n"))
        out = vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert out["findings"]

    def test_unicode_job_names(self, tmp_path):
        """VBR installations with non-ASCII job names (German, Japanese, etc.)."""
        csv_data = (
            "Name,RetentionCount,RetainDaysToKeep,StgEncryptionEnabled\n"
            '"Sicherung Büro-Nürnberg",3,7,False\n'
            '"バックアップ-東京",5,14,True\n'
        )
        d = tmp_path / "unicode"
        d.mkdir()
        (d / "localhost_Jobs.csv").write_text(csv_data, encoding="utf-8")
        out = vhc.run_healthcheck(
            input_dir=str(d),
            output_dir=str(tmp_path / "out"),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        assert any("Büro" in f or "Nürnberg" in f for f in out["findings"])


# =====================================================================
# Analyzer isolation: one failing section must not abort others
# =====================================================================


class TestAnalyzerIsolation:
    def test_jobs_analyzer_failure_does_not_block_others(self, vbr_v12_csv_dir, tmp_path):
        with mock.patch("vhc_simplifier.analyze_jobs", side_effect=RuntimeError("boom")):
            out = vhc.run_healthcheck(
                input_dir=str(vbr_v12_csv_dir),
                output_dir=str(tmp_path),
                demo=False,
                verbose=False,
                write_artifacts=False,
            )
        assert any("Backup Jobs analysis failed" in e for e in out["errors"])
        assert out["sections"]["Repositories"]
        assert out["sections"]["Malware Events"]

    def test_security_analyzer_failure_isolated(self, vbr_v13_csv_dir, tmp_path):
        with mock.patch("vhc_simplifier.analyze_security", side_effect=ValueError("bad")):
            out = vhc.run_healthcheck(
                input_dir=str(vbr_v13_csv_dir),
                output_dir=str(tmp_path),
                demo=False,
                verbose=False,
                write_artifacts=False,
            )
        assert any("Security" in e and "failed" in e for e in out["errors"])
        assert out["sections"]["Backup Jobs"]

    def test_malware_analyzer_failure_isolated(self, vbr_v12_csv_dir, tmp_path):
        with mock.patch("vhc_simplifier.analyze_malware", side_effect=TypeError("oops")):
            out = vhc.run_healthcheck(
                input_dir=str(vbr_v12_csv_dir),
                output_dir=str(tmp_path),
                demo=False,
                verbose=False,
                write_artifacts=False,
            )
        assert any("Malware" in e and "failed" in e for e in out["errors"])
        assert out["sections"]["Backup Jobs"]
        assert out["sections"]["Security & Compliance"]


# =====================================================================
# Artifact write failures
# =====================================================================


class TestArtifactWriteFailures:
    def test_readonly_output_dir_captures_errors(self, vbr_v12_csv_dir, tmp_path):
        """If output directory is unwritable, errors are captured not raised."""
        with mock.patch("vhc_simplifier.write_markdown", side_effect=PermissionError("denied")):
            out = vhc.run_healthcheck(
                input_dir=str(vbr_v12_csv_dir),
                output_dir=str(tmp_path),
                demo=False,
                verbose=False,
                write_artifacts=True,
            )
        assert any("Failed to write markdown" in e for e in out["errors"])
        assert out["findings"], "findings should still be present"

    def test_ps1_write_failure_isolated(self, vbr_v13_csv_dir, tmp_path):
        with mock.patch("vhc_simplifier.write_powershell_script", side_effect=OSError("full")):
            out = vhc.run_healthcheck(
                input_dir=str(vbr_v13_csv_dir),
                output_dir=str(tmp_path),
                demo=False,
                verbose=False,
                write_artifacts=True,
            )
        assert any("powershell" in e and "Failed" in e for e in out["errors"])


# =====================================================================
# Console output validation
# =====================================================================


class TestConsoleOutput:
    def test_verbose_mode_prints_sections(self, vbr_v12_csv_dir, tmp_path, capsys):
        vhc.run_healthcheck(
            input_dir=str(vbr_v12_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=True,
            write_artifacts=False,
        )
        captured = capsys.readouterr()
        assert "Backup Jobs" in captured.out
        assert "Security & Compliance" in captured.out
        assert "Repositories" in captured.out
        assert "Malware Events" in captured.out

    def test_quiet_mode_no_output(self, vbr_v13_csv_dir, tmp_path, capsys):
        vhc.run_healthcheck(
            input_dir=str(vbr_v13_csv_dir),
            output_dir=str(tmp_path),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        captured = capsys.readouterr()
        assert captured.out == ""


# =====================================================================
# Direct analyzer tests using conftest fixtures
# =====================================================================


class TestDirectAnalyzersV12:
    """Test analyzers directly with conftest-generated DataFrames."""

    def test_analyze_jobs_v12(self, vbr_v12_csv_dir):
        jobs = pd.read_csv(vbr_v12_csv_dir / "localhost_Jobs.csv")
        sessions = pd.read_csv(vbr_v12_csv_dir / "VeeamSessionReport.csv")
        findings = vhc.analyze_jobs(jobs, sessions)
        assert len(findings) > 0
        encryption_findings = [f for f in findings if "encryption" in f]
        retention_findings = [f for f in findings if "retention" in f.lower() or "restore points" in f]
        failure_findings = [f for f in findings if "failure" in f]
        assert len(encryption_findings) >= 3
        assert len(retention_findings) >= 2
        assert len(failure_findings) >= 2

    def test_analyze_security_v12(self, vbr_v12_csv_dir):
        sec = pd.read_csv(vbr_v12_csv_dir / "localhost_SecurityCompliance.csv")
        findings = vhc.analyze_security(sec)
        assert len(findings) >= 4
        assert not any("Passed" in f and "NOT implemented" not in f for f in findings)

    def test_analyze_repos_v12(self, vbr_v12_csv_dir):
        repos = pd.read_csv(vbr_v12_csv_dir / "localhost_Repositories.csv")
        findings = vhc.analyze_repositories(repos)
        non_immutable = [
            "Default Backup Repository",
            "NAS Share",
            "Exagrid",
            "Dell DataDomain",
            "ReFS Repo",
        ]
        for name in non_immutable:
            assert any(name in f for f in findings), f"{name} should be flagged"

    def test_analyze_malware_v12(self, vbr_v12_csv_dir):
        malware = pd.read_csv(vbr_v12_csv_dir / "localhostmalware_events.csv")
        findings = vhc.analyze_malware(malware)
        assert len(findings) == 3


class TestDirectAnalyzersV13:
    def test_analyze_jobs_v13(self, vbr_v13_csv_dir):
        jobs = pd.read_csv(vbr_v13_csv_dir / "localhost_Jobs.csv")
        sessions = pd.read_csv(vbr_v13_csv_dir / "VeeamSessionReport.csv")
        findings = vhc.analyze_jobs(jobs, sessions)
        assert len(findings) > 0

    def test_analyze_security_v13(self, vbr_v13_csv_dir):
        sec = pd.read_csv(vbr_v13_csv_dir / "localhost_SecurityCompliance.csv")
        findings = vhc.analyze_security(sec)
        assert any("Four-eyes" in f for f in findings)
        assert any("gMSA" in f for f in findings)

    def test_analyze_repos_v13(self, vbr_v13_csv_dir):
        repos = pd.read_csv(vbr_v13_csv_dir / "localhost_Repositories.csv")
        findings = vhc.analyze_repositories(repos)
        assert any("Default Backup Repository" in f for f in findings)
        assert any("NAS Share" in f for f in findings)
        assert not any("Hardened Linux" in f for f in findings)
        assert not any("S3 Object Lock" in f for f in findings)
        assert not any("Azure Blob" in f for f in findings)

    def test_analyze_malware_v13(self, vbr_v13_csv_dir):
        malware = pd.read_csv(vbr_v13_csv_dir / "localhostmalware_events.csv")
        findings = vhc.analyze_malware(malware)
        assert len(findings) == 3
        assert any("YARA" in f for f in findings)
        assert any("AI-Anomaly" in f for f in findings)
        assert any("Entropy" in f for f in findings)
