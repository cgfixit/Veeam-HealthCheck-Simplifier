"""Mock Veeam Backup & Replication environment tests.

Simulates realistic VBR v12 and v13 health-check export shapes (CSV/JSON) that
the simplifier would encounter in production, and validates that analysis,
enrichment, and artifact generation behave correctly against each version's
quirks.

These tests run on any OS — no actual Veeam installation is required.
"""

from __future__ import annotations

import io
import json
import pathlib
import sys

import pandas as pd
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vhc_simplifier as vhc  # noqa: E402

# =====================================================================
# Realistic VBR v12 export fixtures
# =====================================================================

VBR12_JOBS_CSV = """\
Name,RetentionCount,RetainDaysToKeep,StgEncryptionEnabled
"DC01 - Daily Backup",30,30,True
"SQL-Cluster Backup",7,14,False
"File Server - Weekly",4,7,False
"VMware - Prod (Hyper-V)",14,30,True
"Archive to Tape",3,365,False
"""

VBR12_SESSIONS_CSV = """\
JobName,Status
"DC01 - Daily Backup",Success
"SQL-Cluster Backup",Failed
"File Server - Weekly",Warning
"VMware - Prod (Hyper-V)",Success
"Archive to Tape",Failed
"""

VBR12_SECURITY_CSV = """\
Best Practice,Status
"MFA is enabled for the backup console","Not Implemented"
"Configuration backup is encrypted","Passed"
"Traffic encryption is enabled","Passed"
"Remote desktop protocol is disabled on the VBR server","Not Implemented"
"Backup jobs to cloud repositories is encrypted","Not Implemented"
"Linux hardened repositories are used","Not Implemented"
"Password loss protection is enabled","Unable to detect"
"Immutability is set for all backup jobs","Not Implemented"
"""

VBR12_REPOS_CSV = """\
Name,IsImmutabilitySupported
"Default Backup Repository",False
"Hardened Linux Repo",True
"S3 Object Lock Bucket",True
"NAS Share (CIFS)",False
"Exagrid Appliance",False
"""

VBR12_MALWARE_CSV = """\
ObjectName,Status,DetectionTime
"YARA Rule Match","Infected","2025-04-28 16:37:01"
"InlineScan-VM01","Clean","2025-05-01 08:00:00"
"InlineScan-DC01","Clean","2025-05-01 08:00:12"
"PortScan-SQL01","Infected","2025-04-28 16:36:43"
"Entropy-FS01","Suspicious","2025-05-21 17:19:49"
"""


# =====================================================================
# Realistic VBR v13 export fixtures — adds columns absent in v12
# =====================================================================

VBR13_JOBS_CSV = """\
Name,RetentionCount,RetainDaysToKeep,StgEncryptionEnabled,ObjectStorageTier,BackupCopyEnabled
"DC01 - Daily Backup",30,30,True,"Archive",True
"SQL-Cluster Backup",7,14,False,"Performance",False
"Kubernetes Backup",30,30,True,"Performance",True
"SaaS - M365 Backup",14,30,True,"Archive",True
"NAS Backup - SMB",5,14,False,"",False
"""

VBR13_SESSIONS_CSV = """\
JobName,Status,RetryCount,BottleneckType
"DC01 - Daily Backup",Success,0,"None"
"SQL-Cluster Backup",Failed,3,"Source"
"Kubernetes Backup",Success,0,"None"
"SaaS - M365 Backup",Warning,1,"Network"
"NAS Backup - SMB",Failed,2,"Target"
"""

VBR13_SECURITY_CSV = """\
Best Practice,Status
"MFA is enabled for the backup console","Passed"
"Configuration backup is encrypted","Passed"
"Traffic encryption is enabled","Passed"
"Remote desktop protocol is disabled on the VBR server","Not Implemented"
"Backup jobs to cloud repositories is encrypted","Passed"
"Linux hardened repositories are used","Not Implemented"
"Immutability is set for all backup jobs","Not Implemented"
"Four-eyes authorization is enabled","Not Implemented"
"""

VBR13_REPOS_CSV = """\
Name,IsImmutabilitySupported,CapacityGB,FreeGB
"Default Backup Repository",False,2048,512
"Hardened Linux Repo",True,4096,3200
"S3 Object Lock Bucket",True,0,0
"Azure Blob Immutable",True,10240,9000
"NAS Share (CIFS)",False,1024,128
"""

VBR13_MALWARE_CSV = """\
ObjectName,Status,DetectionTime,ScanEngine
"YARA Rule Match","Infected","2025-04-28 16:37:01","Inline"
"InlineScan-VM01","Clean","2025-05-01 08:00:00","Inline"
"AI-Anomaly-DC01","Suspicious","2025-06-10 03:14:00","ML"
"""


def _write_vbr_csvs(tmp_path: pathlib.Path, version: str) -> pathlib.Path:
    """Write a full set of mock VBR export CSVs into a temp directory."""
    data = {
        "localhost_Jobs.csv": VBR12_JOBS_CSV if version == "v12" else VBR13_JOBS_CSV,
        "VeeamSessionReport.csv": VBR12_SESSIONS_CSV if version == "v12" else VBR13_SESSIONS_CSV,
        "localhost_SecurityCompliance.csv": VBR12_SECURITY_CSV if version == "v12" else VBR13_SECURITY_CSV,
        "localhost_Repositories.csv": VBR12_REPOS_CSV if version == "v12" else VBR13_REPOS_CSV,
        "localhostmalware_events.csv": VBR12_MALWARE_CSV if version == "v12" else VBR13_MALWARE_CSV,
    }
    for name, content in data.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    return tmp_path


def _write_vbr_json(tmp_path: pathlib.Path, version: str) -> pathlib.Path:
    """Write JSON equivalents of VBR exports (wrapped as {"data": [...]})."""
    csv_map = {
        "localhost_Jobs": VBR12_JOBS_CSV if version == "v12" else VBR13_JOBS_CSV,
        "VeeamSessionReport": VBR12_SESSIONS_CSV if version == "v12" else VBR13_SESSIONS_CSV,
        "localhost_SecurityCompliance": VBR12_SECURITY_CSV if version == "v12" else VBR13_SECURITY_CSV,
        "localhost_Repositories": VBR12_REPOS_CSV if version == "v12" else VBR13_REPOS_CSV,
        "localhostmalware_events": VBR12_MALWARE_CSV if version == "v12" else VBR13_MALWARE_CSV,
    }
    for base, csv_text in csv_map.items():
        df = pd.read_csv(io.StringIO(csv_text))
        records = df.to_dict(orient="records")
        (tmp_path / f"{base}.json").write_text(
            json.dumps({"data": records}, indent=2, default=str), encoding="utf-8"
        )
    return tmp_path


# =====================================================================
# VBR v12 tests
# =====================================================================


class TestVBRv12CSV:
    """Full analysis pipeline against mock VBR v12 CSV exports."""

    @pytest.fixture()
    def v12_result(self, tmp_path):
        _write_vbr_csvs(tmp_path, "v12")
        return vhc.run_healthcheck(
            input_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )

    def test_detects_unencrypted_jobs(self, v12_result):
        assert any("SQL-Cluster Backup" in f and "encryption" in f for f in v12_result["findings"])
        assert any("File Server - Weekly" in f and "encryption" in f for f in v12_result["findings"])
        assert any("Archive to Tape" in f and "encryption" in f for f in v12_result["findings"])

    def test_detects_low_retention(self, v12_result):
        assert any("File Server - Weekly" in f and "low retention" in f for f in v12_result["findings"])
        assert any("Archive to Tape" in f and "low retention" in f for f in v12_result["findings"])

    def test_detects_failed_sessions(self, v12_result):
        assert any("SQL-Cluster Backup" in f and "failure" in f for f in v12_result["findings"])
        assert any("Archive to Tape" in f and "failure" in f for f in v12_result["findings"])

    def test_detects_security_gaps(self, v12_result):
        findings_text = " ".join(v12_result["findings"])
        assert "MFA" in findings_text
        assert "Remote desktop" in findings_text or "RDP" in findings_text.upper()

    def test_detects_non_immutable_repos(self, v12_result):
        assert any("Default Backup Repository" in f and "immutability" in f for f in v12_result["findings"])
        assert any("NAS Share" in f and "immutability" in f for f in v12_result["findings"])

    def test_detects_malware_events(self, v12_result):
        assert any("YARA" in f and "Infected" in f for f in v12_result["findings"])
        assert any("PortScan" in f for f in v12_result["findings"])
        assert any("Suspicious" in f for f in v12_result["findings"])

    def test_compliant_job_not_flagged(self, v12_result):
        assert not any(
            "DC01 - Daily Backup" in f and ("encryption" in f or "low retention" in f)
            for f in v12_result["findings"]
        )

    def test_artifacts_generated(self, v12_result, tmp_path):
        out = tmp_path / "out"
        assert (out / "remediation_summary.md").exists()
        assert (out / "fixit.ps1").exists()
        assert (out / "tickets.json").exists()

    def test_enriched_severities(self, v12_result):
        severities = {e["severity"] for e in v12_result["enriched"]}
        assert "High" in severities
        assert "Medium" in severities

    def test_powershell_whatif_safety(self, v12_result, tmp_path):
        ps_text = (tmp_path / "out" / "fixit.ps1").read_text()
        for line in ps_text.splitlines():
            stripped = line.lstrip()
            if stripped.startswith(("Set-", "New-", "Remove-", "Add-", "Convert-")):
                assert "-WhatIf" in line, f"Mutating cmd missing -WhatIf: {line}"


class TestVBRv12JSON:
    """Same VBR v12 data loaded as JSON."""

    @pytest.fixture()
    def v12_json_result(self, tmp_path):
        _write_vbr_json(tmp_path, "v12")
        return vhc.run_healthcheck(
            input_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            input_format="json",
            demo=False,
            verbose=False,
            write_artifacts=True,
        )

    def test_json_matches_csv_finding_count(self, v12_json_result, tmp_path):
        csv_dir = tmp_path / "csv_run"
        csv_dir.mkdir()
        _write_vbr_csvs(csv_dir, "v12")
        csv_result = vhc.run_healthcheck(
            input_dir=str(csv_dir),
            output_dir=str(csv_dir / "out"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert len(v12_json_result["findings"]) == len(csv_result["findings"])

    def test_json_detects_malware(self, v12_json_result):
        assert any("Infected" in f for f in v12_json_result["findings"])


# =====================================================================
# VBR v13 tests — verifies extra columns are tolerated
# =====================================================================


class TestVBRv13CSV:
    """VBR v13 exports include extra columns the code must tolerate."""

    @pytest.fixture()
    def v13_result(self, tmp_path):
        _write_vbr_csvs(tmp_path, "v13")
        return vhc.run_healthcheck(
            input_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )

    def test_extra_columns_tolerated(self, v13_result):
        assert v13_result["findings"], "v13 data should still yield findings"

    def test_detects_v13_specific_security(self, v13_result):
        assert any("Four-eyes" in f for f in v13_result["findings"])

    def test_new_job_types_analyzed(self, v13_result):
        assert any("NAS Backup" in f for f in v13_result["findings"])

    def test_v13_failed_sessions(self, v13_result):
        assert any("SQL-Cluster Backup" in f and "failure" in f for f in v13_result["findings"])
        assert any("NAS Backup" in f and "failure" in f for f in v13_result["findings"])

    def test_v13_ml_malware_detection(self, v13_result):
        assert any("AI-Anomaly" in f and "Suspicious" in f for f in v13_result["findings"])


class TestVBRv13JSON:
    @pytest.fixture()
    def v13_json_result(self, tmp_path):
        _write_vbr_json(tmp_path, "v13")
        return vhc.run_healthcheck(
            input_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            input_format="json",
            demo=False,
            verbose=False,
            write_artifacts=True,
        )

    def test_json_v13_findings_present(self, v13_json_result):
        assert v13_json_result["findings"]

    def test_json_v13_artifacts_written(self, v13_json_result, tmp_path):
        assert (tmp_path / "out" / "remediation_summary.md").exists()


# =====================================================================
# Version-compatibility edge cases
# =====================================================================


class TestVersionEdgeCases:
    def test_mixed_version_columns_tolerated(self, tmp_path):
        """If a v13 export is missing a v12-only column, analysis still works."""
        jobs_csv = 'Name,RetentionCount,StgEncryptionEnabled\n"TestJob",3,False\n'
        (tmp_path / "localhost_Jobs.csv").write_text(jobs_csv)
        out = vhc.run_healthcheck(
            input_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert any("TestJob" in f for f in out["findings"])

    def test_completely_empty_export_set(self, tmp_path):
        """All files present but with only headers (no data rows)."""
        for name in vhc.EXPECTED_BASENAMES.values():
            (tmp_path / f"{name}.csv").write_text("Name\n")
        out = vhc.run_healthcheck(
            input_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        assert out["findings"] == []

    def test_partial_export_graceful(self, tmp_path):
        """Only jobs file present — other sections should still produce findings."""
        (tmp_path / "localhost_Jobs.csv").write_text(VBR12_JOBS_CSV)
        out = vhc.run_healthcheck(
            input_dir=str(tmp_path),
            output_dir=str(tmp_path / "out"),
            demo=False,
            verbose=False,
            write_artifacts=True,
        )
        assert out["findings"], "should still find job issues"
        assert out["missing_files"], "should record the missing files"

    def test_bom_encoded_csv(self, tmp_path):
        """UTF-8 BOM (common from Windows PowerShell exports) must not break CSV loading."""
        bom_csv = "﻿" + VBR12_JOBS_CSV
        (tmp_path / "localhost_Jobs.csv").write_text(bom_csv, encoding="utf-8-sig")
        result = vhc.HealthCheckResult()
        df = vhc._safe_load_csv(tmp_path / "localhost_Jobs.csv", result)
        assert df is not None
        assert not result.errors

    def test_windows_line_endings(self, tmp_path):
        """CRLF line endings (Windows default) must not break parsing."""
        crlf_csv = VBR12_JOBS_CSV.replace("\n", "\r\n")
        (tmp_path / "localhost_Jobs.csv").write_text(crlf_csv)
        result = vhc.HealthCheckResult()
        df = vhc._safe_load_csv(tmp_path / "localhost_Jobs.csv", result)
        assert df is not None
        assert len(df) > 0
