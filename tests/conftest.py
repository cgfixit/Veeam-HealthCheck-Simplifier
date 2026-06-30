"""Shared fixtures for the VHC test suite.

Provides reusable VBR v12.3.2 and v13 export data generators that
simulate the CSV/JSON output produced by running the Veeam Health Check
script (https://vee.am/vhc2) against real VBR installations.
"""

from __future__ import annotations

import io
import json
import pathlib
import sys

import pandas as pd
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))


# ── VBR v12.3.2 (build 12.3.2.4643) realistic export data ──────────

VBR_V12_3_2_JOBS = """\
Name,RetentionCount,RetainDaysToKeep,StgEncryptionEnabled
"DC01 - Domain Controllers",30,30,True
"SQL-Cluster-PROD",7,14,False
"FileServer-Weekly-GFS",4,7,False
"Hyper-V - Prod VMs",14,30,True
"Tape Archive - Monthly",3,365,False
"Oracle-DB-Critical",30,30,True
"Exchange-DAG-Backup",7,14,False
"Linux-Agents-Daily",10,30,True
"""

VBR_V12_3_2_SESSIONS = """\
JobName,Status
"DC01 - Domain Controllers",Success
"SQL-Cluster-PROD",Failed
"FileServer-Weekly-GFS",Warning
"Hyper-V - Prod VMs",Success
"Tape Archive - Monthly",Failed
"Oracle-DB-Critical",Success
"Exchange-DAG-Backup",Failed
"Linux-Agents-Daily",Success
"""

VBR_V12_3_2_SECURITY = """\
Best Practice,Status
"MFA is enabled for the backup console","Not Implemented"
"Configuration backup is encrypted","Passed"
"Traffic encryption is enabled","Passed"
"Remote desktop protocol is disabled on the VBR server","Not Implemented"
"Backup jobs to cloud repositories is encrypted","Not Implemented"
"Linux hardened repositories are used","Not Implemented"
"Password loss protection is enabled","Unable to detect"
"Immutability is set for all backup jobs","Not Implemented"
"Backup infrastructure components are up to date","Passed"
"""

VBR_V12_3_2_REPOS = """\
Name,IsImmutabilitySupported
"Default Backup Repository",False
"Hardened Linux Repo 01",True
"S3 Object Lock - AWS",True
"NAS Share (CIFS)",False
"Exagrid Appliance",False
"Dell DataDomain",False
"ReFS Repo - Local",False
"""

VBR_V12_3_2_MALWARE = """\
ObjectName,Status,DetectionTime
"YARA-Rule-DC01","Infected","2025-04-28 16:37:01"
"InlineScan-VM01","Clean","2025-05-01 08:00:00"
"InlineScan-DC01","Clean","2025-05-01 08:00:12"
"PortScan-SQL01","Infected","2025-04-28 16:36:43"
"Entropy-FS01","Suspicious","2025-05-21 17:19:49"
"InlineScan-Linux01","Clean","2025-05-22 09:00:00"
"""


# ── VBR v13 (latest build 13.0.x) realistic export data ─────────────

VBR_V13_JOBS = """\
Name,RetentionCount,RetainDaysToKeep,StgEncryptionEnabled,ObjectStorageTier,BackupCopyEnabled,CloudConnectEnabled
"DC01 - Domain Controllers",30,30,True,"Archive",True,False
"SQL-Cluster-PROD",7,14,False,"Performance",False,False
"Kubernetes-Cluster-01",30,30,True,"Performance",True,True
"M365-Exchange-Online",14,30,True,"Archive",True,False
"NAS-SMB-DFS",5,14,False,"",False,False
"Veeam ONE - Monitoring",30,30,True,"Performance",True,False
"CDP-VMware-Critical",0,0,True,"","",False
"Azure-VM-Backup",14,30,False,"Archive",True,True
"""

VBR_V13_SESSIONS = """\
JobName,Status,RetryCount,BottleneckType,Duration
"DC01 - Domain Controllers",Success,0,"None","00:12:34"
"SQL-Cluster-PROD",Failed,3,"Source","01:45:00"
"Kubernetes-Cluster-01",Success,0,"None","00:08:12"
"M365-Exchange-Online",Warning,1,"Network","02:30:00"
"NAS-SMB-DFS",Failed,2,"Target","00:55:00"
"Veeam ONE - Monitoring",Success,0,"None","00:02:00"
"CDP-VMware-Critical",Success,0,"None","00:00:10"
"Azure-VM-Backup",Failed,1,"Network","01:00:00"
"""

VBR_V13_SECURITY = """\
Best Practice,Status
"MFA is enabled for the backup console","Passed"
"Configuration backup is encrypted","Passed"
"Traffic encryption is enabled","Passed"
"Remote desktop protocol is disabled on the VBR server","Not Implemented"
"Backup jobs to cloud repositories is encrypted","Passed"
"Linux hardened repositories are used","Not Implemented"
"Immutability is set for all backup jobs","Not Implemented"
"Four-eyes authorization is enabled","Not Implemented"
"Service accounts use gMSA","Not Implemented"
"Backup infrastructure components are up to date","Passed"
"""

VBR_V13_REPOS = """\
Name,IsImmutabilitySupported,CapacityGB,FreeGB,PerVMBackupFiles
"Default Backup Repository",False,2048,512,True
"Hardened Linux Repo",True,4096,3200,True
"S3 Object Lock - AWS",True,0,0,False
"Azure Blob Immutable",True,10240,9000,False
"NAS Share (CIFS)",False,1024,128,True
"MinIO Immutable",True,8192,6000,False
"""

VBR_V13_MALWARE = """\
ObjectName,Status,DetectionTime,ScanEngine,ThreatLevel
"YARA-Rule-DC01","Infected","2025-04-28 16:37:01","Inline","Critical"
"InlineScan-VM01","Clean","2025-05-01 08:00:00","Inline","None"
"AI-Anomaly-SQL01","Suspicious","2025-06-10 03:14:00","ML","High"
"Entropy-K8s-PV","Suspicious","2025-06-12 14:22:00","ML","Medium"
"InlineScan-Azure-VM","Clean","2025-06-15 02:00:00","Inline","None"
"""


def _write_csvs(tmp_path: pathlib.Path, version: str) -> pathlib.Path:
    """Write a full set of mock VBR export CSVs for the given version."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    if version == "v12":
        data_map = {
            "localhost_Jobs.csv": VBR_V12_3_2_JOBS,
            "VeeamSessionReport.csv": VBR_V12_3_2_SESSIONS,
            "localhost_SecurityCompliance.csv": VBR_V12_3_2_SECURITY,
            "localhost_Repositories.csv": VBR_V12_3_2_REPOS,
            "localhostmalware_events.csv": VBR_V12_3_2_MALWARE,
        }
    else:
        data_map = {
            "localhost_Jobs.csv": VBR_V13_JOBS,
            "VeeamSessionReport.csv": VBR_V13_SESSIONS,
            "localhost_SecurityCompliance.csv": VBR_V13_SECURITY,
            "localhost_Repositories.csv": VBR_V13_REPOS,
            "localhostmalware_events.csv": VBR_V13_MALWARE,
        }
    for name, content in data_map.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    return tmp_path


def _write_json(tmp_path: pathlib.Path, version: str) -> pathlib.Path:
    """Write JSON equivalents of VBR exports."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    csv_sources = {
        "localhost_Jobs": VBR_V12_3_2_JOBS if version == "v12" else VBR_V13_JOBS,
        "VeeamSessionReport": VBR_V12_3_2_SESSIONS
        if version == "v12"
        else VBR_V13_SESSIONS,
        "localhost_SecurityCompliance": VBR_V12_3_2_SECURITY
        if version == "v12"
        else VBR_V13_SECURITY,
        "localhost_Repositories": VBR_V12_3_2_REPOS
        if version == "v12"
        else VBR_V13_REPOS,
        "localhostmalware_events": VBR_V12_3_2_MALWARE
        if version == "v12"
        else VBR_V13_MALWARE,
    }
    for base, csv_text in csv_sources.items():
        df = pd.read_csv(io.StringIO(csv_text))
        records = df.to_dict(orient="records")
        (tmp_path / f"{base}.json").write_text(
            json.dumps({"data": records}, indent=2, default=str), encoding="utf-8"
        )
    return tmp_path


@pytest.fixture()
def vbr_v12_csv_dir(tmp_path):
    """Temp directory with full VBR v12.3.2 CSV exports."""
    return _write_csvs(tmp_path / "v12_csv", "v12")


@pytest.fixture()
def vbr_v12_json_dir(tmp_path):
    """Temp directory with full VBR v12.3.2 JSON exports."""
    return _write_json(tmp_path / "v12_json", "v12")


@pytest.fixture()
def vbr_v13_csv_dir(tmp_path):
    """Temp directory with full VBR v13 CSV exports."""
    return _write_csvs(tmp_path / "v13_csv", "v13")


@pytest.fixture()
def vbr_v13_json_dir(tmp_path):
    """Temp directory with full VBR v13 JSON exports."""
    return _write_json(tmp_path / "v13_json", "v13")
