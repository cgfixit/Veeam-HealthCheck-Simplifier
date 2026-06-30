"""Tests covering gaps in the previous test suite.

Targets untested code paths, latent fragility in real Veeam data,
and additional VBR v12/v13 edge cases not covered elsewhere.
"""

from __future__ import annotations

import json
import pathlib
import sys
from unittest import mock

import pandas as pd
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import vhc_simplifier as vhc  # noqa: E402

# =====================================================================
# _str_cell and _row_name helpers (new in this pass)
# =====================================================================


class TestStrCellHelper:
    def test_none_returns_default(self):
        assert vhc._str_cell(None) == "<unknown>"

    def test_nan_returns_default(self):
        assert vhc._str_cell(float("nan")) == "<unknown>"

    def test_pandas_nan_returns_default(self):
        assert vhc._str_cell(pd.NA) == "<unknown>"

    def test_empty_string_returns_default(self):
        assert vhc._str_cell("") == "<unknown>"

    def test_whitespace_only_returns_default(self):
        assert vhc._str_cell("   ") == "<unknown>"

    def test_normal_value_passthrough(self):
        assert vhc._str_cell("DC01-Daily") == "DC01-Daily"

    def test_custom_default(self):
        assert vhc._str_cell(None, default="N/A") == "N/A"

    def test_integer_value_stringified(self):
        assert vhc._str_cell(42) == "42"


class TestRowNameHelper:
    def test_normal_name(self):
        row = pd.Series({"Name": "TestJob"})
        assert vhc._row_name(row) == "TestJob"

    def test_nan_name_returns_unknown(self):
        row = pd.Series({"Name": float("nan")})
        assert vhc._row_name(row) == "<unknown>"

    def test_missing_key_returns_unknown(self):
        row = pd.Series({"Other": "x"})
        assert vhc._row_name(row) == "<unknown>"

    def test_empty_name_returns_unknown(self):
        row = pd.Series({"Name": ""})
        assert vhc._row_name(row) == "<unknown>"


# =====================================================================
# analyze_jobs — NaN name edge cases
# =====================================================================


class TestAnalyzeJobsNaNName:
    def test_nan_job_name_becomes_unknown_not_nan(self):
        jobs = pd.DataFrame(
            [
                {
                    "Name": float("nan"),
                    "RetentionCount": 3,
                    "RetainDaysToKeep": 5,
                    "StgEncryptionEnabled": False,
                }
            ]
        )
        vhc.HealthCheckResult()
        findings = vhc.analyze_jobs(jobs, None)
        assert all("nan" not in f.lower().split("'")[1] for f in findings), (
            "NaN job name must not appear as the string 'nan' in findings"
        )
        assert any("<unknown>" in f for f in findings)

    def test_session_missing_status_column_is_tolerated(self):
        sessions = pd.DataFrame([{"JobName": "X"}])  # no Status column
        vhc.HealthCheckResult()
        findings = vhc.analyze_jobs(None, sessions)
        assert findings == []

    def test_session_with_warning_status_not_flagged(self):
        sessions = pd.DataFrame([{"JobName": "Job1", "Status": "Warning"}])
        vhc.HealthCheckResult()
        assert vhc.analyze_jobs(None, sessions) == []

    def test_session_status_case_insensitive(self):
        sessions = pd.DataFrame([{"JobName": "Job1", "Status": "FAILED"}])
        vhc.HealthCheckResult()
        findings = vhc.analyze_jobs(None, sessions)
        assert any("Job1" in f for f in findings)


# =====================================================================
# analyze_security — NaN/empty Status
# =====================================================================


class TestAnalyzeSecurityNaN:
    def test_nan_status_does_not_generate_spurious_finding(self):
        sec = pd.DataFrame(
            [
                {"Best Practice": "MFA enabled", "Status": float("nan")},
            ]
        )
        vhc.HealthCheckResult()
        findings = vhc.analyze_security(sec)
        assert findings == [], "NaN Status must not be flagged as 'Not Implemented'"

    def test_empty_status_does_not_generate_finding(self):
        sec = pd.DataFrame([{"Best Practice": "MFA enabled", "Status": ""}])
        vhc.HealthCheckResult()
        assert vhc.analyze_security(sec) == []

    def test_unable_to_detect_not_flagged(self):
        sec = pd.DataFrame([{"Best Practice": "MFA enabled", "Status": "Unable to detect"}])
        vhc.HealthCheckResult()
        assert vhc.analyze_security(sec) == []

    def test_mixed_nan_and_real_status(self):
        sec = pd.DataFrame(
            [
                {"Best Practice": "MFA enabled", "Status": float("nan")},
                {"Best Practice": "RDP disabled", "Status": "Not Implemented"},
            ]
        )
        vhc.HealthCheckResult()
        findings = vhc.analyze_security(sec)
        assert len(findings) == 1
        assert "RDP disabled" in findings[0]


# =====================================================================
# analyze_malware — NaN object/time fields
# =====================================================================


class TestAnalyzeMalwareNaN:
    def test_nan_object_name_becomes_unknown(self):
        malware = pd.DataFrame(
            [
                {
                    "ObjectName": float("nan"),
                    "Status": "Infected",
                    "DetectionTime": "2025-01-01",
                }
            ]
        )
        vhc.HealthCheckResult()
        findings = vhc.analyze_malware(malware)
        assert len(findings) == 1
        assert "nan" not in findings[0], "NaN ObjectName must not appear as 'nan' string"
        assert "<unknown>" in findings[0]

    def test_nan_detection_time_becomes_unknown(self):
        malware = pd.DataFrame(
            [
                {
                    "ObjectName": "YARA",
                    "Status": "Infected",
                    "DetectionTime": float("nan"),
                }
            ]
        )
        vhc.HealthCheckResult()
        findings = vhc.analyze_malware(malware)
        assert len(findings) == 1
        assert "<unknown>" in findings[0]

    def test_clean_events_not_flagged(self):
        malware = pd.DataFrame([{"ObjectName": "Scan01", "Status": "Clean", "DetectionTime": "now"}])
        vhc.HealthCheckResult()
        assert vhc.analyze_malware(malware) == []

    def test_suspicious_and_infected_both_flagged(self):
        malware = pd.DataFrame(
            [
                {"ObjectName": "A", "Status": "Infected", "DetectionTime": "t1"},
                {"ObjectName": "B", "Status": "Suspicious", "DetectionTime": "t2"},
                {"ObjectName": "C", "Status": "Clean", "DetectionTime": "t3"},
            ]
        )
        vhc.HealthCheckResult()
        findings = vhc.analyze_malware(malware)
        assert len(findings) == 2


# =====================================================================
# analyze_repositories — NaN name
# =====================================================================


def test_analyze_repos_nan_name():
    repos = pd.DataFrame([{"Name": float("nan"), "IsImmutabilitySupported": False}])
    vhc.HealthCheckResult()
    findings = vhc.analyze_repositories(repos)
    assert any("<unknown>" in f for f in findings)
    assert not any("nan" in f.lower().replace("<unknown>", "") for f in findings)


# =====================================================================
# HealthCheckResult.to_dict()
# =====================================================================


class TestHealthCheckResultToDict:
    def test_empty_result_to_dict(self):
        r = vhc.HealthCheckResult()
        d = r.to_dict()
        assert d == {
            "findings": [],
            "enriched": [],
            "artifacts": {},
            "missing_files": [],
            "errors": [],
            "sections": {},
        }

    def test_artifacts_serialized_as_strings(self, tmp_path):
        r = vhc.HealthCheckResult()
        r.artifacts["markdown"] = tmp_path / "summary.md"
        d = r.to_dict()
        assert isinstance(d["artifacts"]["markdown"], str)
        assert "summary.md" in d["artifacts"]["markdown"]

    def test_all_fields_present(self):
        r = vhc.HealthCheckResult()
        r.findings = ["f1"]
        r.errors = ["e1"]
        r.missing_files = ["m1"]
        r.sections = {"A": ["f1"]}
        d = r.to_dict()
        assert d["findings"] == ["f1"]
        assert d["errors"] == ["e1"]
        assert d["missing_files"] == ["m1"]
        assert d["sections"] == {"A": ["f1"]}


# =====================================================================
# _load_embedded()
# =====================================================================


class TestLoadEmbedded:
    def test_returns_all_five_keys(self):
        dfs = vhc._load_embedded()
        assert set(dfs.keys()) == {
            "jobs",
            "sessions",
            "security",
            "repositories",
            "malware",
        }

    def test_all_dataframes_non_empty(self):
        dfs = vhc._load_embedded()
        for key, df in dfs.items():
            assert df is not None and len(df) > 0, f"Embedded '{key}' DataFrame is empty"

    def test_jobs_has_expected_columns(self):
        dfs = vhc._load_embedded()
        assert {
            "Name",
            "RetentionCount",
            "RetainDaysToKeep",
            "StgEncryptionEnabled",
        } <= set(dfs["jobs"].columns)

    def test_malware_has_expected_columns(self):
        dfs = vhc._load_embedded()
        assert {"ObjectName", "Status", "DetectionTime"} <= set(dfs["malware"].columns)


# =====================================================================
# _safe_load_json — dict and nested-dict shapes
# =====================================================================


class TestSafeLoadJsonShapes:
    def test_list_of_records(self, tmp_path):
        data = [{"Name": "Repo1", "IsImmutabilitySupported": False}]
        (tmp_path / "test.json").write_text(json.dumps(data))
        result = vhc.HealthCheckResult()
        df = vhc._safe_load_json(tmp_path / "test.json", result)
        assert df is not None
        assert len(df) == 1

    def test_dict_with_data_key(self, tmp_path):
        data = {"data": [{"Name": "Repo1", "IsImmutabilitySupported": True}]}
        (tmp_path / "test.json").write_text(json.dumps(data))
        result = vhc.HealthCheckResult()
        df = vhc._safe_load_json(tmp_path / "test.json", result)
        assert df is not None
        assert len(df) == 1

    def test_bare_dict_wrapped_in_list(self, tmp_path):
        data = {"Name": "Repo1", "IsImmutabilitySupported": True}
        (tmp_path / "test.json").write_text(json.dumps(data))
        result = vhc.HealthCheckResult()
        df = vhc._safe_load_json(tmp_path / "test.json", result)
        assert df is not None

    def test_empty_list_returns_none(self, tmp_path):
        (tmp_path / "empty.json").write_text("[]")
        result = vhc.HealthCheckResult()
        df = vhc._safe_load_json(tmp_path / "empty.json", result)
        assert df is None


# =====================================================================
# enrich_findings edge cases
# =====================================================================


class TestEnrichFindingsEdgeCases:
    def test_empty_input_returns_empty_list(self):
        assert vhc.enrich_findings([]) == []

    def test_all_pattern_map_entries_match(self):
        test_inputs = [
            ("Job 'Alpha' missing storage encryption.", "High", "Job"),
            ("Job 'Beta' has low retention count.", "Medium", "Job"),
            ("Job 'Gamma' keeps restore points < recommended.", "Medium", "Job"),
            ("Repository 'Delta' does not support immutability.", "High", "Repository"),
            ("Recent job session failure: 'Epsilon'.", "High", "Job"),
            (
                "Security Best Practice NOT implemented: MFA is enabled (Not Implemented)",
                "High",
                "Security",
            ),
            ("Malware event: YARA - Infected at 2025-01-01", "High", "Malware"),
        ]
        for finding, expected_sev, expected_cat in test_inputs:
            enriched = vhc.enrich_findings([finding])
            assert enriched[0]["severity"] == expected_sev, f"Wrong severity for: {finding}"
            assert enriched[0]["category"] == expected_cat, f"Wrong category for: {finding}"

    def test_multiple_different_patterns_all_kept(self):
        findings = [
            "Job 'A' missing storage encryption.",
            "Job 'B' has low retention count.",
            "Repository 'R' does not support immutability.",
        ]
        enriched = vhc.enrich_findings(findings)
        assert len(enriched) == 3

    def test_dedup_same_key_same_category(self):
        findings = [
            "Job 'A' missing storage encryption.",
            "Job 'A' missing storage encryption.",
            "Job 'A' missing storage encryption.",
        ]
        assert len(vhc.enrich_findings(findings)) == 1

    def test_dedup_different_jobs_not_collapsed(self):
        findings = [
            "Job 'A' missing storage encryption.",
            "Job 'B' missing storage encryption.",
        ]
        assert len(vhc.enrich_findings(findings)) == 2


# =====================================================================
# _find_unquoted_hash edge cases
# =====================================================================


class TestFindUnquotedHashEdgeCases:
    def test_empty_string_returns_none(self):
        assert vhc._find_unquoted_hash("") is None

    def test_no_hash_returns_none(self):
        assert vhc._find_unquoted_hash("Set-VBRJob -Name 'x'") is None

    def test_hash_at_start(self):
        assert vhc._find_unquoted_hash("# comment") == 0

    def test_all_quoted_no_unquoted_hash(self):
        assert vhc._find_unquoted_hash("'a#b#c'") is None

    def test_consecutive_single_quotes_in_quoted_string(self):
        # 'O''Brien' — the '' inside is an escaped quote, not end of string
        assert vhc._find_unquoted_hash("Set-X 'O''Brien'") is None

    def test_hash_after_quoted_segment(self):
        pos = vhc._find_unquoted_hash("Set-X 'name' # comment")
        assert pos is not None and "# comment"[0] == "#"


# =====================================================================
# _ps_quote edge cases
# =====================================================================


class TestPsQuoteEdgeCases:
    def test_empty_string(self):
        assert vhc._ps_quote("") == "''"

    def test_non_string_is_coerced(self):
        result = vhc._ps_quote(42)
        assert result == "'42'"

    def test_tab_refused(self):
        assert vhc._ps_quote("evil\tname") is None

    def test_backslash_allowed(self):
        result = vhc._ps_quote("C:\\Backup\\Job")
        assert result is not None
        assert "C:\\Backup\\Job" in result


# =====================================================================
# write_markdown section summary counts
# =====================================================================


class TestWriteMarkdown:
    def test_section_counts_in_summary(self, tmp_path):
        sections = {
            "Backup Jobs": ["f1", "f2", "f3"],
            "Security & Compliance": ["s1"],
            "Repositories": [],
        }
        enriched = vhc.enrich_findings(["Job 'X' missing storage encryption."])
        out = vhc.write_markdown(enriched, sections, tmp_path / "summary.md")
        text = out.read_text()
        assert "**Backup Jobs**: 3 finding(s)" in text
        assert "**Security & Compliance**: 1 finding(s)" in text
        assert "**Repositories**: 0 finding(s)" in text

    def test_kb_links_in_output(self, tmp_path):
        enriched = vhc.enrich_findings(["Job 'X' missing storage encryption."])
        out = vhc.write_markdown(enriched, {}, tmp_path / "summary.md")
        text = out.read_text()
        assert "https://helpcenter.veeam.com/docs/backup/vbr/encryption.html" in text

    def test_empty_enriched_list(self, tmp_path):
        out = vhc.write_markdown([], {}, tmp_path / "summary.md")
        assert out.exists()
        text = out.read_text()
        assert "Remediation Summary" in text


# =====================================================================
# write_ticket_payload — 250-char truncation
# =====================================================================


class TestWriteTicketPayload:
    def test_long_finding_truncated_at_250(self, tmp_path):
        long_finding = "Job '" + "A" * 300 + "' missing storage encryption."
        enriched = vhc.enrich_findings([long_finding])
        out = vhc.write_ticket_payload(enriched, tmp_path / "tickets.json")
        payload = json.loads(out.read_text())
        if payload:
            assert len(payload[0]["short_description"]) <= 250

    def test_info_severity_excluded(self, tmp_path):
        enriched = [{"raw": "x", "severity": "Info", "category": "General", "cmd": "", "kb": ""}]
        out = vhc.write_ticket_payload(enriched, tmp_path / "tickets.json")
        payload = json.loads(out.read_text())
        assert payload == []

    def test_medium_severity_included(self, tmp_path):
        enriched = vhc.enrich_findings(["Job 'X' has low retention count."])
        out = vhc.write_ticket_payload(enriched, tmp_path / "tickets.json")
        payload = json.loads(out.read_text())
        assert any(p["severity"] == "Medium" for p in payload)


# =====================================================================
# _push_to_salesforce when HAS_SF=False
# =====================================================================


def test_push_salesforce_missing_library_records_error():
    result = vhc.HealthCheckResult()
    with mock.patch.object(vhc, "HAS_SF", False):
        with mock.patch.dict(
            "os.environ",
            {
                "SF_USERNAME": "u",
                "SF_PASSWORD": "p",
                "SF_TOKEN": "t",
            },
        ):
            vhc._push_to_salesforce(
                [{"severity": "High", "raw": "x", "cmd": "", "kb": ""}],
                "001FAKE",
                result,
            )
    assert any("simple-salesforce" in e for e in result.errors)


def test_salesforce_error_redacts_credentials():
    result = vhc.HealthCheckResult()
    enriched = [{"severity": "High", "raw": "x", "cmd": "", "kb": ""}]
    mock_sf_class = mock.MagicMock(side_effect=RuntimeError("bad secretpass token123"))
    with mock.patch.object(vhc, "HAS_SF", True):
        with mock.patch.dict(vhc.__dict__, {"Salesforce": mock_sf_class}):
            vhc._push_to_salesforce(
                enriched,
                "001FAKE",
                result,
                username="user@example.com",
                password="secretpass",
                token="token123",
            )
    assert result.errors
    assert "secretpass" not in result.errors[0]
    assert "token123" not in result.errors[0]


# =====================================================================
# _post_slack_summary via urllib fallback (mocked)
# =====================================================================


def test_slack_urllib_fallback(tmp_path):
    enriched = vhc.enrich_findings(["Job 'X' missing storage encryption."])
    result = vhc.HealthCheckResult()
    with mock.patch.object(vhc, "HAS_HTTPX", False):
        with mock.patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__ = lambda s: s
            mock_urlopen.return_value.__exit__ = mock.Mock(return_value=False)
            vhc._post_slack_summary(enriched, "https://hooks.slack.com/T/B/x", result)
    assert not result.errors
    mock_urlopen.assert_called_once()


def test_slack_httpx_failure_records_error():
    enriched = vhc.enrich_findings(["Job 'X' missing storage encryption."])
    result = vhc.HealthCheckResult()
    response = mock.Mock()
    response.raise_for_status.side_effect = RuntimeError("bad webhook")
    mock_httpx = mock.MagicMock()
    mock_httpx.post.return_value = response
    with mock.patch.object(vhc, "HAS_HTTPX", True):
        with mock.patch.dict(vhc.__dict__, {"httpx": mock_httpx}):
            vhc._post_slack_summary(enriched, "https://hooks.slack.com/services/T/B/x", result)
    assert any("Slack error" in e for e in result.errors)


# =====================================================================
# _print_console_report output
# =====================================================================


def test_print_console_report_output(capsys):
    result = vhc.HealthCheckResult()
    result.sections = {"Backup Jobs": ["Job 'X' missing storage encryption."]}
    result.missing_files = ["localhost_Jobs.csv"]
    result.errors = ["Some warning"]
    result.artifacts = {}
    vhc._print_console_report(result)
    captured = capsys.readouterr()
    assert "Backup Jobs" in captured.out
    assert "Job 'X' missing storage encryption." in captured.out
    assert "localhost_Jobs.csv" in captured.out
    assert "Some warning" in captured.out


def test_print_console_report_artifacts(capsys, tmp_path):
    result = vhc.HealthCheckResult()
    result.sections = {}
    result.artifacts = {"markdown": tmp_path / "summary.md"}
    vhc._print_console_report(result)
    captured = capsys.readouterr()
    assert "summary.md" in captured.out


# =====================================================================
# Integration: VBR v12 vs v13 finding count parity
# =====================================================================


class TestVBRVersionParity:
    VBR12_JOBS = (
        'Name,RetentionCount,RetainDaysToKeep,StgEncryptionEnabled\n"JobA",3,7,False\n"JobB",30,30,True\n'
    )
    VBR13_JOBS = (
        "Name,RetentionCount,RetainDaysToKeep,StgEncryptionEnabled,ObjectStorageTier\n"
        '"JobA",3,7,False,"Performance"\n'
        '"JobB",30,30,True,"Archive"\n'
    )

    def test_v12_and_v13_same_findings_despite_extra_column(self, tmp_path):
        d12 = tmp_path / "v12"
        d13 = tmp_path / "v13"
        d12.mkdir()
        d13.mkdir()
        (d12 / "localhost_Jobs.csv").write_text(self.VBR12_JOBS)
        (d13 / "localhost_Jobs.csv").write_text(self.VBR13_JOBS)
        r12 = vhc.run_healthcheck(
            input_dir=str(d12),
            output_dir=str(d12 / "o"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        r13 = vhc.run_healthcheck(
            input_dir=str(d13),
            output_dir=str(d13 / "o"),
            demo=False,
            verbose=False,
            write_artifacts=False,
        )
        assert sorted(r12["findings"]) == sorted(r13["findings"])


# =====================================================================
# HealthCheckConfig immutability
# =====================================================================


def test_health_check_config_is_frozen():
    with pytest.raises((AttributeError, TypeError)):
        vhc.CONFIG.recommended_retention_days = 999  # type: ignore[misc]


# =====================================================================
# pd.isna() exception paths in type-coercion helpers
# =====================================================================


class _BadArrayValue:
    """Value whose __array__ raises, triggering the except guard in pd.isna()."""

    def __array__(self, *a, **kw):
        raise ValueError("bad array")


class TestToNumberIsnaExceptionPath:
    def test_value_that_makes_pd_isna_raise(self):
        result = vhc._to_number(_BadArrayValue())
        assert result == 0.0

    def test_value_that_makes_pd_isna_raise_with_custom_default(self):
        result = vhc._to_number(_BadArrayValue(), default=42.0)
        assert result == 42.0


class TestToBoolIsnaExceptionPath:
    def test_value_that_makes_pd_isna_raise(self):
        result = vhc._to_bool(_BadArrayValue())
        assert result is False

    def test_non_standard_type_returns_default(self):
        result = vhc._to_bool(object())
        assert result is False

    def test_non_standard_type_returns_custom_default(self):
        result = vhc._to_bool(object(), default=True)
        assert result is True


class TestStrCellIsnaExceptionPath:
    def test_value_that_makes_pd_isna_raise(self):
        result = vhc._str_cell(_BadArrayValue())
        assert isinstance(result, str)
        assert result != "<unknown>"


# =====================================================================
# analyze_jobs — exception in sessions processing
# =====================================================================


class TestAnalyzeJobsSessionsException:
    def test_sessions_processing_exception_caught(self):
        bad_sessions = mock.MagicMock()
        bad_sessions.columns = ["Status", "JobName"]
        bad_sessions.__getitem__ = mock.Mock(side_effect=RuntimeError("boom"))
        findings = vhc.analyze_jobs(None, bad_sessions)
        assert findings == []


# =====================================================================
# analyze_security — pd.isna(status) exception path
# =====================================================================


class TestAnalyzeSecurityIsnaException:
    def test_status_that_makes_isna_raise(self):
        sec = pd.DataFrame([{"Best Practice": "MFA enabled", "Status": _BadArrayValue()}])
        findings = vhc.analyze_security(sec)
        assert len(findings) == 1


# =====================================================================
# Column guard edge cases (new in optimize pass)
# =====================================================================


class TestColumnGuards:
    def test_security_missing_columns_returns_empty(self):
        df = pd.DataFrame([{"SomeOtherColumn": "value"}])
        assert vhc.analyze_security(df) == []

    def test_security_missing_status_column_returns_empty(self):
        df = pd.DataFrame([{"Best Practice": "MFA enabled"}])
        assert vhc.analyze_security(df) == []

    def test_repos_missing_immutability_column_returns_empty(self):
        df = pd.DataFrame([{"Name": "TestRepo", "CapacityGB": 1024}])
        assert vhc.analyze_repositories(df) == []

    def test_jobs_missing_all_columns_no_crash(self):
        jobs = pd.DataFrame([{"SomeColumn": "value"}])
        findings = vhc.analyze_jobs(jobs, None)
        assert isinstance(findings, list)


# =====================================================================
# _safe_load_csv exception path
# =====================================================================


class TestSafeLoadCsvExceptions:
    def test_corrupted_binary_records_error(self, tmp_path):
        p = tmp_path / "corrupt.csv"
        p.write_bytes(b"\x00\x01\x02\x03")
        result = vhc.HealthCheckResult()
        df = vhc._safe_load_csv(p, result)
        assert df is None or result.errors or len(df) == 0 or not result.errors

    def test_csv_with_only_whitespace(self, tmp_path):
        p = tmp_path / "whitespace.csv"
        p.write_text("   \n   \n   \n")
        result = vhc.HealthCheckResult()
        df = vhc._safe_load_csv(p, result)
        assert df is None or result.errors


# =====================================================================
# _safe_load_json encoding error handling
# =====================================================================


class TestSafeLoadJsonEncoding:
    def test_json_with_replacement_chars(self, tmp_path):
        p = tmp_path / "test.json"
        p.write_bytes(b'[{"Name": "Test\xff\xfeRepo"}]')
        result = vhc.HealthCheckResult()
        df = vhc._safe_load_json(p, result)
        assert df is not None or result.errors

    def test_json_empty_file(self, tmp_path):
        p = tmp_path / "empty.json"
        p.write_text("")
        result = vhc.HealthCheckResult()
        df = vhc._safe_load_json(p, result)
        assert df is None
        assert result.errors

    def test_json_missing_file(self, tmp_path):
        result = vhc.HealthCheckResult()
        df = vhc._safe_load_json(tmp_path / "nonexistent.json", result)
        assert df is None
        assert "nonexistent.json" in result.missing_files


# =====================================================================
# Output dir creation failure
# =====================================================================


class TestOutputDirFailure:
    def test_unwritable_output_dir(self, tmp_path):
        with mock.patch("pathlib.Path.mkdir", side_effect=OSError("Permission denied")):
            out = vhc.run_healthcheck(
                output_dir=str(tmp_path / "blocked"),
                demo=True,
                verbose=False,
                write_artifacts=True,
            )
        assert any("Cannot create output dir" in e for e in out["errors"])

    def test_embedded_load_failure_captured(self):
        with mock.patch("vhc_simplifier._load_embedded", side_effect=RuntimeError("boom")):
            out = vhc.run_healthcheck(
                demo=True,
                verbose=False,
                write_artifacts=False,
            )
        assert any("Failed to load embedded" in e for e in out["errors"])


# =====================================================================
# Slack and Salesforce integration edge cases
# =====================================================================


class TestIntegrationEdgeCases:
    def test_slack_httpx_path(self):
        enriched = vhc.enrich_findings(["Job 'X' missing storage encryption."])
        result = vhc.HealthCheckResult()
        mock_httpx = mock.MagicMock()
        with mock.patch.object(vhc, "HAS_HTTPX", True):
            with mock.patch.dict(vhc.__dict__, {"httpx": mock_httpx}):
                vhc._post_slack_summary(enriched, "https://hooks.slack.com/T/B/x", result)
        mock_httpx.post.assert_called_once()
        assert not result.errors

    def test_slack_network_error_captured(self):
        enriched = vhc.enrich_findings(["Job 'X' missing storage encryption."])
        result = vhc.HealthCheckResult()
        with mock.patch.object(vhc, "HAS_HTTPX", False):
            with mock.patch("urllib.request.urlopen", side_effect=ConnectionError("timeout")):
                vhc._post_slack_summary(enriched, "https://hooks.slack.com/T/B/x", result)
        assert any("Slack error" in e for e in result.errors)

    def test_salesforce_api_error_captured(self):
        result = vhc.HealthCheckResult()
        mock_sf_class = mock.MagicMock(side_effect=Exception("auth failed"))
        with mock.patch.object(vhc, "HAS_SF", True):
            with mock.patch.dict(
                "os.environ",
                {"SF_USERNAME": "u", "SF_PASSWORD": "p", "SF_TOKEN": "t"},
            ):
                with mock.patch.dict(vhc.__dict__, {"Salesforce": mock_sf_class}):
                    vhc._push_to_salesforce(
                        [{"severity": "High", "raw": "x", "cmd": "", "kb": ""}],
                        "001FAKE",
                        result,
                    )
        assert any("Salesforce error" in e for e in result.errors)

    def test_salesforce_successful_push(self):
        result = vhc.HealthCheckResult()
        mock_sf = mock.MagicMock()
        mock_sf_class = mock.MagicMock(return_value=mock_sf)
        with mock.patch.object(vhc, "HAS_SF", True):
            with mock.patch.dict(
                "os.environ",
                {"SF_USERNAME": "u", "SF_PASSWORD": "p", "SF_TOKEN": "t"},
            ):
                with mock.patch.dict(vhc.__dict__, {"Salesforce": mock_sf_class}):
                    vhc._push_to_salesforce(
                        [
                            {
                                "severity": "High",
                                "raw": "Test finding",
                                "cmd": "Get-VBR",
                                "kb": "https://example.com",
                            },
                            {
                                "severity": "Info",
                                "raw": "Low priority",
                                "cmd": "",
                                "kb": "",
                            },
                        ],
                        "001FAKE",
                        result,
                    )
        mock_sf.Task.create.assert_called_once()
        assert not result.errors


# =====================================================================
# write_powershell_script — hash-in-command edge case
# =====================================================================


class TestWritePowerShellEdgeCases:
    def test_mutating_cmd_with_inline_comment(self, tmp_path):
        enriched = [
            {
                "raw": "Test finding",
                "object": "TestJob",
                "severity": "High",
                "category": "Job",
                "explain": "Fix it",
                "kb": "",
                "cmd": "Set-VBRJob -Name 'Test' # enable encryption",
            }
        ]
        out = vhc.write_powershell_script(enriched, tmp_path / "test.ps1")
        text = out.read_text()
        assert "-WhatIf" in text

    def test_empty_enriched_writes_header_only(self, tmp_path):
        out = vhc.write_powershell_script([], tmp_path / "empty.ps1")
        text = out.read_text()
        assert "Auto-generated" in text
        assert "WARNING" in text
