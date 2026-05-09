# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import json

import pytest
from click.testing import CliRunner

from mvt.ios.cli import generate_report
from mvt.ios.report import CaseReport, _normalize_alert_counts, _verdict_from_alerts

# ---------------------------------------------------------------------------
# Synthetic fixtures
# ---------------------------------------------------------------------------

_ALERT_HIGH = {
    "level": "HIGH",
    "module": "crash_reports",
    "message": "Suspicious crash observed",
    "event_time": "2024-01-15 10:00:00",
    "event": {"process_name": "SpringBoard"},
    "matched_indicator": {
        "value": "evil.example.org",
        "type": "domain",
        "name": "Test IOC",
        "stix2_file_name": "",
    },
}

_ALERT_LOW = {
    "level": "LOW",
    "module": "fsevents",
    "message": "Suspicious path observed",
    "event_time": "2024-01-15 11:00:00",
    "event": {"path": "/tmp/payload"},
    "matched_indicator": None,
}

_CORRELATION = [
    {
        "correlation_type": "process_and_domain",
        "severity": "high",
        "confidence": "medium",
        "summary": "Process matches domain IOC",
        "rationale": "May indicate C2 communication; requires further investigation",
        "related_records": [],
        "related_iocs": ["evil.example.org"],
        "time_window": None,
    }
]

_JSONL_LINES = [
    '{"timestamp":"2024-01-15 10:00:00","module":"FSEvents","artifact_type":"fsevent",'
    '"path":"/tmp/a","process":"","bundle_id":"","domain":"","url":"",'
    '"event_type":"Created","description":"Created","matched_ioc":"","source_file":"f","raw":null}',
    '{"timestamp":"2024-01-15 11:00:00","module":"FSEvents","artifact_type":"fsevent",'
    '"path":"/tmp/b","process":"","bundle_id":"","domain":"","url":"",'
    '"event_type":"Created","description":"Created","matched_ioc":"","source_file":"f","raw":null}',
]


@pytest.fixture()
def mvt_output_dir(tmp_path):
    (tmp_path / "alerts.json").write_text(
        json.dumps([_ALERT_HIGH, _ALERT_LOW]), encoding="utf-8"
    )
    (tmp_path / "correlation.json").write_text(
        json.dumps(_CORRELATION), encoding="utf-8"
    )
    fsevents = [{"path": "/tmp/a", "event_id": 1}, {"path": "/tmp/b", "event_id": 2}]
    (tmp_path / "fsevents.json").write_text(json.dumps(fsevents), encoding="utf-8")
    (tmp_path / "fsevents_normalized.jsonl").write_text(
        "\n".join(_JSONL_LINES), encoding="utf-8"
    )
    return tmp_path


# ---------------------------------------------------------------------------
# Unit: pure helpers
# ---------------------------------------------------------------------------


class TestVerdictFromAlerts:
    def test_empty_is_clean(self):
        assert _verdict_from_alerts([]) == "CLEAN"

    def test_high_alert(self):
        assert _verdict_from_alerts([{"level": "HIGH"}]) == "HIGH"

    def test_critical_beats_high(self):
        alerts = [{"level": "HIGH"}, {"level": "CRITICAL"}]
        assert _verdict_from_alerts(alerts) == "CRITICAL"

    def test_unknown_level_gives_unknown(self):
        assert _verdict_from_alerts([{"level": "WHATEVER"}]) == "UNKNOWN"

    def test_informational_only(self):
        assert _verdict_from_alerts([{"level": "INFORMATIONAL"}]) == "INFORMATIONAL"


class TestNormalizeAlertCounts:
    def test_counts_levels(self):
        alerts = [{"level": "HIGH"}, {"level": "HIGH"}, {"level": "LOW"}]
        counts = _normalize_alert_counts(alerts)
        assert counts["HIGH"] == 2
        assert counts["LOW"] == 1
        assert counts["total"] == 3

    def test_empty_input(self):
        counts = _normalize_alert_counts([])
        assert counts["total"] == 0
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            assert counts[level] == 0


# ---------------------------------------------------------------------------
# Unit: CaseReport.build()
# ---------------------------------------------------------------------------


class TestCaseReportBuild:
    def test_returns_all_required_keys(self, mvt_output_dir):
        summary = CaseReport(str(mvt_output_dir)).build()
        expected_keys = {
            "mvt_version",
            "generated_at",
            "case_id",
            "analyst",
            "input_dir",
            "verdict",
            "alert_counts",
            "alerts",
            "correlation_findings",
            "ioc_matches",
            "module_artifact_counts",
            "timeline_record_counts",
        }
        assert expected_keys <= set(summary.keys())

    def test_verdict_high(self, mvt_output_dir):
        summary = CaseReport(str(mvt_output_dir)).build()
        assert summary["verdict"] == "HIGH"

    def test_alert_counts(self, mvt_output_dir):
        summary = CaseReport(str(mvt_output_dir)).build()
        assert summary["alert_counts"]["HIGH"] == 1
        assert summary["alert_counts"]["LOW"] == 1
        assert summary["alert_counts"]["total"] == 2

    def test_ioc_match_extracted(self, mvt_output_dir):
        summary = CaseReport(str(mvt_output_dir)).build()
        assert len(summary["ioc_matches"]) == 1
        assert summary["ioc_matches"][0]["value"] == "evil.example.org"
        assert summary["ioc_matches"][0]["type"] == "domain"
        assert summary["ioc_matches"][0]["alert_level"] == "HIGH"

    def test_ioc_deduplication(self, tmp_path):
        alerts = [
            {**_ALERT_HIGH},
            {**_ALERT_HIGH},
        ]
        (tmp_path / "alerts.json").write_text(json.dumps(alerts), encoding="utf-8")
        summary = CaseReport(str(tmp_path)).build()
        assert len(summary["ioc_matches"]) == 1

    def test_null_matched_indicator_not_included(self, tmp_path):
        (tmp_path / "alerts.json").write_text(
            json.dumps([_ALERT_LOW]), encoding="utf-8"
        )
        summary = CaseReport(str(tmp_path)).build()
        assert summary["ioc_matches"] == []

    def test_module_artifact_counts(self, mvt_output_dir):
        summary = CaseReport(str(mvt_output_dir)).build()
        assert summary["module_artifact_counts"]["fsevents"] == 2

    def test_timeline_record_counts(self, mvt_output_dir):
        summary = CaseReport(str(mvt_output_dir)).build()
        assert summary["timeline_record_counts"]["fsevents"] == 2

    def test_correlation_findings(self, mvt_output_dir):
        summary = CaseReport(str(mvt_output_dir)).build()
        assert len(summary["correlation_findings"]) == 1

    def test_case_id_and_analyst_passthrough(self, mvt_output_dir):
        summary = CaseReport(
            str(mvt_output_dir), case_id="CASE-001", analyst="Alice"
        ).build()
        assert summary["case_id"] == "CASE-001"
        assert summary["analyst"] == "Alice"

    def test_empty_dir_gives_clean_verdict(self, tmp_path):
        summary = CaseReport(str(tmp_path)).build()
        assert summary["verdict"] == "CLEAN"
        assert summary["alert_counts"]["total"] == 0
        assert summary["module_artifact_counts"] == {}
        assert summary["timeline_record_counts"] == {}

    def test_skip_files_excluded_from_artifact_counts(self, mvt_output_dir):
        (mvt_output_dir / "case_summary.json").write_text("{}", encoding="utf-8")
        (mvt_output_dir / "info.json").write_text("{}", encoding="utf-8")
        summary = CaseReport(str(mvt_output_dir)).build()
        counts = summary["module_artifact_counts"]
        assert "case_summary" not in counts
        assert "info" not in counts
        assert "alerts" not in counts
        assert "correlation" not in counts

    def test_malformed_json_file_is_skipped(self, mvt_output_dir):
        (mvt_output_dir / "badmodule.json").write_text("NOT JSON", encoding="utf-8")
        summary = CaseReport(str(mvt_output_dir)).build()
        assert summary["module_artifact_counts"].get("badmodule", 0) == 0

    def test_non_array_json_file_counts_zero(self, mvt_output_dir):
        (mvt_output_dir / "weirdmodule.json").write_text(
            '{"not": "an array"}', encoding="utf-8"
        )
        summary = CaseReport(str(mvt_output_dir)).build()
        assert summary["module_artifact_counts"].get("weirdmodule", 0) == 0

    def test_empty_jsonl_lines_not_counted(self, tmp_path):
        (tmp_path / "fsevents_normalized.jsonl").write_text(
            "\n\n\n", encoding="utf-8"
        )
        summary = CaseReport(str(tmp_path)).build()
        assert summary["timeline_record_counts"].get("fsevents", 0) == 0

    def test_mvt_version_present(self, mvt_output_dir):
        from mvt.common.version import MVT_VERSION

        summary = CaseReport(str(mvt_output_dir)).build()
        assert summary["mvt_version"] == MVT_VERSION

    def test_generated_at_is_utc_iso(self, mvt_output_dir):
        summary = CaseReport(str(mvt_output_dir)).build()
        ts = summary["generated_at"]
        assert ts.endswith("+00:00") or ts.endswith("Z"), ts


# ---------------------------------------------------------------------------
# Unit: save_json / save_markdown
# ---------------------------------------------------------------------------


class TestCaseReportSave:
    def test_save_json_writes_valid_json(self, mvt_output_dir, tmp_path):
        out = str(tmp_path / "report.json")
        CaseReport(str(mvt_output_dir)).save_json(out)
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
        assert data["verdict"] == "HIGH"

    def test_save_json_accepts_prebuilt_summary(self, mvt_output_dir, tmp_path):
        report = CaseReport(str(mvt_output_dir))
        summary = report.build()
        out = str(tmp_path / "report.json")
        report.save_json(out, summary=summary)
        data = json.loads(open(out, encoding="utf-8").read())
        assert data["verdict"] == summary["verdict"]

    def test_save_markdown_creates_file(self, mvt_output_dir, tmp_path):
        out = str(tmp_path / "report.md")
        CaseReport(str(mvt_output_dir)).save_markdown(out)
        content = open(out, encoding="utf-8").read()
        assert "# MVT Case Summary" in content

    def test_save_markdown_contains_verdict(self, mvt_output_dir, tmp_path):
        out = str(tmp_path / "report.md")
        CaseReport(str(mvt_output_dir)).save_markdown(out)
        content = open(out, encoding="utf-8").read()
        assert "HIGH" in content

    def test_save_markdown_contains_ioc(self, mvt_output_dir, tmp_path):
        out = str(tmp_path / "report.md")
        CaseReport(str(mvt_output_dir)).save_markdown(out)
        content = open(out, encoding="utf-8").read()
        assert "evil.example.org" in content

    def test_save_markdown_accepts_prebuilt_summary(self, mvt_output_dir, tmp_path):
        report = CaseReport(str(mvt_output_dir))
        summary = report.build()
        out = str(tmp_path / "report.md")
        report.save_markdown(out, summary=summary)
        assert open(out, encoding="utf-8").read().startswith("# MVT")

    def test_save_markdown_no_ioc_section_when_clean(self, tmp_path):
        out = str(tmp_path / "report.md")
        CaseReport(str(tmp_path)).save_markdown(out)
        content = open(out, encoding="utf-8").read()
        assert "## IOC Matches" not in content

    def test_save_markdown_no_correlation_section_when_empty(self, tmp_path):
        out = str(tmp_path / "report.md")
        CaseReport(str(tmp_path)).save_markdown(out)
        content = open(out, encoding="utf-8").read()
        assert "## Correlation Findings" not in content


# ---------------------------------------------------------------------------
# Integration: CLI command
# ---------------------------------------------------------------------------


class TestCLIGenerateReport:
    def test_default_format_is_json(self, mvt_output_dir):
        runner = CliRunner()
        result = runner.invoke(generate_report, [str(mvt_output_dir)])
        assert result.exit_code == 0, result.output
        assert (mvt_output_dir / "case_summary.json").exists()
        assert not (mvt_output_dir / "case_summary.md").exists()

    def test_format_md(self, mvt_output_dir, tmp_path):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        runner = CliRunner()
        result = runner.invoke(
            generate_report,
            ["--format", "md", "--output-dir", str(out_dir), str(mvt_output_dir)],
        )
        assert result.exit_code == 0, result.output
        assert (out_dir / "case_summary.md").exists()
        assert not (out_dir / "case_summary.json").exists()

    def test_format_both(self, mvt_output_dir, tmp_path):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        runner = CliRunner()
        result = runner.invoke(
            generate_report,
            ["--format", "both", "--output-dir", str(out_dir), str(mvt_output_dir)],
        )
        assert result.exit_code == 0, result.output
        assert (out_dir / "case_summary.json").exists()
        assert (out_dir / "case_summary.md").exists()

    def test_output_dir_created_if_missing(self, mvt_output_dir, tmp_path):
        out_dir = tmp_path / "new_dir"
        runner = CliRunner()
        result = runner.invoke(
            generate_report,
            ["--output-dir", str(out_dir), str(mvt_output_dir)],
        )
        assert result.exit_code == 0, result.output
        assert out_dir.is_dir()
        assert (out_dir / "case_summary.json").exists()

    def test_case_id_stored_in_output(self, mvt_output_dir):
        runner = CliRunner()
        result = runner.invoke(
            generate_report,
            ["--case-id", "CASE-001", str(mvt_output_dir)],
        )
        assert result.exit_code == 0, result.output
        data = json.loads((mvt_output_dir / "case_summary.json").read_text())
        assert data["case_id"] == "CASE-001"

    def test_analyst_stored_in_output(self, mvt_output_dir):
        runner = CliRunner()
        result = runner.invoke(
            generate_report,
            ["--analyst", "Alice Smith", str(mvt_output_dir)],
        )
        assert result.exit_code == 0, result.output
        data = json.loads((mvt_output_dir / "case_summary.json").read_text())
        assert data["analyst"] == "Alice Smith"

    def test_verdict_in_output(self, mvt_output_dir):
        runner = CliRunner()
        runner.invoke(generate_report, [str(mvt_output_dir)])
        data = json.loads((mvt_output_dir / "case_summary.json").read_text())
        assert data["verdict"] == "HIGH"

    def test_empty_dir_exits_zero(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(generate_report, [str(tmp_path)])
        assert result.exit_code == 0, result.output
        data = json.loads((tmp_path / "case_summary.json").read_text())
        assert data["verdict"] == "CLEAN"
