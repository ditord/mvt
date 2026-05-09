# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

"""Tests for the normalized timeline helper and per-module normalizers."""

import json
import logging
from dataclasses import asdict
from unittest.mock import MagicMock, patch

import pytest

from mvt.common.indicators import Indicators
from mvt.common.normalized_timeline import (
    NormalizedTimelineMixin,
    NormalizedTimelineRecord,
    write_jsonl,
)
from mvt.ios.modules.fs.fsevents import FSEvents
from mvt.ios.modules.fs.xattr_metadata import XattrMetadata
from mvt.ios.modules.sysdiagnose.crash_reports import CrashReports


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_FSEVENTS_RESULT = {
    "timestamp": "2024-01-15 10:23:41.000000",
    "event_id": 1099511628032,
    "path": "/private/var/mobile/Containers/Data/Application/ABCD/payload",
    "flags_raw": 0x10100,
    "flags_decoded": ["Created", "IsFile"],
    "source_log_file": ".fseventsd/000000004200e000",
}

_XATTR_RESULT = {
    "file_path": "private/var/mobile/Downloads/payload.dmg",
    "attribute_name": "com.apple.metadata:kMDItemWhereFroms",
    "raw_value": "aabbcc",
    "decoded_value": ["https://example.org/payload.dmg", "https://example.org/"],
    "extracted_urls": ["https://example.org/payload.dmg", "https://example.org/"],
    "extracted_domains": ["example.org"],
    "isodate": "2024-01-15 10:23:45.000000",
}

_CRASH_RESULT = {
    "source_file": "DiagnosticLogs/CrashReporter/sb.ips",
    "timestamp": "2024-01-15 10:00:00.000000",
    "process_name": "SpringBoard",
    "bundle_identifier": "com.apple.springboard",
    "process_path": "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
    "os_version": "iPhone OS 17.0 (21A329)",
    "exception_type": "EXC_CRASH",
    "exception_signal": "SIGKILL",
    "termination_reasons": ["watchdog timeout"],
    "crashed_thread": 0,
    "extracted_urls": [],
    "extracted_domains": [],
}


# ---------------------------------------------------------------------------
# NormalizedTimelineRecord dataclass
# ---------------------------------------------------------------------------


class TestNormalizedTimelineRecord:
    def test_all_fields_present(self):
        r = NormalizedTimelineRecord()
        for field in (
            "timestamp", "module", "artifact_type", "path", "process",
            "domain", "url", "description", "matched_ioc", "source_file",
        ):
            assert hasattr(r, field)

    def test_defaults_are_empty_strings(self):
        r = NormalizedTimelineRecord()
        assert all(v == "" for v in asdict(r).values())

    def test_fields_set_correctly(self):
        r = NormalizedTimelineRecord(
            timestamp="2024-01-01 00:00:00.000000",
            module="TestModule",
            artifact_type="test",
            path="/foo/bar",
        )
        assert r.timestamp == "2024-01-01 00:00:00.000000"
        assert r.module == "TestModule"
        assert r.path == "/foo/bar"


# ---------------------------------------------------------------------------
# write_jsonl helper
# ---------------------------------------------------------------------------


class TestWriteJsonl:
    def test_writes_one_line_per_record(self, tmp_path):
        records = [
            NormalizedTimelineRecord(timestamp="2024-01-02", module="A"),
            NormalizedTimelineRecord(timestamp="2024-01-01", module="B"),
        ]
        out = tmp_path / "out.jsonl"
        write_jsonl(records, str(out))
        lines = out.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 2

    def test_sorted_by_timestamp(self, tmp_path):
        records = [
            NormalizedTimelineRecord(timestamp="2024-01-03", module="C"),
            NormalizedTimelineRecord(timestamp="2024-01-01", module="A"),
            NormalizedTimelineRecord(timestamp="2024-01-02", module="B"),
        ]
        out = tmp_path / "out.jsonl"
        write_jsonl(records, str(out))
        lines = out.read_text(encoding="utf-8").strip().splitlines()
        modules = [json.loads(l)["module"] for l in lines]
        assert modules == ["A", "B", "C"]

    def test_each_line_is_valid_json(self, tmp_path):
        records = [NormalizedTimelineRecord(timestamp="2024-01-01", description="x")]
        out = tmp_path / "out.jsonl"
        write_jsonl(records, str(out))
        for line in out.read_text().strip().splitlines():
            obj = json.loads(line)
            assert "timestamp" in obj

    def test_empty_records_writes_empty_file(self, tmp_path):
        out = tmp_path / "out.jsonl"
        write_jsonl([], str(out))
        assert out.read_text() == ""

    def test_empty_timestamp_sorted_last(self, tmp_path):
        records = [
            NormalizedTimelineRecord(timestamp="", module="NoTime"),
            NormalizedTimelineRecord(timestamp="2024-01-01", module="HasTime"),
        ]
        out = tmp_path / "out.jsonl"
        write_jsonl(records, str(out))
        lines = out.read_text().strip().splitlines()
        first = json.loads(lines[0])["module"]
        assert first == "NoTime"  # "" < any date string


# ---------------------------------------------------------------------------
# NormalizedTimelineMixin — base behaviour
# ---------------------------------------------------------------------------


class TestNormalizedTimelineMixin:
    def _make_minimal_module(self, results=None, alerts=None):
        """Build a minimal object that satisfies the mixin's requirements."""
        m = XattrMetadata(results=results or [])
        if alerts:
            for alert in alerts:
                m.alertstore.alerts.append(alert)
        return m

    def test_to_normalized_timeline_empty_results(self):
        m = self._make_minimal_module()
        assert m.to_normalized_timeline() == []

    def test_to_normalized_timeline_calls_normalize_record(self):
        m = XattrMetadata(results=[_XATTR_RESULT])
        records = m.to_normalized_timeline()
        assert len(records) == 1
        assert isinstance(records[0], NormalizedTimelineRecord)

    def test_matched_ioc_populated_from_alertstore(self, indicator_file):
        result = dict(_XATTR_RESULT, extracted_urls=["http://example.com/thisisbad"])
        m = XattrMetadata(results=[result])
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        m.check_indicators()
        assert len(m.alertstore.alerts) == 1

        records = m.to_normalized_timeline()
        assert len(records) == 1
        assert records[0].matched_ioc == "http://example.com/thisisbad"

    def test_matched_ioc_empty_for_benign_record(self, indicator_file):
        result = dict(_XATTR_RESULT, extracted_urls=[], extracted_domains=[])
        m = XattrMetadata(results=[result])
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        m.check_indicators()

        records = m.to_normalized_timeline()
        assert records[0].matched_ioc == ""

    def test_save_normalized_timeline_jsonl_skips_when_no_path(self):
        m = XattrMetadata(results=[_XATTR_RESULT])
        m.results_path = None
        m.save_normalized_timeline_jsonl()  # must not raise

    def test_save_normalized_timeline_jsonl_writes_file(self, tmp_path):
        m = XattrMetadata(results=[_XATTR_RESULT], results_path=str(tmp_path))
        m.save_normalized_timeline_jsonl()
        out = tmp_path / "xattr_metadata_normalized.jsonl"
        assert out.exists()
        lines = out.read_text().strip().splitlines()
        assert len(lines) == 1
        obj = json.loads(lines[0])
        assert obj["artifact_type"] == "xattr"

    def test_save_to_json_writes_both_regular_and_jsonl(self, tmp_path):
        m = XattrMetadata(results=[_XATTR_RESULT], results_path=str(tmp_path))
        m.save_to_json()
        assert (tmp_path / "xattr_metadata.json").exists()
        assert (tmp_path / "xattr_metadata_normalized.jsonl").exists()


# ---------------------------------------------------------------------------
# FSEvents normalizer
# ---------------------------------------------------------------------------


class TestFSEventsNormalizer:
    def test_normalize_record_fields(self):
        m = FSEvents(results=[_FSEVENTS_RESULT])
        r = m.normalize_record(_FSEVENTS_RESULT)
        assert r.artifact_type == "fsevent"
        assert r.module == "FSEvents"
        assert r.timestamp == "2024-01-15 10:23:41.000000"
        assert r.path == "/private/var/mobile/Containers/Data/Application/ABCD/payload"
        assert r.source_file == ".fseventsd/000000004200e000"
        assert "Created" in r.description
        assert "IsFile" in r.description
        assert str(_FSEVENTS_RESULT["event_id"]) in r.description
        assert r.process == ""
        assert r.domain == ""
        assert r.url == ""

    def test_normalize_record_empty_flags(self):
        result = dict(_FSEVENTS_RESULT, flags_decoded=[])
        m = FSEvents(results=[result])
        r = m.normalize_record(result)
        assert "none" in r.description

    def test_to_normalized_timeline_count(self):
        results = [_FSEVENTS_RESULT, dict(_FSEVENTS_RESULT, path="/other/path")]
        m = FSEvents(results=results)
        assert len(m.to_normalized_timeline()) == 2

    def test_save_to_json_writes_jsonl(self, tmp_path):
        m = FSEvents(results=[_FSEVENTS_RESULT], results_path=str(tmp_path))
        m.save_to_json()
        assert (tmp_path / "fsevents_normalized.jsonl").exists()
        # Original output also present
        assert (tmp_path / "fsevents.json").exists()


# ---------------------------------------------------------------------------
# XattrMetadata normalizer
# ---------------------------------------------------------------------------


class TestXattrMetadataNormalizer:
    def test_normalize_record_fields(self):
        m = XattrMetadata(results=[_XATTR_RESULT])
        r = m.normalize_record(_XATTR_RESULT)
        assert r.artifact_type == "xattr"
        assert r.module == "XattrMetadata"
        assert r.timestamp == "2024-01-15 10:23:45.000000"
        assert r.path == "private/var/mobile/Downloads/payload.dmg"
        assert r.domain == "example.org"
        assert r.url == "https://example.org/payload.dmg"
        assert "kMDItemWhereFroms" in r.description
        assert r.source_file == "private/var/mobile/Downloads/payload.dmg"
        assert r.process == ""

    def test_normalize_record_no_urls(self):
        result = dict(_XATTR_RESULT, extracted_urls=[], extracted_domains=[])
        m = XattrMetadata(results=[result])
        r = m.normalize_record(result)
        assert r.url == ""
        assert r.domain == ""

    def test_normalize_record_long_decoded_value_truncated(self):
        result = dict(_XATTR_RESULT, decoded_value="x" * 200)
        m = XattrMetadata(results=[result])
        r = m.normalize_record(result)
        # decoded value is capped at 120 chars; prefix adds attribute name + ": "
        assert "..." in r.description
        assert len(r.description) < len(result["attribute_name"]) + 2 + 200

    def test_quarantine_attr(self):
        result = {
            "file_path": "var/mobile/app",
            "attribute_name": "com.apple.quarantine",
            "raw_value": "30303833",
            "decoded_value": "0083;5e4fbe3c;Safari;GUID",
            "extracted_urls": [],
            "extracted_domains": [],
            "isodate": "2024-01-15 09:00:00.000000",
        }
        m = XattrMetadata(results=[result])
        r = m.normalize_record(result)
        assert r.artifact_type == "xattr"
        assert "quarantine" in r.description


# ---------------------------------------------------------------------------
# CrashReports normalizer
# ---------------------------------------------------------------------------


class TestCrashReportsNormalizer:
    def test_normalize_record_fields(self):
        m = CrashReports(results=[_CRASH_RESULT])
        r = m.normalize_record(_CRASH_RESULT)
        assert r.artifact_type == "crash_report"
        assert r.module == "CrashReports"
        assert r.timestamp == "2024-01-15 10:00:00.000000"
        assert r.process == "SpringBoard"
        assert r.path == "/System/Library/CoreServices/SpringBoard.app/SpringBoard"
        assert r.source_file == "DiagnosticLogs/CrashReporter/sb.ips"
        assert "com.apple.springboard" in r.description
        assert "EXC_CRASH" in r.description
        assert "watchdog timeout" in r.description
        assert r.domain == ""
        assert r.url == ""

    def test_normalize_record_with_url(self):
        result = dict(
            _CRASH_RESULT,
            extracted_urls=["https://example.org/evil"],
            extracted_domains=["example.org"],
        )
        m = CrashReports(results=[result])
        r = m.normalize_record(result)
        assert r.url == "https://example.org/evil"
        assert r.domain == "example.org"

    def test_normalize_record_no_exception(self):
        result = dict(_CRASH_RESULT, exception_type="", exception_signal="")
        m = CrashReports(results=[result])
        r = m.normalize_record(result)
        assert "com.apple.springboard" in r.description

    def test_normalize_record_no_termination_reasons(self):
        result = dict(_CRASH_RESULT, termination_reasons=[])
        m = CrashReports(results=[result])
        r = m.normalize_record(result)
        assert r.description  # should still have something

    def test_save_to_json_writes_jsonl(self, tmp_path):
        m = CrashReports(results=[_CRASH_RESULT], results_path=str(tmp_path))
        m.save_to_json()
        assert (tmp_path / "crash_reports_normalized.jsonl").exists()
        assert (tmp_path / "crash_reports.json").exists()

    def test_matched_ioc_from_process_name(self, indicator_file):
        result = dict(_CRASH_RESULT, process_name="Launch")
        m = CrashReports(results=[result])
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        m.check_indicators()
        assert len(m.alertstore.alerts) == 1

        records = m.to_normalized_timeline()
        assert records[0].matched_ioc == "Launch"
