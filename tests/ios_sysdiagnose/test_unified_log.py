# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

"""Tests for the UnifiedLog sysdiagnose module."""

import io
import json
import logging
import os
import subprocess
import tarfile
import time
from unittest.mock import MagicMock, patch

import pytest

from mvt.common.indicators import Indicators
from mvt.ios.modules.sysdiagnose.unified_log import (
    UnifiedLog,
    _extract_domains,
    _extract_ips,
    _extract_paths,
    _extract_urls,
    _normalize_timestamp,
)

_MODULE = "mvt.ios.modules.sysdiagnose.unified_log"

# ---------------------------------------------------------------------------
# Synthetic log event fixtures
# ---------------------------------------------------------------------------

_EVENT_BENIGN = {
    "timestamp": "2024-01-15 10:23:41.000000-0800",
    "processImagePath": "/usr/libexec/testd",
    "subsystem": "com.apple.system",
    "category": "default",
    "eventMessage": "Service started normally",
    "eventType": "logEvent",
    "senderImagePath": "/usr/lib/libfoo.dylib",
}

_EVENT_WITH_URL = {
    "timestamp": "2024-01-15 10:24:00.000000-0800",
    "processImagePath": "/usr/libexec/networkd",
    "subsystem": "com.apple.network",
    "category": "connection",
    "eventMessage": "Fetching https://example.org/update from /var/tmp/cache/network",
    "eventType": "logEvent",
    "senderImagePath": "/usr/lib/libnetwork.dylib",
}

_EVENT_MALICIOUS = {
    "timestamp": "2024-01-15 10:30:00.000000-0800",
    "processImagePath": "/var/mobile/evil/Launch",
    "subsystem": "com.evil.spy",
    "category": "network",
    "eventMessage": "Sending data to http://example.com/thisisbad with IP 198.51.100.1",
    "eventType": "logEvent",
    "senderImagePath": "/var/mobile/evil/Launch",
}

_EVENT_IOC_PROCESS = {
    "timestamp": "2024-01-15 10:35:00.000000-0800",
    "processImagePath": "/var/mobile/evil/Launch",
    "subsystem": "com.evil.spy",
    "category": "network",
    "eventMessage": "Launch process started",
    "eventType": "logEvent",
    "senderImagePath": "/var/mobile/evil/Launch",
}


def _make_json_output(events: list) -> str:
    """Simulate `log show --style json` output as a multi-line JSON array."""
    return json.dumps(events, indent=2)


def _make_mock_proc(stdout_text: str, returncode: int = 0):
    """Build a mock Popen object with string stdout."""
    proc = MagicMock()
    proc.stdout = io.StringIO(stdout_text)
    proc.returncode = returncode
    proc.communicate.return_value = ("", "")
    return proc


# ---------------------------------------------------------------------------
# 1. Helpers: URL / domain / IP / path extraction, timestamp normalisation
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_extract_urls_http(self):
        text = "error loading https://example.org/payload from server"
        assert "https://example.org/payload" in _extract_urls(text)

    def test_extract_urls_multiple(self):
        text = "a=https://a.com b=https://b.org"
        urls = _extract_urls(text)
        assert "https://a.com" in urls
        assert "https://b.org" in urls

    def test_extract_urls_deduplicates(self):
        text = "https://a.com https://a.com"
        assert _extract_urls(text).count("https://a.com") == 1

    def test_extract_urls_empty(self):
        assert _extract_urls("no urls here") == []

    def test_extract_domains_strips_www(self):
        domains = _extract_domains(["https://www.example.org/path"])
        assert "example.org" in domains

    def test_extract_domains_lowercase(self):
        domains = _extract_domains(["https://Evil.Com/x"])
        assert "evil.com" in domains

    def test_extract_domains_deduplicates(self):
        domains = _extract_domains(["https://example.org/a", "https://example.org/b"])
        assert domains.count("example.org") == 1

    def test_extract_ips_valid(self):
        text = "connecting to 198.51.100.1 on port 443"
        ips = _extract_ips(text)
        assert "198.51.100.1" in ips

    def test_extract_ips_deduplicates(self):
        text = "198.51.100.1 and again 198.51.100.1"
        assert _extract_ips(text).count("198.51.100.1") == 1

    def test_extract_ips_no_match(self):
        assert _extract_ips("no ip address here") == []

    def test_extract_paths_var(self):
        text = "payload written to /var/mobile/app/data"
        assert "/var/mobile/app/data" in _extract_paths(text)

    def test_extract_paths_private_var(self):
        text = "wrote to /private/var/mobile/Downloads/bad.dmg"
        assert "/private/var/mobile/Downloads/bad.dmg" in _extract_paths(text)

    def test_extract_paths_deduplicates(self):
        text = "/var/tmp/x /var/tmp/x"
        assert _extract_paths(text).count("/var/tmp/x") == 1

    def test_normalize_timestamp_standard(self):
        result = _normalize_timestamp("2024-01-15 10:23:41.000000-0800")
        assert "2024-01-15" in result

    def test_normalize_timestamp_utc(self):
        result = _normalize_timestamp("2024-01-15 10:23:41.000000+0000")
        assert "2024-01-15" in result

    def test_normalize_timestamp_empty(self):
        assert _normalize_timestamp("") == ""

    def test_normalize_timestamp_unparseable_passthrough(self):
        raw = "not a timestamp"
        assert _normalize_timestamp(raw) == raw


# ---------------------------------------------------------------------------
# 2. Logarchive discovery — from directory
# ---------------------------------------------------------------------------


class TestLogarchiveDiscoveryDir:
    def test_finds_logarchive_in_dir(self, tmp_path):
        la = tmp_path / "system_logs.logarchive"
        la.mkdir()
        (la / "Persist").mkdir()

        m = UnifiedLog()
        m.extract_path = str(tmp_path)
        found = m._find_logarchives_in_dir()

        assert len(found) == 1
        assert found[0].endswith("system_logs.logarchive")

    def test_finds_multiple_logarchives(self, tmp_path):
        (tmp_path / "a.logarchive").mkdir()
        (tmp_path / "b.logarchive").mkdir()

        m = UnifiedLog()
        m.extract_path = str(tmp_path)
        found = m._find_logarchives_in_dir()

        assert len(found) == 2

    def test_does_not_recurse_into_logarchive(self, tmp_path):
        outer = tmp_path / "outer.logarchive"
        outer.mkdir()
        # A nested logarchive inside should NOT be discovered separately
        inner = outer / "nested.logarchive"
        inner.mkdir()

        m = UnifiedLog()
        m.extract_path = str(tmp_path)
        found = m._find_logarchives_in_dir()

        assert len(found) == 1
        assert found[0].endswith("outer.logarchive")

    def test_no_logarchive_returns_empty(self, tmp_path):
        (tmp_path / "other_dir").mkdir()
        m = UnifiedLog()
        m.extract_path = str(tmp_path)
        assert m._find_logarchives_in_dir() == []

    def test_no_extract_path_returns_empty(self):
        m = UnifiedLog()
        m.extract_path = None
        assert m._find_logarchives_in_dir() == []


# ---------------------------------------------------------------------------
# 2b. Logarchive discovery — from tar archive
# ---------------------------------------------------------------------------


class TestLogarchiveDiscoveryTar:
    def _make_files_list(self, paths):
        return paths

    def test_finds_logarchive_prefix_in_file_list(self):
        files = [
            "sysdiagnose_2024/system_logs.logarchive/Persist/0001.tracev3",
            "sysdiagnose_2024/system_logs.logarchive/timesync/time.timesync",
            "sysdiagnose_2024/other_file.txt",
        ]
        m = UnifiedLog()
        m.all_files = files
        prefixes = m._find_logarchive_prefixes_in_tar()
        assert len(prefixes) == 1
        assert "sysdiagnose_2024/system_logs.logarchive" in prefixes

    def test_finds_multiple_logarchive_prefixes(self):
        files = [
            "root/a.logarchive/Persist/x.tracev3",
            "root/b.logarchive/Persist/y.tracev3",
        ]
        m = UnifiedLog()
        m.all_files = files
        prefixes = m._find_logarchive_prefixes_in_tar()
        assert len(prefixes) == 2

    def test_deduplicates_same_archive_members(self):
        files = [
            "sys.logarchive/Persist/a.tracev3",
            "sys.logarchive/Persist/b.tracev3",
            "sys.logarchive/timesync/t.timesync",
        ]
        m = UnifiedLog()
        m.all_files = files
        prefixes = m._find_logarchive_prefixes_in_tar()
        assert len(prefixes) == 1

    def test_no_logarchive_returns_empty(self):
        m = UnifiedLog()
        m.all_files = ["DiagnosticLogs/CrashReporter/sb.ips"]
        assert m._find_logarchive_prefixes_in_tar() == []

    def test_file_named_logarchive_not_matched(self):
        # File named exactly ".logarchive" without trailing slash — not a bundle
        files = ["some.logarchive"]
        m = UnifiedLog()
        m.all_files = files
        # No trailing '/' means it's a plain file, not a directory bundle
        assert m._find_logarchive_prefixes_in_tar() == []


# ---------------------------------------------------------------------------
# 3. macOS backend — command construction
# ---------------------------------------------------------------------------


class TestBackendCommand:
    def test_make_cmd_structure(self):
        with patch(f"{_MODULE}._LOG_BINARY", "/usr/bin/log"):
            m = UnifiedLog()
            cmd = m._make_cmd("/path/to/system.logarchive")
        assert cmd[0] == "/usr/bin/log"
        assert "show" in cmd
        assert "--style" in cmd
        assert "json" in cmd
        assert "--archive" in cmd
        assert "/path/to/system.logarchive" in cmd
        assert "--info" in cmd
        assert "--debug" in cmd

    def test_make_cmd_no_shell_injection(self):
        with patch(f"{_MODULE}._LOG_BINARY", "/usr/bin/log"):
            m = UnifiedLog()
            path = "/path/to/system; rm -rf /"
            cmd = m._make_cmd(path)
        # Path must be a single list element — no shell expansion possible
        assert path in cmd
        assert len([c for c in cmd if ";" in c]) == 1  # only in the path element


# ---------------------------------------------------------------------------
# 4. JSON stream parsing — _iter_events
# ---------------------------------------------------------------------------


class TestIterEvents:
    def test_parses_single_event(self):
        output = _make_json_output([_EVENT_BENIGN])
        m = UnifiedLog()
        events = list(m._iter_events(io.StringIO(output)))
        assert len(events) == 1
        assert events[0]["subsystem"] == "com.apple.system"

    def test_parses_multiple_events(self):
        output = _make_json_output([_EVENT_BENIGN, _EVENT_WITH_URL, _EVENT_MALICIOUS])
        m = UnifiedLog()
        events = list(m._iter_events(io.StringIO(output)))
        assert len(events) == 3

    def test_skips_malformed_lines(self):
        # Mix valid JSON event with garbage
        raw = '[\n  ' + json.dumps(_EVENT_BENIGN) + ',\n  not json at all,\n  ' + json.dumps(_EVENT_WITH_URL) + '\n]'
        m = UnifiedLog()
        events = list(m._iter_events(io.StringIO(raw)))
        # Should recover and parse the valid events
        assert len(events) >= 1

    def test_empty_output_yields_nothing(self):
        m = UnifiedLog()
        events = list(m._iter_events(io.StringIO("")))
        assert events == []

    def test_empty_array_yields_nothing(self):
        m = UnifiedLog()
        events = list(m._iter_events(io.StringIO("[]")))
        assert events == []

    def test_build_result_fields(self):
        m = UnifiedLog()
        result = m._build_result(_EVENT_WITH_URL, "system_logs.logarchive")
        assert result["process"] == "networkd"
        assert result["process_path"] == "/usr/libexec/networkd"
        assert result["subsystem"] == "com.apple.network"
        assert result["category"] == "connection"
        assert result["source_logarchive"] == "system_logs.logarchive"
        assert "https://example.org/update" in result["extracted_urls"]
        assert "example.org" in result["extracted_domains"]
        assert "/var/tmp/cache/network" in result["extracted_paths"]

    def test_build_result_normalizes_timestamp(self):
        m = UnifiedLog()
        result = m._build_result(_EVENT_BENIGN, "test.logarchive")
        assert "2024-01-15" in result["timestamp"]

    def test_build_result_empty_message(self):
        event = dict(_EVENT_BENIGN, eventMessage="")
        m = UnifiedLog()
        result = m._build_result(event, "test.logarchive")
        assert result["extracted_urls"] == []
        assert result["extracted_domains"] == []
        assert result["extracted_ips"] == []

    def test_build_result_extracts_ips(self):
        m = UnifiedLog()
        result = m._build_result(_EVENT_MALICIOUS, "test.logarchive")
        assert "198.51.100.1" in result["extracted_ips"]


# ---------------------------------------------------------------------------
# 5. IOC matching integration
# ---------------------------------------------------------------------------


class TestIOCIntegration:
    def test_no_indicators_no_alerts(self):
        m = UnifiedLog(results=[m := UnifiedLog()._build_result(_EVENT_BENIGN, "x")])
        m2 = UnifiedLog(results=[UnifiedLog()._build_result(_EVENT_BENIGN, "x")])
        m2.check_indicators()
        assert len(m2.alertstore.alerts) == 0

    def test_url_ioc_match(self, indicator_file):
        result = UnifiedLog()._build_result(_EVENT_MALICIOUS, "test.logarchive")
        m = UnifiedLog(results=[result])
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        m.check_indicators()
        # "http://example.com/thisisbad" is in the test IOC file
        assert len(m.alertstore.alerts) >= 1

    def test_process_name_ioc_match(self, indicator_file):
        result = UnifiedLog()._build_result(_EVENT_IOC_PROCESS, "test.logarchive")
        # "Launch" is an IOC process in the test stix file
        m = UnifiedLog(results=[result])
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        m.check_indicators()
        assert len(m.alertstore.alerts) >= 1

    def test_benign_event_no_alert(self, indicator_file):
        result = UnifiedLog()._build_result(_EVENT_BENIGN, "test.logarchive")
        m = UnifiedLog(results=[result])
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        m.check_indicators()
        assert len(m.alertstore.alerts) == 0

    def test_matched_ioc_in_normalized_record(self, indicator_file):
        result = UnifiedLog()._build_result(_EVENT_MALICIOUS, "test.logarchive")
        m = UnifiedLog(results=[result])
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        m.check_indicators()
        records = m.to_normalized_timeline()
        assert any(r.matched_ioc for r in records)


# ---------------------------------------------------------------------------
# 6. Timeout and error handling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    def test_oserror_on_popen_handled_gracefully(self):
        with (
            patch(f"{_MODULE}._IS_MACOS", True),
            patch(f"{_MODULE}._LOG_BINARY", "/usr/bin/log"),
            patch("subprocess.Popen", side_effect=OSError("no such file")),
        ):
            m = UnifiedLog()
            m.extract_path = "/fake/path"
            m._process_logarchive("/fake/system.logarchive", "system.logarchive")
        assert len(m.results) == 0

    def test_timeout_kills_process(self):
        proc = MagicMock()
        proc.stdout = io.StringIO(_make_json_output([_EVENT_BENIGN]))
        # First communicate() (with timeout kwarg) raises; second (bare, after kill) returns.
        proc.communicate.side_effect = [
            subprocess.TimeoutExpired(cmd="log", timeout=1),
            ("", ""),
        ]

        with (
            patch(f"{_MODULE}._IS_MACOS", True),
            patch(f"{_MODULE}._LOG_BINARY", "/usr/bin/log"),
            patch("subprocess.Popen", return_value=proc),
        ):
            m = UnifiedLog()
            m.timeout = 1
            m._process_logarchive("/fake/system.logarchive", "system.logarchive")
        # Killed — results may be 0 or 1 depending on timing, but no exception raised
        proc.kill.assert_called()

    def test_communicate_called_even_after_event_limit(self):
        many = [_EVENT_BENIGN.copy() for _ in range(10)]
        proc = _make_mock_proc(_make_json_output(many))

        with (
            patch(f"{_MODULE}._IS_MACOS", True),
            patch(f"{_MODULE}._LOG_BINARY", "/usr/bin/log"),
            patch("subprocess.Popen", return_value=proc),
        ):
            m = UnifiedLog()
            m.max_events = 3
            m._process_logarchive("/fake/system.logarchive", "system.logarchive")
        proc.communicate.assert_called()


# ---------------------------------------------------------------------------
# 7. Non-macOS graceful skip
# ---------------------------------------------------------------------------


class TestNonMacOS:
    def test_run_skips_on_non_macos(self, tmp_path):
        (tmp_path / "system_logs.logarchive").mkdir()
        with patch(f"{_MODULE}._IS_MACOS", False):
            m = UnifiedLog()
            m.extract_path = str(tmp_path)
            m.run()
        assert len(m.results) == 0

    def test_run_skips_when_no_log_binary(self, tmp_path):
        (tmp_path / "system_logs.logarchive").mkdir()
        with (
            patch(f"{_MODULE}._IS_MACOS", True),
            patch(f"{_MODULE}._LOG_BINARY", None),
        ):
            m = UnifiedLog()
            m.extract_path = str(tmp_path)
            m.run()
        assert len(m.results) == 0

    def test_run_no_logarchives_returns_empty(self, tmp_path):
        # Directory exists but has no .logarchive
        with (
            patch(f"{_MODULE}._IS_MACOS", True),
            patch(f"{_MODULE}._LOG_BINARY", "/usr/bin/log"),
        ):
            m = UnifiedLog()
            m.extract_path = str(tmp_path)
            m.run()
        assert len(m.results) == 0

    def test_no_logarchives_in_tar_returns_empty(self):
        with (
            patch(f"{_MODULE}._IS_MACOS", True),
            patch(f"{_MODULE}._LOG_BINARY", "/usr/bin/log"),
        ):
            m = UnifiedLog()
            m.all_files = ["DiagnosticLogs/CrashReporter/sb.ips"]
            m.run()
        assert len(m.results) == 0


# ---------------------------------------------------------------------------
# 8. Max event limit
# ---------------------------------------------------------------------------


class TestMaxEventLimit:
    def test_stops_at_max_events(self):
        events = [dict(_EVENT_BENIGN, eventMessage=f"msg {i}") for i in range(50)]
        proc = _make_mock_proc(_make_json_output(events))

        with (
            patch(f"{_MODULE}._IS_MACOS", True),
            patch(f"{_MODULE}._LOG_BINARY", "/usr/bin/log"),
            patch("subprocess.Popen", return_value=proc),
        ):
            m = UnifiedLog()
            m.max_events = 10
            m._process_logarchive("/fake/sys.logarchive", "sys.logarchive")

        assert len(m.results) == 10

    def test_iter_events_stops_at_limit(self):
        events = [_EVENT_BENIGN.copy() for _ in range(20)]
        m = UnifiedLog()
        m.max_events = 5
        parsed = list(m._iter_events(io.StringIO(_make_json_output(events))))
        assert len(parsed) == 5

    def test_default_max_events_is_conservative(self):
        assert UnifiedLog().max_events <= 10_000

    def test_run_from_dir_respects_max_events(self, tmp_path):
        """Full run() path with mocked subprocess respects the event cap."""
        la = tmp_path / "sys.logarchive"
        la.mkdir()
        events = [dict(_EVENT_BENIGN, eventMessage=f"msg {i}") for i in range(20)]
        proc = _make_mock_proc(_make_json_output(events))

        with (
            patch(f"{_MODULE}._IS_MACOS", True),
            patch(f"{_MODULE}._LOG_BINARY", "/usr/bin/log"),
            patch("subprocess.Popen", return_value=proc),
        ):
            m = UnifiedLog()
            m.extract_path = str(tmp_path)
            m.max_events = 7
            m.run()

        assert len(m.results) == 7


# ---------------------------------------------------------------------------
# Normalize record
# ---------------------------------------------------------------------------


class TestNormalizeRecord:
    def test_normalize_record_fields(self):
        result = UnifiedLog()._build_result(_EVENT_WITH_URL, "sys.logarchive")
        m = UnifiedLog(results=[result])
        record = m.normalize_record(result)
        assert record is not None
        assert record.artifact_type == "unified_log"
        assert record.module == "UnifiedLog"
        assert "example.org" == record.domain
        assert "https://example.org/update" == record.url
        assert record.process == "networkd"
        assert record.source_file == "sys.logarchive"
        assert record.raw == result

    def test_normalize_record_description_includes_subsystem(self):
        result = UnifiedLog()._build_result(_EVENT_BENIGN, "x.logarchive")
        m = UnifiedLog(results=[result])
        record = m.normalize_record(result)
        assert "com.apple.system" in record.description

    def test_serialize_structure(self):
        result = UnifiedLog()._build_result(_EVENT_BENIGN, "x.logarchive")
        m = UnifiedLog(results=[result])
        s = m.serialize(result)
        assert s["event"] == "unified_log"
        assert "timestamp" in s
        assert "module" in s
        assert "data" in s
