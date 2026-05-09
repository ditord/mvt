# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import io
import json
import logging
import tarfile
import time

import pytest

from mvt.common.indicators import Indicators
from mvt.ios.modules.sysdiagnose.crash_reports import (
    CrashReports,
    _build_result,
    _extract_domains,
    _extract_urls,
    _normalize_timestamp,
    _parse_crash_text,
    _parse_ips,
)

# ---------------------------------------------------------------------------
# Synthetic crash report fixtures
# ---------------------------------------------------------------------------

_IPS_SIMPLE = {
    "bug_type": "109",
    "timestamp": "2024-01-15 10:23:45.00 +0000",
    "name": "SpringBoard",
    "bundleID": "com.apple.springboard",
    "procPath": "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
    "exception": {
        "type": "EXC_CRASH",
        "signal": "SIGKILL",
        "codes": "0x0000000000000000, 0x0000000000000000",
    },
    "termination": {
        "code": 2147549231,
        "namespace": "SPRINGBOARD",
        "reasons": ["watchdog timeout"],
    },
    "threads": [
        {"id": 0, "crashed": True, "frames": []},
        {"id": 1, "crashed": False, "frames": []},
    ],
    "osVersion": {"train": "iPhone OS 17.0", "build": "21A329"},
}

_IPS_WITH_URL = {
    "bug_type": "109",
    "timestamp": "2024-01-15 11:00:00.00 +0000",
    "name": "MobileSafari",
    "bundleID": "com.apple.mobilesafari",
    "procPath": "/Applications/MobileSafari.app/MobileSafari",
    "exception": {"type": "EXC_BAD_ACCESS", "signal": "SIGSEGV"},
    "termination": {
        "reasons": ["http://example.com/thisisbad contacted before crash"]
    },
    "threads": [],
    "osVersion": "iPhone OS 17.0 (21A329)",
}

_IPS_MALICIOUS_PROCESS = {
    "bug_type": "109",
    "timestamp": "2024-01-15 12:00:00.00 +0000",
    "name": "Launch",  # matches test IOC process "Launch"
    "bundleID": "com.evil.launcher",
    "procPath": "/var/mobile/evil/Launch",
    "exception": {"type": "EXC_CRASH", "signal": "SIGTERM"},
    "termination": {"reasons": []},
    "threads": [],
    "osVersion": "iPhone OS 17.0 (21A329)",
}

_CRASH_TEXT = b"""\
Process:         TestApp [4242]
Path:            /var/mobile/Containers/Bundle/TestApp
Identifier:      com.example.testapp
Exception Type:  EXC_BAD_ACCESS (SIGSEGV)
Exception Codes: 0x0000000000000001 in 0x0000000000000001
Termination Reason: Namespace SIGNAL, Code 11
Date/Time:       2024-02-01 09:00:00.000 +0000
OS Version:      iPhone OS 17.0 (21A329)
"""


def _make_module_with_results(results):
    return CrashReports(results=results)


def _ips_bytes(data: dict) -> bytes:
    return json.dumps(data).encode()


# ---------------------------------------------------------------------------
# Unit tests for helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_normalize_timestamp_standard(self):
        result = _normalize_timestamp("2024-01-15 10:23:45.00 +0000")
        assert "2024-01-15" in result

    def test_normalize_timestamp_no_fraction(self):
        result = _normalize_timestamp("2024-01-15 10:23:45 +0000")
        assert "2024-01-15" in result

    def test_normalize_timestamp_empty(self):
        assert _normalize_timestamp("") == ""

    def test_normalize_timestamp_unparseable_passthrough(self):
        raw = "not a timestamp"
        assert _normalize_timestamp(raw) == raw

    def test_extract_urls_finds_http(self):
        text = 'error loading https://example.org/payload from server'
        assert "https://example.org/payload" in _extract_urls(text)

    def test_extract_urls_deduplicates(self):
        text = "https://a.com https://a.com"
        urls = _extract_urls(text)
        assert urls.count("https://a.com") == 1

    def test_extract_urls_empty(self):
        assert _extract_urls("no urls here") == []

    def test_extract_domains(self):
        urls = ["https://example.org/foo", "https://www.evil.com/bar"]
        domains = _extract_domains(urls)
        assert "example.org" in domains
        assert "evil.com" in domains

    def test_parse_ips_single_json(self):
        data = _parse_ips(_ips_bytes(_IPS_SIMPLE))
        assert data is not None
        assert data["name"] == "SpringBoard"

    def test_parse_ips_two_line_format(self):
        header = json.dumps({"bug_type": "109", "timestamp": "2024-01-15 10:23:45.00 +0000"})
        body = json.dumps({"name": "Foo", "bundleID": "com.foo", "threads": []})
        content = f"{header}\n{body}".encode()
        data = _parse_ips(content)
        assert data is not None
        assert data.get("name") == "Foo"
        assert data.get("bug_type") == "109"

    def test_parse_ips_invalid_returns_none(self):
        assert _parse_ips(b"not json at all ####") is None

    def test_parse_crash_text(self):
        result = _parse_crash_text(_CRASH_TEXT)
        assert result["process_name"] == "TestApp"
        assert result["bundle_identifier"] == "com.example.testapp"
        assert "EXC_BAD_ACCESS" in result["exception_type"]

    def test_build_result_crashed_thread(self):
        result = _build_result(_IPS_SIMPLE, "DiagnosticLogs/CrashReporter/sb.ips", "")
        assert result["crashed_thread"] == 0

    def test_build_result_no_crashed_thread(self):
        data = dict(_IPS_SIMPLE, threads=[{"id": 0, "crashed": False}])
        result = _build_result(data, "x.ips", "")
        assert result["crashed_thread"] is None

    def test_build_result_os_version_dict(self):
        result = _build_result(_IPS_SIMPLE, "x.ips", "")
        assert "iPhone OS 17.0" in result["os_version"]

    def test_build_result_os_version_string(self):
        data = dict(_IPS_SIMPLE, osVersion="iPhone OS 16.0 (20A362)")
        result = _build_result(data, "x.ips", "")
        assert result["os_version"] == "iPhone OS 16.0 (20A362)"


# ---------------------------------------------------------------------------
# CrashReports module — check_indicators tests using pre-built results
# ---------------------------------------------------------------------------


class TestCrashReportsCheckIndicators:
    def test_no_indicators_no_alerts(self):
        result = _build_result(_IPS_SIMPLE, "x.ips", "")
        m = _make_module_with_results([result])
        m.check_indicators()
        assert len(m.alertstore.alerts) == 0

    def test_process_name_ioc_match(self, indicator_file):
        result = _build_result(_IPS_MALICIOUS_PROCESS, "evil.ips", "")
        m = _make_module_with_results([result])
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        m.check_indicators()
        assert len(m.alertstore.alerts) == 1
        assert m.alertstore.alerts[0].matched_indicator is not None

    def test_url_in_crash_ioc_match(self, indicator_file):
        result = _build_result(_IPS_WITH_URL, "safari.ips", "")
        m = _make_module_with_results([result])
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        m.check_indicators()
        # "http://example.com/thisisbad" is in the test IOC file
        assert len(m.alertstore.alerts) == 1

    def test_domain_in_url_ioc_match(self, indicator_file):
        data = dict(_IPS_SIMPLE, termination={
            "reasons": ["failed to reach https://example.org/update"]
        })
        result = _build_result(data, "x.ips", "")
        m = _make_module_with_results([result])
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        m.check_indicators()
        assert len(m.alertstore.alerts) == 1

    def test_benign_crash_no_alert(self, indicator_file):
        result = _build_result(_IPS_SIMPLE, "springboard.ips", "")
        m = _make_module_with_results([result])
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        m.check_indicators()
        assert len(m.alertstore.alerts) == 0


# ---------------------------------------------------------------------------
# CrashReports module — full run() with in-memory data via from_dir/from_tar
# ---------------------------------------------------------------------------


class TestCrashReportsRun:
    def _make_file_listing(self, names):
        """Mock the module's all_files list."""
        return names

    def test_run_no_crash_files(self, tmp_path):
        m = CrashReports()
        m.from_dir(str(tmp_path), [])
        m.run()
        assert len(m.results) == 0

    def test_run_parses_ips_from_dir(self, tmp_path):
        crash_dir = tmp_path / "DiagnosticLogs" / "CrashReporter"
        crash_dir.mkdir(parents=True)
        ips_path = crash_dir / "SpringBoard-2024.ips"
        ips_path.write_bytes(_ips_bytes(_IPS_SIMPLE))

        rel = "DiagnosticLogs/CrashReporter/SpringBoard-2024.ips"
        m = CrashReports()
        m.from_dir(str(tmp_path), [rel])
        m.run()

        assert len(m.results) == 1
        r = m.results[0]
        assert r["process_name"] == "SpringBoard"
        assert r["bundle_identifier"] == "com.apple.springboard"
        assert r["exception_type"] == "EXC_CRASH"
        assert r["crashed_thread"] == 0

    def test_run_parses_crash_text_from_dir(self, tmp_path):
        crash_dir = tmp_path / "DiagnosticLogs" / "CrashReporter"
        crash_dir.mkdir(parents=True)
        crash_path = crash_dir / "TestApp.crash"
        crash_path.write_bytes(_CRASH_TEXT)

        rel = "DiagnosticLogs/CrashReporter/TestApp.crash"
        m = CrashReports()
        m.from_dir(str(tmp_path), [rel])
        m.run()

        assert len(m.results) == 1
        r = m.results[0]
        assert r["process_name"] == "TestApp"
        assert "EXC_BAD_ACCESS" in r["exception_type"]

    def test_run_parses_ips_from_tar(self, tmp_path):
        archive_path = tmp_path / "sysdiagnose.tar.gz"
        ips_data = _ips_bytes(_IPS_SIMPLE)
        member_name = "sysdiagnose_2024/DiagnosticLogs/CrashReporter/sb.ips"

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            info = tarfile.TarInfo(name=member_name)
            info.size = len(ips_data)
            info.mtime = int(time.time())
            tf.addfile(info, io.BytesIO(ips_data))
        archive_path.write_bytes(buf.getvalue())

        with tarfile.open(str(archive_path), "r:gz") as tar:
            files = [m.name for m in tar.getmembers() if m.isfile()]
            m = CrashReports()
            m.from_tar(tar, files)
            m.run()

        assert len(m.results) == 1
        assert m.results[0]["process_name"] == "SpringBoard"

    def test_run_multiple_files(self, tmp_path):
        crash_dir = tmp_path / "DiagnosticLogs" / "CrashReporter"
        crash_dir.mkdir(parents=True)
        (crash_dir / "a.ips").write_bytes(_ips_bytes(_IPS_SIMPLE))
        (crash_dir / "b.ips").write_bytes(_ips_bytes(_IPS_WITH_URL))

        files = [
            "DiagnosticLogs/CrashReporter/a.ips",
            "DiagnosticLogs/CrashReporter/b.ips",
        ]
        m = CrashReports()
        m.from_dir(str(tmp_path), files)
        m.run()

        assert len(m.results) == 2

    def test_run_skips_unparseable_file(self, tmp_path):
        crash_dir = tmp_path / "DiagnosticLogs" / "CrashReporter"
        crash_dir.mkdir(parents=True)
        (crash_dir / "corrupt.ips").write_bytes(b"this is not json #####")

        rel = "DiagnosticLogs/CrashReporter/corrupt.ips"
        m = CrashReports()
        m.from_dir(str(tmp_path), [rel])
        m.run()

        assert len(m.results) == 0

    def test_serialize(self):
        result = _build_result(_IPS_SIMPLE, "springboard.ips", "")
        m = _make_module_with_results([result])
        serialized = m.serialize(result)
        assert serialized["event"] == "crash_report"
        assert "SpringBoard" in serialized["data"]
        assert "EXC_CRASH" in serialized["data"]
