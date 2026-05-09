# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import logging
import plistlib
from unittest.mock import MagicMock, patch

import pytest

from mvt.common.indicators import Indicators
from mvt.ios.modules.fs.xattr_metadata import (
    XattrMetadata,
    _decode_xattr,
    _extract_urls,
    _get_domain,
    _to_serializable,
)


class TestXattrHelpers:
    def test_get_domain_full_url(self):
        assert _get_domain("https://evil.example.org/payload") == "evil.example.org"

    def test_get_domain_strips_www(self):
        assert _get_domain("https://www.example.org/") == "example.org"

    def test_get_domain_empty_on_invalid(self):
        assert _get_domain("not-a-url") == ""

    def test_extract_urls_from_string(self):
        urls = _extract_urls("downloaded from https://example.org/file.zip")
        assert "https://example.org/file.zip" in urls

    def test_extract_urls_from_list(self):
        urls = _extract_urls(["https://a.com/x", "https://b.com/y"])
        assert "https://a.com/x" in urls
        assert "https://b.com/y" in urls

    def test_extract_urls_from_nested_dict(self):
        urls = _extract_urls({"key": "see https://nested.example.com/path"})
        assert "https://nested.example.com/path" in urls

    def test_extract_urls_ignores_dates(self):
        import datetime
        urls = _extract_urls(datetime.datetime(2024, 1, 1))
        assert urls == []

    def test_decode_xattr_quarantine(self):
        raw = b"0083;5e4fbe3c;Safari;ABCD1234-5678-ABCD-EF01-234567890ABC"
        result = _decode_xattr("com.apple.quarantine", raw)
        assert isinstance(result, str)
        assert "Safari" in result

    def test_decode_xattr_plist_list(self):
        payload = plistlib.dumps(
            ["https://example.org/file.dmg", "https://example.org/"],
            fmt=plistlib.FMT_BINARY,
        )
        result = _decode_xattr("com.apple.metadata:kMDItemWhereFroms", payload)
        assert isinstance(result, list)
        assert "https://example.org/file.dmg" in result

    def test_decode_xattr_plist_date(self):
        import datetime
        payload = plistlib.dumps(
            [datetime.datetime(2024, 6, 1, 12, 0, 0)],
            fmt=plistlib.FMT_BINARY,
        )
        result = _decode_xattr("com.apple.metadata:kMDItemDownloadedDate", payload)
        assert isinstance(result, list)

    def test_decode_xattr_fallback_hex(self):
        raw = bytes(range(16))
        result = _decode_xattr("com.apple.metadata:kMDItemUnknown", raw)
        assert isinstance(result, str)

    def test_to_serializable_datetime(self):
        import datetime
        dt = datetime.datetime(2024, 1, 15, 10, 30, 0)
        result = _to_serializable(dt)
        assert isinstance(result, str)
        assert "2024-01-15" in result

    def test_to_serializable_bytes(self):
        result = _to_serializable(b"\x00\x01\x02")
        assert result == "000102"

    def test_to_serializable_nested(self):
        import datetime
        value = [datetime.datetime(2024, 1, 1), b"\xff", "plain"]
        result = _to_serializable(value)
        assert isinstance(result, list)
        assert all(isinstance(v, str) for v in result)


class TestXattrMetadataCheckIndicators:
    def _make_module(self, results):
        return XattrMetadata(results=results)

    def test_no_indicators_skips(self):
        m = self._make_module([
            {
                "file_path": "var/mobile/file.dmg",
                "attribute_name": "com.apple.metadata:kMDItemWhereFroms",
                "raw_value": "aabbcc",
                "decoded_value": ["https://example.org/file.dmg"],
                "extracted_urls": ["https://example.org/file.dmg"],
                "extracted_domains": ["example.org"],
                "isodate": "",
            }
        ])
        m.check_indicators()
        assert len(m.alertstore.alerts) == 0

    def test_url_match_triggers_alert(self, indicator_file):
        m = self._make_module([
            {
                "file_path": "var/mobile/payload",
                "attribute_name": "com.apple.metadata:kMDItemWhereFroms",
                "raw_value": "aabbcc",
                "decoded_value": ["http://example.com/thisisbad"],
                "extracted_urls": ["http://example.com/thisisbad"],
                "extracted_domains": ["example.com"],
                "isodate": "2024-01-01 00:00:00.000000",
            }
        ])
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        m.check_indicators()
        assert len(m.alertstore.alerts) == 1
        alert = m.alertstore.alerts[0]
        assert alert.matched_indicator is not None

    def test_domain_in_url_triggers_alert(self, indicator_file):
        m = self._make_module([
            {
                "file_path": "var/mobile/archive.zip",
                "attribute_name": "com.apple.metadata:kMDItemWhereFroms",
                "raw_value": "aabbcc",
                "decoded_value": ["https://example.org/archive.zip"],
                "extracted_urls": ["https://example.org/archive.zip"],
                "extracted_domains": ["example.org"],
                "isodate": "",
            }
        ])
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        m.check_indicators()
        assert len(m.alertstore.alerts) == 1

    def test_benign_url_no_alert(self, indicator_file):
        m = self._make_module([
            {
                "file_path": "var/mobile/photo.jpg",
                "attribute_name": "com.apple.metadata:kMDItemWhereFroms",
                "raw_value": "aabbcc",
                "decoded_value": ["https://safe.benign-site.net/photo.jpg"],
                "extracted_urls": ["https://safe.benign-site.net/photo.jpg"],
                "extracted_domains": ["safe.benign-site.net"],
                "isodate": "",
            }
        ])
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        m.check_indicators()
        assert len(m.alertstore.alerts) == 0

    def test_quarantine_no_url_no_alert(self, indicator_file):
        m = self._make_module([
            {
                "file_path": "var/mobile/app",
                "attribute_name": "com.apple.quarantine",
                "raw_value": "30303833",
                "decoded_value": "0083;5e4fbe3c;Safari;GUID",
                "extracted_urls": [],
                "extracted_domains": [],
                "isodate": "",
            }
        ])
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        m.check_indicators()
        assert len(m.alertstore.alerts) == 0


class TestXattrMetadataRun:
    @pytest.mark.skipif(
        hasattr(__import__("os"), "listxattr"),
        reason="listxattr is available; this test covers the unsupported-platform path",
    )
    def test_run_skips_on_no_listxattr(self, tmp_path, caplog):
        """On platforms without os.listxattr the module logs a warning and exits."""
        m = XattrMetadata(target_path=str(tmp_path))
        with caplog.at_level(logging.WARNING):
            m.run()
        assert len(m.results) == 0
        assert any("not supported" in r.message for r in caplog.records)

    @pytest.mark.skipif(
        not hasattr(__import__("os"), "listxattr"),
        reason="xattrs not supported on this platform",
    )
    def test_run_processes_files(self, tmp_path):
        """Files with matching xattrs are processed; others are skipped."""
        test_file = tmp_path / "test.dmg"
        test_file.write_bytes(b"dummy")

        where_froms = plistlib.dumps(
            ["https://example.org/test.dmg", "https://example.org/"],
            fmt=plistlib.FMT_BINARY,
        )

        with (
            patch("os.listxattr", return_value=["com.apple.metadata:kMDItemWhereFroms"]),
            patch("os.getxattr", return_value=where_froms),
        ):
            m = XattrMetadata(target_path=str(tmp_path))
            m.run()

        assert len(m.results) == 1
        result = m.results[0]
        assert result["attribute_name"] == "com.apple.metadata:kMDItemWhereFroms"
        assert "https://example.org/test.dmg" in result["extracted_urls"]
        assert "example.org" in result["extracted_domains"]

    @pytest.mark.skipif(
        not hasattr(__import__("os"), "listxattr"),
        reason="xattrs not supported on this platform",
    )
    def test_run_skips_non_apple_xattrs(self, tmp_path):
        """Non-apple xattrs are ignored."""
        test_file = tmp_path / "file.txt"
        test_file.write_bytes(b"hello")

        with (
            patch("os.listxattr", return_value=["user.custom", "security.selinux"]),
            patch("os.getxattr", return_value=b"value"),
        ):
            m = XattrMetadata(target_path=str(tmp_path))
            m.run()

        assert len(m.results) == 0

    @pytest.mark.skipif(
        not hasattr(__import__("os"), "listxattr"),
        reason="xattrs not supported on this platform",
    )
    def test_run_multiple_attributes(self, tmp_path):
        """Multiple relevant xattrs on one file each produce a result."""
        test_file = tmp_path / "app.pkg"
        test_file.write_bytes(b"dummy")

        quarantine = b"0083;5e4fbe3c;Safari;GUID"
        where_froms = plistlib.dumps(
            ["https://example.org/app.pkg"],
            fmt=plistlib.FMT_BINARY,
        )

        def fake_listxattr(path, follow_symlinks=True):
            return [
                "com.apple.quarantine",
                "com.apple.metadata:kMDItemWhereFroms",
            ]

        def fake_getxattr(path, name, follow_symlinks=True):
            if name == "com.apple.quarantine":
                return quarantine
            return where_froms

        with (
            patch("os.listxattr", side_effect=fake_listxattr),
            patch("os.getxattr", side_effect=fake_getxattr),
        ):
            m = XattrMetadata(target_path=str(tmp_path))
            m.run()

        assert len(m.results) == 2
        attr_names = {r["attribute_name"] for r in m.results}
        assert "com.apple.quarantine" in attr_names
        assert "com.apple.metadata:kMDItemWhereFroms" in attr_names
