# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import gzip
import io
import logging
import struct

from mvt.common.indicators import Indicators
from mvt.common.module import run_module
from mvt.ios.modules.fs.fsevents import (
    FSEVENT_FLAGS,
    FSEvents,
    _decode_flags,
)

# ---------------------------------------------------------------------------
# Test fixture helpers
# ---------------------------------------------------------------------------

_DLS1 = b"DLS1"
_DLS2 = b"DLS2"


def _build_page_v1(records):
    """Serialise DLS1 records into raw (uncompressed) page bytes including header.

    :param records: Iterable of (path_str, event_id, flags) tuples.
    :returns: bytes – page header + page data.
    """
    page_buf = io.BytesIO()
    rec_list = list(records)
    for path_str, event_id, flags in rec_list:
        page_buf.write(path_str.encode("utf-8") + b"\x00")
        page_buf.write(struct.pack("<QI", event_id, flags))
    page_data = page_buf.getvalue()
    header = struct.pack("<4sII", _DLS1, len(page_data), len(rec_list))
    return header + page_data


def _build_page_v2(records):
    """Serialise DLS2 records (with node_id) into raw page bytes including header.

    :param records: Iterable of (path_str, event_id, flags, node_id) tuples.
    :returns: bytes – page header + page data.
    """
    page_buf = io.BytesIO()
    rec_list = list(records)
    for path_str, event_id, flags, node_id in rec_list:
        page_buf.write(path_str.encode("utf-8") + b"\x00")
        page_buf.write(struct.pack("<QIQ", event_id, flags, node_id))
    page_data = page_buf.getvalue()
    header = struct.pack("<4sII", _DLS2, len(page_data), len(rec_list))
    return header + page_data


def _gzip(raw_bytes):
    """Gzip-compress raw bytes and return the compressed bytes."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as gz:
        gz.write(raw_bytes)
    return buf.getvalue()


def _write_log(path, pages_bytes):
    """Write gzip-compressed FSEvents log data to *path* (a pathlib.Path)."""
    path.write_bytes(_gzip(pages_bytes))


# ---------------------------------------------------------------------------
# Unit tests for the flag decoder (no I/O needed)
# ---------------------------------------------------------------------------


class TestDecodeFlags:
    def test_no_flags(self):
        assert _decode_flags(0x0) == []

    def test_single_known_flag(self):
        assert _decode_flags(0x00000100) == ["Created"]

    def test_multiple_known_flags(self):
        result = _decode_flags(0x00000100 | 0x00010000)  # Created | IsFile
        assert "Created" in result
        assert "IsFile" in result
        assert len(result) == 2

    def test_all_known_flags_covered(self):
        """Every entry in FSEVENT_FLAGS is decoded for the all-ones mask."""
        all_known = 0
        for bit in FSEVENT_FLAGS:
            all_known |= bit
        decoded = _decode_flags(all_known)
        assert set(decoded) == set(FSEVENT_FLAGS.values())

    def test_unknown_flag_preserved_as_hex(self):
        unknown_bit = 0x80000000  # not in FSEVENT_FLAGS
        decoded = _decode_flags(unknown_bit)
        assert len(decoded) == 1
        assert decoded[0].startswith("Unknown(0x")
        assert "80000000" in decoded[0]

    def test_mixed_known_and_unknown(self):
        flags = 0x00000100 | 0x80000000  # Created + unknown
        decoded = _decode_flags(flags)
        assert "Created" in decoded
        assert any("Unknown" in f for f in decoded)


# ---------------------------------------------------------------------------
# Integration tests – FSEvents module
# ---------------------------------------------------------------------------


class TestFSEvents:
    # ---- basic directory discovery ----------------------------------------

    def test_no_fseventsd(self, tmp_path):
        """Module produces no results when the dump contains no .fseventsd."""
        m = FSEvents(target_path=str(tmp_path))
        run_module(m)
        assert m.results == []
        assert len(m.alertstore.alerts) == 0

    def test_nested_fseventsd(self, tmp_path):
        """A .fseventsd directory nested inside the dump tree is discovered."""
        nested = tmp_path / "private" / "var" / ".fseventsd"
        nested.mkdir(parents=True)
        _write_log(
            nested / "0000000000000001",
            _build_page_v1([("/private/var/mobile/test", 1, 0x00000100)]),
        )

        m = FSEvents(target_path=str(tmp_path))
        run_module(m)
        assert len(m.results) == 1

    def test_uuid_file_skipped(self, tmp_path):
        """fseventsd-uuid is excluded; other files are parsed."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        (fseventsd / "fseventsd-uuid").write_bytes(b"some-uuid-value")
        _write_log(
            fseventsd / "0000000000000001",
            _build_page_v1([("/private/var/mobile/test", 1, 0x00000100)]),
        )

        m = FSEvents(target_path=str(tmp_path))
        run_module(m)
        assert len(m.results) == 1
        assert all("fseventsd-uuid" not in r["source_log_file"] for r in m.results)

    # ---- DLS1 parsing -------------------------------------------------------

    def test_dls1_single_record(self, tmp_path):
        """A single DLS1 record is parsed into a result with correct fields."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        _write_log(
            fseventsd / "0000000000000001",
            _build_page_v1(
                [("/private/var/mobile/spyware", 0xDEADBEEF, 0x00000101)]
            ),
        )

        m = FSEvents(target_path=str(tmp_path))
        run_module(m)

        assert len(m.results) == 1
        r = m.results[0]
        assert r["path"] == "/private/var/mobile/spyware"
        assert r["event_id"] == 0xDEADBEEF
        assert r["flags_raw"] == 0x00000101
        assert "Created" in r["flags_decoded"]
        assert "MustScanSubDirs" in r["flags_decoded"]
        assert r["timestamp"] != ""
        assert "source_log_file" in r

    def test_dls1_multiple_records_same_page(self, tmp_path):
        """Multiple records within one DLS1 page are all parsed."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        records = [
            ("/private/var/mobile/a", 1, 0x00000100),
            ("/private/var/mobile/b", 2, 0x00000200),
            ("/private/var/mobile/c", 3, 0x00001000),
        ]
        _write_log(fseventsd / "0000000000000001", _build_page_v1(records))

        m = FSEvents(target_path=str(tmp_path))
        run_module(m)
        assert len(m.results) == 3
        paths = [r["path"] for r in m.results]
        assert "/private/var/mobile/a" in paths
        assert "/private/var/mobile/b" in paths
        assert "/private/var/mobile/c" in paths

    def test_dls1_multiple_pages(self, tmp_path):
        """Records spread across multiple DLS1 pages in one file are all parsed."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        page1 = _build_page_v1([("/private/var/mobile/a", 1, 0x00000100)])
        page2 = _build_page_v1([("/private/var/mobile/b", 2, 0x00000200)])
        _write_log(fseventsd / "0000000000000001", page1 + page2)

        m = FSEvents(target_path=str(tmp_path))
        run_module(m)
        assert len(m.results) == 2

    def test_dls1_multiple_log_files(self, tmp_path):
        """Records from multiple log files in .fseventsd are all collected."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        for i, name in enumerate(
            ("0000000000000001", "0000000000000002", "0000000000000003")
        ):
            _write_log(
                fseventsd / name,
                _build_page_v1([(f"/private/var/mobile/file{i}", i, 0x00000100)]),
            )

        m = FSEvents(target_path=str(tmp_path))
        run_module(m)
        assert len(m.results) == 3

    # ---- DLS2 parsing -------------------------------------------------------

    def test_dls2_record_parsed(self, tmp_path):
        """A DLS2 record (with node_id) is parsed correctly."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        _write_log(
            fseventsd / "0000000000000001",
            _build_page_v2(
                [("/private/var/mobile/target", 0xCAFE, 0x00010100, 0x1234)]
            ),
        )

        m = FSEvents(target_path=str(tmp_path))
        run_module(m)

        assert len(m.results) == 1
        r = m.results[0]
        assert r["path"] == "/private/var/mobile/target"
        assert r["event_id"] == 0xCAFE
        assert r["flags_raw"] == 0x00010100
        assert "Created" in r["flags_decoded"]
        assert "IsFile" in r["flags_decoded"]

    # ---- result schema and timeline ----------------------------------------

    def test_result_schema(self, tmp_path):
        """Each result contains the required fields."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        _write_log(
            fseventsd / "0000000000000001",
            _build_page_v1([("/some/path", 99, 0x00000100)]),
        )

        m = FSEvents(target_path=str(tmp_path))
        run_module(m)

        required = {"timestamp", "event_id", "path", "flags_raw", "flags_decoded",
                    "source_log_file"}
        for result in m.results:
            assert required.issubset(result.keys()), (
                f"Missing keys: {required - result.keys()}"
            )

    def test_timeline_populated(self, tmp_path):
        """Each record produces one timeline entry with correct module and event."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        records = [
            ("/private/var/a", 1, 0x00000100),
            ("/private/var/b", 2, 0x00000200),
        ]
        _write_log(fseventsd / "0000000000000001", _build_page_v1(records))

        m = FSEvents(target_path=str(tmp_path))
        run_module(m)

        assert len(m.timeline) == 2
        for entry in m.timeline:
            assert entry["module"] == "FSEvents"
            assert entry["event"] == "fseventsd_record"

    def test_source_log_file_set(self, tmp_path):
        """source_log_file on each record is a relative path ending with the
        log file name."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        _write_log(
            fseventsd / "0000000000abcdef",
            _build_page_v1([("/some/path", 1, 0x00000100)]),
        )

        m = FSEvents(target_path=str(tmp_path))
        run_module(m)

        assert len(m.results) == 1
        assert m.results[0]["source_log_file"].endswith("0000000000abcdef")

    # ---- error tolerance ----------------------------------------------------

    def test_not_gzip_skipped_gracefully(self, tmp_path):
        """A file that is not a gzip stream is skipped without crashing.
        The module produces zero results rather than raising an exception."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        (fseventsd / "0000000000000001").write_bytes(b"\x00" * 512)

        m = FSEvents(target_path=str(tmp_path))
        run_module(m)
        # The uncompressed garbage is not parseable; no crash, zero results.
        assert len(m.alertstore.alerts) == 0

    def test_unknown_page_magic_stops_file(self, tmp_path):
        """A page with an unrecognised magic stops parsing that file but does
        not prevent earlier valid pages from being collected."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()

        good_page = _build_page_v1([("/private/var/good", 1, 0x00000100)])
        # Craft a page with unknown magic to corrupt the second page.
        bad_header = struct.pack("<4sII", b"XYZW", 0, 0)
        _write_log(fseventsd / "0000000000000001", good_page + bad_header)

        m = FSEvents(target_path=str(tmp_path))
        run_module(m)
        # The first page's record should have been parsed before the bad magic.
        assert len(m.results) == 1
        assert m.results[0]["path"] == "/private/var/good"

    def test_truncated_file_no_crash(self, tmp_path):
        """A truncated gzip file does not raise an exception."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        full = _gzip(_build_page_v1([("/private/var/truncated", 1, 0x00000100)]))
        # Write only the first half of the gzip stream.
        (fseventsd / "0000000000000001").write_bytes(full[: len(full) // 2])

        m = FSEvents(target_path=str(tmp_path))
        run_module(m)  # must not raise
        assert len(m.alertstore.alerts) == 0

    def test_oversized_page_stops_file(self, tmp_path):
        """A page whose advertised data size exceeds the safety cap is rejected."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        # Craft a header with an implausible data size.
        oversized_header = struct.pack("<4sII", _DLS1, 0xFFFFFFFF, 1)
        _write_log(fseventsd / "0000000000000001", oversized_header)

        m = FSEvents(target_path=str(tmp_path))
        run_module(m)  # must not crash or allocate 4 GiB
        assert m.results == []

    def test_empty_page_skipped(self, tmp_path):
        """A page with record_count=0 is skipped without error."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        empty_page = struct.pack("<4sII", _DLS1, 0, 0)
        real_page = _build_page_v1([("/private/var/ok", 1, 0x00000100)])
        _write_log(fseventsd / "0000000000000001", empty_page + real_page)

        m = FSEvents(target_path=str(tmp_path))
        run_module(m)
        assert len(m.results) == 1

    # ---- IOC detection ------------------------------------------------------

    def test_ioc_detection_via_process_in_path(self, tmp_path, indicator_file):
        """A record whose iOS path contains a known malicious process name
        ('Launch', from the shared STIX fixture) triggers a high alert via
        check_file_path_process()."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        # The path component 'Launch' is in the STIX 'processes' IOC list.
        _write_log(
            fseventsd / "0000000000000001",
            _build_page_v1([("/private/var/mobile/Launch", 1, 0x00000100)]),
        )

        m = FSEvents(target_path=str(tmp_path))
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        run_module(m)

        assert len(m.results) == 1
        assert len(m.alertstore.alerts) == 1
        alert = m.alertstore.alerts[0]
        assert alert.matched_indicator is not None

    def test_no_ioc_match(self, tmp_path, indicator_file):
        """A record with an innocuous path produces no alert."""
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        _write_log(
            fseventsd / "0000000000000001",
            _build_page_v1([("/private/var/mobile/Photos/innocuous.jpg", 1, 0x00001000)]),
        )

        m = FSEvents(target_path=str(tmp_path))
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        run_module(m)

        assert len(m.results) == 1
        assert len(m.alertstore.alerts) == 0

    def test_both_ioc_checks_run_without_fast_mode(self, tmp_path, indicators_factory):
        """Both check_file_path and check_file_path_process run for every
        record when fast_mode is not set.

        The path /private/var/mobile/Launch triggers:
          - check_file_path  via check_file_name("Launch") matching the
            "Launch" entry injected into file_names.
          - check_file_path_process via "Launch" appearing as a path component,
            matching the "Launch" entry already in the processes IOC collection
            (present in the shared STIX fixture).

        Without fast_mode both checks fire, producing two alerts for one record.
        """
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        _write_log(
            fseventsd / "0000000000000001",
            _build_page_v1([("/private/var/mobile/Launch", 1, 0x00000100)]),
        )

        m = FSEvents(target_path=str(tmp_path))
        # "Launch" is already a process IOC in the STIX fixture; also add it
        # as a file_name IOC so check_file_path fires on the same record.
        m.indicators = indicators_factory(file_names=["Launch"])
        run_module(m)

        assert len(m.results) == 1
        assert len(m.alertstore.alerts) == 2

    def test_fast_mode_skips_process_check(self, tmp_path, indicator_file):
        """With fast_mode enabled, check_file_path_process is not run.

        The path /private/var/mobile/Launch matches check_file_path_process
        (since "Launch" is a process IOC) but not check_file_path (no
        file_name or file_path IOC matches its basename or prefix). With
        fast_mode=True the second check is skipped, producing zero alerts.
        """
        fseventsd = tmp_path / ".fseventsd"
        fseventsd.mkdir()
        _write_log(
            fseventsd / "0000000000000001",
            _build_page_v1([("/private/var/mobile/Launch", 1, 0x00000100)]),
        )

        m = FSEvents(
            target_path=str(tmp_path),
            module_options={"fast_mode": True},
        )
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind
        run_module(m)

        assert len(m.results) == 1
        assert len(m.alertstore.alerts) == 0

    def test_path_guard_tolerates_missing_key(self, indicator_file):
        """Results that lack a 'path' key are silently skipped.

        This guards against future code paths that might append incomplete
        result dicts (e.g. partially-parsed records) without crashing the
        entire indicator check loop.
        """
        m = FSEvents(
            results=[
                {"timestamp": "", "event_id": 0, "flags_raw": 0,
                 "flags_decoded": [], "source_log_file": "test"},
            ]
        )
        ind = Indicators(log=logging.getLogger())
        ind.parse_stix2(indicator_file)
        m.indicators = ind

        m.check_indicators()  # must not raise KeyError

        assert len(m.alertstore.alerts) == 0

    def test_slug_is_fsevents(self):
        """Module slug must be 'fsevents' so save_to_json() writes fsevents.json."""
        assert FSEvents.slug == "fsevents"
