# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import gzip
import logging
import os
import struct
from typing import Generator, Iterator, Optional

from mvt.common.module_types import (
    ModuleAtomicResult,
    ModuleResults,
    ModuleSerializedResult,
)
from mvt.common.normalized_timeline import NormalizedTimelineMixin, NormalizedTimelineRecord
from mvt.common.utils import convert_unix_to_iso

from ..base import IOSExtraction

# ---------------------------------------------------------------------------
# File-level constants
# ---------------------------------------------------------------------------

# Files inside .fseventsd that are metadata, not binary log data.
FSEVENTSD_SKIP_FILES = {"fseventsd-uuid"}

# Page magic bytes that identify the FSEvents on-disk format version.
#   DLS1 – records contain: path + event_id(u64) + flags(u32)
#   DLS2 – records contain: path + event_id(u64) + flags(u32) + node_id(u64)
# All integers are little-endian.
_MAGIC_DLS1 = b"DLS1"
_MAGIC_DLS2 = b"DLS2"
_KNOWN_MAGICS = (_MAGIC_DLS1, _MAGIC_DLS2)

# 12-byte page header:  magic(4s)  page_data_size(I)  record_count(I)
# page_data_size is the byte count of the records that follow the header,
# i.e. it does NOT include the header itself.
_PAGE_HEADER = struct.Struct("<4sII")

# Fixed-size tail that follows each null-terminated path string.
# DLS1: event_id(Q) + flags(I)              → 12 bytes
# DLS2: event_id(Q) + flags(I) + node_id(Q) → 20 bytes
_RECORD_TAIL_V1 = struct.Struct("<QI")
_RECORD_TAIL_V2 = struct.Struct("<QIQ")

# Sanity cap on the page data size advertised in the header (16 MiB).
# Guards against corrupt or deliberately crafted size fields causing
# excessive memory allocation.
_MAX_PAGE_DATA_SIZE = 16 * 1024 * 1024

# ---------------------------------------------------------------------------
# FSEvents flag definitions
# ---------------------------------------------------------------------------
# Source: Apple FSEvents.h (public SDK) and community reverse engineering.
# Keys are individual bitmask values; values are short, human-readable names.
FSEVENT_FLAGS: dict = {
    0x00000001: "MustScanSubDirs",
    0x00000002: "UserDropped",
    0x00000004: "KernelDropped",
    0x00000008: "EventIdsWrapped",
    0x00000010: "HistoryDone",
    0x00000020: "RootChanged",
    0x00000040: "Mount",
    0x00000080: "Unmount",
    0x00000100: "Created",
    0x00000200: "Removed",
    0x00000400: "InodeMetaMod",
    0x00000800: "Renamed",
    0x00001000: "Modified",
    0x00002000: "FinderInfoMod",
    0x00004000: "ChangeOwner",
    0x00008000: "XattrMod",
    0x00010000: "IsFile",
    0x00020000: "IsDir",
    0x00040000: "IsSymlink",
    0x00080000: "OwnEvent",
    0x00100000: "IsHardlink",
    0x00200000: "IsLastHardlink",
    0x00400000: "ItemCloned",
}

# Pre-computed OR-mask of every known flag bit.  Used to isolate unknown bits
# without iterating FSEVENT_FLAGS twice.
_KNOWN_FLAGS_MASK: int = 0
for _bit in FSEVENT_FLAGS:
    _KNOWN_FLAGS_MASK |= _bit


def _decode_flags(flags_raw: int) -> list:
    """Decode a raw FSEvents flags bitmask into a list of human-readable names.

    Each set bit that maps to a known flag name is returned by name.
    Any remaining set bits (unknown flags) are appended as a single hex
    string so that no information is lost.

    :param flags_raw: Raw uint32 bitmask from a FSEvents record.
    :returns: List of flag name strings; may include an ``Unknown(0x…)`` entry.
    """
    decoded = [name for bit, name in FSEVENT_FLAGS.items() if flags_raw & bit]
    unknown_bits = flags_raw & ~_KNOWN_FLAGS_MASK
    if unknown_bits:
        decoded.append(f"Unknown(0x{unknown_bits:08x})")
    return decoded


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class FSEvents(NormalizedTimelineMixin, IOSExtraction):
    """Parse FSEvents binary log files from .fseventsd directories in a full
    iOS filesystem dump.

    FSEvents logs record filesystem activity (file creation, deletion, rename,
    modification) and are valuable for establishing file timelines and
    identifying artefacts left by spyware.

    **On-disk format summary**

    Each ``.fseventsd`` log file is a gzip-compressed byte stream containing
    one or more fixed-format *pages*.  A page begins with a 12-byte header::

        magic         4 bytes  – b"DLS1" or b"DLS2"
        page_data_size 4 bytes  – uint32 LE, byte count of records that follow
        record_count  4 bytes  – uint32 LE, number of records in this page

    Immediately after the header come ``record_count`` variable-length records.
    Each record is::

        path          N+1 bytes – UTF-8 string, null-terminated
        event_id      8 bytes   – uint64 LE, monotonically increasing
        flags         4 bytes   – uint32 LE, bitmask (see FSEVENT_FLAGS)
        node_id       8 bytes   – uint64 LE, inode number (DLS2 only)

    **Timestamps**

    FSEvents records do not embed a timestamp.  This module uses the log
    file's ``st_mtime`` as an approximate timestamp for all records within
    that file, and records this explicitly in the ``timestamp`` result field.
    """

    slug = "fsevents"

    def __init__(
        self,
        file_path: Optional[str] = None,
        target_path: Optional[str] = None,
        results_path: Optional[str] = None,
        module_options: Optional[dict] = None,
        log: logging.Logger = logging.getLogger(__name__),
        results: ModuleResults = [],
    ) -> None:
        super().__init__(
            file_path=file_path,
            target_path=target_path,
            results_path=results_path,
            module_options=module_options,
            log=log,
            results=results,
        )

    # ------------------------------------------------------------------
    # MVTModule interface
    # ------------------------------------------------------------------

    def serialize(self, record: ModuleAtomicResult) -> ModuleSerializedResult:
        flags_str = (
            ", ".join(record["flags_decoded"]) if record["flags_decoded"] else "none"
        )
        return {
            "timestamp": record["timestamp"],
            "module": self.__class__.__name__,
            "event": "fseventsd_record",
            "data": (
                f"{record['path']} "
                f"[event_id={record['event_id']} flags={flags_str}] "
                f"(source: {record['source_log_file']})"
            ),
        }

    def normalize_record(self, result: dict) -> NormalizedTimelineRecord:
        flags_str = ", ".join(result.get("flags_decoded") or []) or "none"
        return NormalizedTimelineRecord(
            timestamp=result.get("timestamp", ""),
            module=self.__class__.__name__,
            artifact_type="fsevent",
            path=result.get("path", ""),
            event_type=flags_str,
            description=f"{flags_str} (event_id={result.get('event_id', '')})",
            source_file=result.get("source_log_file", ""),
            raw=dict(result),
        )

    def check_indicators(self) -> None:
        if not self.indicators:
            return

        for result in self.results:
            # result["path"] is the iOS filesystem path recorded in the
            # FSEvents event (e.g. /private/var/mobile/…), not the log file.
            if "path" not in result:
                continue

            ioc_match = self.indicators.check_file_path(result["path"])
            if ioc_match:
                self.alertstore.high(
                    ioc_match.message,
                    result.get("timestamp", ""),
                    result,
                    matched_indicator=ioc_match.ioc,
                )

            # If we are instructed to run fast, we skip the rest.
            if self.module_options.get("fast_mode", None):
                continue

            ioc_match = self.indicators.check_file_path_process(result["path"])
            if ioc_match:
                self.alertstore.high(
                    ioc_match.message,
                    result.get("timestamp", ""),
                    result,
                    matched_indicator=ioc_match.ioc,
                )

    # ------------------------------------------------------------------
    # Binary parsing helpers
    # ------------------------------------------------------------------

    def _parse_page(
        self,
        page_data: bytes,
        magic: bytes,
        record_count: int,
        source_log_file: str,
        file_timestamp: str,
    ) -> Generator[dict, None, None]:
        """Parse records from one decompressed FSEvents page buffer.

        Yields one result dict per successfully decoded record.  On encountering
        a malformed record the remainder of *this page* is skipped (with a
        warning), but the caller continues to the next page.

        :param page_data: Raw decompressed bytes for this page (header excluded).
        :param magic: Page magic bytes – determines whether node_id is present.
        :param record_count: Expected number of records (from page header).
        :param source_log_file: Relative log-file path (for result provenance).
        :param file_timestamp: ISO timestamp from the log file's mtime.
        """
        tail_struct = _RECORD_TAIL_V2 if magic == _MAGIC_DLS2 else _RECORD_TAIL_V1
        tail_size = tail_struct.size
        page_len = len(page_data)
        offset = 0

        for record_idx in range(record_count):
            if offset >= page_len:
                self.log.debug(
                    "Page exhausted after %d/%d records in %s",
                    record_idx,
                    record_count,
                    source_log_file,
                )
                break

            # Locate the null terminator that ends the path string.
            null_pos = page_data.find(b"\x00", offset)
            if null_pos == -1:
                self.log.warning(
                    "No null terminator for record %d in %s; "
                    "skipping remainder of page",
                    record_idx,
                    source_log_file,
                )
                break

            path_bytes = page_data[offset:null_pos]
            offset = null_pos + 1

            # Ensure the fixed tail fits in the remaining page data.
            if offset + tail_size > page_len:
                self.log.warning(
                    "Insufficient bytes for fixed tail of record %d in %s "
                    "(need %d, have %d); skipping remainder of page",
                    record_idx,
                    source_log_file,
                    tail_size,
                    page_len - offset,
                )
                break

            try:
                tail = tail_struct.unpack_from(page_data, offset)
            except struct.error as exc:
                self.log.warning(
                    "Struct unpack failed for record %d in %s: %s; "
                    "skipping remainder of page",
                    record_idx,
                    source_log_file,
                    exc,
                )
                break

            offset += tail_size
            event_id, flags_raw = tail[0], tail[1]
            # tail[2] is node_id (DLS2 only) – captured implicitly by the
            # struct but not exposed in results to keep schema stable.

            try:
                path_str = path_bytes.decode("utf-8")
            except UnicodeDecodeError:
                path_str = path_bytes.decode("utf-8", errors="replace")
                self.log.debug(
                    "Non-UTF-8 bytes in path of record %d in %s; "
                    "replaced invalid bytes with U+FFFD",
                    record_idx,
                    source_log_file,
                )

            yield {
                "timestamp": file_timestamp,
                "event_id": event_id,
                "path": path_str,
                "flags_raw": flags_raw,
                "flags_decoded": _decode_flags(flags_raw),
                "source_log_file": source_log_file,
            }

    def _parse_fseventsd_file(
        self,
        abs_path: str,
        rel_path: str,
        file_timestamp: str,
    ) -> Iterator[dict]:
        """Stream-parse one gzip-compressed FSEvents log file.

        Pages are processed one at a time: the page header is read to
        determine the page data size, that many bytes are decompressed and
        parsed, then the next page header is read.  Only one page worth of
        decompressed data is held in memory at any point.

        Non-fatal errors (truncated pages, unknown magic) emit warnings and
        stop parsing the current file.  Fatal I/O or gzip errors are logged
        and cause an early return, so the caller can continue to the next
        file.

        :param abs_path: Absolute path to the log file on disk.
        :param rel_path: Relative path used as the ``source_log_file`` value.
        :param file_timestamp: ISO timestamp derived from the log file's mtime.
        """
        try:
            gz = gzip.open(abs_path, "rb")
        except OSError as exc:
            self.log.error("Cannot open %s: %s", rel_path, exc)
            return

        page_index = 0
        try:
            while True:
                # ---- read page header ----
                header_bytes = gz.read(_PAGE_HEADER.size)
                if not header_bytes:
                    break  # clean EOF
                if len(header_bytes) < _PAGE_HEADER.size:
                    self.log.warning(
                        "Truncated page header at page %d in %s "
                        "(got %d bytes, expected %d); stopping",
                        page_index,
                        rel_path,
                        len(header_bytes),
                        _PAGE_HEADER.size,
                    )
                    break

                try:
                    magic, page_data_size, record_count = _PAGE_HEADER.unpack(
                        header_bytes
                    )
                except struct.error as exc:
                    self.log.warning(
                        "Cannot unpack page header at page %d in %s: %s; stopping",
                        page_index,
                        rel_path,
                        exc,
                    )
                    break

                if magic not in _KNOWN_MAGICS:
                    self.log.warning(
                        "Unknown magic %r at page %d in %s; stopping",
                        magic,
                        page_index,
                        rel_path,
                    )
                    break

                if page_data_size > _MAX_PAGE_DATA_SIZE:
                    self.log.warning(
                        "Implausible page data size %d at page %d in %s "
                        "(limit %d); stopping",
                        page_data_size,
                        page_index,
                        rel_path,
                        _MAX_PAGE_DATA_SIZE,
                    )
                    break

                # ---- read page data ----
                page_data = gz.read(page_data_size)
                if len(page_data) < page_data_size:
                    self.log.warning(
                        "Truncated page data at page %d in %s "
                        "(expected %d bytes, got %d); attempting partial parse",
                        page_index,
                        rel_path,
                        page_data_size,
                        len(page_data),
                    )
                    # Fall through: _parse_page will stop when bytes run out.

                if record_count > 0:
                    yield from self._parse_page(
                        page_data,
                        magic,
                        record_count,
                        rel_path,
                        file_timestamp,
                    )

                page_index += 1

        except gzip.BadGzipFile:
            self.log.warning(
                "%s is not a valid gzip stream; skipping", rel_path
            )
        except EOFError:
            self.log.warning(
                "Unexpected EOF while reading %s at page %d", rel_path, page_index
            )
        except OSError as exc:
            self.log.error("I/O error reading %s: %s", rel_path, exc)
        finally:
            try:
                gz.close()
            except OSError:
                pass

    # ------------------------------------------------------------------
    # Directory / file enumeration
    # ------------------------------------------------------------------

    def _process_fseventsd_dir(self, fseventsd_path: str) -> None:
        """Parse all FSEvents log files inside a single .fseventsd directory.

        :param fseventsd_path: Absolute path to the .fseventsd directory.
        """
        try:
            entries = list(os.scandir(fseventsd_path))
        except OSError as exc:
            self.log.error(
                "Cannot read .fseventsd directory %s: %s", fseventsd_path, exc
            )
            return

        for entry in entries:
            try:
                is_file = entry.is_file(follow_symlinks=False)
            except OSError as exc:
                self.log.warning(
                    "Cannot determine type of %s: %s", entry.path, exc
                )
                continue

            if not is_file:
                continue

            if entry.name in FSEVENTSD_SKIP_FILES:
                self.log.debug("Skipping non-log file: %s", entry.name)
                continue

            try:
                stat = entry.stat(follow_symlinks=False)
                file_timestamp = convert_unix_to_iso(stat.st_mtime)
                size = stat.st_size
            except OSError as exc:
                self.log.warning(
                    "Cannot stat %s: %s", entry.path, exc
                )
                file_timestamp = ""
                size = None

            rel_path = os.path.relpath(entry.path, self.target_path)
            self.log.info(
                "Parsing FSEvents log file: %s (%s bytes)", rel_path, size
            )

            count_before = len(self.results)
            for record in self._parse_fseventsd_file(
                entry.path, rel_path, file_timestamp
            ):
                self.results.append(record)

            self.log.debug(
                "Parsed %d record(s) from %s",
                len(self.results) - count_before,
                rel_path,
            )

    def run(self) -> None:
        if not self.target_path:
            self.log.error("No target path set; cannot search for .fseventsd")
            return

        found_dirs = 0
        for root, dirs, _ in os.walk(self.target_path):
            for dir_name in dirs:
                if dir_name != ".fseventsd":
                    continue

                fseventsd_path = os.path.join(root, dir_name)
                self.log.info(
                    "Found .fseventsd directory at: %s", fseventsd_path
                )
                self._process_fseventsd_dir(fseventsd_path)
                found_dirs += 1

        if found_dirs == 0:
            self.log.info(
                "No .fseventsd directory found in filesystem dump at %s",
                self.target_path,
            )
        else:
            self.log.info(
                "Extracted %d FSEvents record(s) from %d .fseventsd director%s",
                len(self.results),
                found_dirs,
                "y" if found_dirs == 1 else "ies",
            )
