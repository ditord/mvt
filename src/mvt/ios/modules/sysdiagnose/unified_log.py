# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

"""Prototype: Unified Log extraction from sysdiagnose archives.

Requires macOS with the system `log` binary.  On other platforms the module
logs an informational message and exits without error.  Absence of findings
does NOT rule out compromise — this module has significant coverage gaps
compared to what a full tracev3 parser would provide.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Iterator, List, Optional
from urllib.parse import urlparse

from mvt.common.module_types import (
    ModuleAtomicResult,
    ModuleResults,
    ModuleSerializedResult,
)
from mvt.common.normalized_timeline import NormalizedTimelineMixin, NormalizedTimelineRecord
from mvt.common.utils import convert_datetime_to_iso

from .base import SysdiagnoseModule

# ---------------------------------------------------------------------------
# Platform / binary detection — evaluated once at import time so tests can
# patch them at module level (same pattern as _HAS_XATTR in xattr_metadata).
# ---------------------------------------------------------------------------

_IS_MACOS: bool = sys.platform == "darwin"
_LOG_BINARY: Optional[str] = shutil.which("log") if _IS_MACOS else None
_LOGARCHIVE_SUFFIX: str = ".logarchive"

# Conservative defaults — prevents OOM on large archives.
_DEFAULT_MAX_EVENTS: int = 5_000
_DEFAULT_TIMEOUT_SECONDS: int = 120

# ---------------------------------------------------------------------------
# Extraction regexes
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Paths under directories that are forensically relevant on iOS/macOS.
_PATH_RE = re.compile(
    r"(?<!\w)(/(?:private/)?(?:var|tmp|Library|System|Applications)"
    r"/[^\s\"'<>\[\]{},;:\\]{4,})"
)


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def _extract_urls(text: str) -> List[str]:
    return list(dict.fromkeys(_URL_RE.findall(text)))


def _extract_domains(urls: List[str]) -> List[str]:
    seen: dict = {}
    for url in urls:
        try:
            netloc = urlparse(url).netloc
            if not netloc:
                continue
            domain = netloc[4:] if netloc.startswith("www.") else netloc
            domain = domain.lower()
            if domain:
                seen[domain] = None
        except Exception:
            continue
    return list(seen)


def _extract_ips(text: str) -> List[str]:
    return list(dict.fromkeys(_IPV4_RE.findall(text)))


def _extract_paths(text: str) -> List[str]:
    return list(dict.fromkeys(_PATH_RE.findall(text)))


def _normalize_timestamp(ts: str) -> str:
    """Normalize `log show --style json` timestamps to MVT ISO format.

    `log show` emits timestamps as "2024-01-15 10:23:41.000000-0800".
    """
    import datetime

    if not ts:
        return ""
    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ):
        try:
            dt = datetime.datetime.strptime(ts, fmt)
            return convert_datetime_to_iso(dt)
        except ValueError:
            continue
    return ts  # pass through if unparseable


# ---------------------------------------------------------------------------
# Module
# ---------------------------------------------------------------------------


class UnifiedLog(NormalizedTimelineMixin, SysdiagnoseModule):
    """Prototype: extract forensic events from Apple Unified Log archives.

    Locates .logarchive bundles inside a sysdiagnose archive or extracted
    directory and reads them with the macOS `log show` binary.  On non-macOS
    platforms the module skips gracefully without error.

    Limitations
    -----------
    - Requires macOS; produces no output on Linux/Windows.
    - Only the first ``max_events`` events per archive are ingested.
    - A timeout kills `log show` if it exceeds ``timeout`` seconds.
    - No built-in time-range filter; large archives may hit the event limit.
    - Absence of findings does NOT rule out compromise.
    """

    slug = "unified_log"

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
        self.max_events: int = _DEFAULT_MAX_EVENTS
        self.timeout: int = _DEFAULT_TIMEOUT_SECONDS

    # ------------------------------------------------------------------
    # Logarchive discovery
    # ------------------------------------------------------------------

    def _find_logarchives_in_dir(self) -> List[str]:
        """Return absolute paths of .logarchive directories under extract_path."""
        found: List[str] = []
        if not self.extract_path:
            return found
        for root, dirs, _ in os.walk(self.extract_path):
            for d in list(dirs):
                if d.endswith(_LOGARCHIVE_SUFFIX):
                    found.append(os.path.join(root, d))
                    dirs.remove(d)  # don't recurse inside the bundle
        return found

    def _find_logarchive_prefixes_in_tar(self) -> List[str]:
        """Return the .logarchive relative path prefixes present in the archive."""
        prefixes: dict = {}
        for f in self.all_files:
            normed = f.replace("\\", "/")
            idx = normed.find(_LOGARCHIVE_SUFFIX)
            if idx == -1:
                continue
            end = idx + len(_LOGARCHIVE_SUFFIX)
            # Require a '/' after the suffix — a bare "foo.logarchive" entry
            # with no trailing slash is a plain file, not a directory bundle.
            if end >= len(normed) or normed[end] != "/":
                continue
            prefixes[normed[:end]] = None
        return list(prefixes)

    def _extract_logarchive_from_tar(self, prefix: str, tmpdir: str) -> Optional[str]:
        """Extract a .logarchive bundle from the open tar archive into tmpdir.

        Returns the absolute path to the extracted bundle, or None on failure.
        Path traversal is guarded by checking that every destination path
        starts with the resolved tmpdir.
        """
        if not self.tar_archive:
            return None
        target = os.path.join(tmpdir, os.path.basename(prefix))
        safe_tmpdir = os.path.normpath(tmpdir)
        members = [
            m for m in self.tar_archive.getmembers()
            if m.name.replace("\\", "/").startswith(prefix + "/")
            or m.name.replace("\\", "/") == prefix
        ]
        if not members:
            return None
        for member in members:
            rel = member.name.replace("\\", "/")[len(prefix):].lstrip("/")
            dest = os.path.normpath(os.path.join(target, rel)) if rel else os.path.normpath(target)
            if not dest.startswith(safe_tmpdir + os.sep) and dest != safe_tmpdir:
                self.log.warning("Skipping member with suspicious path: %s", member.name)
                continue
            if member.isdir():
                os.makedirs(dest, exist_ok=True)
            elif member.isfile():
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                fh = self.tar_archive.extractfile(member)
                if fh is not None:
                    with open(dest, "wb") as out:
                        out.write(fh.read())
                    fh.close()
        return target

    # ------------------------------------------------------------------
    # log show execution and streaming JSON parser
    # ------------------------------------------------------------------

    def _make_cmd(self, logarchive_path: str) -> List[str]:
        """Build the `log show` argument list.  No shell=True."""
        assert _LOG_BINARY is not None  # guarded in run()
        return [
            _LOG_BINARY,
            "show",
            "--style", "json",
            "--archive", logarchive_path,
            "--info",
            "--debug",
        ]

    def _iter_events(self, stream) -> Iterator[dict]:
        """Stream-parse `log show --style json` output into event dicts.

        `log show --style json` emits a single large JSON array, potentially
        spanning millions of lines.  Rather than loading the whole array into
        memory, we accumulate lines into a rolling buffer and use
        ``json.JSONDecoder.raw_decode`` to peel off complete JSON objects as
        they become parseable.  The buffer is capped at 8 MB to guard against
        pathological input.
        """
        decoder = json.JSONDecoder()
        buf = ""
        emitted = 0

        for raw_line in stream:
            buf += raw_line

            # Cap buffer to avoid runaway memory use
            if len(buf) > 8 * 1024 * 1024:
                last_brace = buf.rfind("{")
                buf = buf[last_brace:] if last_brace != -1 else ""
                continue

            # Greedily consume complete JSON objects from the front of the buffer
            while True:
                buf = buf.lstrip()
                if not buf:
                    break
                if buf[0] in ("[", "]", ","):
                    buf = buf[1:]
                    continue
                if buf[0] != "{":
                    idx = buf.find("{")
                    buf = buf[idx:] if idx != -1 else ""
                    if not buf:
                        break
                    continue
                try:
                    obj, end = decoder.raw_decode(buf)
                    buf = buf[end:]
                except json.JSONDecodeError:
                    break  # Incomplete object — wait for more lines
                if isinstance(obj, dict):
                    yield obj
                    emitted += 1
                    if emitted >= self.max_events:
                        return

    def _build_result(self, event: dict, source_logarchive: str) -> dict:
        """Convert a raw `log show` event dict into an MVT result dict."""
        message = event.get("eventMessage", "") or ""
        urls = _extract_urls(message)
        domains = _extract_domains(urls)
        ips = _extract_ips(message)
        paths = _extract_paths(message)

        proc_path = event.get("processImagePath", "") or ""
        process = os.path.basename(proc_path) if proc_path else ""

        return {
            "source_logarchive": source_logarchive,
            "timestamp": _normalize_timestamp(event.get("timestamp", "") or ""),
            "process": process,
            "process_path": proc_path,
            "subsystem": event.get("subsystem", "") or "",
            "category": event.get("category", "") or "",
            "event_message": message,
            "event_type": event.get("eventType", "") or "",
            "sender": event.get("senderImagePath", "") or "",
            "extracted_urls": urls,
            "extracted_domains": domains,
            "extracted_ips": ips,
            "extracted_paths": paths,
        }

    def _process_logarchive(self, logarchive_path: str, source_name: str) -> None:
        """Run `log show` on *logarchive_path* and append results."""
        cmd = self._make_cmd(logarchive_path)
        self.log.info("Running: %s", " ".join(cmd))
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            self.log.error("Failed to launch 'log': %s", exc)
            return

        count_before = len(self.results)
        try:
            for event in self._iter_events(proc.stdout):
                self.results.append(self._build_result(event, source_name))
        finally:
            try:
                _, stderr = proc.communicate(timeout=self.timeout)
                if stderr:
                    self.log.debug("log stderr: %s", stderr[:500])
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.communicate()
                self.log.warning(
                    "'log show' exceeded %ds timeout for %s; results may be incomplete",
                    self.timeout,
                    source_name,
                )

        ingested = len(self.results) - count_before
        self.log.info("Extracted %d event(s) from %s", ingested, source_name)
        if ingested >= self.max_events:
            self.log.warning(
                "Event limit (%d) reached for %s; increase max_events for full coverage",
                self.max_events,
                source_name,
            )

    # ------------------------------------------------------------------
    # MVTModule interface
    # ------------------------------------------------------------------

    def serialize(self, record: ModuleAtomicResult) -> ModuleSerializedResult:
        sub = record.get("subsystem", "")
        cat = record.get("category", "")
        label = f"{sub}/{cat}" if sub and cat else sub or cat or "unified_log"
        msg = record.get("event_message", "")[:120]
        return {
            "timestamp": record.get("timestamp", ""),
            "module": self.__class__.__name__,
            "event": "unified_log",
            "data": f"[{label}] {msg}",
        }

    def check_indicators(self) -> None:
        if not self.indicators:
            return
        for result in self.results:
            if result.get("process"):
                ioc = self.indicators.check_process(result["process"])
                if ioc:
                    self.alertstore.high(
                        ioc.message, result.get("timestamp", ""), result,
                        matched_indicator=ioc.ioc,
                    )
            if result.get("process_path"):
                ioc = self.indicators.check_file_path(result["process_path"])
                if ioc:
                    self.alertstore.high(
                        ioc.message, result.get("timestamp", ""), result,
                        matched_indicator=ioc.ioc,
                    )
            for url in result.get("extracted_urls", []):
                ioc = self.indicators.check_url(url)
                if ioc:
                    self.alertstore.high(
                        ioc.message, result.get("timestamp", ""), result,
                        matched_indicator=ioc.ioc,
                    )

    def normalize_record(self, result: dict) -> Optional[NormalizedTimelineRecord]:
        urls = result.get("extracted_urls", [])
        domains = result.get("extracted_domains", [])
        paths = result.get("extracted_paths", [])
        sub = result.get("subsystem", "")
        cat = result.get("category", "")
        label = f"{sub}/{cat}".strip("/") if (sub or cat) else ""
        msg = result.get("event_message", "")[:120]
        description = f"[{label}] {msg}".strip() if label else msg

        return NormalizedTimelineRecord(
            timestamp=result.get("timestamp", ""),
            module=self.__class__.__name__,
            artifact_type="unified_log",
            path=paths[0] if paths else result.get("sender", ""),
            process=result.get("process", ""),
            domain=domains[0] if domains else "",
            url=urls[0] if urls else "",
            event_type=result.get("event_type", ""),
            description=description,
            source_file=result.get("source_logarchive", ""),
            raw=dict(result),
        )

    def run(self) -> None:
        if not _IS_MACOS:
            self.log.info(
                "UnifiedLog module requires macOS with the 'log' binary; "
                "skipping on %s — absence of findings does not rule out compromise",
                sys.platform,
            )
            return
        if not _LOG_BINARY:
            self.log.warning(
                "'log' binary not found on PATH; cannot extract Unified Log events"
            )
            return

        # --- Extracted directory mode ---
        if self.extract_path:
            logarchives = self._find_logarchives_in_dir()
            if not logarchives:
                self.log.info(
                    "No .logarchive directories found in %s", self.extract_path
                )
                return
            self.log.info("Found %d .logarchive bundle(s)", len(logarchives))
            for path in logarchives:
                self._process_logarchive(path, os.path.basename(path))
            self.log.info("Total Unified Log events extracted: %d", len(self.results))
            return

        # --- Tar archive mode ---
        prefixes = self._find_logarchive_prefixes_in_tar()
        if not prefixes:
            self.log.info("No .logarchive entries found in archive")
            return
        self.log.info("Found %d .logarchive bundle(s) in archive", len(prefixes))
        with tempfile.TemporaryDirectory(prefix="mvt_unified_log_") as tmpdir:
            for prefix in prefixes:
                extracted = self._extract_logarchive_from_tar(prefix, tmpdir)
                if extracted:
                    self._process_logarchive(extracted, os.path.basename(prefix))
        self.log.info("Total Unified Log events extracted: %d", len(self.results))
