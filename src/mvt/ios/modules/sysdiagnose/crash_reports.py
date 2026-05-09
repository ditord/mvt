# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import datetime
import json
import logging
import re
from typing import List, Optional
from urllib.parse import urlparse

from mvt.common.module_types import (
    ModuleAtomicResult,
    ModuleResults,
    ModuleSerializedResult,
)
from mvt.common.normalized_timeline import NormalizedTimelineMixin, NormalizedTimelineRecord
from mvt.common.utils import convert_datetime_to_iso

from .base import SysdiagnoseModule

# Patterns to locate crash files inside a sysdiagnose archive/directory.
# The leading wildcard handles the sysdiagnose root directory inside .tar.gz.
_CRASH_PATTERNS = [
    "*/DiagnosticLogs/CrashReporter/*.ips",
    "*/DiagnosticLogs/CrashReporter/*.crash",
    "*/DiagnosticLogs/CrashReporter/*.panic",
    "DiagnosticLogs/CrashReporter/*.ips",
    "DiagnosticLogs/CrashReporter/*.crash",
    "DiagnosticLogs/CrashReporter/*.panic",
    "*/crashes_and_spins/*.ips",
    "*/crashes_and_spins/*.crash",
    "crashes_and_spins/*.ips",
    "crashes_and_spins/*.crash",
]

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")

# Key-value pairs in text-format .crash files
_CRASH_KV_RE = re.compile(r"^([A-Za-z /]+):\s+(.+)$", re.MULTILINE)


def _get_domain(url: str) -> str:
    try:
        netloc = urlparse(url).netloc
        return netloc.lstrip("www.").lower() if netloc else ""
    except Exception:
        return ""


def _normalize_timestamp(ts: str) -> str:
    """Convert .ips timestamp strings to MVT ISO format."""
    if not ts:
        return ""
    # Format: "2024-01-15 10:23:45.00 +0000" — strip extra space before tz
    normalized = re.sub(r"\s+([+-]\d{4})$", r"\1", ts.strip())
    for fmt in ("%Y-%m-%d %H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z"):
        try:
            dt = datetime.datetime.strptime(normalized, fmt)
            return convert_datetime_to_iso(dt)
        except ValueError:
            continue
    return ts


def _extract_urls(text: str) -> List[str]:
    return list(dict.fromkeys(_URL_RE.findall(text)))


def _extract_domains(urls: List[str]) -> List[str]:
    return list(dict.fromkeys(d for u in urls if (d := _get_domain(u))))


def _parse_ips(content: bytes) -> Optional[dict]:
    """Parse a JSON .ips crash report.

    Handles both the single-object and the two-line (header + body) formats.
    """
    text = content.decode("utf-8", errors="replace")

    # Try single-object JSON first
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try two separate JSON objects separated by a newline
    lines = text.splitlines()
    merged: dict = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                merged.update(obj)
        except json.JSONDecodeError:
            continue

    return merged if merged else None


def _parse_crash_text(content: bytes) -> dict:
    """Extract key fields from a text-format .crash file."""
    text = content.decode("utf-8", errors="replace")
    kv: dict = {}
    for m in _CRASH_KV_RE.finditer(text):
        kv[m.group(1).strip()] = m.group(2).strip()

    return {
        "process_name": kv.get("Process", "").split(" [")[0].strip(),
        "bundle_identifier": kv.get("Identifier", ""),
        "process_path": kv.get("Path", ""),
        "exception_type": kv.get("Exception Type", ""),
        "exception_signal": "",
        "termination_reasons": [kv["Termination Reason"]] if "Termination Reason" in kv else [],
        "crashed_thread": None,
        "timestamp": _normalize_timestamp(kv.get("Date/Time", "")),
        "os_version": kv.get("OS Version", ""),
    }


def _build_result(data: dict, source_file: str, fallback_mtime: str) -> dict:
    """Build a normalised result dict from a parsed .ips JSON object."""
    exception = data.get("exception", {})
    termination = data.get("termination", {})
    reasons = termination.get("reasons", [])

    # Crashed thread id
    crashed_thread: Optional[int] = None
    for thread in data.get("threads", []):
        if thread.get("crashed", False):
            crashed_thread = thread.get("id")
            break

    # Collect all text in the report for URL extraction
    report_text = json.dumps(data)
    urls = _extract_urls(report_text)
    domains = _extract_domains(urls)

    timestamp = _normalize_timestamp(data.get("timestamp", "")) or fallback_mtime

    os_version_raw = data.get("osVersion", data.get("os_version", ""))
    if isinstance(os_version_raw, dict):
        os_version = (
            f"{os_version_raw.get('train', '')} ({os_version_raw.get('build', '')})"
        ).strip()
    else:
        os_version = str(os_version_raw)

    return {
        "source_file": source_file,
        "timestamp": timestamp,
        "process_name": data.get("name", data.get("procName", "")),
        "bundle_identifier": data.get("bundleID", ""),
        "process_path": data.get("procPath", ""),
        "os_version": os_version,
        "exception_type": exception.get("type", ""),
        "exception_signal": exception.get("signal", ""),
        "termination_reasons": reasons,
        "crashed_thread": crashed_thread,
        "extracted_urls": urls,
        "extracted_domains": domains,
    }


class CrashReports(NormalizedTimelineMixin, SysdiagnoseModule):
    """Extract and parse iOS crash reports from a sysdiagnose archive.

    Supports .ips (JSON), .crash (text), and .panic files found in
    DiagnosticLogs/CrashReporter/ or crashes_and_spins/.
    """

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

    def serialize(self, record: ModuleAtomicResult) -> ModuleSerializedResult:
        exc = record.get("exception_type", "")
        sig = record.get("exception_signal", "")
        exc_str = f"{exc} ({sig})" if sig else exc
        return {
            "timestamp": record.get("timestamp", ""),
            "module": self.__class__.__name__,
            "event": "crash_report",
            "data": (
                f"Process {record['process_name']!r} "
                f"({record['bundle_identifier']}) crashed"
                + (f" — {exc_str}" if exc_str else "")
                + f" [{record['source_file']}]"
            ),
        }

    def normalize_record(self, result: dict) -> NormalizedTimelineRecord:
        urls: list = result.get("extracted_urls", [])
        domains: list = result.get("extracted_domains", [])
        exc = result.get("exception_type", "")
        sig = result.get("exception_signal", "")
        exc_str = f"{exc} ({sig})" if sig else exc
        reasons = result.get("termination_reasons", [])
        reason_str = reasons[0] if reasons else ""
        desc_parts = [result.get("bundle_identifier", "")]
        if exc_str:
            desc_parts.append(exc_str)
        if reason_str:
            desc_parts.append(reason_str[:80])
        return NormalizedTimelineRecord(
            timestamp=result.get("timestamp", ""),
            module=self.__class__.__name__,
            artifact_type="crash_report",
            path=result.get("process_path", ""),
            process=result.get("process_name", ""),
            bundle_id=result.get("bundle_identifier", ""),
            domain=domains[0] if domains else "",
            url=urls[0] if urls else "",
            event_type=exc_str or "crash_report",
            description=" | ".join(p for p in desc_parts if p),
            source_file=result.get("source_file", ""),
            raw=dict(result),
        )

    def check_indicators(self) -> None:
        if not self.indicators:
            return

        for result in self.results:
            # Check process name
            if result.get("process_name"):
                ioc_match = self.indicators.check_process(result["process_name"])
                if ioc_match:
                    self.alertstore.high(
                        ioc_match.message,
                        result.get("timestamp", ""),
                        result,
                        matched_indicator=ioc_match.ioc,
                    )

            # Check process binary path
            if result.get("process_path"):
                ioc_match = self.indicators.check_file_path(result["process_path"])
                if ioc_match:
                    self.alertstore.high(
                        ioc_match.message,
                        result.get("timestamp", ""),
                        result,
                        matched_indicator=ioc_match.ioc,
                    )

            # Check URLs extracted from the crash body
            for url in result.get("extracted_urls", []):
                ioc_match = self.indicators.check_url(url)
                if ioc_match:
                    self.alertstore.high(
                        ioc_match.message,
                        result.get("timestamp", ""),
                        result,
                        matched_indicator=ioc_match.ioc,
                    )

    def _process_crash_file(self, file_path: str) -> None:
        content = self._get_file_content(file_path)
        if not content:
            return

        fallback_mtime = self._get_file_mtime(file_path)

        if file_path.endswith(".crash"):
            parsed = _parse_crash_text(content)
            parsed["source_file"] = file_path
            if not parsed.get("timestamp"):
                parsed["timestamp"] = fallback_mtime
            # Still try to pull URLs out of the raw text
            urls = _extract_urls(content.decode("utf-8", errors="replace"))
            parsed.setdefault("extracted_urls", urls)
            parsed.setdefault("extracted_domains", _extract_domains(urls))
            self.results.append(parsed)
            return

        # .ips and .panic files — JSON format
        data = _parse_ips(content)
        if data is None:
            self.log.warning("Could not parse crash file: %s", file_path)
            return

        result = _build_result(data, file_path, fallback_mtime)
        self.results.append(result)

    def run(self) -> None:
        crash_files = self._get_files_by_patterns(_CRASH_PATTERNS)
        if not crash_files:
            self.log.info("No crash report files found in sysdiagnose")
            return

        self.log.info("Found %d crash report file(s)", len(crash_files))
        for file_path in crash_files:
            self.log.debug("Processing crash file: %s", file_path)
            self._process_crash_file(file_path)

        self.log.info(
            "Extracted %d crash report record(s)", len(self.results)
        )
