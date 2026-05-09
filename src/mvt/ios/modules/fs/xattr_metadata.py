# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

import datetime
import logging
import os
import plistlib
import re
from typing import List, Optional
from urllib.parse import urlparse

from mvt.common.module_types import (
    ModuleAtomicResult,
    ModuleResults,
    ModuleSerializedResult,
)
from mvt.common.normalized_timeline import NormalizedTimelineMixin, NormalizedTimelineRecord
from mvt.common.utils import convert_unix_to_iso

from ..base import IOSExtraction

_XATTR_QUARANTINE = "com.apple.quarantine"
_XATTR_METADATA_PREFIX = "com.apple.metadata:"

_HAS_XATTR = hasattr(os, "listxattr") and hasattr(os, "getxattr")

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


def _to_serializable(value: object) -> object:
    """Recursively convert plistlib-decoded values to JSON-safe types."""
    if isinstance(value, datetime.datetime):
        return value.isoformat()
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return [_to_serializable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _to_serializable(v) for k, v in value.items()}
    return value


def _extract_urls(value: object) -> List[str]:
    """Recursively extract http/https URLs from a decoded xattr value."""
    urls: List[str] = []
    if isinstance(value, str):
        urls.extend(_URL_RE.findall(value))
    elif isinstance(value, (list, tuple)):
        for item in value:
            urls.extend(_extract_urls(item))
    elif isinstance(value, dict):
        for v in value.values():
            urls.extend(_extract_urls(v))
    elif isinstance(value, bytes):
        urls.extend(_extract_urls(value.decode("utf-8", errors="replace")))
    # datetime, int, float, bool: no URLs
    return urls


def _get_domain(url: str) -> str:
    try:
        netloc = urlparse(url).netloc
        if not netloc:
            return ""
        domain = netloc[4:] if netloc.startswith("www.") else netloc
        return domain.lower()
    except Exception:
        return ""


def _decode_xattr(attr_name: str, raw: bytes) -> object:
    """Decode raw xattr bytes into a Python value."""
    if attr_name == _XATTR_QUARANTINE:
        return raw.decode("utf-8", errors="replace").rstrip("\x00")

    # com.apple.metadata:* values are binary plists
    if raw[:8] in (b"bplist00", b"bplist15", b"bplist16"):
        try:
            return plistlib.loads(raw)
        except Exception:
            pass

    try:
        text = raw.decode("utf-8", errors="replace").rstrip("\x00")
        if text.isprintable():
            return text
    except Exception:
        pass

    return raw.hex()


class XattrMetadata(NormalizedTimelineMixin, IOSExtraction):
    """Extract filesystem extended attributes from a full iOS filesystem dump.

    Targets com.apple.quarantine and com.apple.metadata:* xattrs, which can
    reveal the origin URLs of downloaded files. Extracted URLs and domains are
    checked against IOC network indicators.
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
        return {
            "timestamp": record.get("isodate", ""),
            "module": self.__class__.__name__,
            "event": "xattr_metadata",
            "data": f"{record['file_path']} [{record['attribute_name']}]",
        }

    def normalize_record(self, result: dict) -> NormalizedTimelineRecord:
        urls: list = result.get("extracted_urls", [])
        domains: list = result.get("extracted_domains", [])
        decoded = result.get("decoded_value", "")
        decoded_str = str(decoded)
        if len(decoded_str) > 120:
            decoded_str = decoded_str[:117] + "..."
        return NormalizedTimelineRecord(
            timestamp=result.get("isodate", ""),
            module=self.__class__.__name__,
            artifact_type="xattr",
            path=result.get("file_path", ""),
            domain=domains[0] if domains else "",
            url=urls[0] if urls else "",
            description=f"{result.get('attribute_name', '')}: {decoded_str}",
            source_file=result.get("file_path", ""),
        )

    def check_indicators(self) -> None:
        if not self.indicators:
            return

        for result in self.results:
            for url in result.get("extracted_urls", []):
                ioc_match = self.indicators.check_url(url)
                if ioc_match:
                    self.alertstore.high(
                        ioc_match.message,
                        result.get("isodate", ""),
                        result,
                        matched_indicator=ioc_match.ioc,
                    )

    def _process_file(self, file_path: str) -> None:
        try:
            attr_names = os.listxattr(file_path, follow_symlinks=False)
        except OSError:
            return

        relevant = [
            a for a in attr_names
            if a == _XATTR_QUARANTINE or a.startswith(_XATTR_METADATA_PREFIX)
        ]
        if not relevant:
            return

        try:
            mtime = convert_unix_to_iso(os.lstat(file_path).st_mtime)
        except Exception:
            mtime = ""

        rel_path = os.path.relpath(file_path, self.target_path)

        for attr_name in relevant:
            try:
                raw = os.getxattr(file_path, attr_name, follow_symlinks=False)
            except OSError:
                continue
            if not raw:
                continue

            decoded_raw = _decode_xattr(attr_name, raw)
            decoded_value = _to_serializable(decoded_raw)
            extracted_urls = list(dict.fromkeys(_extract_urls(decoded_raw)))
            extracted_domains = list(
                dict.fromkeys(d for u in extracted_urls if (d := _get_domain(u)))
            )

            self.results.append({
                "file_path": rel_path,
                "attribute_name": attr_name,
                "raw_value": raw.hex(),
                "decoded_value": decoded_value,
                "extracted_urls": extracted_urls,
                "extracted_domains": extracted_domains,
                "isodate": mtime,
            })

    def run(self) -> None:
        if not self.target_path:
            self.log.error("No target path provided for %s", self.__class__.__name__)
            return

        if not _HAS_XATTR:
            self.log.warning(
                "Extended attributes (xattrs) are not supported on this platform; "
                "skipping %s",
                self.__class__.__name__,
            )
            return

        for root, _dirs, files in os.walk(self.target_path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                if os.path.islink(file_path):
                    continue
                self._process_file(file_path)

        self.log.info(
            "Extracted %d xattr metadata record(s) from filesystem dump",
            len(self.results),
        )
