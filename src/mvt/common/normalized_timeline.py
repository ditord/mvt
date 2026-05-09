# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

"""Normalized timeline format for cross-module artifact comparison.

Modules that support this format emit NormalizedTimelineRecord entries
alongside their regular JSON output.  Records are written as JSONL to
``{slug}_normalized.jsonl`` inside the module's results folder whenever
``--output`` is provided on the command line.

Schema
------
timestamp    : ISO-8601 UTC string (empty string when unavailable)
module       : MVT module class name
artifact_type: short type tag, e.g. "fsevent", "xattr", "crash_report"
path         : on-device or relative filesystem path most relevant to the record
process      : process / binary name (empty when not applicable)
domain       : first extracted domain (empty when none)
url          : first extracted URL (empty when none)
description  : human-readable one-line summary of the record
matched_ioc  : IOC indicator value if this record triggered a detection, else ""
source_file  : archive member or log file that the record originated from
"""

import json
import os
from dataclasses import asdict, dataclass
from typing import List, Optional


@dataclass
class NormalizedTimelineRecord:
    timestamp: str = ""
    module: str = ""
    artifact_type: str = ""
    path: str = ""
    process: str = ""
    bundle_id: str = ""
    domain: str = ""
    url: str = ""
    event_type: str = ""
    description: str = ""
    matched_ioc: str = ""
    source_file: str = ""
    raw: Optional[dict] = None


def write_jsonl(records: List[NormalizedTimelineRecord], path: str) -> None:
    """Write records to a JSONL file, sorted by timestamp."""
    with open(path, "w", encoding="utf-8") as fh:
        for record in sorted(records, key=lambda r: r.timestamp or ""):
            fh.write(json.dumps(asdict(record), ensure_ascii=False, default=str))
            fh.write("\n")


class NormalizedTimelineMixin:
    """Mixin that adds normalized JSONL timeline output to an MVTModule subclass.

    The host class must provide:
      - ``self.results``      list of result dicts populated by ``run()``
      - ``self.alertstore``   AlertStore populated by ``check_indicators()``
      - ``self.results_path`` Optional[str]
      - ``self.get_slug()``   classmethod inherited from MVTModule
      - ``self.log``          logger

    Subclasses implement :meth:`normalize_record` to map a single result dict
    to a :class:`NormalizedTimelineRecord`.  Everything else is automatic.

    The ``save_to_json`` override calls ``super().save_to_json()`` first so all
    existing module outputs are written unchanged before the JSONL is appended.
    """

    def normalize_record(self, result: dict) -> Optional[NormalizedTimelineRecord]:
        """Convert one module result dict to a NormalizedTimelineRecord.

        Must be implemented by each module.  Return *None* to skip the record.
        """
        raise NotImplementedError

    def to_normalized_timeline(self) -> List[NormalizedTimelineRecord]:
        """Return normalized records for all results, with matched_ioc populated."""
        # Build a mapping from result-object identity to matched IOC value so
        # that we can annotate records that triggered a detection.
        alert_iocs: dict = {}
        for alert in self.alertstore.alerts:
            if alert.matched_indicator is not None and alert.event is not None:
                alert_iocs[id(alert.event)] = alert.matched_indicator.value

        records: List[NormalizedTimelineRecord] = []
        for result in self.results:
            try:
                record = self.normalize_record(result)
            except Exception:
                continue
            if record is None:
                continue
            record.matched_ioc = alert_iocs.get(id(result), "")
            records.append(record)
        return records

    def save_normalized_timeline_jsonl(self) -> None:
        """Write ``{slug}_normalized.jsonl`` to the results folder."""
        if not self.results_path:
            return
        records = self.to_normalized_timeline()
        if not records:
            return
        out_path = os.path.join(
            self.results_path, f"{self.get_slug()}_normalized.jsonl"
        )
        try:
            write_jsonl(records, out_path)
        except Exception as exc:
            self.log.error(
                "Unable to write normalized timeline for %s: %s",
                self.__class__.__name__,
                exc,
            )

    def save_to_json(self) -> None:
        """Write all regular outputs then append the normalized JSONL."""
        super().save_to_json()
        self.save_normalized_timeline_jsonl()
