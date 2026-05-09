# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

"""Cross-module IOC correlation for normalized timeline records.

This module produces *investigative triage findings*, not verdicts.  Every
finding is labelled "possibly related" or "correlated" — the presence of a
correlation finding does NOT confirm compromise.

Five rules are implemented:

shared_domain
    The same non-empty domain appears in records from two or more distinct
    modules.  When the domain is also a confirmed IOC (matched_ioc) the
    severity is elevated to HIGH.

shared_url
    The same non-empty URL appears in records from two or more distinct
    modules.

shared_path
    The same on-device path (leading '/' stripped for comparison) appears
    in records from two or more distinct modules.

ioc_temporal_cluster
    Two or more IOC-matched records occur within the configurable time
    window.  Records without a valid timestamp are excluded.

ioc_file_proximity
    An IOC-matched record and at least one FSEvents record occur within the
    configurable time window.  Records without a valid timestamp are
    excluded.
"""

import datetime
import json
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from .normalized_timeline import NormalizedTimelineRecord

# ---------------------------------------------------------------------------
# Domain blocklist — high-volume infrastructure seen on virtually every
# iOS device.  Domains whose presence in two modules is essentially
# guaranteed and carries no forensic signal are excluded from shared_domain
# correlations to prevent near-certain false positives.
# ---------------------------------------------------------------------------

_BLOCKLISTED_DOMAINS: frozenset = frozenset({
    # Apple infrastructure
    "apple.com",
    "icloud.com",
    "mzstatic.com",
    "cdn-apple.com",
    "apple-mapkit.com",
    # CDN / cloud providers commonly embedded in crash text or xattr origins
    "akamaized.net",
    "akamai.com",
    "cloudfront.net",
    "amazonaws.com",
    "fastly.net",
    "cloudflare.com",
    "cloudflare-dns.com",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "microsoft.com",
    "windows.com",
})

# Minimum character length of a normalized path (leading '/' stripped) required
# before shared_path fires.  Paths shorter than this are too generic (e.g.
# "var", "tmp", "usr", "System", "private") to produce actionable findings.
_MIN_NORMALIZED_PATH_LEN: int = 10

# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
)


def _parse_ts(ts: str) -> Optional[datetime.datetime]:
    if not ts:
        return None
    for fmt in _TS_FORMATS:
        try:
            return datetime.datetime.strptime(ts, fmt)
        except ValueError:
            continue
    return None


def _within_window(ts1: str, ts2: str, window_minutes: int) -> bool:
    dt1, dt2 = _parse_ts(ts1), _parse_ts(ts2)
    if dt1 is None or dt2 is None:
        return False
    return abs((dt1 - dt2).total_seconds()) <= window_minutes * 60


# ---------------------------------------------------------------------------
# CorrelationFinding dataclass
# ---------------------------------------------------------------------------


@dataclass
class CorrelationFinding:
    """A single cross-module correlation finding.

    Fields
    ------
    correlation_type : str
        Machine-readable rule name, e.g. ``"shared_domain"``.
    severity : str
        ``"low"`` | ``"medium"`` | ``"high"``
    confidence : str
        ``"low"`` | ``"medium"`` | ``"high"``
    summary : str
        One-line human-readable description of the correlation.
    rationale : str
        Why this rule fired and what further investigation is recommended.
    related_records : list[dict]
        Full ``asdict()`` representation of the involved
        :class:`~mvt.common.normalized_timeline.NormalizedTimelineRecord`
        objects.
    related_iocs : list[str]
        Distinct non-empty ``matched_ioc`` values present across the
        related records.
    time_window : str
        Human-readable description of the time constraint used (e.g.
        ``"10 minutes"``), or ``""`` for non-temporal rules.
    """

    correlation_type: str = ""
    severity: str = "low"
    confidence: str = "low"
    summary: str = ""
    rationale: str = ""
    related_records: List[dict] = field(default_factory=list)
    related_iocs: List[str] = field(default_factory=list)
    time_window: str = ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _r2d(r: NormalizedTimelineRecord) -> dict:
    return asdict(r)


def _normalize_path(p: str) -> str:
    """Strip leading '/' and return empty string for paths too generic to correlate."""
    normalized = p.lstrip("/")
    return normalized if len(normalized) >= _MIN_NORMALIZED_PATH_LEN else ""


def _is_blocklisted_domain(domain: str) -> bool:
    """Return True if *domain* is high-volume infrastructure not worth correlating."""
    d = domain.lower()
    return any(d == b or d.endswith("." + b) for b in _BLOCKLISTED_DOMAINS)


def _ioc_wording(has_ioc: bool) -> str:
    return "IOC match detected" if has_ioc else "no IOC match"


# ---------------------------------------------------------------------------
# Correlation rules
# ---------------------------------------------------------------------------


def _rule_shared_value(
    records: List[NormalizedTimelineRecord],
    attr: str,
    correlation_type: str,
    label: str,
    key_fn=None,
    skip_fn=None,
) -> List[CorrelationFinding]:
    """
    Generic rule: group records by attr value; emit one finding per value
    that appears across ≥2 distinct modules.

    key_fn  : optional transform applied to the raw attribute value before
               grouping (e.g. _normalize_path strips leading '/').
    skip_fn : optional predicate — if it returns True for the grouped key,
               the finding is suppressed (e.g. _is_blocklisted_domain).
    """
    if key_fn is None:
        key_fn = lambda v: v

    groups: Dict[str, List[NormalizedTimelineRecord]] = defaultdict(list)
    for r in records:
        raw_val = getattr(r, attr, "") or ""
        val = key_fn(raw_val)
        if val:
            groups[val].append(r)

    findings: List[CorrelationFinding] = []
    for val, recs in groups.items():
        if skip_fn is not None and skip_fn(val):
            continue
        modules = {r.module for r in recs}
        if len(modules) < 2:
            continue

        has_ioc = any(r.matched_ioc for r in recs)
        severity = "high" if has_ioc else "medium"
        confidence = "high" if has_ioc else "medium"
        related_iocs = sorted({r.matched_ioc for r in recs if r.matched_ioc})
        module_list = ", ".join(sorted(modules))

        findings.append(CorrelationFinding(
            correlation_type=correlation_type,
            severity=severity,
            confidence=confidence,
            summary=(
                f"{label} '{val}' possibly related across "
                f"{len(modules)} modules ({module_list})"
            ),
            rationale=(
                f"The same {label} was observed in records from multiple modules "
                f"({_ioc_wording(has_ioc)}). This correlation warrants further "
                "investigation but does not confirm compromise."
            ),
            related_records=[_r2d(r) for r in recs],
            related_iocs=related_iocs,
        ))
    return findings


def _rule_shared_domain(records: List[NormalizedTimelineRecord]) -> List[CorrelationFinding]:
    return _rule_shared_value(
        records, "domain", "shared_domain", "domain",
        skip_fn=_is_blocklisted_domain,
    )


def _rule_shared_url(records: List[NormalizedTimelineRecord]) -> List[CorrelationFinding]:
    return _rule_shared_value(records, "url", "shared_url", "URL")


def _rule_shared_path(records: List[NormalizedTimelineRecord]) -> List[CorrelationFinding]:
    return _rule_shared_value(
        records, "path", "shared_path", "path",
        key_fn=_normalize_path,
    )


def _rule_ioc_temporal_cluster(
    records: List[NormalizedTimelineRecord],
    window_minutes: int,
) -> List[CorrelationFinding]:
    """
    Find chains of ≥2 IOC-matched records where each consecutive pair is
    within *window_minutes* of each other.
    """
    ioc_recs = [
        r for r in records
        if (r.matched_ioc or "") and _parse_ts(r.timestamp) is not None
    ]
    ioc_recs.sort(key=lambda r: _parse_ts(r.timestamp))  # type: ignore[arg-type]

    if len(ioc_recs) < 2:
        return []

    # Greedy chain: extend current cluster while consecutive gap ≤ window
    clusters: List[List[NormalizedTimelineRecord]] = []
    current: List[NormalizedTimelineRecord] = [ioc_recs[0]]
    for rec in ioc_recs[1:]:
        if _within_window(current[-1].timestamp, rec.timestamp, window_minutes):
            current.append(rec)
        else:
            if len(current) >= 2:
                clusters.append(current)
            current = [rec]
    if len(current) >= 2:
        clusters.append(current)

    findings: List[CorrelationFinding] = []
    window_label = f"{window_minutes} minute{'s' if window_minutes != 1 else ''}"
    for cluster in clusters:
        related_iocs = sorted({r.matched_ioc for r in cluster if r.matched_ioc})
        modules = sorted({r.module for r in cluster})
        ts_start = cluster[0].timestamp
        ts_end = cluster[-1].timestamp
        findings.append(CorrelationFinding(
            correlation_type="ioc_temporal_cluster",
            severity="high",
            confidence="high",
            summary=(
                f"{len(cluster)} IOC-matched record(s) possibly related "
                f"within {window_label} "
                f"({ts_start} – {ts_end})"
            ),
            rationale=(
                f"Multiple IOC-matched records were observed across modules "
                f"({', '.join(modules)}) within a {window_label} window. "
                "Temporal proximity may indicate coordinated activity but does "
                "not confirm compromise."
            ),
            related_records=[_r2d(r) for r in cluster],
            related_iocs=related_iocs,
            time_window=window_label,
        ))
    return findings


def _rule_ioc_file_proximity(
    records: List[NormalizedTimelineRecord],
    window_minutes: int,
) -> List[CorrelationFinding]:
    """
    For each IOC-matched record with a valid timestamp, find FSEvents
    records within *window_minutes*.  Emit one finding per IOC record that
    has at least one nearby FSEvent.
    """
    ioc_recs = [
        r for r in records
        if (r.matched_ioc or "") and _parse_ts(r.timestamp) is not None
    ]
    fsevent_recs = [
        r for r in records
        if r.artifact_type == "fsevent" and _parse_ts(r.timestamp) is not None
    ]

    if not ioc_recs or not fsevent_recs:
        return []

    findings: List[CorrelationFinding] = []
    window_label = f"{window_minutes} minute{'s' if window_minutes != 1 else ''}"

    for ioc_rec in ioc_recs:
        nearby = [
            fs for fs in fsevent_recs
            if fs is not ioc_rec
            and _within_window(ioc_rec.timestamp, fs.timestamp, window_minutes)
        ]
        if not nearby:
            continue

        related_iocs = [ioc_rec.matched_ioc]
        related = [ioc_rec] + nearby
        findings.append(CorrelationFinding(
            correlation_type="ioc_file_proximity",
            severity="high",
            confidence="medium",
            summary=(
                f"IOC match in {ioc_rec.module!r} possibly related to "
                f"{len(nearby)} file-system event(s) within {window_label}"
            ),
            rationale=(
                f"An IOC-matched record from {ioc_rec.module!r} "
                f"(IOC: {ioc_rec.matched_ioc!r}) is correlated in time with "
                f"file-system events within a {window_label} window. "
                "Temporal proximity may indicate related activity but does "
                "not confirm compromise."
            ),
            related_records=[_r2d(r) for r in related],
            related_iocs=related_iocs,
            time_window=window_label,
        ))
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def correlate(
    records: List[NormalizedTimelineRecord],
    time_window_minutes: int = 10,
) -> List[CorrelationFinding]:
    """Run all correlation rules against a flat list of normalized records.

    Parameters
    ----------
    records:
        Normalized timeline records from one or more modules.
    time_window_minutes:
        Maximum time delta (in minutes) used by temporal rules.  Defaults
        to 10 minutes.

    Returns
    -------
    list[CorrelationFinding]
        All findings produced by the enabled rules, in rule order.
    """
    findings: List[CorrelationFinding] = []
    findings.extend(_rule_shared_domain(records))
    findings.extend(_rule_shared_url(records))
    findings.extend(_rule_shared_path(records))
    findings.extend(_rule_ioc_temporal_cluster(records, time_window_minutes))
    findings.extend(_rule_ioc_file_proximity(records, time_window_minutes))
    return findings


def correlate_from_modules(
    modules: list,
    time_window_minutes: int = 10,
) -> List[CorrelationFinding]:
    """Convenience wrapper: collect normalized records from executed modules
    then run :func:`correlate`.

    Parameters
    ----------
    modules:
        Any iterable of module instances that may expose
        ``to_normalized_timeline()``.
    time_window_minutes:
        Forwarded to :func:`correlate`.
    """
    records: List[NormalizedTimelineRecord] = []
    for module in modules:
        if hasattr(module, "to_normalized_timeline"):
            records.extend(module.to_normalized_timeline())
    return correlate(records, time_window_minutes)


def write_correlation_json(findings: List[CorrelationFinding], path: str) -> None:
    """Serialise findings to a pretty-printed JSON file.

    An empty findings list writes an empty JSON array rather than skipping
    the file so callers can distinguish "ran but found nothing" from "never ran".
    """
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(
            [asdict(f) for f in findings],
            fh,
            indent=2,
            ensure_ascii=False,
            default=str,
        )
