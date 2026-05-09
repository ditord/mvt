# Mobile Verification Toolkit (MVT)
# Copyright (c) 2021-2023 The MVT Authors.
# Use of this software is governed by the MVT License 1.1 that can be found at
#   https://license.mvt.re/1.1/

"""Tests for src/mvt/common/correlation.py"""

import json

import pytest

from mvt.common.correlation import (
    CorrelationFinding,
    correlate,
    correlate_from_modules,
    write_correlation_json,
)
from mvt.common.normalized_timeline import NormalizedTimelineRecord


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _r(**kwargs) -> NormalizedTimelineRecord:
    """Build a NormalizedTimelineRecord; all fields default to '' / None."""
    defaults = dict(
        timestamp="",
        module="ModuleA",
        artifact_type="test",
        path="",
        process="",
        bundle_id="",
        domain="",
        url="",
        event_type="",
        description="",
        matched_ioc="",
        source_file="",
        raw=None,
    )
    defaults.update(kwargs)
    return NormalizedTimelineRecord(**defaults)


# Shared test constants
_DOM = "evil.example.org"
_URL = "https://evil.example.org/payload.dmg"
_PATH = "/private/var/mobile/Downloads/payload.dmg"


# Use factories instead of module-level mutable instances to prevent one test
# from silently corrupting shared state for subsequent tests.
def _xattr_rec(**overrides) -> NormalizedTimelineRecord:
    return _r(
        timestamp="2024-01-15 10:23:45.000000",
        module="XattrMetadata",
        artifact_type="xattr",
        path="private/var/mobile/Downloads/payload.dmg",
        domain=_DOM,
        url=_URL,
        matched_ioc=_DOM,
        source_file="private/var/mobile/Downloads/payload.dmg",
        **overrides,
    )


def _crash_rec(**overrides) -> NormalizedTimelineRecord:
    return _r(
        timestamp="2024-01-15 10:05:00.000000",
        module="CrashReports",
        artifact_type="crash_report",
        path="/System/Library/CoreServices/SpringBoard.app/SpringBoard",
        process="SpringBoard",
        bundle_id="com.apple.springboard",
        domain=_DOM,
        url=_URL,
        matched_ioc=_DOM,
        source_file="DiagnosticLogs/CrashReporter/sb.ips",
        **overrides,
    )


def _fsevent_rec(**overrides) -> NormalizedTimelineRecord:
    return _r(
        timestamp="2024-01-15 10:10:00.000000",
        module="FSEvents",
        artifact_type="fsevent",
        path=_PATH,
        event_type="Created, IsFile",
        source_file=".fseventsd/000000004200e000",
        **overrides,
    )


# Back-compat aliases used by tests that pre-date the factory refactor.
# These are re-created at import time so they are fresh instances.
_XATTR_REC = _xattr_rec()
_CRASH_REC = _crash_rec()
_FSEVENT_REC = _fsevent_rec()


# ---------------------------------------------------------------------------
# CorrelationFinding defaults
# ---------------------------------------------------------------------------


class TestCorrelationFinding:
    def test_default_severity_is_low(self):
        f = CorrelationFinding()
        assert f.severity == "low"

    def test_default_confidence_is_low(self):
        f = CorrelationFinding()
        assert f.confidence == "low"

    def test_related_records_default_empty(self):
        f = CorrelationFinding()
        assert f.related_records == []

    def test_related_iocs_default_empty(self):
        f = CorrelationFinding()
        assert f.related_iocs == []


# ---------------------------------------------------------------------------
# shared_domain rule
# ---------------------------------------------------------------------------


class TestSharedDomainRule:
    def test_same_domain_across_two_modules(self):
        findings = correlate([_XATTR_REC, _CRASH_REC])
        sd = [f for f in findings if f.correlation_type == "shared_domain"]
        assert len(sd) == 1
        assert _DOM in sd[0].summary

    def test_ioc_match_raises_severity_to_high(self):
        findings = correlate([_XATTR_REC, _CRASH_REC])
        sd = [f for f in findings if f.correlation_type == "shared_domain"]
        assert sd[0].severity == "high"
        assert sd[0].confidence == "high"

    def test_no_ioc_severity_medium(self):
        a = _r(module="ModA", domain="benign.org", matched_ioc="")
        b = _r(module="ModB", domain="benign.org", matched_ioc="")
        findings = correlate([a, b])
        sd = [f for f in findings if f.correlation_type == "shared_domain"]
        assert len(sd) == 1
        assert sd[0].severity == "medium"
        assert sd[0].confidence == "medium"

    def test_same_module_no_finding(self):
        a = _r(module="XattrMetadata", domain=_DOM)
        b = _r(module="XattrMetadata", domain=_DOM)
        findings = correlate([a, b])
        sd = [f for f in findings if f.correlation_type == "shared_domain"]
        assert len(sd) == 0

    def test_empty_domain_no_finding(self):
        a = _r(module="ModA", domain="")
        b = _r(module="ModB", domain="")
        findings = correlate([a, b])
        sd = [f for f in findings if f.correlation_type == "shared_domain"]
        assert len(sd) == 0

    def test_three_modules_single_finding(self):
        a = _r(module="ModA", domain="multi.org")
        b = _r(module="ModB", domain="multi.org")
        c = _r(module="ModC", domain="multi.org")
        findings = correlate([a, b, c])
        sd = [f for f in findings if f.correlation_type == "shared_domain"]
        assert len(sd) == 1
        assert len(sd[0].related_records) == 3

    def test_related_iocs_populated(self):
        findings = correlate([_XATTR_REC, _CRASH_REC])
        sd = [f for f in findings if f.correlation_type == "shared_domain"]
        assert _DOM in sd[0].related_iocs

    def test_wording_avoids_certainty(self):
        findings = correlate([_xattr_rec(), _crash_rec()])
        sd = [f for f in findings if f.correlation_type == "shared_domain"]
        text = sd[0].summary + sd[0].rationale
        assert "possibly" in text or "correlated" in text
        assert "confirmed" not in text.lower()

    def test_blocklisted_apple_domain_no_finding(self):
        a = _r(module="XattrMetadata", domain="apple.com")
        b = _r(module="CrashReports", domain="apple.com")
        findings = correlate([a, b])
        sd = [f for f in findings if f.correlation_type == "shared_domain"]
        assert len(sd) == 0

    def test_blocklisted_subdomain_no_finding(self):
        a = _r(module="XattrMetadata", domain="push.apple.com")
        b = _r(module="CrashReports", domain="push.apple.com")
        findings = correlate([a, b])
        sd = [f for f in findings if f.correlation_type == "shared_domain"]
        assert len(sd) == 0

    def test_blocklisted_cdn_no_finding(self):
        a = _r(module="XattrMetadata", domain="d1.cloudfront.net")
        b = _r(module="CrashReports", domain="d1.cloudfront.net")
        findings = correlate([a, b])
        sd = [f for f in findings if f.correlation_type == "shared_domain"]
        assert len(sd) == 0

    def test_non_blocklisted_domain_still_fires(self):
        a = _r(module="XattrMetadata", domain="malware-c2.io")
        b = _r(module="CrashReports", domain="malware-c2.io")
        findings = correlate([a, b])
        sd = [f for f in findings if f.correlation_type == "shared_domain"]
        assert len(sd) == 1


# ---------------------------------------------------------------------------
# shared_url rule
# ---------------------------------------------------------------------------


class TestSharedUrlRule:
    def test_same_url_across_modules(self):
        findings = correlate([_XATTR_REC, _CRASH_REC])
        su = [f for f in findings if f.correlation_type == "shared_url"]
        assert len(su) == 1
        assert _URL in su[0].summary

    def test_same_module_no_finding(self):
        a = _r(module="XattrMetadata", url=_URL)
        b = _r(module="XattrMetadata", url=_URL)
        findings = correlate([a, b])
        su = [f for f in findings if f.correlation_type == "shared_url"]
        assert len(su) == 0

    def test_empty_url_no_finding(self):
        a = _r(module="ModA", url="")
        b = _r(module="ModB", url="")
        findings = correlate([a, b])
        su = [f for f in findings if f.correlation_type == "shared_url"]
        assert len(su) == 0


# ---------------------------------------------------------------------------
# shared_path rule
# ---------------------------------------------------------------------------


class TestSharedPathRule:
    def test_same_path_across_modules(self):
        a = _r(module="FSEvents", artifact_type="fsevent", path=_PATH)
        b = _r(module="CrashReports", artifact_type="crash_report", path=_PATH)
        findings = correlate([a, b])
        sp = [f for f in findings if f.correlation_type == "shared_path"]
        assert len(sp) == 1

    def test_path_normalized_for_comparison(self):
        # FSEvents stores with leading '/', xattr without — should still match
        a = _r(module="FSEvents", path="/private/var/mobile/app/payload")
        b = _r(module="CrashReports", path="private/var/mobile/app/payload")
        findings = correlate([a, b])
        sp = [f for f in findings if f.correlation_type == "shared_path"]
        assert len(sp) == 1

    def test_empty_path_no_finding(self):
        a = _r(module="ModA", path="")
        b = _r(module="ModB", path="")
        findings = correlate([a, b])
        sp = [f for f in findings if f.correlation_type == "shared_path"]
        assert len(sp) == 0

    def test_same_module_no_finding(self):
        a = _r(module="FSEvents", path=_PATH)
        b = _r(module="FSEvents", path=_PATH)
        findings = correlate([a, b])
        sp = [f for f in findings if f.correlation_type == "shared_path"]
        assert len(sp) == 0

    def test_short_generic_path_no_finding(self):
        # "var" and "tmp" normalize to < 10 chars — too generic to correlate
        for generic in ("/var", "/tmp", "/usr", "/System", "/private"):
            a = _r(module="FSEvents", path=generic)
            b = _r(module="CrashReports", path=generic)
            findings = correlate([a, b])
            sp = [f for f in findings if f.correlation_type == "shared_path"]
            assert len(sp) == 0, f"Unexpected finding for generic path: {generic}"

    def test_specific_path_still_fires(self):
        specific = "/private/var/mobile/Downloads/implant.dylib"
        a = _r(module="FSEvents", path=specific)
        b = _r(module="CrashReports", path=specific)
        findings = correlate([a, b])
        sp = [f for f in findings if f.correlation_type == "shared_path"]
        assert len(sp) == 1


# ---------------------------------------------------------------------------
# ioc_temporal_cluster rule
# ---------------------------------------------------------------------------


class TestIocTemporalCluster:
    def test_two_ioc_records_within_window(self):
        # crash at 10:05, xattr at 10:23 — gap 18 min; use 30-min window
        findings = correlate([_CRASH_REC, _XATTR_REC], time_window_minutes=30)
        tc = [f for f in findings if f.correlation_type == "ioc_temporal_cluster"]
        assert len(tc) == 1
        assert len(tc[0].related_records) == 2

    def test_ioc_cluster_severity_high(self):
        findings = correlate([_CRASH_REC, _XATTR_REC], time_window_minutes=30)
        tc = [f for f in findings if f.correlation_type == "ioc_temporal_cluster"]
        assert tc[0].severity == "high"
        assert tc[0].confidence == "high"

    def test_outside_window_no_cluster(self):
        # gap is 18 min; use 10-min window → no cluster
        findings = correlate([_CRASH_REC, _XATTR_REC], time_window_minutes=10)
        tc = [f for f in findings if f.correlation_type == "ioc_temporal_cluster"]
        assert len(tc) == 0

    def test_missing_timestamp_excluded(self):
        no_ts = _r(module="ModA", matched_ioc="evil.org", timestamp="")
        with_ts = _r(
            module="ModB",
            matched_ioc="evil.org",
            timestamp="2024-01-15 10:00:00.000000",
        )
        findings = correlate([no_ts, with_ts], time_window_minutes=60)
        tc = [f for f in findings if f.correlation_type == "ioc_temporal_cluster"]
        # Only 1 record has a valid timestamp → no cluster of ≥2
        assert len(tc) == 0

    def test_malformed_timestamp_excluded(self):
        # Non-empty but unparseable timestamp must not be treated as a valid time
        bad_ts = _r(module="ModA", matched_ioc="evil.org", timestamp="not-a-date")
        good_ts = _r(
            module="ModB",
            matched_ioc="evil.org",
            timestamp="2024-01-15 10:00:00.000000",
        )
        findings = correlate([bad_ts, good_ts], time_window_minutes=60)
        tc = [f for f in findings if f.correlation_type == "ioc_temporal_cluster"]
        assert len(tc) == 0

    def test_wording_avoids_certainty(self):
        r1 = _r(module="A", matched_ioc="x", timestamp="2024-01-15 10:00:00.000000")
        r2 = _r(module="B", matched_ioc="y", timestamp="2024-01-15 10:05:00.000000")
        findings = correlate([r1, r2], time_window_minutes=10)
        tc = [f for f in findings if f.correlation_type == "ioc_temporal_cluster"]
        text = tc[0].summary + tc[0].rationale
        assert "possibly" in text or "correlated" in text
        assert "confirmed" not in text.lower()

    def test_three_consecutive_ioc_hits_one_cluster(self):
        r1 = _r(module="A", matched_ioc="x", timestamp="2024-01-15 10:00:00.000000")
        r2 = _r(module="B", matched_ioc="y", timestamp="2024-01-15 10:05:00.000000")
        r3 = _r(module="C", matched_ioc="z", timestamp="2024-01-15 10:09:00.000000")
        findings = correlate([r1, r2, r3], time_window_minutes=10)
        tc = [f for f in findings if f.correlation_type == "ioc_temporal_cluster"]
        assert len(tc) == 1
        assert len(tc[0].related_records) == 3

    def test_two_separate_clusters(self):
        r1 = _r(module="A", matched_ioc="x", timestamp="2024-01-15 09:00:00.000000")
        r2 = _r(module="B", matched_ioc="y", timestamp="2024-01-15 09:05:00.000000")
        r3 = _r(module="C", matched_ioc="z", timestamp="2024-01-15 11:00:00.000000")
        r4 = _r(module="D", matched_ioc="w", timestamp="2024-01-15 11:04:00.000000")
        findings = correlate([r1, r2, r3, r4], time_window_minutes=10)
        tc = [f for f in findings if f.correlation_type == "ioc_temporal_cluster"]
        assert len(tc) == 2

    def test_time_window_in_finding(self):
        findings = correlate([_CRASH_REC, _XATTR_REC], time_window_minutes=30)
        tc = [f for f in findings if f.correlation_type == "ioc_temporal_cluster"]
        assert tc[0].time_window == "30 minutes"


# ---------------------------------------------------------------------------
# ioc_file_proximity rule
# ---------------------------------------------------------------------------


class TestIocFileProximity:
    def test_ioc_near_fsevent(self):
        # crash at 10:05, fsevent at 10:10 — gap 5 min, within 10-min window
        findings = correlate([_CRASH_REC, _FSEVENT_REC], time_window_minutes=10)
        fp = [f for f in findings if f.correlation_type == "ioc_file_proximity"]
        assert len(fp) == 1
        assert "CrashReports" in fp[0].summary

    def test_ioc_outside_window_no_proximity(self):
        # crash at 10:05, fsevent at 10:10 — gap 5 min, but window=3 min
        findings = correlate([_CRASH_REC, _FSEVENT_REC], time_window_minutes=3)
        fp = [f for f in findings if f.correlation_type == "ioc_file_proximity"]
        assert len(fp) == 0

    def test_fsevent_without_ioc_not_ioc_record(self):
        # Two FSEvents with no IOC match should not trigger proximity
        fs1 = _r(
            module="FSEvents",
            artifact_type="fsevent",
            timestamp="2024-01-15 10:00:00.000000",
        )
        fs2 = _r(
            module="FSEvents",
            artifact_type="fsevent",
            timestamp="2024-01-15 10:01:00.000000",
        )
        findings = correlate([fs1, fs2], time_window_minutes=10)
        fp = [f for f in findings if f.correlation_type == "ioc_file_proximity"]
        assert len(fp) == 0

    def test_missing_timestamp_excluded(self):
        ioc_no_ts = _r(module="CrashReports", matched_ioc="evil.org", timestamp="")
        fs = _r(
            module="FSEvents",
            artifact_type="fsevent",
            timestamp="2024-01-15 10:10:00.000000",
        )
        findings = correlate([ioc_no_ts, fs], time_window_minutes=60)
        fp = [f for f in findings if f.correlation_type == "ioc_file_proximity"]
        assert len(fp) == 0

    def test_ioc_fsevent_does_not_self_correlate(self):
        """An IOC-matched FSEvent must not appear as a nearby record for itself."""
        ioc_fsevent = _r(
            module="FSEvents",
            artifact_type="fsevent",
            matched_ioc="evil.org",
            timestamp="2024-01-15 10:00:00.000000",
        )
        other_fsevent = _r(
            module="FSEvents",
            artifact_type="fsevent",
            timestamp="2024-01-15 10:02:00.000000",
        )
        findings = correlate([ioc_fsevent, other_fsevent], time_window_minutes=10)
        fp = [f for f in findings if f.correlation_type == "ioc_file_proximity"]
        assert len(fp) == 1
        # related_records: [ioc_fsevent, other_fsevent] — exactly 2, not 3
        assert len(fp[0].related_records) == 2

    def test_finding_severity_high_confidence_medium(self):
        findings = correlate([_CRASH_REC, _FSEVENT_REC], time_window_minutes=10)
        fp = [f for f in findings if f.correlation_type == "ioc_file_proximity"]
        assert fp[0].severity == "high"
        assert fp[0].confidence == "medium"

    def test_time_window_in_finding(self):
        findings = correlate([_CRASH_REC, _FSEVENT_REC], time_window_minutes=10)
        fp = [f for f in findings if f.correlation_type == "ioc_file_proximity"]
        assert fp[0].time_window == "10 minutes"


# ---------------------------------------------------------------------------
# correlate() — edge cases
# ---------------------------------------------------------------------------


class TestCorrelateEdgeCases:
    def test_empty_records_returns_empty(self):
        assert correlate([]) == []

    def test_single_record_no_findings(self):
        assert correlate([_XATTR_REC]) == []

    def test_all_rules_fire_together(self):
        # xattr + crash share domain + url; both have matched_ioc;
        # fsevent is close in time to crash
        findings = correlate(
            [_xattr_rec(), _crash_rec(), _fsevent_rec()],
            time_window_minutes=30,
        )
        types = {f.correlation_type for f in findings}
        assert "shared_domain" in types
        assert "shared_url" in types
        assert "ioc_temporal_cluster" in types
        assert "ioc_file_proximity" in types

    def test_no_false_findings_for_empty_fields(self):
        a = _r(module="ModA", domain="", url="", path="")
        b = _r(module="ModB", domain="", url="", path="")
        assert correlate([a, b]) == []


# ---------------------------------------------------------------------------
# correlate_from_modules()
# ---------------------------------------------------------------------------


class TestCorrelateFromModules:
    def test_modules_without_mixin_ignored(self):
        class FakeModule:
            pass

        findings = correlate_from_modules([FakeModule()])
        assert findings == []

    def test_modules_with_mixin_used(self):
        class FakeModule:
            def to_normalized_timeline(self):
                return [_XATTR_REC, _CRASH_REC]

        findings = correlate_from_modules([FakeModule()], time_window_minutes=30)
        assert any(f.correlation_type == "shared_domain" for f in findings)

    def test_records_aggregated_across_modules(self):
        class ModA:
            def to_normalized_timeline(self):
                return [_XATTR_REC]

        class ModB:
            def to_normalized_timeline(self):
                return [_CRASH_REC]

        findings = correlate_from_modules([ModA(), ModB()])
        assert any(f.correlation_type == "shared_domain" for f in findings)


# ---------------------------------------------------------------------------
# write_correlation_json()
# ---------------------------------------------------------------------------


class TestWriteCorrelationJson:
    def test_writes_valid_json_array(self, tmp_path):
        findings = correlate([_XATTR_REC, _CRASH_REC])
        out = tmp_path / "correlation.json"
        write_correlation_json(findings, str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert isinstance(data, list)
        assert len(data) > 0

    def test_empty_findings_writes_empty_array(self, tmp_path):
        out = tmp_path / "correlation.json"
        write_correlation_json([], str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data == []

    def test_finding_fields_present_in_json(self, tmp_path):
        findings = correlate([_XATTR_REC, _CRASH_REC])
        out = tmp_path / "correlation.json"
        write_correlation_json(findings, str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        for record in data:
            for key in (
                "correlation_type", "severity", "confidence",
                "summary", "rationale", "related_records",
                "related_iocs", "time_window",
            ):
                assert key in record, f"Missing key: {key}"

    def test_raw_field_serialized_in_related_records(self, tmp_path):
        rec = _r(
            module="ModA",
            domain="x.com",
            raw={"original": "data"},
        )
        rec2 = _r(module="ModB", domain="x.com")
        findings = correlate([rec, rec2])
        out = tmp_path / "correlation.json"
        write_correlation_json(findings, str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        recs = data[0]["related_records"]
        raws = [r["raw"] for r in recs]
        assert {"original": "data"} in raws
