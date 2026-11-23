"""Offline, source-bound comparison of a saved retest and a signal export.

ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
"""
from __future__ import annotations

from datetime import datetime
from hashlib import sha256
import re

from .studio import parse_json

MAX_BYTES = 512 * 1024
RETEST_STATUSES = frozenset({"not_retested", "inconclusive", "fix_verified", "violation_persists",
                           "testability_restored", "regression", "unchanged"})
RIGHTS = "ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag)."


def _object(value):
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object.")
    return value


def _rows(value):
    if not isinstance(value, list) or len(value) > 4096:
        raise ValueError("Expected up to 4096 records in a list.")
    return value


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.:/-]{1,160}", value):
        raise ValueError("Expected a bounded, non-secret identifier.")
    return value


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        raise ValueError("Expected a SHA-256 digest.")
    return value


def _instant(value):
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})", value
    ):
        raise ValueError("Use a timestamp with date, time and explicit UTC offset.")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _compare(sample, expected, start, end):
    sample = _object(sample)
    events = _rows(sample.get("events"))
    alerts = _rows(sample.get("alerts"))
    seen, matches = set(), set()
    for raw in events:
        row = _object(raw)
        identifier = _identifier(row.get("event"))
        if identifier in seen:
            raise ValueError("Event identifiers must be unique within a sample.")
        seen.add(identifier)
        binding = {key: _identifier(row.get(key)) for key in ("assessment", "scope", "finding", "source")}
        instant = _instant(row.get("at"))
        if start <= instant < end and all(value == expected[key] for key, value in binding.items()):
            matches.add(identifier)
    alarmed = set()
    for raw in alerts:
        row = _object(raw)
        event = _identifier(row.get("event"))
        rule = _identifier(row.get("rule"))
        if event in matches and rule == expected["rule"]:
            alarmed.add(event)
    if alarmed:
        status = "observed"
    elif matches:
        status = "telemetry_only"
    elif events or alerts:
        status = "incomparable"
    else:
        status = "unavailable"
    unlinked = sorted(matches - alarmed)
    return {
        "status": status, "event_count": len(events), "alert_count": len(alerts),
        "matching_events": sorted(matches), "alerted_events": sorted(alarmed),
        "alert_coverage": {
            "eligible_events": len(matches),
            "linked_events": len(alarmed),
            "excluded_events": len(events) - len(matches),
            "unlinked_event_ids": unlinked,
        },
    }


def correlate_retest(anchor_bytes: bytes, signal_bytes: bytes) -> dict:
    """Read two local artifacts; return an unsigned derivative, without modifying either."""
    if any(not isinstance(raw, bytes) or len(raw) > MAX_BYTES for raw in (anchor_bytes, signal_bytes)):
        raise ValueError("Each input must be at most 512 KiB.")
    source = parse_json(anchor_bytes)
    signals = parse_json(signal_bytes)
    anchor_hash = sha256(anchor_bytes).hexdigest()
    if _digest(signals.get("anchor_sha256")) != anchor_hash:
        raise ValueError("Original retest bytes do not match the declared anchor.")
    schema = signals.get("schema")
    if schema == "authzledger.website-lab.v1" and signals.get("dataset") == "synthetic-control-signals":
        synthetic = True
    elif schema == "authzledger.control-signals.v1" and signals.get("dataset") == "operator-supplied-signals":
        synthetic = False
    else:
        raise ValueError("Unsupported signal export profile.")
    expected = _object(signals.get("expectation"))
    context = {key: _identifier(expected.get(key)) for key in ("assessment", "scope", "finding", "source", "rule")}
    if context["assessment"] != source.get("assessment_id") or context["scope"] != _digest(source.get("scope_digest")):
        raise ValueError("Assessment or scope does not match the retest.")
    start, end = _instant(expected.get("from_utc")), _instant(expected.get("until_utc"))
    if start >= end:
        raise ValueError("Empty or reversed observation window.")
    coverage = {}
    for raw in _rows(source.get("transitions")):
        row = _object(raw)
        finding = _identifier(row.get("finding_id"))
        if finding in coverage:
            raise ValueError("Ambiguous finding identifier in the source retest.")
        status = _identifier(row.get("status"))
        if status not in RETEST_STATUSES:
            raise ValueError("Unsupported source retest status.")
        _digest(row.get("baseline_finding_digest"))
        if status == "not_retested":
            if row.get("current_finding_digest") is not None:
                raise ValueError("An omitted finding has a conflicting current digest.")
        else:
            _digest(row.get("current_finding_digest"))
        coverage[finding] = status
    if context["finding"] not in coverage:
        raise ValueError("Expected finding is missing from the source retest.")
    controls = _object(signals.get("controls"))
    if not 1 <= len(controls) <= 32:
        raise ValueError("Supply between one and 32 sample windows.")
    samples = {_identifier(key): _compare(sample, context, start, end) for key, sample in controls.items()}
    return {
        "schema": "authzledger.blue-evidence.v1", "rights": RIGHTS, "signed": False, "synthetic": synthetic,
        "source_assertions_verified": False, "input_profile": schema, "retest_sha256": anchor_hash, "signals_sha256": sha256(signal_bytes).hexdigest(),
        "source_snapshot_digest": _digest(source.get("snapshot_digest")), "binding": context,
        "window": {"from": expected["from_utc"], "until": expected["until_utc"]},
        "source_retest_status": coverage[context["finding"]], "source_coverage": coverage, "samples": samples,
    }
