"""Reproducible local evidence hashes and outcome comparisons.

The chain binds report metadata, every complete case record, and case order. It
detects changes relative to an existing seal; it is not a signature or proof of
origin. A party able to change a report can also reseal it. Keep ``root_sha256``
in a separately trusted system when independent integrity checking is needed.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from typing import Any


_OUTCOMES = ("pass", "fail", "error", "inconclusive")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_METADATA_DOMAIN = b"AuthzLedger:v1:metadata\n"
_RECORD_DOMAIN = b"AuthzLedger:v1:record\n"


def _canonical(value: Any) -> bytes:
    """Canonical representation used by this version of the local format."""
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("report must contain finite, UTF-8 JSON data") from exc


def _shape_errors(report: Any) -> list[str]:
    if not isinstance(report, dict):
        return ["report must be an object"]
    errors: list[str] = []
    if type(report.get("schema_version")) is not int or report["schema_version"] != 1:
        errors.append("unsupported report schema version")
    for key in ("name", "target", "started_at", "finished_at"):
        if not isinstance(report.get(key), str) or not report[key]:
            errors.append(f"invalid report field: {key}")
    tool = report.get("tool")
    if not isinstance(tool, dict) or any(
        not isinstance(tool.get(key), str) or not tool[key] for key in ("name", "version")
    ):
        errors.append("invalid tool metadata")
    digest = report.get("contract_sha256")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        errors.append("invalid contract digest")
    results = report.get("results")
    if not isinstance(results, list):
        return errors + ["results must be an array"]
    counts = dict.fromkeys(_OUTCOMES, 0)
    ids: set[str] = set()
    for index, result in enumerate(results):
        prefix = f"result {index + 1}"
        if not isinstance(result, dict):
            errors.append(f"{prefix} must be an object")
            continue
        case_id = result.get("id")
        if not isinstance(case_id, str) or not case_id:
            errors.append(f"{prefix} has an invalid stable ID")
        elif case_id in ids:
            errors.append(f"{prefix} has a duplicate stable ID")
        else:
            ids.add(case_id)
        outcome = result.get("outcome")
        if not isinstance(outcome, str) or outcome not in counts:
            errors.append(f"{prefix} has an invalid outcome")
        else:
            counts[outcome] += 1
        for key in ("identity", "method", "path", "reason"):
            if not isinstance(result.get(key), str):
                errors.append(f"{prefix} has an invalid {key}")
        status = result.get("status")
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            errors.append(f"{prefix} has an invalid HTTP status")
        duration = result.get("duration_ms")
        if (
            type(duration) not in (int, float)
            or (isinstance(duration, float) and not math.isfinite(duration))
            or duration < 0
        ):
            errors.append(f"{prefix} has an invalid duration")
        checks = result.get("checks")
        valid_checks = isinstance(checks, list) and all(
            isinstance(check, dict)
            and isinstance(check.get("type"), str)
            and bool(check["type"])
            and type(check.get("passed")) is bool
            for check in checks
        )
        if not valid_checks:
            errors.append(f"{prefix} has invalid checks")
        elif outcome == "pass" and (not checks or not all(check["passed"] for check in checks)):
            errors.append(f"{prefix} pass requires nonempty, successful checks")
        elif outcome == "fail" and not any(not check["passed"] for check in checks):
            errors.append(f"{prefix} fail requires at least one failed check")
        elif outcome in ("error", "inconclusive") and checks:
            errors.append(f"{prefix} {outcome} must not contain assertion results")
        if outcome in ("pass", "fail") and status is None:
            errors.append(f"{prefix} assessed outcome requires an HTTP status")
        if "requires" in result and (
            not isinstance(result["requires"], list)
            or any(not isinstance(item, str) or not item for item in result["requires"])
        ):
            errors.append(f"{prefix} has invalid required controls")
        if "control_type" in result and not isinstance(result["control_type"], str):
            errors.append(f"{prefix} has an invalid control type")
        response_digest = result.get("response_sha256")
        if response_digest is not None and (
            not isinstance(response_digest, str) or not _SHA256.fullmatch(response_digest)
        ):
            errors.append(f"{prefix} has an invalid response digest")
    expected_summary = {**counts, "total": len(results)}
    summary = report.get("summary")
    if not isinstance(summary, dict) or summary != expected_summary or any(
        type(value) is not int for value in summary.values()
    ):
        errors.append("summary does not match case outcomes")
    return errors


def _seal(report: dict) -> dict:
    metadata = {key: value for key, value in report.items() if key not in ("results", "evidence")}
    metadata_sha256 = hashlib.sha256(_METADATA_DOMAIN + _canonical(metadata)).hexdigest()
    previous = metadata_sha256
    records = []
    for result in report["results"]:
        digest = hashlib.sha256(
            _RECORD_DOMAIN + previous.encode("ascii") + b"\n" + _canonical(result)
        ).hexdigest()
        records.append({"id": result["id"], "previous_sha256": previous, "sha256": digest})
        previous = digest
    return {
        "version": 1,
        "algorithm": "sha256",
        "metadata_sha256": metadata_sha256,
        "records": records,
        "root_sha256": previous,
    }


def seal_report(report: dict) -> dict:
    """Return a sealed copy; input and nested result records are not modified.

    Existing evidence is replaced. Resealing is intentionally possible and does
    not preserve an external trust claim. Comparison with an independently kept
    root is the caller's responsibility.
    """
    errors = _shape_errors(report)
    if errors:
        raise ValueError("cannot seal report: " + "; ".join(errors))
    clean = json.loads(_canonical({key: value for key, value in report.items() if key != "evidence"}))
    clean["evidence"] = _seal(clean)
    return clean


def verify_report(report: dict) -> list[str]:
    """Return stable validation errors, or [] for a consistent local chain."""
    errors = _shape_errors(report)
    if errors:
        return errors
    evidence = report.get("evidence")
    if not isinstance(evidence, dict):
        return ["missing or invalid evidence object"]
    try:
        _canonical(report)
        expected = _seal(report)
    except ValueError:
        return ["report contains unsupported JSON data"]
    if set(evidence) != set(expected):
        errors.append("unexpected or missing evidence fields")
    if type(evidence.get("version")) is not int or evidence.get("version") != 1:
        errors.append("unsupported evidence version")
    if evidence.get("algorithm") != "sha256":
        errors.append("unsupported evidence algorithm")
    if evidence.get("metadata_sha256") != expected["metadata_sha256"]:
        errors.append("metadata hash mismatch")
    records = evidence.get("records")
    if not isinstance(records, list):
        errors.append("evidence records must be an array")
    elif len(records) != len(expected["records"]):
        errors.append("evidence record count mismatch")
    else:
        for index, (actual, correct) in enumerate(zip(records, expected["records"])):
            if actual != correct:
                errors.append(f"evidence record {index + 1} mismatch")
    if evidence.get("root_sha256") != expected["root_sha256"]:
        errors.append("root hash mismatch")
    return errors


def compare_reports(baseline: dict, current: dict) -> dict:
    """Compare validated reports using stable IDs, never position or case name.

    A regression is pass -> fail/error. Resolution is fail/error -> pass.
    Transitions involving inconclusive results are classified separately; they
    never imply resolution. ``unchanged`` means no change in conclusive success
    versus failure, so fail -> error remains unchanged in that narrow sense.
    Exact old/new outcomes are retained in ``transitions``. Version 1 reports
    contain every configured case, including skipped controls, so a different
    case-ID set under the same claimed digest is contradictory and is rejected.
    ``added`` and ``removed`` remain empty reserved API fields in this version.
    """
    for label, report in (("baseline", baseline), ("current", current)):
        errors = verify_report(report)
        if errors:
            raise ValueError(f"invalid {label} report: " + "; ".join(errors))
    if baseline["contract_sha256"] != current["contract_sha256"]:
        raise ValueError("cannot compare different contract digests")
    for field in ("schema_version", "tool", "name", "target"):
        if baseline[field] != current[field]:
            raise ValueError(f"cannot compare reports with different {field}")
    old = {result["id"]: result for result in baseline["results"]}
    new = {result["id"]: result for result in current["results"]}
    if old.keys() != new.keys():
        raise ValueError("cannot compare contradictory case-ID sets under the same contract digest")
    for case_id in old:
        for field in ("identity", "method", "path"):
            if old[case_id][field] != new[case_id][field]:
                raise ValueError(f"cannot compare contradictory case {field} under the same contract digest")
        if old[case_id].get("requires", []) != new[case_id].get("requires", []):
            raise ValueError("cannot compare contradictory required controls under the same contract digest")
        if old[case_id].get("control_type", "configured") != new[case_id].get("control_type", "configured"):
            raise ValueError("cannot compare contradictory control types under the same contract digest")
    groups: dict[str, list[str]] = {
        key: [] for key in ("regressions", "resolved", "unchanged", "added", "removed", "inconclusive")
    }
    transitions = []
    # Sorting by stable ID makes the comparison independent of report ordering.
    for case_id in sorted(old.keys() | new.keys()):
        before = old[case_id]["outcome"] if case_id in old else None
        after = new[case_id]["outcome"] if case_id in new else None
        if before is None:
            category = "added"
        elif after is None:
            category = "removed"
        elif "inconclusive" in (before, after):
            category = "inconclusive"
        elif before == "pass" and after in ("fail", "error"):
            category = "regressions"
        elif before in ("fail", "error") and after == "pass":
            category = "resolved"
        else:
            category = "unchanged"
        groups[category].append(case_id)
        transitions.append({"id": case_id, "baseline": before, "current": after, "category": category})
    return {
        "schema_version": 1,
        "name": current["name"],
        "target": current["target"],
        "contract_sha256": current["contract_sha256"],
        "baseline_root_sha256": baseline["evidence"]["root_sha256"],
        "current_root_sha256": current["evidence"]["root_sha256"],
        "baseline_finished_at": baseline["finished_at"],
        "current_finished_at": current["finished_at"],
        "baseline_summary": dict(baseline["summary"]),
        "current_summary": dict(current["summary"]),
        **groups,
        "summary": {key: len(value) for key, value in groups.items()},
        "transitions": transitions,
    }
