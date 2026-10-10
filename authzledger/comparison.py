"""Offline, source-bound full-baseline/selected-retest comparisons.

Version 1 deliberately does not alter the strict ``evidence.compare_reports``
API. Originals remain embedded unchanged, including their tool metadata and
evidence roots. Verification rebuilds every derived field from those originals.
An internally consistent envelope is not an attestation of network execution,
credential values, response truth, policy deployment, or vulnerability repair.
"""

from __future__ import annotations

import hashlib
import json

from .assurance import retest_plan
from .intelligence import build_graph, verify_graph
from .model import contract_digest, load_contract


class ComparisonError(ValueError):
    """Sources are invalid, unsupported, or not comparable under this profile."""


_DOMAIN = b"AuthzLedger:comparison-envelope:v1\n"
_STATUSES = ("regression", "resolved_check", "testability_restored",
             "testability_lost", "inconclusive", "unchanged", "not_retested")
# An explicit format compatibility registration, not a wildcard for future 1.x
# engines. The listed release/development entries describe unchanged v1 observation semantics; this
# does not certify any future executable merely because it claims this version.
_PROFILES = {
    "1.0.0": "authzledger-1.0.0-report-v1-checks-v1",
    "1.0.5": "authzledger-1.0.5-report-v1-checks-v1",
    "1.1.0": "authzledger-1.1.0-report-v1-checks-v1",
    "1.1.0.dev0": "authzledger-1.1.0.dev0-report-v1-checks-v1",
}
_LIMITATIONS = [
    "resolved_check means the same configured assertion now passes; it does not establish vulnerability remediation.",
    "Evidence hashes prove internal consistency, not execution, response truth, authorship, or authenticity without a separately trusted signature/root.",
    "Identity header definitions and environment references are bound; resolved credential values and authenticated runtime identity are not attested.",
    "Mutable application state, deployment revisions, and resource ownership outside configured assertions are not attested.",
    "Report timestamps are retained but are not a trusted ordering or freshness attestation.",
    "Only selected cases and their declared control closure are retested; all remaining cases are not_retested.",
    "No independent policy evaluations are supplied or compared; no policy-drift or policy-remediation claim is made.",
]


def _canonical(value) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        raise ComparisonError("comparison inputs must contain finite JSON data") from None


def _copy(value):
    return json.loads(_canonical(value))


def _digest(value) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _profile(report, label):
    if not isinstance(report, dict):
        raise ComparisonError(f"{label} report must be an object")
    tool = report.get("tool")
    if (not isinstance(tool, dict) or set(tool) != {"name", "version"}
            or tool.get("name") != "AuthzLedger"
            or not isinstance(tool.get("version"), str)
            or tool["version"] not in _PROFILES):
        raise ComparisonError(f"not comparable: unsupported {label} tool metadata or version profile")
    return _PROFILES[tool["version"]]


def _bound_graph(contract, report, label):
    try:
        # build_graph invokes verify_report and _bind_report, including complete
        # case sets, exact identity/method/path/control dependencies, assertion
        # layout, status membership, JSON parse consistency and response hashes.
        graph = build_graph(contract, report)
        errors = verify_graph(graph, contract, report)
        if errors:
            raise ComparisonError(f"not comparable: invalid {label} graph semantics")
        return graph
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        if isinstance(exc, ComparisonError):
            raise
        raise ComparisonError(f"not comparable: {label} report is not bound to its exact contract: {exc}") from None


def _controls(case_id, edges):
    """Evaluate all declared ancestors, not just direct dependency outcomes."""
    edge = edges[case_id]
    reasons = []
    seen = set()
    pending = list(edge["requires"])
    positive = False
    while pending:
        identifier = pending.pop()
        if identifier in seen:
            continue
        seen.add(identifier)
        control = edges[identifier]
        pending.extend(control["requires"])
        intent = control["intended"]["decision"]
        observation = control["observed"]
        if intent == "unknown":
            reasons.append("unknown_control_intent:" + identifier)
        if observation["outcome"] != "pass":
            reasons.append("control_not_passed:" + identifier)
        if intent == "allow":
            positive = True
            if (observation["decision"] != "allow"
                    or observation["content_evidence"] != "matched-positive-assertions"):
                reasons.append("unproven_positive_control:" + identifier)
        elif intent == "deny" and observation["decision"] != "deny":
            reasons.append("unproven_negative_control:" + identifier)
    if edge["intended"]["decision"] == "deny" and not positive:
        reasons.append("unanchored_negative_case")
    return {"valid": not reasons, "reasons": sorted(set(reasons))}


def _state(edge):
    return {key: edge["observed"].get(key)
            for key in ("outcome", "status", "decision", "assessment", "content_evidence")}


def _classification(before, after, old_controls, new_controls):
    if not old_controls["valid"] or not new_controls["valid"]:
        return "inconclusive", ["control_validity_not_established"]
    if before["intended"]["decision"] == "unknown":
        return "inconclusive", ["configured_intent_ambiguous"]
    old = before["observed"]["outcome"]
    new = after["observed"]["outcome"]
    if "inconclusive" in (old, new):
        return "inconclusive", ["inconclusive_observation"]
    if new == "error":
        return ("inconclusive", ["both_runs_unassessed"]) if old == "error" else ("testability_lost", ["current_execution_error"])
    if old == "error":
        return ("testability_restored", ["previous_execution_error_current_checks_pass"]) if new == "pass" else ("inconclusive", ["previous_execution_error_no_comparable_assertion"])
    if old == "pass" and new == "fail":
        return "regression", ["same_configured_check_now_fails"]
    if old == "fail" and new == "pass":
        return "resolved_check", ["same_configured_check_now_passes_not_remediation_attestation"]
    return "unchanged", ["configured_check_outcome_unchanged"]


def create_comparison(source_contract, baseline_report, current_report, selected_ids=None) -> dict:
    """Build a deterministic ComparisonEnvelope v1 without I/O or execution.

    ``source_contract`` must be a JSON object, and the baseline must bind its
    complete normalized contract. The current report must bind exactly the
    dependency-closed contract from ``retest_plan(source, selected_ids)``. A
    changed identity definition, request, assertion, control, limit, target or
    contract order is not silently accepted as a repair. Report result order may
    differ: each original chain is verified and cases are joined by stable ID.

    Omitted ``selected_ids`` selects all source cases. No credentials are read,
    no reports are resealed, and accepting mutating case definitions here grants
    no execution permission. Compatibility with 1.0.5 is an explicit report
    format profile, not a claim that an untrusted executable was verified.
    """
    if not isinstance(source_contract, dict):
        raise ComparisonError("source_contract must be an object; offline comparison does not read files")
    baseline_profile = _profile(baseline_report, "baseline")
    current_profile = _profile(current_report, "current")
    # Isolate from callers and reject non-JSON/NaN inputs before validation.
    original_source = _copy(source_contract)
    baseline = _copy(baseline_report)
    current = _copy(current_report)
    try:
        source = load_contract(original_source, allow_mutations=True)
        selection = retest_plan(source, selected_ids, allow_mutations=True)
    except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise ComparisonError(f"invalid comparison source or selection: {exc}") from None
    baseline_graph = _bound_graph(source, baseline, "baseline")
    current_graph = _bound_graph(selection["contract"], current, "current")
    old_edges = {edge["case_id"]: edge for edge in baseline_graph["edges"]}
    new_edges = {edge["case_id"]: edge for edge in current_graph["edges"]}
    transitions = []
    for case in source["cases"]:
        identifier = case["id"]
        before, after = old_edges[identifier], new_edges.get(identifier)
        old_controls = _controls(identifier, old_edges)
        new_controls = _controls(identifier, new_edges) if after is not None else None
        status, reasons = (("not_retested", ["outside_selected_dependency_closure"])
                           if after is None else _classification(before, after, old_controls, new_controls))
        transitions.append({
            "case_id": identifier, "status": status,
            "before": _state(before), "after": _state(after) if after is not None else None,
            "reasons": reasons,
            "controls": {"baseline": old_controls, "current": new_controls},
            "evidence": {"baseline": before["evidence"], "current": after["evidence"] if after is not None else None},
            "case_definition_sha256": _digest(case),
            "identity_definition_sha256": _digest(source["identities"][case["identity"]]),
        })
    envelope = {
        "schema_version": 1, "kind": "comparison-envelope",
        "canonicalization": "json-sort-keys-ascii-escaped-v1",
        "source_contract": original_source,
        "baseline_report": baseline, "current_report": current,
        "selected_ids": selection["selected_ids"], "dependency_ids": selection["dependency_ids"],
        "profiles": {"baseline": baseline_profile, "current": current_profile,
                     "semantics": "source-bound-configured-check-transitions-v1",
                     "registration": "Explicit report-format profiles, not executable certification."},
        "bindings": {
            "original_source_sha256": _digest(original_source),
            "source_contract_sha256": contract_digest(source),
            "retest_contract_sha256": contract_digest(selection["contract"]),
            "baseline_report_sha256": _digest(baseline), "current_report_sha256": _digest(current),
            "baseline_root_sha256": baseline["evidence"]["root_sha256"],
            "current_root_sha256": current["evidence"]["root_sha256"],
            "baseline_tool_sha256": _digest(baseline["tool"]), "current_tool_sha256": _digest(current["tool"]),
            "credential_definitions": "identical-source-bound-references",
            "runtime_credentials": "not-attested",
        },
        "policy": {"status": "not_compared", "reason": "No independent policy evaluations supplied."},
        "transitions": transitions,
        "coverage": {"source_cases": len(source["cases"]),
                     "selected_cases": len(selection["selected_ids"]),
                     "dependency_cases": len(selection["dependency_ids"]),
                     "retested_cases": len(new_edges), "not_retested_cases": len(old_edges) - len(new_edges)},
        "summary": {status: sum(item["status"] == status for item in transitions) for status in _STATUSES},
        "limitations": list(_LIMITATIONS),
    }
    envelope["comparison_sha256"] = hashlib.sha256(_DOMAIN + _canonical(envelope)).hexdigest()
    return envelope


def verify_comparison(envelope) -> list[str]:
    """Recompute all claims from original sources; return errors or ``[]``.

    Rehashing a modified derived summary cannot hide a contradiction. Like any
    unsigned self-contained evidence, a wholly replaced set of consistent
    originals still requires a separately trusted root/signature for provenance.
    """
    if (not isinstance(envelope, dict) or type(envelope.get("schema_version")) is not int
            or envelope.get("schema_version") != 1 or envelope.get("kind") != "comparison-envelope"):
        return ["unsupported comparison envelope kind or schema version"]
    required = {"source_contract", "baseline_report", "current_report", "selected_ids", "comparison_sha256"}
    if required - envelope.keys():
        return ["comparison envelope is missing original sources, selection or digest"]
    if not isinstance(envelope["selected_ids"], list):
        return ["comparison selected_ids must be an explicit nonempty list"]
    try:
        expected = create_comparison(envelope["source_contract"], envelope["baseline_report"],
                                     envelope["current_report"], envelope["selected_ids"])
        if _canonical(expected) != _canonical(envelope):
            return ["comparison envelope does not match recomputed sources, claims or digest"]
    except (ValueError, TypeError, KeyError, RecursionError):
        return ["comparison envelope original sources or selection are invalid or not comparable"]
    return []
