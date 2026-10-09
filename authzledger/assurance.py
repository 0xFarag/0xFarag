"""Explicit dependency-closed retests and finite local continuous assurance.

Every iteration resolves fresh credentials and performs the same scoped,
control-gated checks. No automatic discovery, authentication refresh request,
hosted service, or unbounded background task is introduced here.
"""

from __future__ import annotations

import math
import threading
from datetime import datetime, timezone

from . import engine
from .evidence import verify_report
from .history import HistoryError, HistoryStore
from .model import ContractError, contract_digest, load_contract, plan


class AssuranceError(ValueError):
    """An assurance execution cannot be performed safely or conclusively."""


class StaleHistoryError(AssuranceError):
    """A prior baseline cannot be treated as fresh assurance context."""


_GENESIS = "0" * 64
_REGRESSION_TYPES = {"unexpected-access", "policy-bypass", "denial-body-leak", "policy-intent-drift", "unexpected-success-status"}


def retest_plan(contract, selected_ids=None, *, allow_mutations: bool = False) -> dict:
    """Expand selected IDs with declared prerequisites, and send no requests.

    The closure only includes cases already present in the source contract.
    A selected negative case can never omit its positive controls. The result
    exposes every added prerequisite before the caller explicitly executes it.
    """
    source = load_contract(contract, allow_mutations=allow_mutations)
    by_id = {case["id"]: case for case in source["cases"]}
    if selected_ids is None:
        selected = set(by_id)
    else:
        if (not isinstance(selected_ids, (list, tuple)) or not selected_ids
                or any(not isinstance(item, str) for item in selected_ids)):
            raise AssuranceError("retest selection must be a nonempty list of stable case IDs")
        selected = set(selected_ids)
        if len(selected) != len(selected_ids):
            raise AssuranceError("retest selection contains duplicate case IDs")
        if selected - by_id.keys():
            raise AssuranceError("retest selection references an unknown case ID")
    closure = set(selected)
    pending = list(selected)
    while pending:
        for dependency in by_id[pending.pop()]["requires"]:
            if dependency not in closure:
                closure.add(dependency)
                pending.append(dependency)
    specification = dict(source, cases=[case for case in source["cases"] if case["id"] in closure])
    specification = load_contract(specification, allow_mutations=allow_mutations)
    execution = plan(specification)
    return {"schema_version": 1, "source_contract_sha256": contract_digest(source),
            "selected_ids": [case["id"] for case in source["cases"] if case["id"] in selected],
            "dependency_ids": [case["id"] for case in source["cases"] if case["id"] in closure - selected],
            "request_count": execution["request_count"], "mutating_requests": execution["mutating_requests"],
            "contract": specification, "plan": execution}


def _snapshot(history: HistoryStore | None, contract: dict) -> tuple[dict | None, str]:
    if history is None:
        return None, _GENESIS
    errors = history.verify_chain()
    if errors:
        raise HistoryError("history integrity check failed before execution: " + "; ".join(errors))
    summaries = history.list_runs(limit=1000)
    tail = summaries[0]["record_sha256"] if summaries else _GENESIS
    baseline = next((row for row in summaries if row["target"] == contract["target"] and row["name"] == contract["name"]), None)
    return history.get_run(baseline["id"]) if baseline else None, tail


def history_snapshot(history: HistoryStore | None, contract: dict) -> tuple[dict | None, str]:
    """Validate retained history and select a scoped baseline before traffic."""
    return _snapshot(history, load_contract(contract, allow_mutations=True))


def _assert_fresh(baseline: dict | None, max_age: float | None) -> None:
    if max_age is None or baseline is None:
        return
    try:
        finished_at = datetime.fromisoformat(baseline["finished_at"].replace("Z", "+00:00"))
        if finished_at.tzinfo is None:
            raise ValueError
        age = (datetime.now(timezone.utc) - finished_at.astimezone(timezone.utc)).total_seconds()
    except (ValueError, TypeError, KeyError):
        raise StaleHistoryError("history baseline timestamp is invalid") from None
    if age < -5 or age > max_age:
        raise StaleHistoryError("history baseline is stale or has a future timestamp; select a new baseline explicitly")


def _status(report: dict, graph: dict, comparison: dict | None) -> tuple[str, int, str | None]:
    summary = report["summary"]
    findings = graph.get("findings", [])
    if summary["error"]:
        return "error", 2, "execution-error"
    if any(item.get("type") == "positive-control-failed" for item in findings):
        return "inconclusive", 2, "invalid-control"
    edges = {edge["case_id"]: edge for edge in graph.get("edges", [])}
    required_positive = {case_id for edge in edges.values()
                         for case_id in edge.get("controls", {}).get("positive", [])}
    for case_id in required_positive:
        observed = edges.get(case_id, {}).get("observed", {})
        if (observed.get("decision") != "allow"
                or observed.get("content_evidence") != "matched-positive-assertions"):
            return "inconclusive", 2, "unproven-positive-control"
    if summary["inconclusive"]:
        return "inconclusive", 2, "inconclusive-control"
    if any(item.get("type") == "unanchored-negative-control" for item in findings):
        return "inconclusive", 2, "unanchored-negative-control"
    if graph.get("coverage", {}).get("intended_known", summary["total"]) != summary["total"]:
        return "inconclusive", 2, "ambiguous-intent"
    if summary["fail"] or any(item.get("type") in _REGRESSION_TYPES for item in findings):
        return "fail", 1, "authorization-mismatch"
    if comparison and comparison.get("inconclusive"):
        return "inconclusive", 2, "inconclusive-comparison"
    if comparison and (comparison.get("regressions") or comparison.get("privilege_escalations")
                       or comparison.get("policy_drift") or comparison.get("intended_drift")
                       or comparison.get("context_drift") or comparison.get("removed")):
        return "fail", 1, "authorization-change"
    return "pass", 0, None


def assessment_status(report: dict, graph: dict, comparison: dict | None = None) -> tuple[str, int, str | None]:
    """Classify a verified report and source-bound graph for Studio/CLI parity.

    Callers must build/bind the graph first. This function sends no traffic and
    does not alter evidence or transform advisory AI text into a decision.
    """
    errors = verify_report(report)
    if errors:
        raise AssuranceError("assessment requires verified report evidence")
    return _status(report, graph, comparison)


def run_once(contract, policy=None, history: HistoryStore | None = None, *,
             allow_mutations: bool = False, max_history_age_seconds: float | None = None) -> dict:
    """Perform one local assurance run and optionally retain/compare its context.

    Exit codes: 0 configured checks passed, 1 authorization mismatch/change,
    2 execution error or inconclusive controls. A pass is scoped to configured
    checks; it does not assert complete or continuously observed authorization.
    """
    from .intelligence import build_graph, differential_graphs
    from .policy import evaluate_policy, load_policy

    specification = load_contract(contract, allow_mutations=allow_mutations)
    if max_history_age_seconds is not None:
        _number(max_history_age_seconds, "max_history_age_seconds", minimum=0, maximum=31536000)
    # Local policy loading is validation only. A remote PDP is evaluated exactly
    # once, after retained history is checked and before application traffic.
    configuration = None
    if policy is not None:
        if isinstance(policy, dict) and policy.get("kind") == "policy-evaluation":
            build_graph(specification, None, policy)
        else:
            configuration = load_policy(policy)
    baseline, tail = _snapshot(history, specification)
    _assert_fresh(baseline, max_history_age_seconds)
    # Fail closed across both network channels if application credentials are
    # missing or malformed. engine.run resolves them again for the actual run.
    engine._credentials(specification)
    evaluation = evaluate_policy(specification, configuration) if configuration is not None else policy
    report = engine.run(specification)
    errors = verify_report(report)
    if errors:
        raise AssuranceError("execution produced invalid evidence: " + "; ".join(errors))
    graph = build_graph(specification, report, evaluation)
    comparison = differential_graphs(baseline["graph"], graph) if baseline else None
    status, exit_code, reason = _status(report, graph, comparison)
    result = {"report": report, "graph": graph, "status": status, "exit_code": exit_code,
              "stop_reason": reason}
    if comparison is not None:
        result["comparison"] = comparison
        result["baseline_run_id"] = baseline["id"]
    if history is not None:
        result["history"] = history.append(specification, report, graph, expected_previous_sha256=tail)
    return result


def _number(value, label: str, *, minimum: float, maximum: float, integer: bool = False) -> None:
    if (type(value) not in ((int,) if integer else (int, float))
            or not minimum <= value <= maximum or not math.isfinite(value)):
        raise AssuranceError(f"{label} must be {'an integer' if integer else 'finite'} between {minimum:g} and {maximum:g}")


def watch(contract, policy=None, history: HistoryStore | None = None, *,
          max_iterations: int = 1, interval_seconds: float = 0,
          max_requests_total: int = 1000, max_history_age_seconds: float | None = None,
          allow_mutations: bool = False, stop_event: threading.Event | None = None,
          on_iteration=None) -> dict:
    """Run a bounded synchronous local watch, stopping on the first unsafe result.

    A full case count is reserved before each iteration, including cases later
    blocked by controls. This conservative accounting caps total network scope
    across the entire watch. Cancellation is checked before each iteration and
    interrupts intervals; in-flight requests remain bounded by their deadline.
    """
    _number(max_iterations, "max_iterations", minimum=1, maximum=1000, integer=True)
    _number(interval_seconds, "interval_seconds", minimum=0, maximum=3600)
    _number(max_requests_total, "max_requests_total", minimum=1, maximum=1000000, integer=True)
    if max_history_age_seconds is not None:
        _number(max_history_age_seconds, "max_history_age_seconds", minimum=0, maximum=31536000)
    if stop_event is not None and not isinstance(stop_event, threading.Event):
        raise AssuranceError("stop_event must be a threading.Event")
    if on_iteration is not None and not callable(on_iteration):
        raise AssuranceError("on_iteration must be callable")
    specification = load_contract(contract, allow_mutations=allow_mutations)
    if policy is not None and not (isinstance(policy, dict) and policy.get("kind") == "policy-evaluation"):
        from .policy import load_policy
        policy = load_policy(policy)
    application_requests = len(specification["cases"])
    policy_requests = application_requests if isinstance(policy, dict) and policy.get("engine") == "opa" and policy.get("kind") != "policy-evaluation" else 0
    request_count = application_requests + policy_requests
    if request_count > max_requests_total:
        raise AssuranceError("the first iteration exceeds the total request budget")
    results = []
    reserved = 0
    event = stop_event or threading.Event()
    status, exit_code, reason = "pass", 0, "iteration-limit"
    for iteration in range(max_iterations):
        if event.is_set():
            status, exit_code, reason = "cancelled", 2, "cancelled"
            break
        if reserved + request_count > max_requests_total:
            status, exit_code, reason = "inconclusive", 2, "request-budget"
            break
        reserved += request_count
        try:
            result = run_once(specification, policy, history, allow_mutations=allow_mutations,
                              max_history_age_seconds=max_history_age_seconds)
        except (AssuranceError, HistoryError, ContractError, ValueError) as exc:
            # Avoid leaking credential-bearing exception text from future APIs.
            category = "stale-history" if isinstance(exc, StaleHistoryError) else "history-error" if isinstance(exc, HistoryError) else "assurance-error"
            status, exit_code, reason = "error", 2, category
            break
        results.append(result)
        if on_iteration is not None:
            on_iteration(iteration + 1, result)
        if result["exit_code"]:
            status, exit_code, reason = result["status"], result["exit_code"], result["stop_reason"]
            break
        if iteration + 1 < max_iterations and event.wait(interval_seconds):
            status, exit_code, reason = "cancelled", 2, "cancelled"
            break
    return {"schema_version": 1, "iterations": results, "completed_iterations": len(results),
            "max_iterations": max_iterations, "interval_seconds": interval_seconds,
            "max_requests_total": max_requests_total, "requests_reserved": reserved,
            "application_requests_per_iteration": application_requests,
            "policy_requests_per_iteration": policy_requests,
            "status": status, "exit_code": exit_code, "stop_reason": reason,
            "scope": "Only explicit contract cases; intervals are unobserved, not a continuous enforcement guarantee."}
