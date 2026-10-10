"""Deterministic, evidence-preserving reduction with freshly executed controls.

Only explicitly selected request units are removed. The original execution is
retained verbatim; every accepted candidate has independent execution evidence.
"""
from __future__ import annotations

import copy
import re
from urllib.parse import unquote_plus

from .model import _pointer as validate_pointer
from .workflows import _canonical, _seal, _set_json


class ReductionError(ValueError):
    pass


_PROTECTED = re.compile(r"auth|cookie|token|key|secret|credential|session|role|permission|identity|tenant|account|owner|principal|marker|resource|(^|[_-])id($|[_-])", re.I)


def _adapter(execution):
    if not isinstance(execution, dict):
        raise ReductionError("A verified confirmed execution is required.")
    if execution.get("kind") == "workflow-trace":
        from .workflows import verify_workflow, compile_workflow, execute_workflow
        if verify_workflow(execution):
            raise ReductionError("Workflow trace verification failed.")
        variants = execution.get("variants", [])
        if len(variants) != 1 or variants[0]["interpretation"] != "violation" or not variants[0]["controls_valid"] or variants[0]["cleanup"] != "complete":
            raise ReductionError("Reduction requires one confirmed isolated workflow variant with completed cleanup.")
        spec = execution["plan"]["spec"]
        case_ids = {step["case_id"] for step in spec["steps"]}
        protected = set(spec["controls"]) | {spec[key]["case_id"] for key in ("setup", "precondition", "postcondition")} | {step["case_id"] for step in spec["cleanup"]}
        case_ids -= protected
        fingerprint = {"rule_digest": execution["plan"]["rule_digest"], "fixture": spec["fixture"],
                       "subjects": [[step["id"], step.get("identity")] for step in execution["plan"]["variants"][0]["steps"]]}
        return spec, case_ids, fingerprint, compile_workflow, execute_workflow, "workflow_digest"
    from .experiments import verify_execution, compile_experiment, execute_experiment
    if verify_execution(execution):
        raise ReductionError("Experiment verification failed.")
    findings = execution.get("findings", [])
    if len(findings) != 1 or findings[0].get("status") != "confirmed" or findings[0].get("interpretation") != "violation":
        raise ReductionError("Select one confirmed variant before reduction.")
    spec = execution["plan"]["spec"]
    if any(case["method"] not in {"GET", "HEAD", "OPTIONS"} for case in spec["contract"]["cases"]):
        raise ReductionError("Mutating reductions require a WorkflowTrace with fresh fixture isolation and cleanup.")
    finding = findings[0]
    fingerprint = {key: finding[key] for key in ("rule_digest", "resource_id", "identity", "case_id")}
    return spec, {finding["case_id"]}, fingerprint, compile_experiment, execute_experiment, "execution_digest"


def _tokens(pointer):
    return [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]


def _has_protected(value):
    if isinstance(value, dict):
        return any(_PROTECTED.search(name) or _has_protected(child) for name, child in value.items())
    if isinstance(value, list):
        return any(_has_protected(child) for child in value)
    return False


def _json_fields(value, prefix=""):
    # Array element removal changes later indices. Only object fields are offered;
    # callers may address a nested object through a fixed array index.
    if isinstance(value, dict):
        for name in sorted(value):
            path = prefix + "/" + name.replace("~", "~0").replace("/", "~1")
            if not _PROTECTED.search(name):
                if not _has_protected(value[name]):
                    yield path
                yield from _json_fields(value[name], path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _json_fields(child, prefix + "/" + str(index))


def removable_units(execution):
    """Offer stable, nonsecret units only in the explicit investigation request."""
    spec, selected, _, _, _, _ = _adapter(execution)
    units = []
    protected_pointers = []
    protected_units = set()
    if execution.get("kind") == "workflow-trace":
        for step in spec["steps"]:
            protected_pointers.extend((step["case_id"], binding["target"].get("pointer")) for binding in step["bindings"] if binding["target"]["kind"] == "json")
            for binding in step["bindings"]:
                target = binding["target"]
                if target["kind"] == "query":
                    protected_units.add((step["case_id"], "query", target["name"], target["occurrence"]))
                elif target["kind"] == "header":
                    protected_units.add((step["case_id"], "header", target["name"].lower(), 0))
    for case in spec["contract"]["cases"]:
        if case["id"] not in selected:
            continue
        for name in sorted(case["headers"], key=str.lower):
            if not _PROTECTED.search(name) and (case["id"], "header", name.lower(), 0) not in protected_units:
                units.append({"kind": "header", "case_id": case["id"], "name": name.lower(), "occurrence": 0})
        counts = {}
        query = case["path"].partition("?")[2]
        for pair in query.split("&") if query else []:
            name = unquote_plus(pair.split("=", 1)[0])
            occurrence = counts.get(name, 0)
            counts[name] = occurrence + 1
            if not _PROTECTED.search(name) and (case["id"], "query", name, occurrence) not in protected_units:
                units.append({"kind": "query", "case_id": case["id"], "name": name, "occurrence": occurrence})
        for pointer in _json_fields(case.get("body")):
            if not any(case_id == case["id"] and (pointer == bound or pointer.startswith(bound + "/") or bound.startswith(pointer + "/")) for case_id, bound in protected_pointers):
                units.append({"kind": "json", "case_id": case["id"], "pointer": pointer})
    return sorted(units, key=lambda item: _canonical(item))


def plan_reduction(execution, units, *, max_requests=40):
    """Freeze explicit removals and original evidence before any requests occur."""
    spec, _, fingerprint, _, _, digest_field = _adapter(execution)
    if type(max_requests) is not int or not 1 <= max_requests <= 40:
        raise ReductionError("Reduction budget must be between one and forty requests, including all controls.")
    if not isinstance(units, list) or not 1 <= len(units) <= 64:
        raise ReductionError("Select one to sixty-four removable request units.")
    allowed = {_canonical(unit) for unit in removable_units(execution)}
    selected = set()
    for unit in units:
        encoded = _canonical(unit)
        if encoded not in allowed or encoded in selected:
            raise ReductionError("A selected unit is protected, ambiguous, absent or duplicated.")
        selected.add(encoded)
    for left in units:
        for right in units:
            if left is right or left.get("kind") != "json" or right.get("kind") != "json" or left["case_id"] != right["case_id"]:
                continue
            if right["pointer"].startswith(left["pointer"] + "/"):
                raise ReductionError("Overlapping JSON field removals are ambiguous; choose parent or child.")
    request_count = execution["plan"]["request_upper_bound"]
    cleanup_count = execution["plan"].get("cleanup_reserve", 0)
    return _seal({"schema_id": "authzledger.reduction-plan", "schema_version": 1, "kind": "reduction-plan", "original_execution": copy.deepcopy(execution),
                  "original_digest": execution[digest_field], "fingerprint": fingerprint,
                  "units": sorted(copy.deepcopy(units), key=_canonical), "max_requests": max_requests,
                  "requests_per_attempt": request_count, "cleanup_reserve": (max_requests // request_count) * cleanup_count,
                  "scope": {"target": spec["contract"]["target"]}}, "plan_digest")


def _remove(spec, units):
    output = copy.deepcopy(spec)
    by_case = {}
    for unit in units:
        by_case.setdefault(unit["case_id"], []).append(unit)
    for case in output["contract"]["cases"]:
        selected = by_case.get(case["id"], [])
        headers = {unit["name"] for unit in selected if unit["kind"] == "header"}
        case["headers"] = {name: value for name, value in case["headers"].items() if name.lower() not in headers}
        query_units = {(unit["name"], unit["occurrence"]) for unit in selected if unit["kind"] == "query"}
        if query_units:
            path, _, query = case["path"].partition("?")
            counts, pairs = {}, []
            for pair in query.split("&"):
                name = unquote_plus(pair.split("=", 1)[0]); occurrence = counts.get(name, 0)
                counts[name] = occurrence + 1
                if (name, occurrence) not in query_units:
                    pairs.append(pair)
            case["path"] = path + (("?" + "&".join(pairs)) if pairs else "")
        for unit in selected:
            if unit["kind"] != "json":
                continue
            parts = _tokens(unit["pointer"])
            current = case["body"]
            for part in parts[:-1]:
                current = current[int(part)] if isinstance(current, list) else current[part]
            # Offered units always end in an object field, never an array position.
            del current[parts[-1]]
    return output


def _classify(execution, fingerprint):
    if execution.get("kind") == "workflow-trace":
        from .workflows import verify_workflow
        if verify_workflow(execution):
            return "inconclusive"
        variants = execution.get("variants", [])
        if len(variants) != 1 or not variants[0].get("controls_valid") or variants[0].get("cleanup") != "complete":
            return "inconclusive"
        spec = execution["plan"]["spec"]
        actual = {"rule_digest": execution["plan"]["rule_digest"], "fixture": spec["fixture"],
                  "subjects": [[step["id"], step.get("identity")] for step in execution["plan"]["variants"][0]["steps"]]}
        interpretation = variants[0]["interpretation"]
    else:
        from .experiments import verify_execution
        if verify_execution(execution):
            return "inconclusive"
        findings = execution.get("findings", [])
        if len(findings) != 1:
            return "inconclusive"
        finding = findings[0]
        actual = {key: finding[key] for key in ("rule_digest", "resource_id", "identity", "case_id")}
        observation = next((item for item in execution["observations"] if item["case_id"] == finding["case_id"]), None)
        if not observation or not observation["controls_valid"]:
            return "inconclusive"
        interpretation = finding["interpretation"]
    if _canonical(actual) != _canonical(fingerprint):
        return "inconclusive"
    return {"violation": "reproduced", "satisfied": "not_reproduced"}.get(interpretation, "inconclusive")


def execute_reduction(plan, *, context=None, credential_resolver=None):
    """Run deterministic chunk reduction then a conclusive final single-unit gate."""
    if not isinstance(plan, dict) or plan_reduction(plan.get("original_execution"), plan.get("units"), max_requests=plan.get("max_requests")) != plan:
        raise ReductionError("Reduction plan was modified after review.")
    from .execution import ExecutionContext
    original = plan["original_execution"]
    spec, _, _, compile_candidate, execute_candidate, digest_field = _adapter(original)
    if context is None:
        context = ExecutionContext(plan["max_requests"], [plan["scope"]["target"]], timeout_seconds=spec["contract"]["limits"]["timeout_seconds"],
                                   concurrency=1, cleanup_reserve=plan["cleanup_reserve"], allow_cleanup_after_cancel=True)
    start = context.snapshot()["dispatched_total"]
    accepted, attempts = [], []
    accepted_execution = copy.deepcopy(original)
    stop_reason, unstable, exhausted = "complete", False, False
    all_indices = list(range(len(plan["units"])))
    def trial(indices, phase):
        nonlocal stop_reason, exhausted, unstable
        consumed = context.snapshot()["dispatched_total"] - start
        candidate_spec = _remove(spec, [plan["units"][index] for index in sorted(indices)])
        candidate = compile_candidate(candidate_spec)
        cleanup = candidate.get("cleanup_reserve", 0)
        if (consumed + candidate["request_upper_bound"] > plan["max_requests"]
                or context.remaining() < candidate["request_upper_bound"] - cleanup
                or context.remaining("cleanup") < cleanup):
            stop_reason, exhausted = "budget_exhausted", True
            return None, None
        execution = execute_candidate(candidate, context=context, credential_resolver=credential_resolver)
        interpretation = _classify(execution, plan["fingerprint"])
        attempts.append({"removed": sorted(indices), "phase": phase, "interpretation": interpretation, "execution": execution})
        if interpretation == "inconclusive":
            unstable = True
        return interpretation, execution
    # Remove deterministic chunks, refine on rejection; accepted indices always
    # reference original units so duplicate query occurrence indices never drift.
    granularity = 2
    while not exhausted:
        remaining = [index for index in all_indices if index not in accepted]
        if not remaining:
            break
        width = max(1, (len(remaining) + granularity - 1) // granularity)
        chunks = [remaining[offset:offset + width] for offset in range(0, len(remaining), width)]
        progress = False
        for chunk in chunks:
            state, candidate_execution = trial(sorted(accepted + chunk), "chunk")
            if state is None:
                break
            if state == "reproduced":
                accepted = sorted(accepted + chunk)
                accepted_execution = candidate_execution
                granularity = max(2, granularity - 1)
                progress = True
                break
        if progress:
            continue
        if exhausted or width == 1:
            break
        granularity = min(len(remaining), granularity * 2)
    # Recheck every remaining single unit against the final candidate. Accepted
    # removal invalidates earlier negative tests and restarts this final gate.
    one_minimal = False
    final_checks = []
    while not exhausted:
        final_checks = []
        restart = False
        for index in [item for item in all_indices if item not in accepted]:
            state, candidate_execution = trial(sorted(accepted + [index]), "single")
            if state is None:
                break
            final_checks.append({"unit": index, "interpretation": state, "attempt": len(attempts) - 1})
            if state == "reproduced":
                accepted = sorted(accepted + [index])
                accepted_execution = candidate_execution
                restart = True
                break
        if restart:
            continue
        if exhausted:
            break
        # Even zero remaining units require a final repeat to detect observed
        # flakiness. This is bounded sampled repeatability, not a global proof.
        state, repeated = trial(accepted, "confirmation")
        if state == "reproduced":
            accepted_execution = repeated
            one_minimal = not unstable and all(check["interpretation"] == "not_reproduced" for check in final_checks)
        else:
            unstable = True
            if state is not None:
                stop_reason = "repeatability_failed"
        break
    if unstable and stop_reason == "complete":
        stop_reason = "inconclusive_attempts"
    return _seal({"schema_id": "authzledger.reduction-trace", "schema_version": 1, "kind": "reduction-trace", "plan": copy.deepcopy(plan),
                  "original_execution": copy.deepcopy(original), "accepted_execution": accepted_execution,
                  "accepted_removed": accepted, "attempts": attempts, "final_checks": final_checks,
                  "one_minimal": one_minimal, "stop_reason": stop_reason,
                  "requests_used": context.snapshot()["dispatched_total"] - start, "starting_dispatched": start, "budget_ledger": context.snapshot(),
                  "label": "1-minimal within approved units" if one_minimal else ("reduced; minimality not confirmed" if accepted else "no confirmed reduction; minimality not confirmed"),
                  "limitations": ["Minimality is relative to selected removable units, never globally shortest.",
                                   "Each attempt re-executes controls; mutation attempts require a fresh workflow fixture.",
                                   "Observed repeatability is bounded by the approved request budget."]}, "reduction_digest")


def verify_reduction(trace):
    """Recompute plan, candidates, interestingness and the final minimality gate."""
    errors = []
    try:
        fields = {"schema_id", "schema_version", "kind", "plan", "original_execution", "accepted_execution", "accepted_removed", "attempts", "final_checks", "one_minimal", "stop_reason", "requests_used", "starting_dispatched", "budget_ledger", "label", "limitations", "reduction_digest"}
        if (not isinstance(trace, dict) or set(trace) != fields or trace.get("schema_id") != "authzledger.reduction-trace"
                or type(trace.get("schema_version")) is not int or trace.get("schema_version") != 1 or trace.get("kind") != "reduction-trace"):
            raise ReductionError("Unsupported reduction trace.")
        if type(trace["one_minimal"]) is not bool:
            raise ReductionError("Minimality must be an explicit boolean.")
        if trace["stop_reason"] not in {"complete", "budget_exhausted", "repeatability_failed", "inconclusive_attempts"}:
            raise ReductionError("Unknown reduction stop reason.")
        expected_label = "1-minimal within approved units" if trace["one_minimal"] else ("reduced; minimality not confirmed" if trace["accepted_removed"] else "no confirmed reduction; minimality not confirmed")
        if trace["label"] != expected_label:
            errors.append("Reduction label contradicts its minimality result.")
        if trace["one_minimal"] != (trace["stop_reason"] == "complete"):
            errors.append("Reduction completion/minimality state is inconsistent.")
        candidate = copy.deepcopy(trace)
        claimed = candidate.pop("reduction_digest")
        if _seal(candidate, "reduction_digest")["reduction_digest"] != claimed:
            errors.append("Reduction digest mismatch.")
        plan = trace["plan"]
        if plan_reduction(plan["original_execution"], plan["units"], max_requests=plan["max_requests"]) != plan:
            errors.append("Reduction plan mismatch.")
        if trace["original_execution"] != plan["original_execution"]:
            errors.append("Original reduction evidence changed.")
        spec, _, _, compile_candidate, _, _ = _adapter(trace["original_execution"])
        accepted_execution = trace["original_execution"]
        accepted = []
        observed_inconclusive = False
        if not isinstance(trace["attempts"], list) or len(trace["attempts"]) > 512:
            raise ReductionError("Invalid reduction attempt list.")
        for attempt in trace["attempts"]:
            if not isinstance(attempt, dict) or set(attempt) != {"removed", "phase", "interpretation", "execution"} or attempt["phase"] not in {"chunk", "single", "confirmation"}:
                raise ReductionError("Invalid reduction attempt fields.")
            if attempt["execution"].get("kind") == "workflow-trace":
                from .workflows import verify_workflow
                attempt_errors = verify_workflow(attempt["execution"])
            else:
                from .experiments import verify_execution
                attempt_errors = verify_execution(attempt["execution"])
            if attempt_errors:
                errors.append("Reduction attempt contains invalid execution evidence.")
            indices = attempt["removed"]
            if any(type(index) is not int or index < 0 or index >= len(plan["units"]) for index in indices) or indices != sorted(set(indices)):
                raise ReductionError("Invalid unit indices.")
            expected = compile_candidate(_remove(spec, [plan["units"][index] for index in indices]))
            if attempt["execution"]["plan"] != expected:
                errors.append("Candidate was not the declared reduction.")
            state = _classify(attempt["execution"], plan["fingerprint"])
            if state != attempt["interpretation"]:
                errors.append("Reduction interestingness mismatch.")
            if state == "reproduced":
                if not set(accepted) <= set(indices):
                    errors.append("Accepted reductions must form a monotone chain.")
                accepted, accepted_execution = indices, attempt["execution"]
            elif state == "inconclusive":
                observed_inconclusive = True
        if accepted != trace["accepted_removed"] or accepted_execution != trace["accepted_execution"]:
            errors.append("Accepted reduction evidence mismatch.")
        if type(trace["requests_used"]) is not int or not 0 <= trace["requests_used"] <= plan["max_requests"]:
            errors.append("Reduction exceeds the approved budget.")
        ledger = trace["budget_ledger"]
        dispatched = [record for record in ledger["requests"] if record["state"] in {"dispatched", "finished"}]
        if (type(trace["starting_dispatched"]) is not int or trace["starting_dispatched"] < 0
                or type(ledger["dispatched_total"]) is not int or type(ledger["approved_total"]) is not int
                or len(dispatched) != ledger["dispatched_total"]
                or not 0 <= ledger["dispatched_total"] <= ledger["approved_total"]
                or ledger["dispatched_total"] - trace["starting_dispatched"] != trace["requests_used"]
                or sum(ledger["by_kind"].values()) != ledger["dispatched_total"]):
            errors.append("Reduction request accounting mismatch.")
        previous_count = trace["starting_dispatched"]
        attempt_requests = 0
        for attempt in trace["attempts"]:
            execution = attempt["execution"]
            current_count = execution["budget_ledger"]["dispatched_total"]
            reports = [execution["report"]] if execution["kind"] != "workflow-trace" else [
                record["report"] for variant in execution["variants"]
                for record in ([variant["controls"]] if "controls" in variant else []) + variant["steps"]]
            actual_requests = sum(result["outcome"] != "inconclusive" for report in reports for result in report["results"])
            attempt_requests += actual_requests
            if not previous_count <= current_count <= ledger["dispatched_total"] or current_count - previous_count != actual_requests:
                errors.append("Reduction attempt request accounting contradicts its original reports.")
            previous_count = current_count
        if attempt_requests != trace["requests_used"]:
            errors.append("Reduction request total differs from its attempt evidence.")
        if trace["attempts"] and previous_count != ledger["dispatched_total"]:
            errors.append("Final reduction budget differs from the final attempt.")
        if trace["stop_reason"] == "budget_exhausted":
            cleanup = trace["original_execution"]["plan"].get("cleanup_reserve", 0)
            if (trace["requests_used"] + plan["requests_per_attempt"] <= plan["max_requests"]
                    and ledger["remaining"] >= plan["requests_per_attempt"] - cleanup
                    and ledger["cleanup_remaining"] >= cleanup):
                errors.append("Budget exhaustion is not supported by the final ledger.")
        if trace["stop_reason"] == "inconclusive_attempts" and not observed_inconclusive:
            errors.append("Inconclusive stop reason has no inconclusive attempt.")
        if trace["stop_reason"] == "repeatability_failed" and (not trace["attempts"]
                or trace["attempts"][-1]["phase"] != "confirmation"
                or trace["attempts"][-1]["interpretation"] not in {"not_reproduced", "inconclusive"}):
            errors.append("Repeatability failure has no failed confirmation.")
        if trace["one_minimal"]:
            remaining = set(range(len(plan["units"]))) - set(accepted)
            checked = set()
            for check in trace["final_checks"]:
                if (not isinstance(check, dict) or set(check) != {"unit", "interpretation", "attempt"}
                        or type(check["unit"]) is not int or check["unit"] not in remaining or check["unit"] in checked
                        or type(check["attempt"]) is not int or not 0 <= check["attempt"] < len(trace["attempts"])):
                    raise ReductionError("Invalid final single-removal reference.")
                attempt = trace["attempts"][check["attempt"]]
                if (check["interpretation"] != "not_reproduced" or attempt["interpretation"] != "not_reproduced" or attempt["phase"] != "single"
                        or attempt["removed"] != sorted(accepted + [check["unit"]])):
                    errors.append("Invalid final single-removal check.")
                checked.add(check["unit"])
            if (remaining != checked or observed_inconclusive or not trace["attempts"]
                    or trace["attempts"][-1]["phase"] != "confirmation"
                    or trace["attempts"][-1]["interpretation"] != "reproduced"
                    or trace["attempts"][-1]["removed"] != accepted):
                errors.append("Minimality was not conclusively established.")
    except (ValueError, TypeError, KeyError, IndexError, RecursionError):
        errors.append("Malformed reduction trace.")
    return errors
