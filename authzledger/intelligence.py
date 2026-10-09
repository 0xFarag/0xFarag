"""Three independently sourced authorization layers and truthful differences.

A graph binds configured intent, independent policy decisions and sealed
observations. Status families are signals, not proof that a real subject was
authenticated or that every possible response field is safe.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re

from .evidence import verify_report
from .model import contract_digest, load_contract
from .policy import evaluate_policy


class IntelligenceError(ValueError):
    """Sources cannot safely be bound or compared."""


_DECISIONS = {"allow", "deny", "unknown"}
_SHA = re.compile(r"[a-f0-9]{64}\Z")


def _digest(value):
    try:
        raw = json.dumps(value, ensure_ascii=True, sort_keys=True,
                         separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        raise IntelligenceError("intelligence input must be finite JSON") from None
    return hashlib.sha256(raw).hexdigest()


def _id(kind, *parts):
    return kind + ":" + _digest(list(parts))[:32]


def _status_decision(statuses):
    if statuses and all(200 <= status < 300 for status in statuses):
        return "allow"
    if statuses and all(status in {401, 403, 404} for status in statuses):
        return "deny"
    return "unknown"


def _expected_check_types(case):
    expected = case["expect"]
    types = ["status"]
    if expected.get("json") or expected.get("json_absent"):
        types += ["json_parse"] + ["json"] * len(expected.get("json", {}))
        types += ["json_absent"] * len(expected.get("json_absent", []))
    return types


def _bind_report(contract, report):
    errors = verify_report(report)
    if errors:
        raise IntelligenceError("invalid observed report: " + "; ".join(errors))
    if report["contract_sha256"] != contract_digest(contract):
        raise IntelligenceError("observed report contract digest does not match")
    if report["target"] != contract["target"] or report["name"] != contract["name"]:
        raise IntelligenceError("observed report target or contract name does not match")
    cases = {case["id"]: case for case in contract["cases"]}
    results = {result["id"]: result for result in report["results"]}
    if cases.keys() != results.keys():
        raise IntelligenceError("observed report case set does not match the contract")
    for case_id, case in cases.items():
        result = results[case_id]
        if any(result[key] != case[key] for key in ("identity", "method", "path")):
            raise IntelligenceError("observed report case identity, method or resource does not match")
        if result.get("requires", []) != case["requires"]:
            raise IntelligenceError("observed report control dependencies do not match")
        intended = _status_decision(case["expect"]["status"])
        control = {"allow": "positive", "deny": "negative", "unknown": "configured"}[intended]
        if result.get("control_type", "configured") != control:
            raise IntelligenceError("observed report control type does not match")
        if result["outcome"] in {"pass", "fail"}:
            checks = result["checks"]
            if [check["type"] for check in checks] != _expected_check_types(case):
                raise IntelligenceError("observed report assertion layout does not match")
            if checks[0]["passed"] is not (result["status"] in case["expect"]["status"]):
                raise IntelligenceError("observed report status assertion contradicts its contract")
            if len(checks) > 1 and not checks[1]["passed"] and any(check["passed"] for check in checks[2:]):
                raise IntelligenceError("observed report contains successful checks after invalid JSON")
            if result.get("response_sha256") is None:
                raise IntelligenceError("assessed report is missing its response digest")
    return results


def _bind_policy(contract, policy):
    if policy is None:
        return None
    if not isinstance(policy, dict) or policy.get("kind") != "policy-evaluation":
        policy = evaluate_policy(contract, policy)
    if (type(policy.get("schema_version")) is not int or policy["schema_version"] != 1
            or policy.get("contract_sha256") != contract_digest(contract)
            or policy.get("target") != contract["target"]):
        raise IntelligenceError("policy evaluation is not bound to this contract and target")
    digest = policy.get("policy_sha256")
    if not isinstance(digest, str) or not _SHA.fullmatch(digest):
        raise IntelligenceError("policy evaluation is missing a policy digest")
    if policy.get("engine") not in ("local", "opa"):
        raise IntelligenceError("policy evaluation has an invalid declared engine")
    decisions = policy.get("decisions")
    if not isinstance(decisions, dict) or decisions.keys() != {case["id"] for case in contract["cases"]}:
        raise IntelligenceError("policy evaluation case set does not match")
    for value in decisions.values():
        if (not isinstance(value, dict) or value.get("decision") not in ("allow", "deny", "unknown")
                or value.get("source") not in ("local-policy", "opa")
                or not isinstance(value.get("provenance"), dict)
                or value["provenance"].get("policy_sha256") != digest
                or not isinstance(value.get("explanation"), str)):
            raise IntelligenceError("policy decision is invalid or has contradictory provenance")
        source, engine = ("local-policy", "authzledger-rules-v1") if policy["engine"] == "local" else ("opa", "opa-rest-v1")
        if value["source"] != source or value["provenance"].get("engine") != engine:
            raise IntelligenceError("policy decision contradicts its declared evaluation engine")
        if not isinstance(value.get("input_sha256"), str) or not _SHA.fullmatch(value["input_sha256"]):
            raise IntelligenceError("policy decision is missing a valid input fingerprint")
    _digest(policy)
    return policy


def _observed(result, intended):
    if result is None:
        return {"decision": "unknown", "outcome": "unobserved", "status": None,
                "checks": [], "assessment": "unobserved", "reason": "No report supplied.",
                "content_evidence": "not-established"}
    outcome = result["outcome"]
    decision = _status_decision([result.get("status")]) if outcome in {"pass", "fail"} else "unknown"
    content_evidence = "not-established"
    assessment = {"error": "execution-error", "inconclusive": "inconclusive"}.get(outcome)
    if assessment is None:
        assessment = {"allow": "allowed", "deny": "denied", "unknown": "ambiguous-status"}[decision]
        valid_json = any(check["type"] == "json_parse" and check["passed"] for check in result["checks"])
        leaking = any(check["type"] == "json_absent" and not check["passed"] for check in result["checks"])
        content_checks = [check for check in result["checks"] if check["type"] == "json"]
        matched_positive = intended == "allow" and valid_json and bool(content_checks) and all(check["passed"] for check in content_checks)
        if valid_json and leaking:
            content_evidence = "protected-field-present"
        elif matched_positive:
            content_evidence = "matched-positive-assertions"
        if decision == "allow" and content_evidence == "not-established":
            decision = "unknown"
            assessment = "unexpected-success-status" if intended == "deny" else "status-only-acceptance"
        if decision == "deny" and valid_json and leaking:
            assessment = "unsafe-denial"
        elif intended == "allow" and outcome == "fail":
            assessment = "rejected-control"
        elif outcome == "fail" and assessment not in {"unexpected-success-status", "status-only-acceptance"}:
            assessment = "configured-check-failure"
    return {"decision": decision, "outcome": outcome, "status": result.get("status"),
            "checks": copy.deepcopy(result["checks"]), "assessment": assessment,
            "reason": result["reason"], "content_evidence": content_evidence}


def _findings(edge):
    intended, policy, observed = (edge[key]["decision"] for key in ("intended", "policy", "observed"))
    findings = []

    def add(kind, severity, *basis):
        findings.append({"type": kind, "severity": severity, "case_id": edge["case_id"],
                         "edge_id": edge["id"], "basis": list(basis)})

    if intended != "unknown" and policy != "unknown" and intended != policy:
        add("policy-intent-drift", "high" if policy == "allow" else "medium", "Explicit contract intent differs from independent policy decision.")
    if intended == "deny" and observed == "allow":
        add("unexpected-access", "high", "A configured denial produced an assessed 2xx response containing an explicitly forbidden JSON field.")
    if intended == "allow" and observed == "deny":
        add("unexpected-denial", "medium", "A configured positive control produced an assessed denial response.")
    if policy == "deny" and observed == "allow":
        add("policy-bypass", "high", "Observed assessed 2xx behavior differs from the supplied deny policy.")
    if edge["observed"]["content_evidence"] == "protected-field-present":
        add("denial-body-leak" if intended == "deny" else "protected-field-leak", "high", "Valid JSON contains a field explicitly required to be absent; this establishes configured field presence, not its sensitive value.")
    if edge["observed"]["assessment"] == "unexpected-success-status":
        add("unexpected-success-status", "medium", "A denial expectation produced 2xx but no configured content evidence established protected access.")
    if edge["observed"]["assessment"] == "rejected-control":
        add("positive-control-failed", "medium", "Positive-control assertions failed; dependent cases cannot establish a pass.")
    if intended == "deny" and not edge["controls"]["anchored"]:
        add("unanchored-negative-control", "info", "No explicit positive-control prerequisite is declared for this negative control.")
    return findings


def build_graph(contract, report=None, policy=None) -> dict:
    """Bind intent, optional verified observations and independent policy input.

    A normalized contract is accepted without executing it. A supplied report
    must have a valid local evidence chain and exactly match its whole contract.
    Hash consistency is not a claim of network execution or trusted authorship.
    """
    contract = load_contract(contract, allow_mutations=True)
    results = _bind_report(contract, report) if report is not None else {}
    policy = _bind_policy(contract, policy)
    cases = {case["id"]: case for case in contract["cases"]}
    node_map = {}
    edges = []
    records = {item["id"]: item["sha256"] for item in report["evidence"]["records"]} if report else {}
    root = report["evidence"]["root_sha256"] if report else None
    for case in sorted(contract["cases"], key=lambda item: item["id"]):
        identity_id = _id("identity", case["identity"])
        resource_id = _id("resource", contract["target"], case["path"])
        edge_id = _id("access", contract["target"], case["identity"], case["method"], case["path"], case["id"])
        node_map[identity_id] = {"id": identity_id, "kind": "identity", "label": case["identity"], "identity": case["identity"]}
        node_map[resource_id] = {"id": resource_id, "kind": "resource", "label": case["path"], "path": case["path"], "target": contract["target"]}
        intended = _status_decision(case["expect"]["status"])
        caveats = ["HTTP status families are configured signals; they do not prove identity authentication or complete data isolation."]
        if 401 in case["expect"]["status"]:
            caveats.append("401 may establish authentication rejection rather than an authenticated authorization decision.")
        if 404 in case["expect"]["status"]:
            caveats.append("404 may conceal a resource or indicate it is absent; a passing positive resource control establishes only the configured resource evidence.")
        control_groups = {"positive": [], "negative": [], "other": []}
        for prerequisite in case["requires"]:
            kind = {"allow": "positive", "deny": "negative", "unknown": "other"}[_status_decision(cases[prerequisite]["expect"]["status"])]
            control_groups[kind].append(prerequisite)
        control_groups["anchored"] = bool(control_groups["positive"])
        result = results.get(case["id"])
        policy_decision = copy.deepcopy(policy["decisions"][case["id"]]) if policy else {
            "decision": "unknown", "source": "not-evaluated", "provenance": {},
            "explanation": "No independent policy input supplied."}
        edge = {"id": edge_id, "case_id": case["id"], "source": identity_id, "target": resource_id,
                "identity": case["identity"], "method": case["method"], "path": case["path"],
                "requires": list(case["requires"]), "controls": control_groups,
                "intended": {"decision": intended, "source": "contract", "statuses": list(case["expect"]["status"]),
                             "checks_sha256": _digest({key: case.get(key) for key in ("expect", "requires", "body", "headers")}),
                             "caveats": caveats},
                "policy": policy_decision, "observed": _observed(result, intended),
                "evidence": {"report_root_sha256": root, "record_sha256": records[case["id"]],
                             "response_sha256": result.get("response_sha256")} if result else None}
        edge["findings"] = _findings(edge)
        edges.append(edge)
    coverage = _coverage(edges)
    graph = {"schema_version": 1, "kind": "authorization-graph", "name": contract["name"],
             "target": contract["target"], "contract_sha256": contract_digest(contract),
             "evidence_report_root_sha256": root, "policy_sha256": policy["policy_sha256"] if policy else None,
             "nodes": [node_map[key] for key in sorted(node_map)], "edges": edges,
             "findings": [finding for edge in edges for finding in edge["findings"]], "coverage": coverage,
             "trust": "Local evidence consistency checked; execution, identity binding and supplied policy deployment are not independently attested."}
    graph["graph_sha256"] = _digest(graph)
    return graph


def _coverage(edges):
    return {"total": len(edges),
                "intended_known": sum(edge["intended"]["decision"] != "unknown" for edge in edges),
                "policy_known": sum(edge["policy"]["decision"] != "unknown" for edge in edges),
                "observed_known": sum(edge["observed"]["decision"] != "unknown" for edge in edges),
                "assessed": sum(edge["observed"]["outcome"] in {"pass", "fail"} for edge in edges),
                "unobserved": sum(edge["observed"]["outcome"] == "unobserved" for edge in edges),
                "errors": sum(edge["observed"]["outcome"] == "error" for edge in edges),
                "inconclusive": sum(edge["observed"]["outcome"] == "inconclusive" for edge in edges),
                "anchored_negative": sum(edge["intended"]["decision"] == "deny" and edge["controls"]["anchored"] for edge in edges)}
def _validate_graph(graph, label):
    if (not isinstance(graph, dict) or type(graph.get("schema_version")) is not int
            or graph["schema_version"] != 1 or graph.get("kind") != "authorization-graph"):
        raise IntelligenceError(f"invalid {label} authorization graph")
    if graph.get("graph_sha256") != _digest({key: value for key, value in graph.items() if key != "graph_sha256"}):
        raise IntelligenceError(f"{label} graph hash does not match")
    edges = graph.get("edges")
    if not isinstance(edges, list):
        raise IntelligenceError(f"{label} graph edges must be an array")
    ids = set()
    if not isinstance(graph.get("target"), str) or not isinstance(graph.get("contract_sha256"), str) or not _SHA.fullmatch(graph["contract_sha256"]):
        raise IntelligenceError(f"{label} graph scope or contract digest is invalid")
    if graph.get("policy_sha256") is not None and (not isinstance(graph["policy_sha256"], str) or not _SHA.fullmatch(graph["policy_sha256"])):
        raise IntelligenceError(f"{label} graph policy digest is invalid")
    nodes = graph.get("nodes")
    if not isinstance(nodes, list) or any(not isinstance(node, dict) or not isinstance(node.get("id"), str) for node in nodes):
        raise IntelligenceError(f"{label} graph nodes are invalid")
    node_ids = {node["id"] for node in nodes}
    if len(node_ids) != len(nodes):
        raise IntelligenceError(f"{label} graph nodes contain duplicate ids")
    node_map = {node["id"]: node for node in nodes}
    by_case = {}
    for edge in edges:
        if not isinstance(edge, dict) or not isinstance(edge.get("id"), str) or edge["id"] in ids:
            raise IntelligenceError(f"{label} graph edges contain invalid or duplicate ids")
        ids.add(edge["id"])
        if any(not isinstance(edge.get(key), str) for key in ("case_id", "identity", "method", "path")):
            raise IntelligenceError(f"{label} graph edge scope is invalid")
        if edge["case_id"] in by_case:
            raise IntelligenceError(f"{label} graph case ids must be unique")
        by_case[edge["case_id"]] = edge
        if edge["id"] != _id("access", graph.get("target"), edge["identity"], edge["method"], edge["path"], edge["case_id"]):
            raise IntelligenceError(f"{label} graph edge id contradicts its scope")
        for layer in ("intended", "policy", "observed"):
            if not isinstance(edge.get(layer), dict) or edge[layer].get("decision") not in ("allow", "deny", "unknown"):
                raise IntelligenceError(f"{label} graph decision layer is invalid")
        if edge["observed"].get("outcome") not in ("pass", "fail", "error", "inconclusive", "unobserved"):
            raise IntelligenceError(f"{label} graph outcome is invalid")
        if not isinstance(edge["intended"].get("checks_sha256"), str) or not _SHA.fullmatch(edge["intended"]["checks_sha256"]):
            raise IntelligenceError(f"{label} graph is missing its assertion fingerprint")
        statuses = edge["intended"].get("statuses")
        if (not isinstance(statuses, list) or not statuses or any(type(status) is not int or not 100 <= status <= 599 for status in statuses)
                or edge["intended"]["decision"] != _status_decision(statuses)):
            raise IntelligenceError(f"{label} graph intent contradicts its statuses")
        if edge.get("source") != _id("identity", edge["identity"]) or edge.get("target") != _id("resource", graph["target"], edge["path"]):
            raise IntelligenceError(f"{label} graph endpoints contradict scope")
        if edge["source"] not in node_ids or edge["target"] not in node_ids:
            raise IntelligenceError(f"{label} graph refers to missing nodes")
        if node_map[edge["source"]] != {"id": edge["source"], "kind": "identity", "label": edge["identity"], "identity": edge["identity"]}:
            raise IntelligenceError(f"{label} graph identity node contradicts edge scope")
        if node_map[edge["target"]] != {"id": edge["target"], "kind": "resource", "label": edge["path"], "path": edge["path"], "target": graph["target"]}:
            raise IntelligenceError(f"{label} graph resource node contradicts edge scope")
        policy = edge["policy"]
        if graph.get("policy_sha256") is None:
            if policy != {"decision": "unknown", "source": "not-evaluated", "provenance": {}, "explanation": "No independent policy input supplied."}:
                raise IntelligenceError(f"{label} graph policy layer has no bound input")
        elif (policy.get("source") not in ("local-policy", "opa") or not isinstance(policy.get("provenance"), dict)
              or policy["provenance"].get("policy_sha256") != graph["policy_sha256"]):
            raise IntelligenceError(f"{label} graph policy provenance is contradictory")
        else:
            engine = "authzledger-rules-v1" if policy["source"] == "local-policy" else "opa-rest-v1"
            if policy["provenance"].get("engine") != engine or not isinstance(policy.get("input_sha256"), str) or not _SHA.fullmatch(policy["input_sha256"]):
                raise IntelligenceError(f"{label} graph policy engine or input fingerprint is invalid")
        observed = edge["observed"]
        checks = observed.get("checks")
        if not isinstance(checks, list) or any(not isinstance(check, dict) or not isinstance(check.get("type"), str) or type(check.get("passed")) is not bool for check in checks):
            raise IntelligenceError(f"{label} graph assertion results are invalid")
        outcome = observed["outcome"]
        if outcome in {"pass", "fail"}:
            status = observed.get("status")
            if type(status) is not int or not 100 <= status <= 599:
                raise IntelligenceError(f"{label} graph observation contradicts its status")
            if not checks or checks[0].get("type") != "status" or checks[0]["passed"] is not (status in statuses):
                raise IntelligenceError(f"{label} graph status assertion contradicts its intent")
            if outcome == "pass" and not all(check["passed"] for check in checks) or outcome == "fail" and all(check["passed"] for check in checks):
                raise IntelligenceError(f"{label} graph outcome contradicts assertions")
        elif checks or observed["decision"] != "unknown":
            raise IntelligenceError(f"{label} graph unassessed observation contains a decision")
        expected_observed = _observed({"outcome": outcome, "status": observed.get("status"), "checks": checks,
                                       "reason": observed.get("reason")}, edge["intended"]["decision"]) if outcome != "unobserved" else _observed(None, edge["intended"]["decision"])
        if observed != expected_observed:
            raise IntelligenceError(f"{label} graph assessment contradicts observations")
        if not isinstance(edge.get("controls"), dict) or type(edge["controls"].get("anchored")) is not bool:
            raise IntelligenceError(f"{label} graph controls are invalid")
        if edge.get("findings") != _findings(edge):
            raise IntelligenceError(f"{label} graph findings contradict its layers")
        evidence = edge.get("evidence")
        if outcome == "unobserved":
            if evidence is not None:
                raise IntelligenceError(f"{label} graph unobserved edge contains evidence")
        elif (not isinstance(evidence, dict) or evidence.get("report_root_sha256") != graph.get("evidence_report_root_sha256")
              or any(not isinstance(evidence.get(key), str) or not _SHA.fullmatch(evidence[key]) for key in ("report_root_sha256", "record_sha256"))):
            raise IntelligenceError(f"{label} graph evidence binding is invalid")
        if evidence is not None:
            response_hash = evidence.get("response_sha256")
            if response_hash is not None and (not isinstance(response_hash, str) or not _SHA.fullmatch(response_hash)):
                raise IntelligenceError(f"{label} graph response digest is invalid")
            if outcome in {"pass", "fail"} and response_hash is None:
                raise IntelligenceError(f"{label} graph assessed response is missing its digest")
    # Derive controls instead of trusting submitted positive/negative labels.
    pending = {}
    for case_id, edge in by_case.items():
        requires = edge.get("requires")
        if (not isinstance(requires, list) or any(not isinstance(item, str) or item not in by_case for item in requires)
                or len(set(requires)) != len(requires)):
            raise IntelligenceError(f"{label} graph prerequisites are undefined or ambiguous")
        pending[case_id] = set(requires)
        groups = {"positive": [], "negative": [], "other": []}
        for prerequisite in requires:
            kind = {"allow": "positive", "deny": "negative", "unknown": "other"}[by_case[prerequisite]["intended"]["decision"]]
            groups[kind].append(prerequisite)
        groups["anchored"] = bool(groups["positive"])
        if edge["controls"] != groups:
            raise IntelligenceError(f"{label} graph controls contradict prerequisites")
        if any(by_case[item]["observed"]["outcome"] not in {"pass", "unobserved"} for item in requires):
            observed = edge["observed"]
            if observed["outcome"] != "inconclusive" or observed["status"] is not None or edge["evidence"].get("response_sha256") is not None:
                raise IntelligenceError(f"{label} graph assessed a case after its prerequisite failed")
        elif any(by_case[item]["observed"]["outcome"] == "unobserved" for item in requires) and edge["observed"]["outcome"] != "unobserved":
            raise IntelligenceError(f"{label} graph assessed a case without observed prerequisites")
    resolved = set()
    while pending:
        ready = {case_id for case_id, dependencies in pending.items() if dependencies <= resolved}
        if not ready:
            raise IntelligenceError(f"{label} graph prerequisites contain a cycle")
        resolved.update(ready)
        for case_id in ready:
            del pending[case_id]
    if node_ids != {edge[key] for edge in edges for key in ("source", "target")}:
        raise IntelligenceError(f"{label} graph contains unbound nodes")
    if graph.get("findings") != [finding for edge in edges for finding in edge["findings"]] or graph.get("coverage") != _coverage(edges):
        raise IntelligenceError(f"{label} graph findings or coverage are inconsistent")
    return {edge["id"]: edge for edge in edges}


def verify_graph(graph, contract=None, report=None) -> list[str]:
    """Check graph consistency and optionally reconstruct its bound sources.

    A graph hash alone proves local consistency, not the source's authenticity.
    With contract and report, all contract/report binding checks are repeated.
    Retained policy decisions remain operator-supplied input, never attestation.
    """
    try:
        _validate_graph(graph, "supplied")
        if report is not None and contract is None:
            raise IntelligenceError("graph source verification requires its contract")
        if contract is not None:
            normalized = load_contract(contract, allow_mutations=True)
            if graph["contract_sha256"] != contract_digest(normalized):
                raise IntelligenceError("graph contract digest does not match")
            if graph.get("evidence_report_root_sha256") is not None and report is None:
                raise IntelligenceError("graph source verification requires its observed report")
            policy = None
            if graph.get("policy_sha256") is not None:
                sources = {edge["policy"]["source"] for edge in graph["edges"]}
                if len(sources) != 1:
                    raise IntelligenceError("graph policy decisions have contradictory engines")
                policy = {"schema_version": 1, "kind": "policy-evaluation", "contract_sha256": graph["contract_sha256"],
                          "engine": "local" if sources == {"local-policy"} else "opa",
                          "target": graph["target"], "policy_sha256": graph["policy_sha256"],
                          "decisions": {edge["case_id"]: edge["policy"] for edge in graph["edges"]}}
            rebuilt = build_graph(normalized, report, policy)
            if rebuilt["graph_sha256"] != graph["graph_sha256"]:
                raise IntelligenceError("graph does not match its retained contract and report")
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        return [str(exc) if isinstance(exc, ValueError) else "graph contains invalid structural data"]
    return []


def _state(edge):
    return {"intended": edge["intended"]["decision"], "policy": edge["policy"]["decision"],
            "observed": edge["observed"]["decision"], "outcome": edge["observed"]["outcome"],
            "assessment": edge["observed"].get("assessment")}


def differential_graphs(before, after) -> dict:
    """Compare layer changes, coverage and regressions without inventing fixes.

    Changed expectations or policy definitions are drift, never resolution of a
    previously failing assertion. An unknown or skipped observation also cannot
    resolve a failure. Different targets are refused rather than merged.
    """
    old, new = _validate_graph(before, "before"), _validate_graph(after, "after")
    if before.get("target") != after.get("target"):
        raise IntelligenceError("cannot compare authorization graphs for different targets")
    groups = {key: [] for key in ("policy_drift", "intended_drift", "context_drift", "privilege_escalations", "regressions",
                                 "resolved", "coverage_changes", "added", "removed", "unchanged", "inconclusive")}
    transitions = []
    for identifier in sorted(old.keys() | new.keys()):
        previous, current = old.get(identifier), new.get(identifier)
        entry = {"edge_id": identifier, "case_id": (current or previous)["case_id"],
                 "before": _state(previous) if previous else None, "after": _state(current) if current else None}
        categories = []

        def classify(category):
            groups[category].append(copy.deepcopy(entry))
            categories.append(category)

        if previous is None:
            classify("added")
            classify("coverage_changes")
        elif current is None:
            classify("removed")
            classify("coverage_changes")
        else:
            intended_changed = previous["intended"] != current["intended"]
            # OPA response digests change with the output and are observations,
            # not a policy revision. Config plus context fingerprints define the
            # independent policy assumptions actually available for comparison.
            def policy_definition(edge):
                return (edge["policy"].get("source"), edge["policy"].get("input_sha256"),
                        edge["policy"].get("provenance", {}).get("policy_sha256"))
            policy_changed = (previous["policy"]["decision"] != current["policy"]["decision"]
                              or policy_definition(previous) != policy_definition(current))
            if intended_changed:
                classify("intended_drift")
            contract_changed = before["contract_sha256"] != after["contract_sha256"]
            if contract_changed:
                classify("context_drift")
            if policy_changed:
                classify("policy_drift")
            a, b = previous["observed"], current["observed"]
            if a["decision"] == "deny" and b["decision"] == "allow":
                classify("privilege_escalations")
            elif previous["policy"]["decision"] == "deny" and current["policy"]["decision"] == "allow":
                classify("privilege_escalations")
            if (a["decision"] == "unknown") != (b["decision"] == "unknown"):
                classify("coverage_changes")
            # The whole contract includes identity credential references and
            # every prerequisite's assertions. Changing those can make an
            # unchanged negative case pass with a different actor or weaker
            # controls. A stable edge alone must never turn that into a fix.
            comparable = not contract_changed and not intended_changed and not policy_changed
            if comparable and a["outcome"] == "pass" and b["outcome"] in {"fail", "error"}:
                classify("regressions")
            if comparable and a["outcome"] in {"fail", "error"} and b["outcome"] == "pass":
                classify("resolved")
            if a["outcome"] in {"unobserved", "inconclusive"} or b["outcome"] in {"unobserved", "inconclusive"}:
                classify("inconclusive")
            if not categories:
                classify("unchanged")
        transitions.append({**entry, "categories": categories})
    return {"schema_version": 1, "kind": "authorization-differential", "target": after["target"],
            "before_graph_sha256": before["graph_sha256"], "after_graph_sha256": after["graph_sha256"],
            "before_contract_sha256": before["contract_sha256"], "after_contract_sha256": after["contract_sha256"],
            **groups, "transitions": transitions,
            "summary": {key: len(value) for key, value in groups.items()},
            "trust": "Changes reflect configured observations and supplied policy; privilege-escalation signals require analyst confirmation."}
