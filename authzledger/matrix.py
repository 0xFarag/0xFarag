"""Compile explicit access decisions into controlled HTTP checks; never infer policy."""
from __future__ import annotations

import copy
import re

from .model import (ContractError, _fields, _string, _identifier, _path, _target,
                    _expect, _ENV, contract_digest, load_contract)
from .evidence import verify_report

_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,39}\Z")


def normalize(value):
    _fields(value, {"version", "name", "target", "actors", "resources", "decisions", "limits"},
            "matrix", {"version", "name", "target", "actors", "resources", "decisions"})
    if type(value["version"]) is not int or value["version"] != 1:
        raise ContractError("Only matrix version 1 is supported.")
    actors, resources = value["actors"], value["resources"]
    if not isinstance(actors, list) or not 1 <= len(actors) <= 30:
        raise ContractError("A matrix needs 1–30 actors.")
    if not isinstance(resources, list) or not 1 <= len(resources) <= 30:
        raise ContractError("A matrix needs 1–30 resources.")
    out = {"version": 1, "name": _string(value["name"], "matrix name"),
           "target": _target(value["target"]), "actors": [], "resources": [], "decisions": {}}
    for actor in actors:
        _fields(actor, {"id", "label", "tenant", "role", "env"}, "actor", {"id", "env"})
        a = {"id": _identifier(actor["id"], "actor id", _KEY),
             "env": _identifier(actor["env"], "credential environment", _ENV)}
        for key in ("label", "tenant", "role"):
            fallback = a["id"] if key == "label" else "unspecified"
            a[key] = _string(actor.get(key) or fallback, "actor " + key, 100)
        out["actors"].append(a)
    actor_ids = {a["id"] for a in out["actors"]}
    if len(actor_ids) != len(actors):
        raise ContractError("Actor IDs must be unique.")
    if len({a["env"] for a in out["actors"]}) != len(actors):
        raise ContractError("Actors need distinct credential environment references.")
    for resource in resources:
        _fields(resource, {"id", "label", "path", "owner", "tenant", "assertions", "deny_status", "absent"},
                "resource", {"id", "path", "assertions"})
        r = {"id": _identifier(resource["id"], "resource id", _KEY), "path": _path(resource["path"])}
        r["label"] = _string(resource.get("label") or r["id"], "resource label", 100)
        r["tenant"] = _string(resource.get("tenant") or "unspecified", "resource tenant", 100)
        r["owner"] = resource.get("owner", "")
        if not isinstance(r["owner"], str) or r["owner"] and r["owner"] not in actor_ids:
            raise ContractError("Resource owner must reference a declared actor or be empty.")
        assertion = _expect({"status": [200], "json": resource["assertions"]})["json"]
        if not assertion or "" in assertion:
            raise ContractError("Every resource needs a non-root JSON assertion to identify its response.")
        deny = _expect({"status": resource.get("deny_status", [403, 404]),
                        "json_absent": resource.get("absent", list(assertion))})
        if set(deny["status"]) - {403, 404}:
            raise ContractError("Matrix denials accept 403/404 only; authentication failures are not policy evidence.")
        r.update(assertions=assertion, deny_status=deny["status"], absent=deny["json_absent"])
        out["resources"].append(r)
    resource_ids = {r["id"] for r in out["resources"]}
    if len(resource_ids) != len(resources):
        raise ContractError("Resource IDs must be unique.")
    if len({r["path"] for r in out["resources"]}) != len(resources):
        raise ContractError("Resource paths must be distinct in a matrix.")
    decisions = value["decisions"]
    _fields(decisions, actor_ids, "decisions")
    for aid in sorted(actor_ids):
        row = decisions.get(aid, {})
        _fields(row, resource_ids, "decision row")
        out["decisions"][aid] = {}
        for rid in sorted(resource_ids):
            decision = row.get(rid, "unknown")
            if not isinstance(decision, str) or decision not in {"allow", "deny", "unknown"}:
                raise ContractError("A decision must be allow, deny or unknown.")
            out["decisions"][aid][rid] = decision
    out["actors"].sort(key=lambda a: a["id"])
    out["resources"].sort(key=lambda r: r["id"])
    # Validate limits, credentials and target through the same core as execution.
    probe = load_contract({"version": 1, "name": out["name"], "target": out["target"],
        "identities": {a["id"]: {"headers": {"Authorization": {"env": a["env"]}}} for a in out["actors"]},
        "limits": value.get("limits", {"max_requests": 1000}),
        "cases": [{"id": "validation", "identity": out["actors"][0]["id"], "method": "GET",
                   "path": out["resources"][0]["path"], "expect": {"status": [200]}}]})
    out["limits"] = probe["limits"]
    if len(actors) * len(resources) > out["limits"]["max_requests"]:
        raise ContractError("Matrix exceeds the configured request budget.")
    return out


def compile_matrix(value, *, require_complete=True):
    project = normalize(value)
    rules = project["decisions"]
    case_id = lambda a, r: "m:" + a + ":" + r
    actor_controls, resource_controls = {}, {}
    for a in project["actors"]:
        aid = a["id"]
        available = [r for r in project["resources"] if rules[aid][r["id"]] == "allow"]
        available.sort(key=lambda r: (r["owner"] != aid, r["id"]))
        if available:
            actor_controls[aid] = case_id(aid, available[0]["id"])
    for r in project["resources"]:
        rid = r["id"]
        available = [a for a in project["actors"] if rules[a["id"]][rid] == "allow"]
        available.sort(key=lambda a: (a["id"] != r["owner"], a["id"]))
        if available:
            resource_controls[rid] = case_id(available[0]["id"], rid)
    cases, trace, gaps = [], [], []
    counts = {"allow": 0, "deny": 0, "unknown": 0, "blocked": 0,
              "total": len(project["actors"]) * len(project["resources"])}
    for a in project["actors"]:
        for r in project["resources"]:
            aid, rid = a["id"], r["id"]
            decision = rules[aid][rid]
            counts[decision] += 1
            reasons, dependencies = [], []
            if decision == "unknown":
                reasons.append("Expected permission has not been reviewed.")
            if decision == "deny":
                if aid not in actor_controls:
                    reasons.append("Actor has no successful-access control.")
                if rid not in resource_controls:
                    reasons.append("Resource has no successful-access control.")
                dependencies = sorted({actor_controls[aid], resource_controls[rid]}) if not reasons else []
            boundary = "cross-identity"
            if a["tenant"] != "unspecified" and r["tenant"] != "unspecified" and a["tenant"] != r["tenant"]:
                boundary = "cross-tenant"
            elif r["owner"] == aid:
                boundary = "own-resource"
            item = {"case_id": case_id(aid, rid), "actor": aid, "resource": rid,
                    "decision": decision, "boundary": boundary, "requires": dependencies,
                    "actor_control": actor_controls.get(aid), "resource_control": resource_controls.get(rid),
                    "blocked": reasons}
            trace.append(item)
            if reasons:
                gaps.append(item)
                if decision != "unknown":
                    counts["blocked"] += 1
                continue
            cases.append({"id": item["case_id"], "identity": aid, "method": "GET", "path": r["path"],
                "requires": dependencies,
                "expect": {"status": [200], "json": r["assertions"]} if decision == "allow"
                          else {"status": r["deny_status"], "json_absent": r["absent"]}})
    complete = not gaps
    if require_complete and not complete:
        raise ContractError("Matrix has unknown decisions or missing positive controls. Resolve coverage gaps before compiling.")
    contract = None
    if complete:
        contract = load_contract({"version": 1, "name": project["name"], "target": project["target"],
            "identities": {a["id"]: {"headers": {"Authorization": {"env": a["env"]}}} for a in project["actors"]},
            "limits": project["limits"], "cases": cases})
    manifest = {"schema_version": 1, "generator": "authzledger.matrix.v1",
                "project_sha256": contract_digest(project),
                "contract_sha256": contract_digest(contract) if contract else None,
                "coverage": counts, "complete": complete, "trace": trace}
    return {"project": project, "contract": contract, "manifest": manifest, "gaps": gaps}


def explain_report(project, report):
    compiled = compile_matrix(project)
    if not isinstance(report, dict) or verify_report(report):
        raise ContractError("Report integrity validation failed.")
    contract, manifest = compiled["contract"], compiled["manifest"]
    if (report.get("contract_sha256") != manifest["contract_sha256"] or
            report.get("target") != contract["target"] or report.get("name") != contract["name"]):
        raise ContractError("Report does not belong to this exact matrix contract.")
    by_id = {item["id"]: item for item in report["results"]}
    if set(by_id) != {c["id"] for c in contract["cases"]}:
        raise ContractError("Report case set does not match the matrix.")
    for c in contract["cases"]:
        result = by_id[c["id"]]
        if any(result.get(key) != c[key] for key in ("identity", "method", "path", "requires")):
            raise ContractError("Report case scope does not match the matrix.")
    trace = copy.deepcopy(manifest["trace"])
    for item in trace:
        result = by_id[item["case_id"]]
        item.update(outcome=result["outcome"], status=result["status"],
                    failed_controls=[key for key in item["requires"] if by_id[key]["outcome"] != "pass"])
        if result["outcome"] == "inconclusive":
            item["explanation"] = "Not executed: a required control did not pass. Denial has not been established."
        elif result["outcome"] == "error":
            item["explanation"] = "Execution error: the expected access decision could not be established."
        elif result["outcome"] == "pass":
            item["explanation"] = "Observed response satisfies this explicit access rule and its assertions."
        elif item["decision"] == "deny":
            item["explanation"] = "Denial expectation violated after both actor and resource controls passed. Review the failed assertions."
        else:
            item["explanation"] = "Permitted-access control failed. Its dependent denial checks cannot establish isolation."
    return {"manifest": manifest, "trace": trace, "summary": report["summary"]}


def policy_diff(before, after):
    """Explain a proposed policy migration. Never classify a policy edit as a fix."""
    old, new = compile_matrix(before, require_complete=False), compile_matrix(after, require_complete=False)
    p, q = old["project"], new["project"]
    left = {(x["actor"], x["resource"]): x for x in old["manifest"]["trace"]}
    right = {(x["actor"], x["resource"]): x for x in new["manifest"]["trace"]}
    actors_p, actors_q = ({x["id"]: x for x in z["actors"]} for z in (p, q))
    resources_p, resources_q = ({x["id"]: x for x in z["resources"]} for z in (p, q))
    changes = []
    for key in sorted(left.keys() | right.keys()):
        a, b = left.get(key), right.get(key)
        aid, rid = key
        reasons = []
        if a is None:
            reasons.append("added")
        elif b is None:
            reasons.append("removed")
        else:
            if a["decision"] != b["decision"]:
                reasons.append("policy-change")
            if actors_p[aid] != actors_q[aid]:
                reasons.append("actor-binding-change")
            if resources_p[rid] != resources_q[rid]:
                reasons.append("resource-binding-change")
            if a["requires"] != b["requires"]:
                reasons.append("control-change")
        if reasons:
            changes.append({"actor": aid, "resource": rid, "before": a["decision"] if a else None,
                            "after": b["decision"] if b else None, "reasons": reasons})
    return {"schema_version": 1, "kind": "proposed-policy-migration",
            "before_project_sha256": old["manifest"]["project_sha256"],
            "after_project_sha256": new["manifest"]["project_sha256"],
            "scope_changed": p["target"] != q["target"], "limits_changed": p["limits"] != q["limits"],
            "before_coverage": old["manifest"]["coverage"], "after_coverage": new["manifest"]["coverage"],
            "changes": changes, "approval_required": True,
            "interpretation": "Configuration comparison only. No vulnerability is classified as resolved by changing policy."}
