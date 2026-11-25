# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Deterministic assessment of imported evidence. Never connects to a target."""
from collections import Counter, defaultdict
import re

from .evidence_formats import MAX_ROWS, canonical, sha
from .proof_imports import CREDENTIAL, import_source, safe_host, source_object

RIGHTS = "© Nasser Aldin Farag (0xFarag). All rights reserved."
METHOD = "AuthzLedger 1.5.0 · passive evidence review"
DEPENDENCIES = {"token": [], "identity": ["token"], "owner": ["identity"], "denial": ["identity"]}
RULE = "protected-marker"
MAX_SOURCES = 32
MAX_RUNS = 128


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(value):
    return sha(canonical(value))


def make_scope(hosts, roe, budget):
    require(isinstance(hosts, list) and 1 <= len(hosts) <= 32, "provide 1–32 explicit scoped hosts")
    values = [safe_host(value) for value in hosts]
    require(len(set(values)) == len(values), "duplicate scoped host")
    require(isinstance(roe, str) and 0 < len(roe.strip()) <= 1200 and len(roe) <= 1200
            and not CREDENTIAL.search(roe) and not re.search(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]", roe), "invalid rules of engagement")
    require(type(budget) is int and 0 <= budget <= 1000000, "invalid budget")
    return {"hosts": values, "roe": roe.strip(), "budget": budget}


def _controls(intended):
    require(isinstance(intended, dict) and set(intended) == set(DEPENDENCIES)
            and all(type(v) is bool for v in intended.values()), "four explicit control decisions are required")
    result = {}
    for name, parents in DEPENDENCIES.items():
        result[name] = {"intended": intended[name], "dependsOn": list(parents),
                        "effective": intended[name] and all(result[p]["effective"] for p in parents)}
    return result


def _one_source(source):
    require(isinstance(source, dict) and {"format", "sha256", "observations"} <= set(source) <= {"format", "sha256", "observations", "observedAbsent"}, "invalid source")
    sanitized = source_object(source["format"], source["sha256"], source["observations"], source.get("observedAbsent"))
    require(canonical(sanitized) == canonical(source), "source has not been normalized")
    return sanitized


def _lab(after):
    rows = [{"id": ("after-" if after else "") + f"invoice-{number}", "host": "lab.authz.local",
             "method": "GET", "path": f"/invoices/{number}", "status": 403, "marker": not after,
             "rule": RULE, "source": "Lab"} for number in ((1042,1043,1044) if after else (1042,1043,1044,1048))]
    absent = [r["id"] for r in rows] if after else []
    return source_object("lab", digest({"observations": rows, "observedAbsent": absent}), rows, absent)


def lab_source():
    return _lab(False)


def lab_after_source():
    return _lab(True)


def _contract(row):
    return (row["source"], row["host"], row["method"], row["path"], row["rule"])


def _testable(row):
    return row["method"] not in ("UNKNOWN", "SERVICE") and row["status"] is not None and 200 <= row["status"] < 500


def _verdict(row, controls_ok):
    if not controls_ok or not _testable(row):
        return "inconclusive"
    return "confirmed" if row["marker"] else "no_marker"


def evaluate(scope, sources, intended):
    """One budget unit admits one in-scope observed operation. Out-of-scope rows spend none."""
    require(isinstance(scope, dict) and set(scope) == {"hosts","roe","budget"}, "invalid scope")
    scope = make_scope(**scope)
    controls = _controls(intended)
    controls_ok = all(item["effective"] for item in controls.values())
    require(isinstance(sources, list) and len(sources) <= MAX_SOURCES, "too many sources")
    sources = [_one_source(src) for src in sources]
    require(not any(src["format"] == "lab" for src in sources) or all(src["format"] == "lab" for src in sources),
            "lab and commercial evidence must remain separate")
    require(len({src["sha256"] for src in sources}) == len(sources), "duplicate source")
    identifiers = [row["id"] for src in sources for row in src["observations"]]
    require(len(identifiers) <= MAX_ROWS and len(identifiers) == len(set(identifiers)), "duplicate or excessive case identifiers")
    contract_root = digest({"method": METHOD, "scope": scope, "dependsOn": DEPENDENCIES,
                            "operations": [_contract(row) for src in sources for row in src["observations"]]})
    evidence_root = digest({"contractRoot": contract_root, "controls": controls, "source": sources})
    spent, findings, graph = 0, [], {"intent": [], "relationship": [], "result": []}
    for src in sources:
        for row in src["observations"]:
            ident = row["id"]
            charged = False
            if row["host"] not in scope["hosts"]:
                status = "out_of_scope"
            elif spent >= scope["budget"]:
                status = "budget_blocked"
            else:
                charged = True
                spent += 1
                status = _verdict(row, controls_ok)
            ref = {"id": ident, "sourceSha256": src["sha256"], "observationDigest": digest(row)}
            reduced = ({"observations": [ref], "controls": controls, "contractRoot": contract_root}
                       if status == "confirmed" else None)
            findings.append({"id": ident, "status": status, "observation": row, "sourceSha256": src["sha256"],
                             "charged": charged, "minimalReproducer": reduced})
            intent_id = "intent:" + ident
            relationship_id = "relationship:" + ident
            graph["intent"].append({"id": intent_id, "observationId": ident, "rule": row["rule"],
                                    "check": "protected_marker_absent", "basis": "configured_expectation"})
            graph["relationship"].append({"id": relationship_id, "intentId": intent_id, "observationId": ident,
                                         "host": row["host"], "method": row["method"], "path": row["path"],
                                         "sourceSha256": src["sha256"], "requires": ["identity", "owner", "denial"]})
            graph["result"].append({"id": "result:" + ident, "relationshipId": relationship_id, "observationId": ident,
                                    "status": status, "observationDigest": ref["observationDigest"]})
    report = {"product": "AuthzLedger", "method": METHOD, "scope": scope, "budget": scope["budget"], "spent": spent,
              "source": sources, "controls": controls, "findings": findings, "evidenceRoot": evidence_root,
              "contractRoot": contract_root, "graph": graph, "rights": RIGHTS,
              "assurance": {"budget": scope["budget"], "baselineSpent": spent, "spent": spent, "remaining": scope["budget"] - spent,
                            "stopReason": "budget_blocked" if any(r["status"] == "budget_blocked" for r in findings) else None,
                            "history": [{"id": f["id"], "stage": "baseline", "status": f["status"], "charged": f["charged"]} for f in findings]}}
    report["retests"] = compare(report, [], None, intended)
    report["retestRuns"] = []
    return report


def compare(report, selected, after_source, after_controls, previous=None):
    controls = _controls(after_controls)
    all_valid = all(item["effective"] for item in controls.values())
    findings = report["findings"]
    require(isinstance(selected, list) and all(isinstance(x, str) for x in selected) and
            len(selected) == len(set(selected)) and set(selected) <= {f["id"] for f in findings}, "invalid retest selection")
    selected = set(selected)
    after = _one_source(after_source) if after_source is not None else None
    if after:
        require(not report["source"] or ((after["format"] == "lab") == all(s["format"] == "lab" for s in report["source"])),
                "lab and commercial evidence must remain separate")
        require(after["sha256"] not in {s["sha256"] for s in report["source"]}, "retest needs a separate capture")
    by_contract, by_id = defaultdict(list), {}
    for row in after["observations"] if after else []:
        by_contract[_contract(row)].append(row)
        by_id[row["id"]] = row
    contract_count = Counter(_contract(f["observation"]) for f in findings)
    prior = {r["id"]: r for r in previous or []}
    spent = sum(int(f["charged"]) for f in findings) + sum(r["chargedTotal"] for r in prior.values())
    results = []
    for finding in findings:
        ident = finding["id"]
        past = prior.get(ident, {})
        old = past.get("lastAssessment", "fail")
        count = past.get("chargedTotal", 0)
        prior_sources = past.get("usedSources", [])
        prior_observations = past.get("usedObservations", [])
        observation = finding["observation"]
        match, ref, charge = None, None, False
        status, reason, latest = "not_retested", "not_selected", old
        if finding["status"] != "confirmed":
            status, reason = "not_applicable", "baseline_not_confirmed"
        elif ident in selected:
            key = _contract(observation)
            candidates = by_contract.get(key, [])
            exact = by_id.get(ident)
            if exact and _contract(exact) == key:
                match = exact
            elif exact is None and len(candidates) == 1 and contract_count[key] == 1:
                match = candidates[0]
            if not match:
                status, reason = "inconclusive", "missing_or_ambiguous_comparable_evidence"
            elif not after or after["sha256"] in prior_sources or digest(match) in prior_observations or digest(match) == digest(observation):
                status, reason = "inconclusive", "fresh_evidence_required"
            elif spent >= report["budget"]:
                status, reason = "inconclusive", "budget_blocked"
            else:
                charge = True
                spent += 1
                ref = {"id": match["id"], "sourceSha256": after["sha256"], "observationDigest": digest(match)}
                # Valid controls alone cannot turn a redirect, server error or
                # an unreviewed empty status into a verified fix.
                if not all_valid:
                    status, reason = "inconclusive", "control_validity_not_established"
                elif not _testable(match):
                    latest = "error"
                    status, reason = ("inconclusive", "both_runs_unassessed") if old == "error" else (
                        "testability_lost", "current_observation_not_testable")
                elif match["id"] in after.get("observedAbsent", []):
                    latest = "pass"
                    if old == "error":
                        status, reason = "testability_restored", "previously_untestable_now_checked"
                    elif old == "fail":
                        status, reason = "resolved_check", "same_marker_check_now_passes"
                    else:
                        status, reason = "inconclusive", "no_new_transition"
                elif match["marker"]:
                    latest = "fail"
                    status, reason = ("regression", "previously_passing_check_now_fails") if old == "pass" else (
                        "inconclusive", "marker_present_without_prior_passing_check")
                else:
                    status, reason = "inconclusive", "explicit_marker_absence_and_comparable_denial_required"
        results.append({"id": ident, "status": status, "reason": reason, "selected": ident in selected,
                        "baselineRoot": report["evidenceRoot"], "contractRoot": report["contractRoot"],
                        "after": ref, "lastAssessment": latest, "chargedTotal": count + int(charge),
                        "usedSources": [*prior_sources, after["sha256"]] if charge else list(prior_sources),
                        "usedObservations": [*prior_observations, digest(match)] if charge else list(prior_observations)})
    return results


def record_retest(report, selected, after_source, after_controls):
    """Append one comparison without changing the original source or evidence root."""
    runs = report["retestRuns"]
    require(len(runs) < MAX_RUNS, "retest history limit reached")
    previous = runs[-1]["results"] if runs else None
    result = compare(report, selected, after_source, after_controls, previous)
    runs.append({"selected": list(selected), "afterSource": after_source, "afterControls": dict(after_controls),
                 "results": result})
    report["retests"] = result
    ledger = report["assurance"]
    spent = ledger["baselineSpent"] + sum(row["chargedTotal"] for row in result)
    ledger.update(spent=spent, remaining=report["budget"] - spent)
    report["spent"] = spent
    prior_counts = {row["id"]: row["chargedTotal"] for row in previous or []}
    for row in result:
        if row["selected"]:
            ledger["history"].append({"id": row["id"], "stage": "retest", "run": len(runs),
                                      "status": row["status"], "reason": row["reason"],
                                      "charged": row["chargedTotal"] > prior_counts.get(row["id"], 0)})
            if row["reason"] == "budget_blocked":
                ledger["stopReason"] = "budget_blocked"
    return result


def verify_semantics(report):
    """Replay every choice, budget allocation and source-bound comparison from sanitized bytes."""
    try:
        require(isinstance(report, dict), "invalid report")
        intended = {key: value["intended"] for key, value in report["controls"].items()}
        expected = evaluate(report["scope"], report["source"], intended)
        runs = report["retestRuns"]
        require(isinstance(runs, list) and len(runs) <= MAX_RUNS, "invalid retest history")
        for run in runs:
            require(isinstance(run, dict) and set(run) == {"selected", "afterSource", "afterControls", "results"},
                    "invalid retest history entry")
            record_retest(expected, run["selected"], run["afterSource"], run["afterControls"])
        for key, value in expected.items():
            require(key in report and canonical(report[key]) == canonical(value), "invalid report field: " + key)
        return True
    except (TypeError, AttributeError, KeyError, IndexError, OverflowError, RecursionError) as error:
        raise ValueError("invalid report structure") from error
