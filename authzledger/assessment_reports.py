"""Offline assessment snapshots and exact, reproducible report exports.

Reserved bundle attachments are reconstructed from retained execution evidence.
A signature establishes integrity and signer identity, never remote execution truth.
"""
from __future__ import annotations

import copy
import hashlib
import html
import io
import json
from pathlib import Path
import re
import shutil
import threading
from typing import Iterable

RENDERER_PROFILE = "assessment-html-pdf-v1-reportlab-4.4.9-dejavu-2.37"
CATALOG_PROFILE = "owasp-asvs-5.0.0-wstg-4.2-api-2023-cvss-4.0-v1"
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
_DOMAIN = b"AuthzLedger:assessment-snapshot:v1\n"
_PDF_LOCK = threading.RLock()
_FONT_HASHES = {"DejaVuSans.ttf": "ae7b7855e115a5966d8b1b3f80f254ccc117ec86f9965e202ee2940453837280",
                "DejaVuSans-Bold.ttf": "5c1247acef7f2b8522a31742c76d6adcb5569bacc0be7ceaa4dc39dd252ce895"}
_SOURCES = {
    "ASVS": {"version": "5.0.0", "url": "https://github.com/OWASP/ASVS/tree/v5.0.0"},
    "WSTG": {"version": "4.2", "url": "https://wstg.owasp.org/v4.2/"},
    "API": {"version": "2023", "url": "https://api-security.owasp.org/editions/2023/en/0x11-t10/"},
    "CVSS": {"version": "4.0", "url": "https://www.first.org/cvss/v4.0/specification-document"},
}
# This deliberately small catalog makes no claims about complete standards coverage.
_CATALOG_IDS = {
    "ASVS": {"8.1.1", "8.1.2", "8.1.3", "8.1.4", "8.2.1", "8.2.2", "8.2.3", "8.2.4", "8.3.1", "8.3.2", "8.3.3", "8.4.1", "8.4.2"},
    "WSTG": {"WSTG-ATHZ-01", "WSTG-ATHZ-02", "WSTG-ATHZ-03", "WSTG-ATHZ-04", "WSTG-BUSL-01", "WSTG-BUSL-02", "WSTG-BUSL-03", "WSTG-BUSL-04", "WSTG-BUSL-05", "WSTG-BUSL-06", "WSTG-BUSL-07", "WSTG-BUSL-08", "WSTG-BUSL-09"},
    "API": {f"API{i}:2023" for i in range(1, 11)},
}
_METRICS = [
    ("AV", "NALP"), ("AC", "LH"), ("AT", "NP"), ("PR", "NLH"), ("UI", "NPA"),
    ("VC", "HLN"), ("VI", "HLN"), ("VA", "HLN"), ("SC", "HLN"), ("SI", "HLN"), ("SA", "HLN"),
    ("E", "XAPU"), ("CR", "XHML"), ("IR", "XHML"), ("AR", "XHML"),
    ("MAV", "XNALP"), ("MAC", "XLH"), ("MAT", "XNP"), ("MPR", "XNLH"), ("MUI", "XNPA"),
    ("MVC", "XNLH"), ("MVI", "XNLH"), ("MVA", "XNLH"), ("MSC", "XNLH"), ("MSI", "XNLHS"), ("MSA", "XNLHS"),
    ("S", "XNP"), ("AU", "XNY"), ("R", "XAUI"), ("V", "XDC"), ("RE", "XLMH"),
    ("U", ("X", "Clear", "Green", "Amber", "Red")),
]
_LIMITATIONS = [
    "This is a scoped assessment, not certification or complete ASVS/WSTG/API coverage.",
    "Finding status, technical severity and business risk are separate dimensions.",
    "A restored configured check is not automatically a verified vulnerability fix.",
    "Retest omissions retain not_retested and historical evidence only.",
    "Signatures authenticate retained bytes and signing keys; they do not prove remote execution truth.",
    "Replayed oracle inputs are approved projections; their relationship to unavailable raw response bytes remains signer-attested.",
    "The standalone verifier provides integrity_only; semantic verification requires AuthzLedger and the pinned report renderer.",
]


def _canonical(value) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("expected finite JSON data") from exc


def _text(value, name, *, limit=16384, empty=False):
    if not isinstance(value, str) or len(value) > limit or (not empty and not value.strip()):
        raise ValueError(f"invalid {name}")
    if any(ord(c) < 32 and c not in "\n\t" for c in value) or any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise ValueError(f"invalid control character in {name}")
    return value


def _strings(value, name, *, limit=256):
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"invalid {name}")
    return [_text(v, name) for v in value]


def validate_cvss_vector(vector: str) -> dict:
    """Validate every CVSS 4.0 metric/value/order. Do not invent a score."""
    _text(vector, "CVSS vector", limit=512)
    if not vector.startswith("CVSS:4.0/"):
        raise ValueError("CVSS vector must use CVSS:4.0")
    order = {key: i for i, (key, _) in enumerate(_METRICS)}
    allowed = {key: set(values) for key, values in _METRICS}
    found, previous = {}, -1
    for item in vector.split("/")[1:]:
        if item.count(":") != 1:
            raise ValueError("invalid CVSS metric")
        key, value = item.split(":")
        if key not in allowed or value not in allowed[key] or order[key] <= previous:
            raise ValueError("invalid, duplicated or out-of-order CVSS metric")
        found[key], previous = value, order[key]
    if not {key for key, _ in _METRICS[:11]} <= found.keys():
        raise ValueError("all eleven CVSS base metrics are required")
    return {"version": "4.0", "vector": vector, "status": "not_scored", "score": None,
            "validation": "metric_values_and_order", "rationale": "Vector retained for analyst review; no numerical score calculated."}


def reporting_catalog() -> dict:
    """Return a detached public profile for CLI/Studio annotation editors."""
    return {"profile": CATALOG_PROFILE,
            "standards": {name: {**_SOURCES[name], "ids": sorted(ids)} for name, ids in _CATALOG_IDS.items()},
            "relations": ["supports", "partially_covers", "related"],
            "cvss": {**_SOURCES["CVSS"], "status": "not_scored", "scoring_supported": False,
                     "metrics": [{"id": name, "values": list(values), "required": i < 11}
                                 for i, (name, values) in enumerate(_METRICS)]}}


def _metadata(value, findings, origins):
    allowed = {"assessment_id", "title", "reviewer", "executive_summary", "scope", "period", "limitations", "finding_annotations"}
    if not isinstance(value, dict) or set(value) - allowed:
        raise ValueError("unknown assessment metadata fields")
    result = {
        "assessment_id": _text(value.get("assessment_id", "assessment"), "assessment id", limit=256),
        "title": _text(value.get("title", "Authorization assessment"), "title", limit=1024),
        "reviewer": _text(value.get("reviewer", "Not assigned"), "reviewer", limit=512),
        "executive_summary": _text(value.get("executive_summary", "Evidence-backed assessment of explicitly selected security rules."), "executive summary"),
        "scope": _strings(value.get("scope", sorted(origins)), "scope"),
        "period": _text(value.get("period", "Retained execution timestamps"), "period", limit=1024),
        "limitations": _strings(value.get("limitations", []), "limitations"),
        "finding_annotations": {},
    }
    annotations = value.get("finding_annotations", {})
    if not isinstance(annotations, dict) or set(annotations) - findings.keys():
        raise ValueError("annotations reference an absent finding")
    for fid, annotation in sorted(annotations.items()):
        if not isinstance(annotation, dict) or set(annotation) - {"impact", "remediation", "business_risk", "cvss_vector", "standard_refs"}:
            raise ValueError("unknown finding annotation fields; computed statuses cannot be overridden")
        row = {}
        for key in ("impact", "remediation", "business_risk"):
            if key in annotation:
                row[key] = _text(annotation[key], key)
        if "cvss_vector" in annotation:
            validate_cvss_vector(annotation["cvss_vector"])
            row["cvss_vector"] = annotation["cvss_vector"]
        refs = annotation.get("standard_refs", [])
        if not isinstance(refs, list) or len(refs) > 64:
            raise ValueError("invalid standards references")
        validated = []
        seen = set()
        for ref in refs:
            if not isinstance(ref, dict) or set(ref) != {"standard", "version", "id", "relation", "rationale", "evidence_refs"}:
                raise ValueError("invalid standards reference fields")
            standard = ref["standard"]
            if not isinstance(standard, str) or standard not in _CATALOG_IDS:
                raise ValueError("unsupported mapped standard")
            if not isinstance(ref["id"], str) or ref["version"] != _SOURCES[standard]["version"] or ref["id"] not in _CATALOG_IDS[standard]:
                raise ValueError("standard reference is not in the pinned catalog")
            if ref["relation"] not in ("supports", "partially_covers", "related"):
                raise ValueError("invalid standard relation")
            _text(ref["rationale"], "mapping rationale")
            evidence = _strings(ref["evidence_refs"], "mapping evidence")
            if not evidence or not set(evidence) <= set(findings[fid]["evidence_refs"]):
                raise ValueError("standard mapping references unrelated evidence")
            key = (standard, ref["id"])
            if key in seen:
                raise ValueError("duplicate standard mapping")
            seen.add(key)
            validated.append(copy.deepcopy(ref))
        row["standard_refs"] = sorted(validated, key=lambda r: (r["standard"], r["id"]))
        result["finding_annotations"][fid] = row
    return result


def freeze_assessment(executions: list[dict], metadata: dict, comparisons: list[dict] | None = None,
                      *, workflows: list[dict] | None = None, reductions: list[dict] | None = None,
                      assurances: list[dict] | None = None) -> dict:
    """Create a detached, content-addressed snapshot; never rewrite source evidence."""
    from .experiments import verify_execution
    from .comparison import verify_comparison
    if not isinstance(executions, list) or len(executions) > 100:
        raise ValueError("assessment accepts up to 100 retained executions")
    workflows = [] if workflows is None else copy.deepcopy(workflows)
    reductions = [] if reductions is None else copy.deepcopy(reductions)
    assurances = [] if assurances is None else copy.deepcopy(assurances)
    if not isinstance(workflows, list) or len(workflows) > 100 or not isinstance(reductions, list) or len(reductions) > 100:
        raise ValueError("invalid workflow or reduction trace list")
    if not isinstance(assurances, list) or len(assurances) > 100:
        raise ValueError("invalid workflow assurance list")
    seen_assurances = set()
    for assurance in assurances:
        from .workflow_assurance import verify_workflow_assurance
        errors = verify_workflow_assurance(assurance)
        if errors:
            raise ValueError("invalid workflow assurance: " + "; ".join(errors))
        if assurance["assurance_digest"] in seen_assurances:
            raise ValueError("duplicate workflow assurance")
        seen_assurances.add(assurance["assurance_digest"])
        for cycle in assurance["cycles"]:
            trace = cycle["trace"]
            matches = [w for w in workflows if w.get("workflow_digest") == trace["workflow_digest"]]
            if matches and any(_canonical(w) != _canonical(trace) for w in matches):
                raise ValueError("assurance cycle conflicts with retained workflow evidence")
            if not matches:
                workflows.append(copy.deepcopy(trace))
    if len(workflows) > 100:
        raise ValueError("assurance cycles exceed the assessment workflow trace limit")
    if not executions and not workflows:
        raise ValueError("assessment requires an execution or workflow trace")
    if len(_canonical(executions)) > MAX_SNAPSHOT_BYTES:
        raise ValueError("assessment executions exceed size limit")
    retained = copy.deepcopy(executions)
    findings, provenance, versions, origins, execution_ids = {}, {}, {}, set(), set()
    finding_bindings, finding_records = {}, {}
    for execution in retained:
        errors = verify_execution(execution)
        if errors:
            raise ValueError("invalid execution: " + "; ".join(errors))
        if execution["execution_id"] in execution_ids:
            raise ValueError("duplicate execution id")
        execution_ids.add(execution["execution_id"])
        origins.add(execution["contract"]["target"])
        observations = {o["observation_digest"]: o for o in execution["observations"]}
        for finding in execution["findings"]:
            if not finding["evidence_refs"] or any(ref not in observations for ref in finding["evidence_refs"]):
                raise ValueError("finding has unresolvable observation references")
            for ref in finding["evidence_refs"]:
                observation = observations[ref]
                if observation["case_id"] != finding["case_id"] or observation["report_root"] != execution["report"]["evidence"]["root_sha256"]:
                    raise ValueError("finding evidence references a foreign case or report")
            fid = finding["id"]
            source_case = next(c for c in execution["contract"]["cases"] if c["id"] == finding["case_id"])
            binding = {"target": execution["contract"]["target"], "rule_digest": finding["rule_digest"],
                       "resource_id": finding["resource_id"], "case": source_case,
                       "identity": execution["contract"]["identities"][finding["identity"]]}
            if fid in finding_bindings and _canonical(finding_bindings[fid]) != _canonical(binding):
                raise ValueError("conflicting source bindings for the same finding id; use separate assessments or distinct rule/variant ids")
            finding_bindings[fid] = binding
            findings[fid] = finding
            provenance[fid] = {"execution_id": execution["execution_id"], "execution_digest": execution["execution_digest"],
                               "report_root": execution["report"]["evidence"]["root_sha256"], "contract_digest": execution["report"]["contract_sha256"]}
            versions.setdefault(fid, []).append({"finding_digest": finding["finding_digest"], **provenance[fid]})
            finding_records.setdefault(fid, []).append((finding, copy.deepcopy(provenance[fid])))
    workflow_findings = []
    workflow_digests = set()
    for trace in workflows:
        from .workflows import verify_workflow
        errors = verify_workflow(trace)
        if errors:
            raise ValueError("invalid workflow trace: " + "; ".join(errors))
        if trace["workflow_digest"] in workflow_digests:
            raise ValueError("duplicate workflow trace")
        workflow_digests.add(trace["workflow_digest"])
        for variant in trace["variants"]:
            origins.update(step["contract"]["target"] for step in variant["steps"])
            state = variant["interpretation"]
            workflow_findings.append({"id": "workflow-" + trace["workflow_digest"][:24] + ":" + variant["id"],
                                      "workflow_digest": trace["workflow_digest"], "variant_id": variant["id"],
                                      "status": "confirmed" if state == "violation" else "rejected" if state == "satisfied" else "candidate",
                                      "interpretation": state, "controls_valid": variant["controls_valid"],
                                      "verification_level": "evaluation_attested", "cleanup": variant["cleanup"],
                                      "evidence_refs": [step["report"]["evidence"]["root_sha256"] for step in variant["steps"]]})
    reduction_digests = set()
    retained_digests = {e["execution_digest"] for e in retained} | workflow_digests
    for trace in reductions:
        from .minimize import verify_reduction
        errors = verify_reduction(trace)
        if errors:
            raise ValueError("invalid reduction trace: " + "; ".join(errors))
        if trace["reduction_digest"] in reduction_digests:
            raise ValueError("duplicate reduction trace")
        reduction_digests.add(trace["reduction_digest"])
        original = trace["original_execution"]
        original_digest = original.get("execution_digest", original.get("workflow_digest"))
        if original_digest not in retained_digests:
            raise ValueError("reduction original is not a retained execution")
    if len(findings) > 500:
        raise ValueError("too many findings in assessment")
    annotation_findings = copy.deepcopy(findings)
    for fid, records in finding_records.items():
        annotation_findings[fid]["evidence_refs"] = sorted({ref for finding, _ in records for ref in finding["evidence_refs"]})
    normalized = _metadata(metadata, annotation_findings, origins)
    comps = [] if comparisons is None else copy.deepcopy(comparisons)
    if not isinstance(comps, list) or len(comps) > 100:
        raise ValueError("invalid comparison list")
    seen_comparisons, envelopes = set(), []
    for retained_comparison in comps:
        comparison = retained_comparison
        if retained_comparison.get("kind") == "experiment-comparison":
            from .experiments import compare_executions
            executions_by_digest = {e["execution_digest"]: e for e in retained}
            before = executions_by_digest.get(retained_comparison.get("baseline_execution_digest"))
            after = executions_by_digest.get(retained_comparison.get("current_execution_digest"))
            if before is None or after is None or _canonical(compare_executions(before, after)) != _canonical(retained_comparison):
                raise ValueError("experiment comparison does not match retained executions")
            comparison = retained_comparison["comparison_envelope"]
        errors = verify_comparison(comparison)
        if errors:
            raise ValueError("invalid comparison: " + "; ".join(errors))
        if comparison["comparison_sha256"] in seen_comparisons:
            raise ValueError("duplicate assessment comparison")
        seen_comparisons.add(comparison["comparison_sha256"])
        envelopes.append(comparison)
        retained_roots = {e["report"]["evidence"]["root_sha256"] for e in retained}
        if comparison["baseline_report"]["evidence"]["root_sha256"] not in retained_roots:
            raise ValueError("comparison baseline is unrelated to retained executions")
    # Chronology is established by explicit comparison edges, never argument order.
    wrappers = [c for c in comps if c.get("kind") == "experiment-comparison"]
    pending = {(c["baseline_execution_digest"], c["current_execution_digest"]) for c in wrappers}
    while pending:
        incoming = {after for _, after in pending}
        roots = {before for before, _ in pending} - incoming
        if not roots:
            raise ValueError("assessment comparisons contain a chronology cycle")
        pending = {(before, after) for before, after in pending if before not in roots}
    rows = []
    for fid, finding in sorted(findings.items()):
        records = finding_records[fid]
        historical_confirmed = any(f["status"] == "confirmed" for f, _ in records)
        relevant = [c for c in wrappers if any(t["finding_id"] == fid for t in c["transitions"])]
        parents = {c["baseline_execution_digest"] for c in relevant}
        terminals = [c for c in relevant if c["current_execution_digest"] not in parents]
        current_ids = {c["current_execution_digest"] for c in terminals}
        current = [item for item in records if item[1]["execution_digest"] in current_ids] if len(current_ids) == 1 else []
        rank = {"confirmed": 0, "candidate": 1, "rejected": 2}
        finding, source = min(current or records, key=lambda item: (rank[item[0]["status"]], item[0]["finding_digest"], item[1]["execution_digest"]))
        terminal_statuses = {t["status"] for c in terminals for t in c["transitions"] if t["finding_id"] == fid}
        ancestors = set(current_ids)
        while True:
            expanded = ancestors | {c["baseline_execution_digest"] for c in relevant if c["current_execution_digest"] in ancestors}
            if expanded == ancestors:
                break
            ancestors = expanded
        unlinked_confirmation = any(f["status"] == "confirmed" and source["execution_digest"] not in ancestors for f, source in records)
        if len(current_ids) == 1 and terminal_statuses == {"fix_verified"} and not unlinked_confirmation:
            lifecycle = "retest_verified"
        elif historical_confirmed:
            lifecycle = "retest_pending" if terminals and terminal_statuses != {"violation_persists"} else "confirmed"
        else:
            lifecycle = finding["status"]
        annotation = normalized["finding_annotations"].get(fid, {})
        retests = []
        historical_roots = {v["report_root"] for v in versions[fid]}
        for retained_comparison, comparison in zip(comps, envelopes):
            if comparison["baseline_report"]["evidence"]["root_sha256"] in historical_roots:
                for change in comparison["transitions"]:
                    if change["case_id"] == finding["case_id"]:
                        retest = {"comparison_sha256": comparison["comparison_sha256"], "status": change["status"], "case_id": change["case_id"],
                                  "baseline_root": comparison["baseline_report"]["evidence"]["root_sha256"], "current_root": comparison["current_report"]["evidence"]["root_sha256"]}
                        if retained_comparison.get("kind") == "experiment-comparison":
                            transition = next(t for t in retained_comparison["transitions"] if t["finding_id"] == fid)
                            retest["finding_status"] = transition["status"]
                            retest["comparison_digest"] = retained_comparison["comparison_digest"]
                        retests.append(retest)
        rows.append({"id": fid, "status": lifecycle, "record": finding, "source": source,
                     "versions": sorted(versions[fid], key=lambda v: (v["execution_digest"], v["finding_digest"])),
                     "impact": annotation.get("impact", finding["impact"]), "remediation": annotation.get("remediation", finding["remediation"]),
                     "business_risk": annotation.get("business_risk", "Not assessed by reviewer"),
                     "severity": validate_cvss_vector(annotation["cvss_vector"]) if "cvss_vector" in annotation else {"version": "4.0", "vector": None, "status": "not_scored", "score": None, "validation": "not_supplied", "rationale": "No analyst vector supplied."},
                     "standard_refs": annotation.get("standard_refs", []), "retests": retests})
    summary = {status: sum(r["status"] == status for r in rows) + sum(r["status"] == status for r in workflow_findings)
               for status in ("confirmed", "candidate", "rejected", "retest_pending", "retest_verified")}
    coverage = [{"comparison_sha256": c["comparison_sha256"], **c["coverage"]} for c in envelopes]
    snapshot = {"schema_id": "authzledger.assessment-snapshot", "schema_version": 1, "kind": "assessment-snapshot",
                "renderer_profile": RENDERER_PROFILE, "catalog_profile": CATALOG_PROFILE,
                "metadata": normalized, "executions": retained, "comparisons": comps, "findings": rows,
                "workflows": workflows, "workflow_findings": workflow_findings, "reductions": reductions,
                "summary": summary, "coverage": coverage, "standards": copy.deepcopy(_SOURCES),
                "limitations": [*_LIMITATIONS, *normalized["limitations"]]}
    if assurances:
        snapshot["assurances"] = assurances
    snapshot["snapshot_digest"] = hashlib.sha256(_DOMAIN + _canonical(snapshot)).hexdigest()
    if len(_canonical(snapshot)) > MAX_SNAPSHOT_BYTES:
        raise ValueError("assessment snapshot exceeds size limit")
    return snapshot


def verify_assessment(snapshot: dict) -> list[str]:
    try:
        if not isinstance(snapshot, dict):
            raise ValueError("assessment must be a JSON object")
        expected = freeze_assessment(snapshot["executions"], snapshot["metadata"], snapshot["comparisons"],
                                     workflows=snapshot["workflows"], reductions=snapshot["reductions"],
                                     assurances=snapshot.get("assurances"))
        if _canonical(snapshot) != _canonical(expected):
            raise ValueError("assessment snapshot differs from retained execution evidence or reporting profile")
        return []
    except (ValueError, TypeError, KeyError, IndexError, RecursionError, AttributeError) as exc:
        return [str(exc) or "invalid assessment snapshot"]


def _require(snapshot):
    errors = verify_assessment(snapshot)
    if errors:
        raise ValueError("invalid assessment: " + "; ".join(errors))


def render_assessment_json(snapshot: dict) -> str:
    _require(snapshot)
    return _canonical(snapshot).decode("utf-8") + "\n"


def _sections(snapshot):
    """Single ordered text view shared by HTML and PDF; JSON retains its sources."""
    meta = snapshot["metadata"]
    yield ("Assessment", [("Title", meta["title"]), ("Assessment ID", meta["assessment_id"]), ("Reviewer", meta["reviewer"]),
                          ("Period", meta["period"]), ("Snapshot", snapshot["snapshot_digest"]), ("Renderer", snapshot["renderer_profile"])])
    yield ("Executive summary", [("Summary", meta["executive_summary"]), ("Finding status", json.dumps(snapshot["summary"], sort_keys=True))])
    yield ("Scope and methodology", [("Scope", "\n".join(meta["scope"]) or "No declared scope"),
                                      ("Method", "Explicit rules, source-bound requests and valid controls. Evidence remains local; observations are reviewed at their recorded verification level."),
                                      ("Coverage", json.dumps(snapshot["coverage"], sort_keys=True) if snapshot["coverage"] else "No selective retest comparison supplied; no claim of current coverage beyond retained executions.")])
    for row in snapshot["findings"]:
        f = row["record"]
        execution = next(e for e in snapshot["executions"] if e["execution_digest"] == row["source"]["execution_digest"])
        case = next(c for c in execution["contract"]["cases"] if c["id"] == f["case_id"])
        observations = [{key: o[key] for key in ("status", "interpretation", "controls_valid", "body_complete", "verification_level")}
                        for o in execution["observations"] if o["observation_digest"] in f["evidence_refs"]]
        steps = f"{case['method']} {case['path']} as {f['identity']}; execute controls before this case. Use the retained source contract and environment/session credential references."
        fields = [("Finding ID", row["id"]), ("Status", row["status"]), ("Execution record status", f["status"]), ("Interpretation", f["interpretation"]),
                  ("Category", f["category"]), ("Rule digest", f["rule_digest"]), ("Resource", f["resource_id"]),
                  ("Identity", f["identity"]), ("Case", f["case_id"]), ("Reproduction", steps),
                  ("Expected checks", json.dumps(case["expect"], sort_keys=True, ensure_ascii=False)),
                  ("Observation", json.dumps(observations, sort_keys=True, ensure_ascii=False)),
                  ("Controls", ", ".join(f["control_refs"]) or "None"), ("Evidence", "\n".join(f["evidence_refs"])),
                  ("Source report root", row["source"]["report_root"]), ("Finding record digest", f["finding_digest"]),
                  ("Verification level", f["verification_level"]), ("Impact", row["impact"]), ("Remediation", row["remediation"]),
                  ("Business risk", row["business_risk"]), ("CVSS 4.0", f"{row['severity']['status']}; vector: {row['severity']['vector'] or 'not supplied'}"),
                  ("Retest", json.dumps(row["retests"], sort_keys=True) if row["retests"] else "not_retested"),
                  ("Standards mapping", json.dumps(row["standard_refs"], sort_keys=True, ensure_ascii=False) if row["standard_refs"] else "No requirement-level mapping reviewed."),
                  ("Limitations", "\n".join(f["limitations"]) or "None additionally declared")]
        yield (f["title"], fields)
    for finding in snapshot["workflow_findings"]:
        trace = next(t for t in snapshot["workflows"] if t["workflow_digest"] == finding["workflow_digest"])
        variant = next(v for v in trace["variants"] if v["id"] == finding["variant_id"])
        fields = [("Finding ID", finding["id"]), ("Status", finding["status"]), ("Interpretation", finding["interpretation"]),
                  ("Controls valid", str(finding["controls_valid"])), ("Cleanup", finding["cleanup"]),
                  ("Rule", json.dumps(trace["plan"]["spec"]["rule"], sort_keys=True, ensure_ascii=False)),
                  ("Reason", variant.get("reason", "No conclusive result")), ("Workflow trace", finding["workflow_digest"]),
                  ("Evidence", "\n".join(finding["evidence_refs"])), ("Verification level", finding["verification_level"]),
                  ("CVSS 4.0", "not_scored"), ("Retest", "not_retested"),
                  ("Reproduction sequence", "\n".join(f"{step['step_id']} / attempt {step['attempt']} / {step['kind']} / report {step['report']['evidence']['root_sha256']}" for step in variant["steps"])),
                  ("Limitations", "\n".join(trace["limitations"]))]
        yield ("Workflow variant " + finding["variant_id"], fields)
    for trace in snapshot["reductions"]:
        yield ("Minimal reproducer", [("Reduction digest", trace["reduction_digest"]),
                                      ("Original execution", trace["original_execution"].get("execution_digest", trace["original_execution"].get("workflow_digest"))),
                                      ("Accepted execution", trace["accepted_execution"].get("execution_digest", trace["accepted_execution"].get("workflow_digest"))),
                                      ("One-minimal", str(trace["one_minimal"])), ("Stop reason", trace["stop_reason"]),
                                      ("Attempts", str(len(trace["attempts"]))),
                                      ("Removed approved units", json.dumps([trace["plan"]["units"][i] for i in trace["accepted_removed"]], sort_keys=True)),
                                      ("Accepted plan digest", trace["accepted_execution"]["plan"]["plan_digest"]),
                                      ("Scope", "Minimality applies only to the explicitly allowed removal units and recorded budget; original evidence is retained unchanged.")])
    for assurance in snapshot.get("assurances", []):
        cycle_metadata = [{key: value for key, value in cycle.items() if key != "trace"} for cycle in assurance["cycles"]]
        run_metadata = {key: value for key, value in assurance.items()
                        if key not in {"cycles", "plan", "budget_ledger", "assurance_digest", "schema_id", "schema_version", "kind"}}
        ledger = assurance["budget_ledger"]
        budget_summary = {key: value for key, value in ledger.items() if not isinstance(value, (list, dict))}
        yield ("Bounded workflow assurance", [("Assurance digest", assurance["assurance_digest"]),
                                              ("Plan digest", assurance["plan"]["plan_digest"]),
                                              ("Retained cycles", str(len(assurance["cycles"]))),
                                              ("Scheduling result", json.dumps(run_metadata, sort_keys=True, ensure_ascii=False)),
                                              ("Shared request budget", json.dumps(budget_summary, sort_keys=True, ensure_ascii=False)),
                                              ("Cycle status and history anchors", json.dumps(cycle_metadata, sort_keys=True, ensure_ascii=False)),
                                              ("Scope", "Each cycle retains its original workflow trace and materialized report roots. The shared budget and finite schedule bound this observation period; no future assurance is implied.")])
    yield ("Standards profile", [(key + " " + value["version"], value["url"]) for key, value in sorted(snapshot["standards"].items())])
    yield ("Limitations and independent verification", [("Limitation", item) for item in snapshot["limitations"]] +
           [("Verify", "Obtain the public-key fingerprint through an independent trusted channel. Run: python3 -I verify_bundle.py PACKAGE --public-key TRUSTED.pem. The package manifest supplies the signer fingerprint. Then run AuthzLedger verify-bundle for retained evidence and exact report semantics. Never trust a key solely because it is inside the package.")])


def render_assessment_html(snapshot: dict) -> str:
    _require(snapshot)
    esc = lambda x: html.escape(str(x), quote=True)
    sections = []
    for title, fields in _sections(snapshot):
        content = "".join(f"<dt>{esc(k)}</dt><dd>{esc(v)}</dd>" for k, v in fields)
        sections.append(f"<section><h2>{esc(title)}</h2><dl>{content}</dl></section>")
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
            f"<title>{esc(snapshot['metadata']['title'])} - AuthzLedger</title><style>"
            "*{box-sizing:border-box}body{margin:0;background:#edf1f6;color:#162338;font:15px/1.6 system-ui,sans-serif}"
            "main{max-width:1000px;margin:36px auto;background:#fff;padding:48px 60px;border-top:5px solid #3d66d9}"
            ".brand{font-size:12px;letter-spacing:.15em;color:#52688d}h1{font-size:34px;line-height:1.15;margin:16px 0 36px}"
            "h2{font-size:21px;line-height:1.3;margin:0 0 22px}section{margin:30px 0;padding-top:28px;border-top:1px solid #dce2ec}"
            "dl{display:grid;grid-template-columns:170px minmax(0,1fr);gap:12px 20px}dt{color:#546580;font-weight:600}"
            "dd{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}footer{color:#546580;font-size:12px}"
            "@media(max-width:650px){main{margin:0;padding:24px}dl{display:block}dd{margin:4px 0 16px}}"
            "@media print{body{background:white}main{margin:0;padding:0;max-width:none}h2{break-after:avoid}dt,dd{orphans:3;widows:3}}"
            "</style></head><body><main><div class=\"brand\">AUTHZLEDGER / ASSESSMENT EVIDENCE</div>"
            f"<h1>{esc(snapshot['metadata']['title'])}</h1>{''.join(sections)}"
            f"<footer>Snapshot {esc(snapshot['snapshot_digest'])}</footer></main></body></html>\n")


def render_assessment_pdf(snapshot: dict) -> bytes:
    _require(snapshot)
    try:
        import reportlab
        if reportlab.Version != "4.4.9":
            raise ValueError("PDF profile requires reportlab==4.4.9; install AuthzLedger[reports]")
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, KeepTogether
    except ImportError as exc:
        raise ValueError("PDF renderer unavailable; install AuthzLedger[reports] (reportlab==4.4.9)") from exc
    with _PDF_LOCK:
        fontdir = Path(__file__).with_name("fonts")
        for name, filename in (("AuthzDejaVu", "DejaVuSans.ttf"), ("AuthzDejaVuBold", "DejaVuSans-Bold.ttf")):
            if hashlib.sha256((fontdir / filename).read_bytes()).hexdigest() != _FONT_HASHES[filename]:
                raise ValueError("PDF profile font integrity mismatch")
            if name not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont(name, str(fontdir / filename)))
        chars = pdfmetrics.getFont("AuthzDejaVu").face.charToGlyph
        sections = list(_sections(snapshot))
        for text in [snapshot["metadata"]["title"], *[str(v) for title, fields in sections for v in [title, *[x for pair in fields for x in pair]]]]:
            if any(ord(c) not in chars for c in text if c not in "\n\t\r"):
                raise ValueError("PDF font does not cover every character; unsupported text must be reviewed")
        body = ParagraphStyle("Body", fontName="AuthzDejaVu", fontSize=9, leading=13.2, textColor=colors.HexColor("#162338"), spaceAfter=7, splitLongWords=True, alignment=TA_LEFT)
        label = ParagraphStyle("Label", parent=body, fontName="AuthzDejaVuBold", fontSize=8, leading=11, textColor=colors.HexColor("#52688d"), spaceBefore=6, spaceAfter=3, keepWithNext=True)
        heading = ParagraphStyle("Heading", parent=body, fontName="AuthzDejaVuBold", fontSize=17, leading=21, spaceBefore=22, spaceAfter=13, keepWithNext=True)
        title_style = ParagraphStyle("Title", parent=heading, fontSize=29, leading=35, spaceAfter=26)
        esc = lambda v: html.escape(str(v), quote=False).replace("\n", "<br/>")
        story = [Paragraph("AUTHZLEDGER / ASSESSMENT EVIDENCE", label), Paragraph(esc(snapshot["metadata"]["title"]), title_style)]
        for title, fields in sections:
            story.append(Paragraph(esc(title), heading))
            for key, value in fields:
                story.extend([Paragraph(esc(key), label), Paragraph(esc(value), body)])
        buffer = io.BytesIO()
        document = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=48, leftMargin=48, topMargin=52, bottomMargin=48,
                                     title=snapshot["metadata"]["title"], author="AuthzLedger", subject="Scoped, evidence-backed assessment", creator=RENDERER_PROFILE,
                                     pageCompression=1, invariant=1)
        def page(canvas, doc):
            canvas.saveState()
            canvas.setStrokeColor(colors.HexColor("#3d66d9"))
            canvas.setLineWidth(2)
            canvas.line(48, A4[1]-32, A4[0]-48, A4[1]-32)
            canvas.setFillColor(colors.HexColor("#52688d"))
            canvas.setFont("AuthzDejaVu", 7)
            canvas.drawString(48, 25, "AuthzLedger | " + snapshot["snapshot_digest"][:24])
            canvas.drawRightString(A4[0]-48, 25, f"Page {doc.page}")
            canvas.restoreState()
        document.build(story, onFirstPage=page, onLaterPages=page)
        return buffer.getvalue()


def assessment_attachments(snapshot: dict, formats: Iterable[str] = ("json", "html", "pdf")) -> dict[str, bytes]:
    selected = tuple(formats)
    if not selected or len(set(selected)) != len(selected) or set(selected) - {"json", "html", "pdf"}:
        raise ValueError("formats must be unique json/html/pdf values")
    # Snapshot is mandatory even when exporting only one visual representation.
    result = {"assessment.json": render_assessment_json(snapshot).encode("utf-8")}
    if "html" in selected:
        result["assessment.html"] = render_assessment_html(snapshot).encode("utf-8")
    if "pdf" in selected:
        result["assessment.pdf"] = render_assessment_pdf(snapshot)
    return result


def export_assessment(snapshot: dict, out: str | Path, formats: Iterable[str] = ("json", "html", "pdf")) -> dict[str, Path]:
    from .signing import _no_symlink_components, _write_new
    destination = Path(out).absolute()
    _no_symlink_components(destination)
    if destination.exists():
        raise ValueError("assessment destination already exists")
    files = assessment_attachments(snapshot, formats)
    destination.mkdir(parents=False, mode=0o700)
    try:
        for name, raw in files.items():
            _write_new(destination / name, raw)
    except BaseException:
        shutil.rmtree(destination)
        raise
    return {name: destination / name for name in files}


def create_assessment_bundle(snapshot: dict, out: str | Path, key: str | Path,
                             formats: Iterable[str] = ("json", "html", "pdf")) -> dict:
    from .signing import create_bundle
    attachments = assessment_attachments(snapshot, formats)
    return create_bundle(_anchor_report(snapshot), out, key, attachments)


def _anchor_report(snapshot):
    if snapshot["executions"]:
        wrappers = [c for c in snapshot["comparisons"] if c.get("kind") == "experiment-comparison"]
        parents = {c["baseline_execution_digest"] for c in wrappers}
        terminals = {c["current_execution_digest"] for c in wrappers} - parents
        candidates = [e for e in snapshot["executions"] if e["execution_digest"] in terminals] if len(terminals) == 1 else []
        return min(candidates or snapshot["executions"], key=lambda e: e["execution_digest"])["report"]
    for trace in reversed(snapshot["workflows"]):
        for variant in reversed(trace["variants"]):
            if variant["steps"]:
                return variant["steps"][-1]["report"]
            if "controls" in variant:
                return variant["controls"]["report"]
    raise ValueError("assessment contains no executed report to anchor")


def verify_assessment_attachments(report: dict, contents: dict[str, bytes]) -> None:
    """Reserved attachment semantics, called by both package build and verify."""
    from .signing import _json
    name = "attachments/assessment.json"
    visuals = {"attachments/assessment.html", "attachments/assessment.pdf"}
    if visuals.intersection(contents) and name not in contents:
        raise ValueError("assessment visual exports require assessment.json")
    if name not in contents:
        return
    if len(contents[name]) > MAX_SNAPSHOT_BYTES:
        raise ValueError("reserved assessment snapshot exceeds size limit")
    snapshot = _json(contents[name])
    _require(snapshot)
    if _canonical(_anchor_report(snapshot)) != _canonical(report):
        raise ValueError("assessment final report does not match signed report")
    if contents[name] != render_assessment_json(snapshot).encode("utf-8"):
        raise ValueError("assessment.json is not the canonical snapshot export")
    if "attachments/assessment.html" in contents and contents["attachments/assessment.html"] != render_assessment_html(snapshot).encode("utf-8"):
        raise ValueError("assessment.html does not match retained snapshot")
    if "attachments/assessment.pdf" in contents and contents["attachments/assessment.pdf"] != render_assessment_pdf(snapshot):
        raise ValueError("assessment.pdf does not match retained snapshot")
