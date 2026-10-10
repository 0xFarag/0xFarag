"""Bounded stateful experiments materialized through the existing v1 HTTP engine.

Plans are offline, explicit and immutable. Captures live only for one variant;
traces retain original sealed reports and content digests, never response bodies.
"""
from __future__ import annotations

import base64
import copy
import html
import hashlib
import json
import re
from urllib.parse import quote, quote_plus, unquote, unquote_plus

from . import engine
from .model import ContractError, contract_digest, load_contract, _fields, _identifier, _pointer as validate_pointer, _json_value


class WorkflowError(ValueError):
    pass


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def _seal(value, field):
    result = copy.deepcopy(value)
    result[field] = hashlib.sha256(("AuthzLedger:" + result["kind"] + ":v1\n").encode() + _canonical(result)).hexdigest()
    return result


def _object(value, allowed, required=None):
    try:
        return _fields(value, set(allowed), "workflow", set(required or allowed))
    except ContractError as exc:
        raise WorkflowError(str(exc)) from None


def _id(value):
    try:
        return _identifier(value, "workflow identifier")
    except ContractError as exc:
        raise WorkflowError(str(exc)) from None


def _pointer(value):
    try:
        validate_pointer(value)
    except (ContractError, TypeError):
        raise WorkflowError("Invalid JSON pointer.") from None
    return value


def _step(raw, cases, known):
    _object(raw, {"id", "case_id", "bindings"}, {"id", "case_id"})
    item = copy.deepcopy(raw)
    _id(item["id"])
    if item["id"] in known or item["case_id"] not in cases:
        raise WorkflowError("Step identifiers must be unique and reference an approved operation.")
    bindings = item.setdefault("bindings", [])
    if not isinstance(bindings, list) or len(bindings) > 16:
        raise WorkflowError("A step accepts at most 16 explicit bindings.")
    for binding in bindings:
        _object(binding, {"source_step", "pointer", "header", "type", "target"}, {"source_step", "type", "target"})
        if ("pointer" in binding) == ("header" in binding):
            raise WorkflowError("A binding needs exactly one JSON pointer or public response header selector.")
        if binding["source_step"] not in known:
            raise WorkflowError("A binding must reference an earlier step.")
        if "pointer" in binding:
            _pointer(binding["pointer"])
            if re.search(r"password|passwd|authorization|cookie|credential|secret|token|api.?key|session", binding["pointer"], re.I):
                raise WorkflowError("Secret response fields cannot be materialized or persisted as bindings.")
        elif (not isinstance(binding["header"], str) or binding["header"].lower() not in {"etag", "x-request-id", "x-correlation-id"}
              or binding["type"] != "string"):
            raise WorkflowError("Response header extraction is limited to declared public scalar identifiers.")
        if binding["type"] not in {"string", "integer", "number", "boolean"}:
            raise WorkflowError("Only explicitly typed scalar bindings are accepted.")
        target = binding["target"]
        if not isinstance(target, dict):
            raise WorkflowError("Binding target must be an object.")
        kind = target.get("kind")
        if kind == "path_segment":
            _object(target, {"kind", "index"})
            segments = cases[item["case_id"]]["path"].split("?", 1)[0].split("/")
            if type(target["index"]) is not int or not 1 <= target["index"] < len(segments):
                raise WorkflowError("Path binding must name one existing path segment.")
        elif kind == "query":
            _object(target, {"kind", "name", "occurrence"})
            if not isinstance(target["name"], str) or type(target["occurrence"]) is not int or target["occurrence"] < 0:
                raise WorkflowError("Query binding must select one occurrence.")
        elif kind == "json":
            _object(target, {"kind", "pointer"})
            _pointer(target["pointer"])
            if not target["pointer"]:
                raise WorkflowError("A binding cannot replace the entire request body.")
        elif kind == "header":
            _object(target, {"kind", "name"})
            if target["name"].lower() not in {"x-request-id", "x-correlation-id"}:
                raise WorkflowError("Only public request/correlation identifier headers can be bound.")
        else:
            raise WorkflowError("Binding targets cannot alter an origin or arbitrary URL.")
    known.add(item["id"])
    return item


def compile_workflow(spec):
    """Validate and freeze a deterministic, sequential workflow plan (no I/O)."""
    _object(spec, {"schema_version", "kind", "id", "title", "contract", "controls", "setup", "precondition", "steps", "postcondition", "cleanup", "fixture", "rule", "variants", "mutation_approval"})
    if type(spec["schema_version"]) is not int or spec["schema_version"] != 1 or spec["kind"] != "workflow-spec":
        raise WorkflowError("Only workflow-spec v1 is supported.")
    _id(spec["id"])
    if not isinstance(spec["title"], str) or not 1 <= len(spec["title"]) <= 200:
        raise WorkflowError("Workflow title is required.")
    normalized = copy.deepcopy(spec)
    try:
        contract = load_contract(normalized["contract"], allow_mutations=True)
    except ContractError as exc:
        raise WorkflowError(str(exc)) from None
    from .experiments import _reject_literal_credentials
    _reject_literal_credentials(contract)
    normalized["contract"] = contract
    cases = {case["id"]: case for case in contract["cases"]}
    controls = normalized["controls"]
    if not isinstance(controls, list) or not controls or len(controls) != len(set(controls)) or any(item not in cases for item in controls):
        raise WorkflowError("Workflow requires distinct, explicitly approved controls.")
    for item in controls:
        case = cases[item]
        if not (case["expect"].get("json") or case["expect"].get("json_absent")):
            raise WorkflowError("Workflow controls require content evidence.")
        if set(case["requires"]) - set(controls):
            raise WorkflowError("All transitive control prerequisites must be listed.")
    if not isinstance(normalized["steps"], list) or not normalized["steps"] or not isinstance(normalized["cleanup"], list) or not normalized["cleanup"]:
        raise WorkflowError("Workflow needs ordered steps and a cleanup list.")
    known = set()
    for key in ("setup", "precondition"):
        normalized[key] = _step(normalized[key], cases, known)
    normalized["steps"] = [_step(step, cases, known) for step in normalized["steps"]]
    normalized["postcondition"] = _step(normalized["postcondition"], cases, known)
    normalized["cleanup"] = [_step(step, cases, known) for step in normalized["cleanup"]]
    fixture = normalized["fixture"]
    _object(fixture, {"source_step", "pointer", "type", "read_pointer"})
    if fixture["source_step"] != normalized["setup"]["id"] or fixture["type"] not in {"string", "integer"}:
        raise WorkflowError("Fresh fixture identifier must originate at setup.")
    _pointer(fixture["pointer"])
    _pointer(fixture["read_pointer"])
    for key in ("precondition", "postcondition"):
        step = normalized[key]
        if cases[step["case_id"]]["method"] not in {"GET", "HEAD"}:
            raise WorkflowError("State probes must be independent read operations.")
        if not any(binding["source_step"] == fixture["source_step"] and binding.get("pointer") == fixture["pointer"] for binding in step["bindings"]):
            raise WorkflowError("Independent state probes must bind the fresh fixture identifier.")
    if not cases[normalized["precondition"]["case_id"]]["expect"].get("json"):
        raise WorkflowError("The initial state must be explicitly asserted.")
    rule = normalized["rule"]
    if not isinstance(rule, dict):
        raise WorkflowError("Workflow rule must be an object.")
    if rule.get("kind") == "forbidden_state":
        _object(rule, {"id", "kind", "pointer", "value"})
        _json_value(rule["value"], "workflow state")
    elif rule.get("kind") == "effect_increase":
        _object(rule, {"id", "kind", "pointer", "max_delta"})
        if type(rule["max_delta"]) is not int or not 0 <= rule["max_delta"] <= 1000:
            raise WorkflowError("Effect bound must be a nonnegative integer.")
    else:
        raise WorkflowError("Unsupported workflow state oracle.")
    _id(rule["id"])
    _pointer(rule["pointer"])
    variants = normalized["variants"]
    if not isinstance(variants, list) or not 1 <= len(variants) <= 8:
        raise WorkflowError("Select between one and eight explicit variants.")
    step_ids = {step["id"] for step in normalized["steps"]}
    approved = normalized["mutation_approval"]
    if not isinstance(approved, list) or any(item not in cases for item in approved) or len(set(approved)) != len(approved):
        raise WorkflowError("Mutation approval must name exact approved operations.")
    all_steps = [normalized["setup"], normalized["precondition"], *normalized["steps"], normalized["postcondition"], *normalized["cleanup"]]
    used = {step["case_id"] for step in all_steps} | set(controls)
    if any(cases[item]["method"] not in {"GET", "HEAD", "OPTIONS"} and item not in approved for item in used):
        raise WorkflowError("Every mutating operation requires explicit plan-bound approval.")
    if any(cases[item]["requires"] for item in used - set(controls)):
        raise WorkflowError("Workflow sequencing uses step bindings; operation templates must have no external requires.")
    ids = set()
    expanded = []
    for variant in variants:
        _object(variant, {"id", "omit", "identity_overrides", "repeat"}, {"id"})
        _id(variant["id"])
        if variant["id"] in ids:
            raise WorkflowError("Variant IDs must be unique.")
        ids.add(variant["id"])
        omitted = variant.setdefault("omit", [])
        overrides = variant.setdefault("identity_overrides", {})
        repeats = variant.setdefault("repeat", {})
        if not isinstance(omitted, list) or len(set(omitted)) != len(omitted) or set(omitted) - step_ids:
            raise WorkflowError("Only declared workflow steps may be omitted.")
        if not isinstance(overrides, dict) or set(overrides) - step_ids or any(identity not in contract["identities"] for identity in overrides.values()):
            raise WorkflowError("Identity changes must reference declared step and identity.")
        if not isinstance(repeats, dict) or set(repeats) - step_ids or any(type(count) is not int or not 1 <= count <= 3 for count in repeats.values()):
            raise WorkflowError("Explicit replay count must be between one and three.")
        if rule["kind"] == "effect_increase":
            repeated = [step for step in normalized["steps"] if repeats.get(step["id"], 1) > 1]
            if not repeated:
                raise WorkflowError("Effect/replay oracle requires an explicitly repeated step.")
            for step in repeated:
                operation = cases[step["case_id"]]
                headers = dict(contract["identities"][overrides.get(step["id"], operation["identity"])]["headers"], **operation["headers"])
                body = operation.get("body", {})
                if not (any(name.lower() == "idempotency-key" for name in headers)
                        or isinstance(body, dict) and any(key in body for key in ("operation_id", "idempotency_key"))):
                    raise WorkflowError("Replay needs an explicit stable operation identifier or Idempotency-Key reference.")
        sequence = []
        available = {normalized["setup"]["id"], normalized["precondition"]["id"]}
        for step in normalized["steps"]:
            if step["id"] in omitted:
                continue
            if any(binding["source_step"] not in available for binding in step["bindings"]):
                raise WorkflowError("Variant would leave an unresolved step binding.")
            for attempt in range(repeats.get(step["id"], 1)):
                sequence.append(dict(copy.deepcopy(step), attempt=attempt + 1, identity=overrides.get(step["id"], cases[step["case_id"]]["identity"])))
            available.add(step["id"])
        for step in [normalized["postcondition"], *normalized["cleanup"]]:
            if any(binding["source_step"] not in available for binding in step["bindings"]):
                raise WorkflowError("Variant would leave a probe or cleanup binding unresolved.")
            available.add(step["id"])
        count = len(controls) + 3 + len(sequence) + len(normalized["cleanup"])
        if count > 12:
            raise WorkflowError("A variant may dispatch at most twelve logical steps including controls/probes/cleanup.")
        expanded.append({"id": variant["id"], "steps": sequence, "request_upper_bound": count})
    total = sum(variant["request_upper_bound"] for variant in expanded)
    if total > contract["limits"]["max_requests"]:
        raise WorkflowError("Workflow upper bound exceeds the approved total budget.")
    return _seal({"schema_id": "authzledger.workflow-plan", "schema_version": 1, "kind": "workflow-plan", "spec": normalized, "variants": expanded,
                  "contract_digest": contract_digest(contract), "request_upper_bound": total,
                  "cleanup_reserve": len(expanded) * len(normalized["cleanup"]), "rule_digest": hashlib.sha256(_canonical(rule)).hexdigest()}, "plan_digest")


def _document(capture):
    if not capture or not capture.get("complete") or capture.get("error_code"):
        raise WorkflowError("Complete capture required.")
    try:
        document = json.loads(capture["body"], object_pairs_hook=engine._unique_pairs, parse_constant=engine._reject_constant)
        _json_value(document, "workflow response")
        return document
    except (ValueError, UnicodeError, TypeError, KeyError, RecursionError):
        raise WorkflowError("Unambiguous JSON capture required.") from None


def _extract(capture, pointer, expected_type):
    value = engine._pointer(_document(capture), pointer)
    accepted = {"string": lambda x: type(x) is str and 0 < len(x) <= 256,
                "integer": lambda x: type(x) is int,
                "number": lambda x: type(x) in {int, float}, "boolean": lambda x: type(x) is bool}
    if expected_type not in accepted or not accepted[expected_type](value):
        raise WorkflowError("A required typed binding is absent or has an incompatible type.")
    return value


def _set_json(document, pointer, value):
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
    current = document
    for part in parts[:-1]:
        if isinstance(current, list) and part.isdigit() and str(int(part)) == part and int(part) < len(current):
            current = current[int(part)]
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise WorkflowError("Binding target does not exist.")
    final = parts[-1]
    if isinstance(current, dict) and final in current:
        current[final] = value
    elif isinstance(current, list) and final.isdigit() and str(int(final)) == final and int(final) < len(current):
        current[int(final)] = value
    else:
        raise WorkflowError("Binding target does not exist.")


def _materialize(step, cases, captures, credential_guard=None):
    case = copy.deepcopy(cases[step["case_id"]])
    case["requires"] = []
    case["identity"] = step.get("identity", case["identity"])
    provenance = []
    for binding in step["bindings"]:
        capture = captures.get(binding["source_step"])
        if "pointer" in binding:
            value = _extract(capture, binding["pointer"], binding["type"])
        else:
            if not capture or not capture.get("complete"):
                raise WorkflowError("Complete capture required for header binding.")
            matches = [value for name, value in capture.get("headers", []) if name.lower() == binding["header"].lower()]
            if len(matches) != 1 or not isinstance(matches[0], str) or not 0 < len(matches[0]) <= 256:
                raise WorkflowError("Public response header is absent, duplicated or invalid.")
            value = matches[0]
        if credential_guard is not None and credential_guard(value):
            raise WorkflowError("Credential reflection was withheld from a workflow binding.")
        target = binding["target"]
        string = value if isinstance(value, str) else json.dumps(value)
        if target["kind"] == "path_segment":
            if any(char in string for char in "/\\%?#") or string in {".", ".."}:
                raise WorkflowError("Fixture values cannot introduce routing delimiters or traversal.")
            path, separator, query = case["path"].partition("?")
            parts = path.split("/")
            parts[target["index"]] = quote(string, safe="")
            case["path"] = "/".join(parts) + (separator + query if separator else "")
        elif target["kind"] == "query":
            path, separator, query = case["path"].partition("?")
            pairs = query.split("&") if separator else []
            found = [i for i, pair in enumerate(pairs) if unquote(pair.split("=", 1)[0]) == target["name"]]
            if target["occurrence"] >= len(found):
                raise WorkflowError("Selected query occurrence does not exist.")
            index = found[target["occurrence"]]
            pairs[index] = pairs[index].split("=", 1)[0] + "=" + quote(string, safe="")
            case["path"] = path + "?" + "&".join(pairs)
        elif target["kind"] == "json":
            _set_json(case.get("body"), target["pointer"], value)
        else:
            case["headers"][target["name"]] = string
        provenance.append({"source_step": binding["source_step"], "source_body_sha256": hashlib.sha256(capture["body"]).hexdigest(),
                           "selector": {key: binding[key] for key in ("pointer", "header") if key in binding},
                           "selected_headers_sha256": hashlib.sha256(_canonical([(name, value) for name, value in capture.get("headers", []) if name.lower() == binding.get("header", "").lower()])).hexdigest() if "header" in binding else None,
                           "type": binding["type"], "target": copy.deepcopy(target)})
    return case, provenance


def execute_workflow(plan, *, context=None, credential_resolver=None, fixture_registry=None):
    """Execute fresh-fixture variants with one shared budget and existing engine."""
    if not isinstance(plan, dict) or compile_workflow(plan.get("spec")) != plan:
        raise WorkflowError("Workflow plan was modified after compilation.")
    from .execution import ExecutionContext
    spec = plan["spec"]
    template = spec["contract"]
    from .credentials import CredentialResolver
    resolver = credential_resolver if credential_resolver is not None else CredentialResolver()
    resolved = resolver.resolve_contract(template)
    secret_values = set()
    for identity, config in template["identities"].items():
        for name, reference in config["headers"].items():
            if not isinstance(reference, dict):
                continue
            value = resolved[identity][name]
            secret_values.add(value)
            if name.lower() == "authorization" and " " in value:
                secret_values.add(value.split(" ", 1)[1])
            if name.lower() == "cookie":
                secret_values.update(cookie.split("=", 1)[1].strip() for cookie in value.split(";") if "=" in cookie)
    secret_values.discard("")
    encoded_secrets = {encoded for secret in secret_values for encoded in (
        secret, quote(secret, safe=""), quote_plus(secret, safe=""),
        base64.b64encode(secret.encode()).decode(), base64.urlsafe_b64encode(secret.encode()).decode(),
        json.dumps(secret, ensure_ascii=True)[1:-1], html.escape(secret))}
    def credential_guard(value, strict_dynamic=True):
        if isinstance(value, dict):
            return any(credential_guard(key, strict_dynamic) or credential_guard(item, strict_dynamic) for key, item in value.items())
        if isinstance(value, (list, tuple)):
            return any(credential_guard(item, strict_dynamic) for item in value)
        if not isinstance(value, str):
            value = json.dumps(value, ensure_ascii=True, allow_nan=False)
        forms = {value}
        current = value
        for _ in range(8):
            decoded = html.unescape(unquote(current))
            forms.add(decoded)
            forms.add(html.unescape(unquote_plus(current)))
            if decoded == current:
                break
            current = decoded
        return any(secret == form or (strict_dynamic or len(secret) >= 8 or " " in secret) and secret in form
                   for form in forms for secret in encoded_secrets)
    if secret_values and credential_guard(plan, strict_dynamic=False):
        resolved.clear(); secret_values.clear(); encoded_secrets.clear()
        raise WorkflowError("A resolved credential appears in the workflow plan; no request was sent.")
    class PinnedResolver:
        def resolve_contract(self, contract):
            if contract["target"] != template["target"] or contract["identities"] != template["identities"]:
                raise WorkflowError("Credential scope changed during workflow execution.")
            return copy.deepcopy(resolved)
    pinned_resolver = PinnedResolver()
    if context is None:
        context = ExecutionContext(max_requests=plan["request_upper_bound"], allowed_origins=[template["target"]],
                                   timeout_seconds=template["limits"]["timeout_seconds"], concurrency=1,
                                   cleanup_reserve=plan["cleanup_reserve"], allow_cleanup_after_cancel=True)
    cases = {case["id"]: case for case in template["cases"]}
    if fixture_registry is not None and (not isinstance(fixture_registry, set) or any(type(item) is not bytes for item in fixture_registry)):
        raise WorkflowError("Fixture registry must be a set of canonical fixture identifier bytes.")
    traces = []
    used_fixtures = fixture_registry if fixture_registry is not None else set()
    for variant in plan["variants"]:
        trace = {"id": variant["id"], "interpretation": "inconclusive", "controls_valid": False, "steps": [],
                 "reason": "Workflow did not complete.", "cleanup": "not_needed"}
        captures = {}
        setup_started = False
        lease = None
        variant_context = None
        def dispatch(step, kind):
            case, provenance = _materialize(step, cases, captures, credential_guard)
            contract = copy.deepcopy(template)
            contract["cases"] = [case]
            contract["limits"]["concurrency"] = 1
            contract = load_contract(contract, allow_mutations=True)
            observed = []
            report = engine.run(contract, context=variant_context, credential_resolver=pinned_resolver,
                                observation_sink=observed.append, request_kind=kind)
            capture = observed[0] if observed else None
            if capture:
                captures[step["id"]] = capture
            trace["steps"].append({"step_id": step["id"], "attempt": step.get("attempt", 1), "kind": kind,
                                   "contract": contract, "report": report, "bindings": provenance})
            return report["results"][0], capture
        try:
            # Reserve sufficient room for the entire sequence before its first
            # mutating step; other dispatches continue to share this same context.
            cleanup_count = len(spec["cleanup"])
            lease = context.lease(variant["request_upper_bound"] - cleanup_count, cleanup_requests=cleanup_count)
            variant_context = lease.__enter__()
            control_contract = copy.deepcopy(template)
            control_contract["cases"] = [copy.deepcopy(cases[item]) for item in spec["controls"]]
            control_contract["limits"]["concurrency"] = 1
            control_contract = load_contract(control_contract, allow_mutations=True)
            control_report = engine.run(control_contract, context=variant_context, credential_resolver=pinned_resolver,
                                        request_kind="identity_control")
            trace["controls"] = {"contract": control_contract, "report": control_report}
            trace["controls_valid"] = all(result["outcome"] == "pass" for result in control_report["results"])
            if not trace["controls_valid"]:
                raise WorkflowError("Control validity failed.")
            setup_started = True
            result, capture = dispatch(spec["setup"], "setup")
            if result["outcome"] != "pass":
                raise WorkflowError("Fresh fixture setup failed.")
            fixture = spec["fixture"]
            fixture_value = _extract(capture, fixture["pointer"], fixture["type"])
            if credential_guard(fixture_value):
                raise WorkflowError("Credential reflection was withheld from the fixture binding.")
            fixture_token = _canonical(fixture_value)
            if fixture_token in used_fixtures:
                raise WorkflowError("Fixture identifier was reused; isolation is not established.")
            used_fixtures.add(fixture_token)
            trace["fixture_binding"] = {"source_step": fixture["source_step"], "pointer": fixture["pointer"], "type": fixture["type"]}
            result, before = dispatch(spec["precondition"], "state_probe")
            if result["outcome"] != "pass" or not engine._json_equal(_extract(before, fixture["read_pointer"], fixture["type"]), fixture_value):
                raise WorkflowError("Initial state or fixture binding could not be established.")
            rule = spec["rule"]
            prior = engine._pointer(_document(before), rule["pointer"])
            if prior is engine._MISSING:
                raise WorkflowError("Initial state oracle input is absent.")
            if rule["kind"] == "forbidden_state" and engine._json_equal(prior, rule["value"]):
                raise WorkflowError("Fixture already had the forbidden state before the test.")
            if rule["kind"] == "effect_increase" and type(prior) is not int:
                raise WorkflowError("Initial effect count is not an integer.")
            for step in variant["steps"]:
                result, _ = dispatch(step, "replay" if step["attempt"] > 1 else "application")
                if result["outcome"] in {"error", "inconclusive"}:
                    raise WorkflowError("A workflow operation could not be observed.")
            result, after = dispatch(spec["postcondition"], "state_probe")
            if result["outcome"] != "pass" or not engine._json_equal(_extract(after, fixture["read_pointer"], fixture["type"]), fixture_value):
                raise WorkflowError("Independent state probe or fixture binding failed.")
            final = engine._pointer(_document(after), rule["pointer"])
            if final is engine._MISSING:
                raise WorkflowError("Final state oracle input is absent.")
            if rule["kind"] == "forbidden_state":
                violation = engine._json_equal(final, rule["value"])
            else:
                if type(final) is not int or final < prior:
                    raise WorkflowError("Final effect count is invalid or reset unexpectedly.")
                violation = final - prior > rule["max_delta"]
            trace["interpretation"] = "violation" if violation else "satisfied"
            trace["reason"] = "Independent state probe established the configured transition result."
            trace["oracle"] = {"rule_digest": plan["rule_digest"], "verification_level": "evaluation_attested",
                               "before_body_sha256": hashlib.sha256(before["body"]).hexdigest(),
                               "after_body_sha256": hashlib.sha256(after["body"]).hexdigest()}
        except (WorkflowError, ContractError, ValueError) as exc:
            # Only locally authored reasons; do not include arbitrary capture values.
            trace["reason"] = str(exc) if isinstance(exc, WorkflowError) else "Workflow execution could not establish its prerequisites."
        finally:
            if setup_started and spec["cleanup"]:
                trace["cleanup"] = "complete"
                for step in spec["cleanup"]:
                    try:
                        result, _ = dispatch(step, "cleanup")
                        if result["outcome"] != "pass":
                            trace["cleanup"] = "cleanup_pending"
                    except (WorkflowError, ContractError, ValueError):
                        trace["cleanup"] = "cleanup_pending"
                if trace["cleanup"] != "complete":
                    trace["interpretation"] = "inconclusive"
                    trace["reason"] = "Cleanup failed; isolation for further work is unconfirmed."
            captures.clear()
            if variant_context is not None:
                lease.__exit__(None, None, None)
        traces.append(trace)
        if trace["cleanup"] == "cleanup_pending":
            break
    resolved.clear(); secret_values.clear(); encoded_secrets.clear()
    return _seal({"schema_id": "authzledger.workflow-trace", "schema_version": 1, "kind": "workflow-trace", "plan": copy.deepcopy(plan), "variants": traces,
                  "budget_ledger": context.snapshot(), "limitations": ["Fresh fixture identifiers and independent probes bind the configured object only.",
                  "Response bodies are transient; signed state evaluations are attested, not independently replayable from body digests."]}, "workflow_digest")


def verify_workflow(trace):
    """Verify original reports, controls and bounded sequence; state is attested.

    Raw bodies are deliberately absent. This checks the signed evaluation's
    prerequisites, but cannot recompute state values from a body digest.
    """
    from .evidence import verify_report
    from .intelligence import build_graph
    errors = []
    try:
        fields = {"schema_id", "schema_version", "kind", "plan", "variants", "budget_ledger", "limitations", "workflow_digest"}
        if (not isinstance(trace, dict) or set(trace) != fields or trace.get("schema_id") != "authzledger.workflow-trace"
                or trace.get("kind") != "workflow-trace" or type(trace.get("schema_version")) is not int or trace.get("schema_version") != 1):
            raise WorkflowError("Unsupported workflow trace.")
        candidate = copy.deepcopy(trace)
        claimed = candidate.pop("workflow_digest")
        if _seal(candidate, "workflow_digest")["workflow_digest"] != claimed:
            errors.append("Workflow trace digest mismatch.")
        plan = compile_workflow(trace["plan"]["spec"])
        if plan != trace["plan"]:
            errors.append("Workflow plan cannot be reconstructed.")
        spec = plan["spec"]
        template = spec["contract"]
        cases = {case["id"]: case for case in template["cases"]}
        ledger = trace["budget_ledger"]
        dispatched = [record for record in ledger["requests"] if record["state"] in {"dispatched", "finished"}]
        if (type(ledger["dispatched_total"]) is not int or type(ledger["approved_total"]) is not int
                or not 0 <= ledger["dispatched_total"] <= ledger["approved_total"]
                or len(dispatched) != ledger["dispatched_total"]
                or sum(ledger["by_kind"].values()) != ledger["dispatched_total"]):
            errors.append("Workflow request accounting mismatch.")
        seen = set()
        if not 1 <= len(trace["variants"]) <= len(plan["variants"]):
            errors.append("Invalid workflow variant coverage.")
        for index, variant in enumerate(trace["variants"]):
            required_variant_fields = {"id", "interpretation", "controls_valid", "steps", "reason", "cleanup"}
            if not isinstance(variant, dict) or set(variant) - (required_variant_fields | {"controls", "fixture_binding", "oracle"}) or required_variant_fields - set(variant):
                raise WorkflowError("Invalid workflow variant fields.")
            if variant["cleanup"] not in {"not_needed", "complete", "cleanup_pending"}:
                raise WorkflowError("Invalid cleanup state.")
            planned = plan["variants"][index]
            if variant["id"] != planned["id"] or variant["id"] in seen:
                errors.append("Workflow variant identity/order mismatch.")
            seen.add(variant["id"])
            records = list(variant["steps"])
            controls_valid = False
            if "controls" in variant:
                control = variant["controls"]
                control_contract = copy.deepcopy(template)
                control_contract["cases"] = [copy.deepcopy(cases[item]) for item in spec["controls"]]
                control_contract["limits"]["concurrency"] = 1
                if control["contract"] != control_contract:
                    errors.append("Workflow controls differ from the approved plan.")
                controls_valid = all(result["outcome"] == "pass" for result in control["report"]["results"])
                records.append(control)
            if type(variant["controls_valid"]) is not bool or variant["controls_valid"] != controls_valid:
                errors.append("Workflow control validity does not match its evidence.")
            for record in records:
                errors.extend(verify_report(record["report"]))
                build_graph(record["contract"], record["report"])
                if contract_digest(record["contract"]) != record["report"]["contract_sha256"]:
                    errors.append("Materialized workflow contract/report mismatch.")
            expected_steps = [spec["setup"], spec["precondition"], *planned["steps"], spec["postcondition"], *spec["cleanup"]]
            by_step = {step["id"]: step for step in expected_steps}
            previous_records = {}
            for record in variant["steps"]:
                if not isinstance(record, dict) or set(record) != {"step_id", "attempt", "kind", "contract", "report", "bindings"}:
                    raise WorkflowError("Invalid workflow step trace fields.")
                if record["step_id"] not in by_step:
                    errors.append("Workflow executed an unapproved step.")
                    continue
                step = by_step[record["step_id"]]
                expected_kind = ("setup" if step["id"] == spec["setup"]["id"] else
                                 "state_probe" if step["id"] in {spec["precondition"]["id"], spec["postcondition"]["id"]} else
                                 "cleanup" if step["id"] in {item["id"] for item in spec["cleanup"]} else
                                 "replay" if record["attempt"] > 1 else "application")
                if record["kind"] != expected_kind or type(record["attempt"]) is not int or record["attempt"] < 1:
                    errors.append("Workflow request kind or attempt mismatch.")
                if len(record["bindings"]) != len(step["bindings"]):
                    errors.append("Missing workflow binding provenance.")
                for binding, provenance in zip(step["bindings"], record["bindings"]):
                    source = previous_records.get(binding["source_step"])
                    expected_fields = {"source_step", "source_body_sha256", "selector", "selected_headers_sha256", "type", "target"}
                    if source is None or set(provenance) != expected_fields:
                        errors.append("Invalid workflow binding provenance.")
                        continue
                    if (provenance["source_step"] != binding["source_step"]
                            or provenance["source_body_sha256"] != source["report"]["results"][0]["response_sha256"]
                            or provenance["selector"] != {key: binding[key] for key in ("pointer", "header") if key in binding}
                            or provenance["type"] != binding["type"] or provenance["target"] != binding["target"]
                            or ("header" not in binding and provenance["selected_headers_sha256"] is not None)
                            or ("header" in binding and not re.fullmatch(r"[0-9a-f]{64}", str(provenance["selected_headers_sha256"])))):
                        errors.append("Workflow binding does not match its approved source observation.")
                actual_contract = record["contract"]
                actual_case = actual_contract["cases"][0]
                expected_case = copy.deepcopy(cases[step["case_id"]])
                expected_case["requires"] = []
                expected_case["identity"] = step.get("identity", expected_case["identity"])
                # Replace only plan-approved scalar positions with their actual
                # materialized values; every other byte remains source-bound.
                for binding in step["bindings"]:
                    target = binding["target"]
                    if target["kind"] == "path_segment":
                        before, separator, query = expected_case["path"].partition("?")
                        parts = before.split("/")
                        actual_parts = actual_case["path"].partition("?")[0].split("/")
                        if len(parts) != len(actual_parts):
                            raise WorkflowError("Dynamic binding altered route shape.")
                        parts[target["index"]] = actual_parts[target["index"]]
                        expected_case["path"] = "/".join(parts) + (separator + query if separator else "")
                    elif target["kind"] == "json":
                        actual_value = engine._pointer(actual_case.get("body"), target["pointer"])
                        if actual_value is engine._MISSING:
                            raise WorkflowError("Materialized binding is absent.")
                        _set_json(expected_case.get("body"), target["pointer"], actual_value)
                    elif target["kind"] == "header":
                        expected_case["headers"][target["name"]] = actual_case["headers"][target["name"]]
                    elif target["kind"] == "query":
                        path, _, query = expected_case["path"].partition("?")
                        pairs = query.split("&")
                        actual_pairs = actual_case["path"].partition("?")[2].split("&")
                        if len(pairs) != len(actual_pairs):
                            raise WorkflowError("Dynamic binding altered query shape.")
                        found = [i for i, pair in enumerate(pairs) if unquote(pair.split("=", 1)[0]) == target["name"]]
                        position = found[target["occurrence"]]
                        if pairs[position].split("=", 1)[0] != actual_pairs[position].split("=", 1)[0]:
                            raise WorkflowError("Dynamic binding altered query name.")
                        pairs[position] = actual_pairs[position]
                        expected_case["path"] = path + "?" + "&".join(pairs)
                expected_contract = copy.deepcopy(template)
                expected_contract["limits"]["concurrency"] = 1
                expected_contract["cases"] = [expected_case]
                if actual_contract != expected_contract:
                    errors.append("Materialized request exceeds the approved binding positions.")
                previous_records[record["step_id"]] = record
            conclusive = variant["interpretation"] in {"violation", "satisfied"}
            if conclusive:
                actual_sequence = [(record["step_id"], record["attempt"]) for record in variant["steps"]]
                expected_sequence = [(step["id"], step.get("attempt", 1)) for step in expected_steps]
                if actual_sequence != expected_sequence:
                    errors.append("Conclusive workflow is missing required steps or independent probes.")
                if not controls_valid or not variant.get("oracle") or variant["cleanup"] != "complete":
                    errors.append("Conclusive workflow result has invalid prerequisites.")
                else:
                    oracle = variant["oracle"]
                    if (set(oracle) != {"rule_digest", "verification_level", "before_body_sha256", "after_body_sha256"}
                            or oracle["verification_level"] != "evaluation_attested"):
                        errors.append("Workflow oracle verification level or fields are invalid.")
                    for record in variant["steps"]:
                        prerequisite = record["step_id"] in {spec["setup"]["id"], spec["precondition"]["id"], spec["postcondition"]["id"]} | {item["id"] for item in spec["cleanup"]}
                        outcome = record["report"]["results"][0]["outcome"]
                        if (prerequisite and outcome != "pass") or outcome in {"error", "inconclusive"}:
                            errors.append("Conclusive workflow contradicts a failed prerequisite or operation.")
                    before = next(record for record in variant["steps"] if record["step_id"] == spec["precondition"]["id"])
                    after = next(record for record in variant["steps"] if record["step_id"] == spec["postcondition"]["id"])
                    if (oracle["rule_digest"] != plan["rule_digest"]
                            or oracle["before_body_sha256"] != before["report"]["results"][0]["response_sha256"]
                            or oracle["after_body_sha256"] != after["report"]["results"][0]["response_sha256"]
                            or before["report"]["results"][0]["outcome"] != "pass"
                            or after["report"]["results"][0]["outcome"] != "pass"):
                        errors.append("Workflow oracle evidence does not match independent state probes.")
                    # When configured equality checks retain the state value,
                    # their successful original report is stronger than an
                    # otherwise opaque signed state evaluation. Contradictions
                    # must fail even if the outer trace was freshly rehashed.
                    rule = spec["rule"]
                    prior_expected = before["contract"]["cases"][0]["expect"].get("json", {}).get(rule["pointer"], engine._MISSING)
                    final_expected = after["contract"]["cases"][0]["expect"].get("json", {}).get(rule["pointer"], engine._MISSING)
                    if rule["kind"] == "forbidden_state":
                        if prior_expected is not engine._MISSING and engine._json_equal(prior_expected, rule["value"]):
                            errors.append("Workflow fixture already had the forbidden state.")
                        if final_expected is not engine._MISSING:
                            expected_interpretation = "violation" if engine._json_equal(final_expected, rule["value"]) else "satisfied"
                            if variant["interpretation"] != expected_interpretation:
                                errors.append("Workflow state assertion contradicts the original postcondition report.")
                    elif prior_expected is not engine._MISSING and final_expected is not engine._MISSING:
                        if type(prior_expected) is not int or type(final_expected) is not int or final_expected < prior_expected:
                            errors.append("Workflow effect assertions cannot establish a valid counter transition.")
                        elif variant["interpretation"] != ("violation" if final_expected - prior_expected > rule["max_delta"] else "satisfied"):
                            errors.append("Workflow effect claim contradicts original counter assertions.")
            elif variant["interpretation"] != "inconclusive":
                errors.append("Invalid workflow interpretation.")
    except (ValueError, TypeError, KeyError, IndexError, StopIteration, RecursionError):
        errors.append("Malformed workflow trace.")
    return errors
