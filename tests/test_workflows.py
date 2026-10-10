import contextlib
import copy
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from authzledger.workflows import compile_workflow, execute_workflow, verify_workflow, WorkflowError, _seal
from authzledger.execution import ExecutionContext


@contextlib.contextmanager
def fixture():
    state = {"objects": {}, "next": 0, "vulnerable": True, "replay": False, "control": True,
             "cleanup": True, "duplicate": False, "reuse": False, "bad_id": False, "requests": [], "cancel": None, "binding_response": None}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def send(self, status, body):
            payload = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)
        def do_GET(self):
            state["requests"].append(("GET", self.path))
            if self.path == "/control":
                return self.send(200, {"principal": "operator" if state["control"] else "wrong"})
            key = self.path.split("/")[-1]
            if key not in state["objects"]: return self.send(404, {})
            self.send(200, dict(state["objects"][key], id=key))
        def do_POST(self):
            state["requests"].append(("POST", self.path))
            self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.path == "/objects":
                state["next"] += 1
                key = "fixed" if state["reuse"] else str(state["next"])
                if state["bad_id"]: key = "../outside"
                state["objects"][key] = {"state": "draft", "effects": 0}
                if state["duplicate"]: return self.send(201, b'{"id":"1","id":"2"}')
                if state["binding_response"] is not None: return self.send(201, state["binding_response"])
                return self.send(201, {"id": key})
            _, _, key, action = self.path.split("/")
            obj = state["objects"][key]
            if action == "approve": obj["state"] = "approved"
            if action == "complete":
                if not state["vulnerable"] and obj["state"] not in {"approved", "completed"}:
                    return self.send(403, {})
                obj["state"] = "completed"
                obj["effects"] = obj["effects"] + 1 if state["replay"] else 1
                if state["cancel"] is not None: state["cancel"].cancel()
            self.send(200, {})
        def do_DELETE(self):
            state["requests"].append(("DELETE", self.path))
            if not state["cleanup"]: return self.send(500, {})
            state["objects"].pop(self.path.split("/")[-1], None)
            self.send(200, {})
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
    try: yield "http://127.0.0.1:" + str(server.server_port), state
    finally: server.shutdown(); server.server_close(); worker.join()


def spec(origin):
    def op(id, method, path, expect):
        return {"id": id, "identity": "operator", "method": method, "path": path, "expect": expect}
    def step(id, case_id, bind=True):
        result = {"id": id, "case_id": case_id, "bindings": []}
        if bind:
            result["bindings"] = [{"source_step": "create", "pointer": "/id", "type": "string", "target": {"kind": "path_segment", "index": 2}}]
        return result
    result = {"schema_version": 1, "kind": "workflow-spec", "id": "approval", "title": "Approval must precede completion",
            "contract": {"version": 1, "name": "Workflow fixture", "target": origin, "identities": {"operator": {"headers": {}}},
                         "limits": {"max_requests": 100, "concurrency": 1}, "cases": [
                op("control", "GET", "/control", {"status": [200], "json": {"/principal": "operator"}}),
                op("create", "POST", "/objects", {"status": [201]}),
                op("before", "GET", "/objects/placeholder", {"status": [200], "json": {"/state": "draft", "/effects": 0}}),
                op("approve", "POST", "/objects/placeholder/approve", {"status": [200]}),
                op("complete", "POST", "/objects/placeholder/complete", {"status": [200, 403]}),
                op("after", "GET", "/objects/placeholder", {"status": [200]}),
                op("delete", "DELETE", "/objects/placeholder", {"status": [200]})]},
            "controls": ["control"], "setup": step("create", "create", False), "precondition": step("before", "before"),
            "steps": [step("approve", "approve"), step("complete", "complete")], "postcondition": step("after", "after"),
            "cleanup": [step("delete", "delete")], "fixture": {"source_step": "create", "pointer": "/id", "type": "string", "read_pointer": "/id"},
            "rule": {"id": "approval", "kind": "forbidden_state", "pointer": "/state", "value": "completed"},
            "variants": [{"id": "skip-approval", "omit": ["approve"]}], "mutation_approval": ["create", "approve", "complete", "delete"]}
    result["contract"]["cases"][4]["body"] = {"operation_id": "placeholder"}
    result["steps"][1]["bindings"].append({"source_step": "create", "pointer": "/id", "type": "string", "target": {"kind": "json", "pointer": "/operation_id"}})
    return result


class WorkflowTests(unittest.TestCase):
    def test_safe_and_vulnerable_are_independently_observed(self):
        with fixture() as (origin, state):
            plan = compile_workflow(spec(origin))
            self.assertEqual(plan, compile_workflow(copy.deepcopy(spec(origin))))
            vulnerable = execute_workflow(plan)
            self.assertEqual(vulnerable["variants"][0]["interpretation"], "violation")
            self.assertEqual(vulnerable["variants"][0]["cleanup"], "complete")
            self.assertEqual(vulnerable["budget_ledger"]["dispatched_total"], 6)
            self.assertEqual(verify_workflow(vulnerable), [])
            state["vulnerable"] = False
            safe = execute_workflow(plan)
            self.assertEqual(safe["variants"][0]["interpretation"], "satisfied")
            self.assertEqual(state["objects"], {})
    def test_two_successes_need_second_effect(self):
        with fixture() as (origin, state):
            source = spec(origin)
            source["rule"] = {"id": "idempotency", "kind": "effect_increase", "pointer": "/effects", "max_delta": 1}
            source["variants"] = [{"id": "repeat", "repeat": {"complete": 2}}]
            plan = compile_workflow(source)
            self.assertEqual(execute_workflow(plan)["variants"][0]["interpretation"], "satisfied")
            state["replay"] = True
            self.assertEqual(execute_workflow(plan)["variants"][0]["interpretation"], "violation")
    def test_invalid_controls_do_not_start_mutation(self):
        with fixture() as (origin, state):
            state["control"] = False
            trace = execute_workflow(compile_workflow(spec(origin)))
            self.assertEqual(trace["variants"][0]["interpretation"], "inconclusive")
            self.assertEqual(state["requests"], [("GET", "/control")])
    def test_duplicate_binding_and_traversal_never_dispatch_mutation(self):
        for flag in ("duplicate", "bad_id"):
            with self.subTest(flag=flag), fixture() as (origin, state):
                state[flag] = True
                trace = execute_workflow(compile_workflow(spec(origin)))
                self.assertEqual(trace["variants"][0]["interpretation"], "inconclusive")
                self.assertFalse(any("complete" in path for _, path in state["requests"]))
    def test_cleanup_failure_stops_following_variants(self):
        with fixture() as (origin, state):
            state["cleanup"] = False
            source = spec(origin); source["variants"].append({"id": "second", "omit": ["approve"]})
            trace = execute_workflow(compile_workflow(source))
            self.assertEqual(len(trace["variants"]), 1)
            self.assertEqual(trace["variants"][0]["cleanup"], "cleanup_pending")
            self.assertEqual(trace["variants"][0]["interpretation"], "inconclusive")
    def test_reused_fixture_cannot_confirm_second_variant(self):
        with fixture() as (origin, state):
            state["reuse"] = True
            source = spec(origin); source["variants"].append({"id": "second", "omit": ["approve"]})
            trace = execute_workflow(compile_workflow(source))
            self.assertEqual(trace["variants"][1]["interpretation"], "inconclusive")
    def test_insufficient_postprobe_budget_prevents_setup(self):
        with fixture() as (origin, state):
            context = ExecutionContext(5, [origin], 5, 1, cleanup_reserve=1)
            trace = execute_workflow(compile_workflow(spec(origin)), context=context)
            self.assertEqual(trace["variants"][0]["interpretation"], "inconclusive")
            self.assertEqual(state["requests"], [])
    def test_review_bound_and_upper_limits(self):
        source = spec("http://127.0.0.1:9999")
        changed = compile_workflow(source); changed["spec"]["variants"][0]["omit"] = []
        with self.assertRaises(WorkflowError): execute_workflow(changed)
        source["mutation_approval"].remove("complete")
        with self.assertRaises(WorkflowError): compile_workflow(source)
        source = spec("http://127.0.0.1:9999"); source["variants"] *= 9
        with self.assertRaises(WorkflowError): compile_workflow(source)
    def test_original_is_not_modified(self):
        with fixture() as (origin, _):
            source = spec(origin); original = copy.deepcopy(source)
            plan = compile_workflow(source); original_plan = copy.deepcopy(plan)
            execute_workflow(plan)
            self.assertEqual(source, original); self.assertEqual(plan, original_plan)
    def test_semantic_controls_cannot_be_upgraded_by_rehashing(self):
        with fixture() as (origin, state):
            state["control"] = False
            trace = execute_workflow(compile_workflow(spec(origin)))
            trace["variants"][0].update(interpretation="violation", controls_valid=True, oracle={})
            trace.pop("workflow_digest"); trace = _seal(trace, "workflow_digest")
            self.assertTrue(verify_workflow(trace))

    def test_stop_after_mutation_preserves_cleanup_and_inconclusive(self):
        with fixture() as (origin, state):
            plan = compile_workflow(spec(origin))
            context = ExecutionContext(6, [origin], 5, 1, cleanup_reserve=1, allow_cleanup_after_cancel=True)
            state["cancel"] = context
            trace = execute_workflow(plan, context=context)
            self.assertEqual(trace["variants"][0]["interpretation"], "inconclusive")
            self.assertEqual(trace["variants"][0]["cleanup"], "complete")
            self.assertTrue(trace["budget_ledger"]["cancelled"])
            self.assertEqual(state["objects"], {})
            self.assertEqual(trace["budget_ledger"]["dispatched_total"], 5)
    def test_eight_variants_twelve_steps_have_exact_shared_upper_bound(self):
        with fixture() as (origin, state):
            value = spec(origin)
            approval = value["steps"][0]
            value["steps"] = [dict(copy.deepcopy(approval), id="approve" + str(index)) for index in range(6)] + [value["steps"][1]]
            value["variants"] = [{"id": "variant" + str(index)} for index in range(8)]
            plan = compile_workflow(value)
            self.assertEqual(plan["request_upper_bound"], 96)
            trace = execute_workflow(plan)
            self.assertEqual(len(trace["variants"]), 8)
            self.assertEqual(trace["budget_ledger"]["dispatched_total"], 96)
            self.assertEqual(verify_workflow(trace), [])
    def test_trace_roundtrip_and_unknown_fields_fail_closed(self):
        with fixture() as (origin, state):
            trace = execute_workflow(compile_workflow(spec(origin)))
        self.assertEqual(verify_workflow(json.loads(json.dumps(trace))), [])
        trace["extra"] = "not permitted"; trace.pop("workflow_digest"); trace = _seal(trace, "workflow_digest")
        self.assertTrue(verify_workflow(trace))

    def test_missing_null_and_wrong_type_binding_never_dispatch_dependent_steps(self):
        for response in ({"unrelated": "1"}, {"id": None}, {"id": True}, {"id": 1}, {"id": []}):
            with self.subTest(response=response), fixture() as (origin, state):
                state["binding_response"] = response
                trace = execute_workflow(compile_workflow(spec(origin)))
                self.assertEqual(trace["variants"][0]["interpretation"], "inconclusive")
                self.assertEqual(state["requests"], [("GET", "/control"), ("POST", "/objects")])
                self.assertEqual(verify_workflow(trace), [])
    def test_forged_state_and_effect_claims_contradict_retained_report_checks(self):
        from unittest.mock import patch
        for kind in ("forbidden_state", "effect_increase"):
            with self.subTest(kind=kind), fixture() as (origin, state):
                value = spec(origin)
                if kind == "forbidden_state":
                    state["vulnerable"] = False
                    value["contract"]["cases"][5]["expect"]["json"] = {"/state": "draft"}
                else:
                    value["rule"] = {"id": "effects", "kind": "effect_increase", "pointer": "/effects", "max_delta": 1}
                    value["variants"] = [{"id": "repeated", "repeat": {"complete": 2}}]
                    value["contract"]["cases"][5]["expect"]["json"] = {"/effects": 1}
                trace = execute_workflow(compile_workflow(value))
                self.assertEqual(trace["variants"][0]["interpretation"], "satisfied")
                self.assertEqual(verify_workflow(trace), [])
            trace["variants"][0]["interpretation"] = "violation"
            trace.pop("workflow_digest"); trace = _seal(trace, "workflow_digest")
            with patch("socket.getaddrinfo", side_effect=AssertionError("offline")):
                self.assertTrue(verify_workflow(trace))
    def test_forged_verification_level_cleanup_and_binding_source_rejected(self):
        with fixture() as (origin, state):
            original = execute_workflow(compile_workflow(spec(origin)))
        alterations = [lambda t: t["variants"][0]["oracle"].update(verification_level="captured_inputs_replayed"),
                       lambda t: t["variants"][0].update(cleanup="not_needed"),
                       lambda t: t["variants"][0]["steps"][1]["bindings"][0].update(source_body_sha256="0" * 64)]
        for mutate in alterations:
            trace = copy.deepcopy(original); mutate(trace)
            trace.pop("workflow_digest"); trace = _seal(trace, "workflow_digest")
            self.assertTrue(verify_workflow(trace))

    def test_shared_fixture_registry_blocks_reuse_across_execution_cycles(self):
        with fixture() as (origin, state):
            state["reuse"] = True
            registry = set()
            plan = compile_workflow(spec(origin))
            first = execute_workflow(plan, fixture_registry=registry)
            self.assertEqual(first["variants"][0]["interpretation"], "violation")
            self.assertEqual(registry, {b'"fixed"'})
            before = len(state["requests"])
            second = execute_workflow(plan, fixture_registry=registry)
            self.assertEqual(second["variants"][0]["interpretation"], "inconclusive")
            self.assertEqual(second["variants"][0]["cleanup"], "complete")
            self.assertEqual(state["requests"][before:], [("GET", "/control"), ("POST", "/objects"), ("DELETE", "/objects/fixed")])
            self.assertEqual(verify_workflow(second), [])

    def test_reflected_credentials_raw_and_encoded_never_enter_binding_or_registry(self):
        import base64
        from urllib.parse import quote
        from unittest.mock import patch
        secret = "Bearer workflow-reflection-private"
        forms = [secret, secret.split(" ", 1)[1], quote(secret, safe=""),
                 quote(quote(secret, safe=""), safe=""), base64.b64encode(secret.encode()).decode()]
        for location in ("fixture", "bound_field"):
            for reflected in forms:
                with self.subTest(location=location, reflected=reflected), fixture() as (origin, state):
                    value = spec(origin)
                    value["contract"]["identities"]["operator"]["headers"] = {"Authorization": {"env": "WORKFLOW_GUARD_SECRET"}}
                    if location == "fixture":
                        state["binding_response"] = {"id": reflected}
                    else:
                        state["binding_response"] = {"id": "1", "public_value": reflected}
                        value["contract"]["cases"][4]["body"]["note"] = "placeholder"
                        value["steps"][1]["bindings"].append({"source_step": "create", "pointer": "/public_value", "type": "string", "target": {"kind": "json", "pointer": "/note"}})
                    registry = set()
                    with patch.dict("os.environ", {"WORKFLOW_GUARD_SECRET": secret}):
                        trace = execute_workflow(compile_workflow(value), fixture_registry=registry)
                    encoded = json.dumps(trace)
                    self.assertNotIn(secret, encoded)
                    self.assertNotIn("workflow-reflection-private", encoded)
                    self.assertNotIn(reflected, encoded)
                    self.assertEqual(trace["variants"][0]["interpretation"], "inconclusive")
                    self.assertFalse(any("complete" in path for _, path in state["requests"]))
                    if location == "fixture":
                        self.assertEqual(registry, set())
                        self.assertEqual(trace["variants"][0]["cleanup"], "cleanup_pending")
                    else:
                        self.assertEqual(trace["variants"][0]["cleanup"], "complete")
                    self.assertEqual(verify_workflow(trace), [])

    def test_resolved_credential_literal_in_plan_rejected_before_any_request(self):
        from unittest.mock import patch
        from urllib.parse import quote
        with fixture() as (origin, state):
            value = spec(origin)
            secret = "Bearer workflow-preflight-private"
            value["contract"]["identities"]["operator"]["headers"] = {"Authorization": {"env": "WORKFLOW_GUARD_SECRET"}}
            value["title"] = "Untrusted reflected title " + quote(secret, safe="")
            plan = compile_workflow(value)
            with patch.dict("os.environ", {"WORKFLOW_GUARD_SECRET": secret}), self.assertRaises(WorkflowError):
                execute_workflow(plan)
            self.assertEqual(state["requests"], [])
