import contextlib
import copy
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from authzledger.experiments import compile_experiment, execute_experiment
from authzledger.execution import ExecutionContext
from authzledger.minimize import plan_reduction, execute_reduction, verify_reduction, removable_units, ReductionError, _remove
from authzledger.workflows import compile_workflow, execute_workflow, _seal
from test_experiments import fixture_spec
from test_workflows import fixture as workflow_fixture, spec as workflow_spec


@contextlib.contextmanager
def fixture(*, port=0):
    state = {"invalid_controls": False, "flaky": False, "seen": 0, "requests": [], "require_two": False, "different_bug": False, "owner_credential": "Bearer owner", "peer_credential": "Bearer peer"}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            state["requests"].append(self.path)
            path = urlsplit(self.path)
            if self.headers.get("Authorization") not in {state["owner_credential"], state["peer_credential"]}:
                status, body = 401, {"error": "invalid credential"}
            elif path.path == "/me":
                status, body = 200, {"principal": "wrong" if state["invalid_controls"] else "peer", "tenant": "B"}
            elif path.path == "/known-denial": status, body = 403, {"error": "denied"}
            elif self.headers.get("Authorization") == state["owner_credential"]: status, body = 200, {"marker": "synthetic-A"}
            else:
                state["seen"] += 1
                leaking = parse_qs(path.query).get("required") == ["1"]
                if state["require_two"]: leaking = leaking and parse_qs(path.query).get("second") == ["2"]
                if state["flaky"] and state["seen"] % 2 == 0: leaking = False
                status, body = 403, {"marker": "synthetic-A"} if leaking else {"error": "denied"}
                if state["different_bug"] and not parse_qs(path.query).get("noise"):
                    body = {"marker": "different-object-B"}
            raw = json.dumps(body).encode(); self.send_response(status)
            self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True); worker.start()
    with patch.dict("os.environ", {"CONTRAST_OWNER": "Bearer owner", "CONTRAST_PEER": "Bearer peer"}):
        try: yield "http://127.0.0.1:" + str(server.server_port), state
        finally: server.shutdown(); server.server_close(); worker.join()


def source(origin):
    value = fixture_spec(origin)
    case = value["contract"]["cases"][-1]
    case["path"] += "?required=1&noise=a&noise=b"
    case["headers"] = {"Accept-Language": "en", "X-Request-Id": "synthetic"}
    return value


class ReductionTests(unittest.TestCase):
    def test_real_request_reduction_keeps_original_and_uses_fresh_controls(self):
        with fixture() as (origin, state):
            execution = execute_experiment(compile_experiment(source(origin)))
            original = copy.deepcopy(execution)
            units = [unit for unit in removable_units(execution) if unit.get("name") == "noise"]
            plan = plan_reduction(execution, units)
            trace = execute_reduction(plan)
            self.assertEqual(trace["accepted_removed"], [0, 1])
            self.assertTrue(trace["one_minimal"])
            self.assertEqual(trace["requests_used"], 12)
            self.assertEqual(verify_reduction(trace), [])
            self.assertEqual(execution, original)
            self.assertEqual(trace["accepted_execution"]["contract"]["cases"][-1]["path"], "/invoice/A?required=1")
            self.assertEqual(sum(path == "/me" for path in state["requests"]), 4)
            self.assertNotIn("Bearer", json.dumps(trace))
    def test_necessary_parameter_survives_and_final_single_gate_is_real(self):
        with fixture() as (origin, state):
            execution = execute_experiment(compile_experiment(source(origin)))
            units = [unit for unit in removable_units(execution) if unit.get("name") in {"required", "noise"}]
            trace = execute_reduction(plan_reduction(execution, units))
            self.assertTrue(trace["one_minimal"])
            self.assertEqual(len(trace["accepted_removed"]), 2)
            self.assertEqual(trace["final_checks"][0]["interpretation"], "not_reproduced")
            self.assertEqual(verify_reduction(trace), [])
    def test_budget_stop_keeps_last_proven_candidate(self):
        with fixture() as (origin, state):
            execution = execute_experiment(compile_experiment(source(origin)))
            units = [unit for unit in removable_units(execution) if unit.get("name") == "noise"]
            trace = execute_reduction(plan_reduction(execution, units, max_requests=4))
            self.assertEqual(len(trace["accepted_removed"]), 1)
            self.assertFalse(trace["one_minimal"])
            self.assertEqual(trace["requests_used"], 4)
            self.assertEqual(trace["stop_reason"], "budget_exhausted")
            self.assertEqual(verify_reduction(trace), [])
    def test_control_failure_never_accepts_candidate(self):
        with fixture() as (origin, state):
            execution = execute_experiment(compile_experiment(source(origin)))
            unit = next(unit for unit in removable_units(execution) if unit.get("name") == "noise")
            state["invalid_controls"] = True
            trace = execute_reduction(plan_reduction(execution, [unit], max_requests=12))
            self.assertEqual(trace["accepted_removed"], [])
            self.assertFalse(trace["one_minimal"])
            self.assertTrue(all(attempt["interpretation"] == "inconclusive" for attempt in trace["attempts"]))
            self.assertEqual(trace["label"], "no confirmed reduction; minimality not confirmed")
            self.assertEqual(verify_reduction(trace), [])
    def test_protected_unit_and_control_cannot_be_selected(self):
        with fixture() as (origin, _):
            execution = execute_experiment(compile_experiment(source(origin)))
            for unit in [{"kind": "header", "case_id": "target", "name": "authorization", "occurrence": 0},
                         {"kind": "query", "case_id": "actor", "name": "noise", "occurrence": 0}]:
                with self.subTest(unit=unit), self.assertRaises(ReductionError): plan_reduction(execution, [unit])
    def test_duplicate_queries_preserve_occurrence_and_encoding(self):
        spec = {"contract": {"cases": [{"id": "x", "headers": {}, "path": "/x?a=one&a=two&a=three&b=%2B"}]}}
        reduced = _remove(spec, [{"kind": "query", "case_id": "x", "name": "a", "occurrence": 1}])
        self.assertEqual(reduced["contract"]["cases"][0]["path"], "/x?a=one&a=three&b=%2B")
        self.assertEqual(spec["contract"]["cases"][0]["path"], "/x?a=one&a=two&a=three&b=%2B")
    def test_nested_json_removal_keeps_siblings(self):
        spec = {"contract": {"cases": [{"id": "x", "headers": {}, "path": "/x", "body": {"a": {"keep": 1, "noise": 2}}}]}}
        reduced = _remove(spec, [{"kind": "json", "case_id": "x", "pointer": "/a/noise"}])
        self.assertEqual(reduced["contract"]["cases"][0]["body"], {"a": {"keep": 1}})
    def test_rehashed_minimality_without_final_gate_rejected(self):
        with fixture() as (origin, _):
            execution = execute_experiment(compile_experiment(source(origin)))
            unit = next(unit for unit in removable_units(execution) if unit.get("name") == "noise")
            trace = execute_reduction(plan_reduction(execution, [unit], max_requests=4))
        trace["one_minimal"] = True; trace.pop("reduction_digest"); trace = _seal(trace, "reduction_digest")
        self.assertTrue(verify_reduction(trace))
    def test_fresh_workflow_isolation_for_mutating_reduction(self):
        with workflow_fixture() as (origin, state):
            spec = workflow_spec(origin)
            spec["contract"]["cases"][4]["body"]["noise"] = "unneeded"
            execution = execute_workflow(compile_workflow(spec))
            units = removable_units(execution)
            unit = next(unit for unit in units if unit.get("pointer") == "/noise")
            trace = execute_reduction(plan_reduction(execution, [unit], max_requests=18))
            self.assertTrue(trace["one_minimal"])
            self.assertEqual(trace["requests_used"], 12)
            self.assertEqual(state["next"], 3)
            self.assertEqual(state["objects"], {})
            self.assertEqual(verify_reduction(trace), [])
    def test_shared_context_never_gets_reset_between_attempts(self):
        with fixture() as (origin, _):
            execution = execute_experiment(compile_experiment(source(origin)))
            unit = next(unit for unit in removable_units(execution) if unit.get("name") == "noise")
            context = ExecutionContext(4, [origin], 5, 1)
            trace = execute_reduction(plan_reduction(execution, [unit]), context=context)
            self.assertEqual(context.snapshot()["dispatched_total"], 4)
            self.assertFalse(trace["one_minimal"])

    def test_observed_flakiness_never_claims_minimality(self):
        with fixture() as (origin, state):
            execution = execute_experiment(compile_experiment(source(origin)))
            unit = next(unit for unit in removable_units(execution) if unit.get("name") == "noise")
            state["flaky"] = True
            trace = execute_reduction(plan_reduction(execution, [unit]))
            self.assertFalse(trace["one_minimal"])
            self.assertIn(trace["stop_reason"], {"repeatability_failed", "inconclusive_attempts"})
            self.assertEqual(verify_reduction(trace), [])
    def test_workflow_reduction_plan_roundtrip(self):
        with workflow_fixture() as (origin, state):
            value = workflow_spec(origin)
            value["contract"]["cases"][4]["body"]["noise"] = "unneeded"
            execution = execute_workflow(compile_workflow(value))
            units = [unit for unit in removable_units(execution) if unit.get("pointer") == "/noise"]
            plan = json.loads(json.dumps(plan_reduction(execution, units, max_requests=12)))
            trace = execute_reduction(plan)
            self.assertTrue(trace["one_minimal"])
            self.assertEqual(verify_reduction(json.loads(json.dumps(trace))), [])

    def test_exact_three_irrelevant_and_two_necessary_units(self):
        with fixture() as (origin, state):
            state["require_two"] = True
            value = source(origin)
            value["contract"]["cases"][-1]["path"] = "/invoice/A?noise=a&noise=b&other=c&required=1&second=2"
            execution = execute_experiment(compile_experiment(value))
            units = [unit for unit in removable_units(execution) if unit["kind"] == "query"]
            self.assertEqual(len(units), 5)
            trace = execute_reduction(plan_reduction(execution, units))
            self.assertEqual(len(trace["accepted_removed"]), 3)
            self.assertEqual(trace["accepted_execution"]["contract"]["cases"][-1]["path"], "/invoice/A?required=1&second=2")
            self.assertEqual(len(trace["final_checks"]), 2)
            self.assertTrue(trace["one_minimal"])
            self.assertLessEqual(trace["requests_used"], 40)
            self.assertEqual(verify_reduction(trace), [])
    def test_different_object_bug_is_not_accepted_as_same_violation(self):
        with fixture() as (origin, state):
            value = source(origin)
            value["contract"]["cases"][-1]["path"] = "/invoice/A?required=1&noise=a"
            execution = execute_experiment(compile_experiment(value))
            state["different_bug"] = True
            units = [unit for unit in removable_units(execution) if unit.get("name") == "noise"]
            trace = execute_reduction(plan_reduction(execution, units))
            self.assertEqual(trace["accepted_removed"], [])
            self.assertTrue(any(attempt["interpretation"] == "not_reproduced" for attempt in trace["attempts"]))
            self.assertEqual(trace["accepted_execution"]["findings"][0]["rule_digest"], execution["findings"][0]["rule_digest"])
            self.assertEqual(verify_reduction(trace), [])
    def test_exported_reproducer_runs_in_fresh_fixture_with_new_credentials(self):
        with fixture() as (origin, state):
            execution = execute_experiment(compile_experiment(source(origin)))
            units = [unit for unit in removable_units(execution) if unit.get("name") == "noise"]
            trace = execute_reduction(plan_reduction(execution, units))
            exported = json.dumps(trace["accepted_execution"]["plan"])
            port = int(urlsplit(origin).port)
            rule_digest = trace["accepted_execution"]["findings"][0]["rule_digest"]
        self.assertNotIn("Bearer", exported)
        with fixture(port=port) as (fresh_origin, state):
            state.update(owner_credential="new-owner-credential", peer_credential="new-peer-credential")
            with patch.dict("os.environ", {"CONTRAST_OWNER": state["owner_credential"], "CONTRAST_PEER": state["peer_credential"]}):
                replayed = execute_experiment(json.loads(exported))
            self.assertEqual(fresh_origin, origin)
            self.assertEqual(replayed["findings"][0]["status"], "confirmed")
            self.assertEqual(replayed["findings"][0]["rule_digest"], rule_digest)
            self.assertNotIn("new-owner-credential", json.dumps(replayed))
            self.assertNotIn("new-peer-credential", json.dumps(replayed))
    def test_rehashed_labels_stop_reasons_boolean_and_request_count_rejected_offline(self):
        with fixture() as (origin, state):
            execution = execute_experiment(compile_experiment(source(origin)))
            unit = next(unit for unit in removable_units(execution) if unit.get("name") == "noise")
            original = execute_reduction(plan_reduction(execution, [unit]))
        alterations = [lambda t: t.update(label="globally minimal"), lambda t: t.update(one_minimal=1),
                       lambda t: t.update(stop_reason="budget_exhausted"),
                       lambda t: t.update(requests_used=t["requests_used"] - 1, starting_dispatched=1),
                       lambda t: t["attempts"][0].update(phase="invented")]
        for mutate in alterations:
            trace = copy.deepcopy(original); mutate(trace)
            trace.pop("reduction_digest"); trace = _seal(trace, "reduction_digest")
            with patch("socket.getaddrinfo", side_effect=AssertionError("offline")):
                self.assertTrue(verify_reduction(trace))
