"""Real loopback controls, PDP budgets, fresh credentials and stale baselines."""

import contextlib
import copy
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from authzledger.assurance import AssuranceError, retest_plan, run_once, watch
from authzledger.evidence import seal_report
from authzledger.history import HistoryError, HistoryStore
from authzledger.intelligence import build_graph
from authzledger.model import ContractError, load_contract


@contextlib.contextmanager
def service():
    state = {"fixed": True, "expired": False, "policy_drift": False, "owner_login_body": False,
             "negative_unauthenticated": False, "application": [], "policy": [], "owner_token": "Bearer owner-fixture-token"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _respond(self, status, payload):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            credential = self.headers.get("Authorization")
            state["application"].append((self.path, credential))
            actor = "owner" if credential == state["owner_token"] else "peer" if credential == "Bearer peer-fixture-token" else None
            if actor == "owner" and state["owner_login_body"]:
                self._respond(200, {"login_required": True})
            elif actor == "peer" and self.path == "/owner" and state["negative_unauthenticated"]:
                self._respond(401, {"error": "authentication_required"})
            elif actor is None or state["expired"] and actor == "owner":
                self._respond(401, {"error": "expired"})
            elif self.path == "/peer" and actor == "peer":
                self._respond(200, {"owner": "peer"})
            elif self.path == "/owner" and (actor == "owner" or not state["fixed"]):
                self._respond(200, {"owner": "owner"})
            else:
                self._respond(403, {"error": "denied"})

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            state["policy"].append(body)
            value = body["input"]
            allowed = value["identity"] == value["path"].strip("/") or state["policy_drift"]
            self._respond(200, {"result": allowed})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def specification(target):
    return load_contract({"version": 1, "name": "Assurance fixture", "target": target,
        "limits": {"max_requests": 3, "timeout_seconds": 1, "concurrency": 2},
        "identities": {"owner": {"headers": {"Authorization": {"env": "AUTHZ_ASSURANCE_OWNER"}}},
                       "peer": {"headers": {"Authorization": {"env": "AUTHZ_ASSURANCE_PEER"}}}},
        "cases": [
            {"id": "owner-positive", "identity": "owner", "method": "GET", "path": "/owner", "expect": {"status": [200], "json": {"/owner": "owner"}}},
            {"id": "peer-positive", "identity": "peer", "method": "GET", "path": "/peer", "expect": {"status": [200], "json": {"/owner": "peer"}}},
            {"id": "peer-denied-owner", "identity": "peer", "method": "GET", "path": "/owner", "requires": ["owner-positive", "peer-positive"], "expect": {"status": [403], "json_absent": ["/owner"]}},
        ]})


def local_policy():
    return {"schema_version": 1, "engine": "local", "default": "deny", "rules": [
        {"id": "owner-own", "effect": "allow", "identities": ["owner"], "paths": ["/owner"]},
        {"id": "peer-own", "effect": "allow", "identities": ["peer"], "paths": ["/peer"]}]}


class AssuranceTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict(os.environ, {"AUTHZ_ASSURANCE_OWNER": "Bearer owner-fixture-token", "AUTHZ_ASSURANCE_PEER": "Bearer peer-fixture-token"})
        environment.start()
        self.addCleanup(environment.stop)
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.store = HistoryStore(Path(self.folder.name) / "history.sqlite3")

    def test_retest_closure_is_complete_and_readonly(self):
        source = specification("http://127.0.0.1:1")
        frozen = copy.deepcopy(source)
        selected = retest_plan(source, ["peer-denied-owner"])
        self.assertEqual(selected["selected_ids"], ["peer-denied-owner"])
        self.assertEqual(selected["dependency_ids"], ["owner-positive", "peer-positive"])
        self.assertEqual(selected["request_count"], 3)
        self.assertEqual(source, frozen)
        for bad in ([], ["missing"], ["owner-positive", "owner-positive"], "owner-positive"):
            with self.assertRaises(AssuranceError):
                retest_plan(source, bad)

    def test_mutations_require_explicit_permission_even_in_retest_plan(self):
        source = specification("http://127.0.0.1:1")
        source["cases"][0]["method"] = "POST"
        with self.assertRaises(ContractError):
            retest_plan(source)
        self.assertEqual(retest_plan(source, allow_mutations=True)["mutating_requests"], 1)

    def test_run_once_retains_three_layer_sources_and_detects_regression(self):
        with service() as (target, state):
            source = specification(target)
            first = run_once(source, local_policy(), self.store)
            self.assertEqual((first["status"], first["exit_code"]), ("pass", 0))
            state["fixed"] = False
            second = run_once(source, local_policy(), self.store)
        self.assertEqual((second["status"], second["exit_code"]), ("fail", 1))
        self.assertEqual(second["baseline_run_id"], first["history"]["id"])
        self.assertTrue(second["comparison"]["regressions"])
        self.assertTrue(second["comparison"]["privilege_escalations"])
        self.assertEqual(self.store.verify_chain(), [])
        self.assertNotIn("owner-fixture-token", json.dumps(self.store.get_run(2)))

    def test_failed_positive_control_stops_and_blocks_negative_request(self):
        with service() as (target, state):
            state["expired"] = True
            result = watch(specification(target), local_policy(), self.store, max_iterations=5)
        self.assertEqual(result["completed_iterations"], 1)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["stop_reason"], "invalid-control")
        self.assertEqual(len(state["application"]), 2)
        self.assertFalse(any(path == "/owner" and token == "Bearer peer-fixture-token" for path, token in state["application"]))

    def test_watch_caps_total_app_and_opa_requests_without_hidden_evaluations(self):
        with service() as (target, state):
            policy = {"schema_version": 1, "engine": "opa", "endpoint": target + "/v1/data/authz/allow", "allowed_origins": [target]}
            result = watch(specification(target), policy, self.store, max_iterations=5, max_requests_total=12)
        self.assertEqual(result["completed_iterations"], 2)
        self.assertEqual(result["requests_reserved"], 12)
        self.assertEqual(result["policy_requests_per_iteration"], 3)
        self.assertEqual(result["application_requests_per_iteration"], 3)
        self.assertEqual(result["stop_reason"], "request-budget")
        self.assertEqual(len(state["application"]) + len(state["policy"]), 12)

    def test_policy_intent_disagreement_stops_even_when_application_passes(self):
        policy = local_policy()
        policy["rules"].append({"id": "bad-peer-cross", "effect": "allow", "identities": ["peer"], "paths": ["/owner"]})
        with service() as (target, _):
            result = run_once(specification(target), policy)
        self.assertEqual(result["report"]["summary"]["pass"], 3)
        self.assertEqual(result["exit_code"], 1)
        self.assertTrue(any(finding["type"] == "policy-intent-drift" for finding in result["graph"]["findings"]))

    def test_fresh_credentials_resolved_on_every_iteration(self):
        with service() as (target, state):
            def completed(iteration, _):
                if iteration == 1:
                    state["owner_token"] = "Bearer owner-renewed-fixture-token"
                    os.environ["AUTHZ_ASSURANCE_OWNER"] = state["owner_token"]
            result = watch(specification(target), local_policy(), self.store, max_iterations=2, on_iteration=completed)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["completed_iterations"], 2)
        self.assertIn(("/owner", "Bearer owner-renewed-fixture-token"), state["application"])

    def test_corrupt_history_blocks_application_and_remote_policy_traffic(self):
        with service() as (target, state):
            source = specification(target)
            run_once(source, local_policy(), self.store)
            with sqlite3.connect(self.store.path) as connection:
                connection.execute("DROP TRIGGER runs_no_update")
                connection.execute("UPDATE runs SET record_sha256 = ? WHERE id = 1", ("a" * 64,))
            state["application"].clear()
            policy = {"schema_version": 1, "engine": "opa", "endpoint": target + "/v1/data/authz/allow", "allowed_origins": [target]}
            with self.assertRaises(HistoryError):
                run_once(source, policy, self.store)
            result = watch(source, policy, self.store, max_iterations=2)
        self.assertEqual(state["application"], [])
        self.assertEqual(state["policy"], [])
        self.assertEqual(result["stop_reason"], "history-error")

    def test_missing_application_credentials_block_remote_policy_too(self):
        with service() as (target, state):
            source = specification(target)
            os.environ.pop("AUTHZ_ASSURANCE_OWNER")
            policy = {"schema_version": 1, "engine": "opa", "endpoint": target + "/v1/data/authz/allow", "allowed_origins": [target]}
            with self.assertRaises(ContractError):
                run_once(source, policy, self.store)
        self.assertEqual(state["application"], [])
        self.assertEqual(state["policy"], [])
        self.assertEqual(self.store.list_runs(), [])

    def test_unanchored_negatives_do_not_establish_assurance(self):
        with service() as (target, _):
            source = specification(target)
            source["cases"][-1]["requires"] = []
            result = run_once(source, local_policy())
        self.assertEqual(result["report"]["summary"]["pass"], 3)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["stop_reason"], "unanchored-negative-control")

    def test_status_only_login_control_cannot_establish_denial_assurance(self):
        with service() as (target, state):
            source = specification(target)
            source["cases"][0]["expect"] = {"status": [200]}
            source["cases"][-1]["expect"]["status"] = [401, 403]
            state.update(owner_login_body=True, negative_unauthenticated=True)
            result = watch(source, local_policy(), self.store, max_iterations=3)
        self.assertEqual(result["completed_iterations"], 1)
        self.assertEqual(result["iterations"][0]["report"]["summary"]["pass"], 3)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["stop_reason"], "unproven-positive-control")
        positive = next(edge for edge in result["iterations"][0]["graph"]["edges"] if edge["case_id"] == "owner-positive")
        self.assertEqual(positive["observed"]["decision"], "unknown")

    def test_stale_history_blocks_all_next_requests(self):
        with service() as (target, state):
            source = specification(target)
            result = run_once(source, local_policy())
            yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
            report = seal_report(dict(result["report"], started_at=yesterday, finished_at=yesterday))
            self.store.append(source, report, build_graph(source, report, local_policy()))
            state["application"].clear()
            result = watch(source, local_policy(), self.store, max_history_age_seconds=60, max_iterations=3)
        self.assertEqual(result["stop_reason"], "stale-history")
        self.assertEqual(result["completed_iterations"], 0)
        self.assertEqual(state["application"], [])

    def test_invalid_bounds_budget_and_pre_cancelled_watch_send_no_requests(self):
        with service() as (target, state):
            source = specification(target)
            for arguments in ({"max_iterations": 0}, {"max_iterations": True}, {"interval_seconds": float("nan")},
                              {"max_requests_total": 2}, {"interval_seconds": -1}, {"max_history_age_seconds": -1},
                              {"max_iterations": 10 ** 400}, {"max_requests_total": 10 ** 400}):
                with self.subTest(arguments=arguments), self.assertRaises(AssuranceError):
                    watch(source, **arguments)
            event = threading.Event()
            event.set()
            result = watch(source, max_iterations=10, stop_event=event)
        self.assertEqual(state["application"], [])
        self.assertEqual(result["stop_reason"], "cancelled")
        self.assertEqual(result["requests_reserved"], 0)


if __name__ == "__main__":
    unittest.main()
