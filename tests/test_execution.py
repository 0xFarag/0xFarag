"""Real transport and adversarial accounting coverage for shared execution."""
import concurrent.futures
import contextlib
import json
import os
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from authzledger.engine import run
from authzledger.evidence import verify_report
from authzledger.execution import ExecutionContext, ExecutionError
from authzledger.policy import evaluate_policy, PolicyError
from authzledger.assurance import watch
from authzledger.model import load_contract


@contextlib.contextmanager
def service():
    state = {"requests": [], "active": 0, "peak": 0}
    lock = threading.Lock()
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            with lock:
                state["requests"].append(self.path)
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            if self.path == "/slow":
                time.sleep(0.05)
            body = json.dumps({"principal": "owner", "echo": self.headers.get("Authorization")}).encode()
            self.send_response(200)
            self.send_header("X-Proof", "first")
            self.send_header("X-Proof", "second")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            with lock:
                state["active"] -= 1
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            state["requests"].append(self.path)
            body = b'{"result":true}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def specification(target, count=1, dependent=False, path="/data"):
    return load_contract({"version": 1, "name": "Shared execution test", "target": target,
        "identities": {"owner": {"headers": {"Authorization": {"env": "EXECUTION_TEST_SECRET"}}}},
        "limits": {"max_requests": 32, "concurrency": 16},
        "cases": [{"id": "case-" + str(index), "identity": "owner", "method": "GET", "path": path,
                   "requires": ["case-" + str(index - 1)] if dependent and index else [],
                   "expect": {"status": [200], "json": {"/principal": "owner"}}} for index in range(count)]})


class ExecutionContextTests(unittest.TestCase):
    def reserve(self, context, kind="application", **kwargs):
        return context.reserve(kind=kind, operation_id="case", target_origin="http://127.0.0.1", **kwargs)

    def test_concurrent_reservation_never_overshoots_remaining_three(self):
        context = ExecutionContext(3, ["http://127.0.0.1"], 1, 16)
        barrier = threading.Barrier(16)
        dispatched = []
        def attempt(index):
            barrier.wait()
            try:
                reservation = self.reserve(context)
                context.dispatch(reservation, lambda: dispatched.append(index))
            except ExecutionError as error:
                self.assertEqual(error.code, "request-budget")
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(attempt, range(16)))
        self.assertEqual(len(dispatched), 3)
        self.assertEqual(context.snapshot()["dispatched_total"], 3)
        self.assertEqual(context.remaining(), 0)

    def test_cleanup_reserve_is_unavailable_to_normal_traffic(self):
        context = ExecutionContext(3, ["http://127.0.0.1"], 1, 1, cleanup_reserve=1)
        for _ in range(2):
            context.dispatch(self.reserve(context), lambda: None)
        with self.assertRaises(ExecutionError):
            self.reserve(context)
        self.assertEqual(context.remaining("cleanup"), 1)
        context.dispatch(self.reserve(context, "cleanup"), lambda: None)
        self.assertEqual(context.snapshot()["dispatched_total"], 3)
        self.assertEqual(context.remaining("cleanup"), 0)

    def test_cancel_between_reservation_and_dispatch_releases_not_refunds_io(self):
        context = ExecutionContext(2, ["http://127.0.0.1"], 1, 1)
        reservation = self.reserve(context)
        context.cancel()
        with self.assertRaises(ExecutionError):
            context.dispatch(reservation, lambda: self.fail("network after cancel"))
        self.assertEqual(context.snapshot()["dispatched_total"], 0)
        self.assertEqual(context.snapshot()["reserved_pending"], 0)

    def test_cleanup_after_cancel_requires_explicit_permission_and_reserve(self):
        for allowed in (False, True):
            context = ExecutionContext(2, ["http://127.0.0.1"], 1, 1, cleanup_reserve=1,
                                       allow_cleanup_after_cancel=allowed)
            context.cancel()
            if allowed:
                context.dispatch(self.reserve(context, "cleanup"), lambda: None)
                self.assertEqual(context.snapshot()["by_kind"]["cleanup"], 1)
            else:
                with self.assertRaises(ExecutionError):
                    self.reserve(context, "cleanup")
            with self.assertRaises(ExecutionError):
                self.reserve(context)

    def test_failed_transport_counts_and_dispatch_cannot_reuse(self):
        context = ExecutionContext(1, ["http://127.0.0.1"], 1, 1)
        reservation = self.reserve(context)
        def fail():
            raise OSError("unsafe reflected secret")
        with self.assertRaises(OSError):
            context.dispatch(reservation, fail)
        self.assertEqual(context.snapshot()["dispatched_total"], 1)
        self.assertNotIn("unsafe", json.dumps(context.snapshot()))
        with self.assertRaises(ExecutionError):
            context.dispatch(reservation, lambda: None)
        with self.assertRaises(ExecutionError):
            context.release(reservation)

    def test_app_scope_does_not_authorize_pdp_and_endpoint_is_exact(self):
        context = ExecutionContext(3, ["http://127.0.0.1"], 1, 1)
        with self.assertRaises(ExecutionError):
            self.reserve(context, "pdp", method="POST", path="/v1/data/authz/allow")
        context = ExecutionContext(3, {"pdp": ["http://127.0.0.1/v1/data/authz/allow"]}, 1, 1)
        for method, path in (("GET", "/v1/data/authz/allow"), ("POST", "/v1/data/other/allow")):
            with self.assertRaises(ExecutionError):
                self.reserve(context, "pdp", method=method, path=path)
        with self.assertRaises(ExecutionError):
            self.reserve(context)
        context.dispatch(self.reserve(context, "pdp", method="POST", path="/v1/data/authz/allow"), lambda: None)

    def test_explicit_operation_scope_and_foreign_reservation(self):
        context = ExecutionContext(2, ["http://127.0.0.1"], 1, 1,
                                   approved_operations=[("application", "GET", "/approved")])
        with self.assertRaises(ExecutionError):
            self.reserve(context, method="POST", path="/approved")
        with self.assertRaises(ExecutionError):
            self.reserve(context, method="GET", path="/other")
        reservation = self.reserve(context, method="GET", path="/approved")
        other = ExecutionContext(2, ["http://127.0.0.1"], 1, 1)
        with self.assertRaises(ExecutionError):
            other.dispatch(reservation, lambda: self.fail("foreign reservation"))
        context.release(reservation)
        self.assertEqual(context.remaining(), 2)

    def test_deadline_and_invalid_inputs_fail_closed(self):
        context = ExecutionContext(1, ["http://127.0.0.1"], 1, 1)
        with self.assertRaises(ExecutionError):
            self.reserve(context, deadline=time.monotonic() - 1)
        for kwargs in ({"max_requests": True}, {"concurrency": 17}, {"timeout_seconds": float("nan")}, {"timeout_seconds": 10 ** 400},
                       {"cleanup_reserve": 2}, {"allowed_origins": ["https://secret@host"]},
                       {"allowed_origins": {"advisory": ["http://example.test/api/generate"]}}):
            args = dict(max_requests=1, allowed_origins=["http://127.0.0.1"], timeout_seconds=1, concurrency=1)
            args.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(ExecutionError):
                ExecutionContext(**args)

    def test_atomic_lease_protects_post_mutation_probe_and_cleanup(self):
        context = ExecutionContext(4, ["http://127.0.0.1"], 1, 2, cleanup_reserve=1,
                                   allow_cleanup_after_cancel=True)
        with context.lease(2, cleanup_requests=1) as workflow:
            self.assertEqual(context.remaining(), 1)
            context.dispatch(self.reserve(context), lambda: None)
            with self.assertRaises(ExecutionError):
                self.reserve(context)
            workflow.dispatch(self.reserve(workflow, "setup"), lambda: None)
            self.assertEqual(workflow.remaining(), 1)
            workflow.dispatch(self.reserve(workflow, "state_probe"), lambda: None)
            context.cancel()
            workflow.dispatch(self.reserve(workflow, "cleanup"), lambda: None)
        self.assertEqual(context.snapshot()["dispatched_total"], 4)
        self.assertEqual(context.snapshot()["leased_pending"], 0)
        with self.assertRaises(ExecutionError):
            self.reserve(workflow)

    def test_lease_returns_only_unused_quota_and_invalidates_pending_reservations(self):
        context = ExecutionContext(3, ["http://127.0.0.1"], 1, 2)
        with context.lease(3) as child:
            child.dispatch(self.reserve(child), lambda: None)
            pending = self.reserve(child)
            self.assertEqual(context.remaining(), 0)
        self.assertEqual(context.remaining(), 2)
        self.assertEqual(context.snapshot()["dispatched_total"], 1)
        with self.assertRaises(ExecutionError):
            child.dispatch(pending, lambda: self.fail("closed lease"))

    def test_advisory_scope_is_separate_and_literal_loopback(self):
        context = ExecutionContext(1, {"advisory": ["http://127.0.0.1/api/generate"]}, 1, 1)
        with self.assertRaises(ExecutionError):
            self.reserve(context)
        context.dispatch(self.reserve(context, "advisory", method="POST", path="/api/generate"), lambda: None)
        self.assertEqual(context.snapshot()["by_kind"]["advisory"], 1)


class SharedTransportTests(unittest.TestCase):
    def setUp(self):
        patcher = patch.dict(os.environ, {"EXECUTION_TEST_SECRET": "Bearer runtime-only-secret"})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_engine_runs_share_global_budget_and_case_categories(self):
        with service() as (target, state):
            context = ExecutionContext(3, [target], 1, 16)
            first = run(specification(target, 2), context=context, request_kind={"case-0": "identity_control"})
            second = run(specification(target, 2), context=context, request_kind="reduction")
        self.assertEqual(first["summary"]["pass"], 2)
        self.assertEqual(second["summary"]["pass"], 1)
        self.assertEqual(second["summary"]["inconclusive"], 1)
        self.assertEqual(len(state["requests"]), 3)
        self.assertEqual(context.snapshot()["by_kind"]["identity_control"], 1)
        self.assertEqual(context.snapshot()["by_kind"]["reduction"], 1)
        self.assertEqual(verify_report(second), [])

    def test_shared_app_and_pdp_budget_and_exact_entrypoint(self):
        with service() as (target, state):
            source = specification(target, 2)
            policy = {"schema_version": 1, "engine": "opa", "endpoint": target + "/v1/data/authz/allow", "allowed_origins": [target]}
            context = ExecutionContext(3, {"application": [target], "pdp": [policy["endpoint"]]}, 1, 16)
            evaluation = evaluate_policy(source, policy, context=context)
            result = run(source, context=context)
            with self.assertRaises(PolicyError):
                evaluate_policy(source, policy, context=context)
        self.assertEqual(len(evaluation["decisions"]), 2)
        self.assertEqual(result["summary"]["pass"], 1)
        self.assertEqual(len(state["requests"]), 3)
        self.assertEqual(context.snapshot()["by_kind"]["pdp"], 2)

    def test_sixteen_concurrent_app_and_real_opa_starts_share_three_remaining_slots(self):
        with service() as (target, state):
            source = specification(target)
            policy = {"schema_version": 1, "engine": "opa", "endpoint": target + "/v1/data/authz/allow", "allowed_origins": [target]}
            context = ExecutionContext(5, {"application": [target], "pdp": [policy["endpoint"]]}, 2, 16)
            self.assertEqual(run(source, context=context)["summary"]["pass"], 1)
            evaluate_policy(source, policy, context=context)
            self.assertEqual(context.remaining(), 3)
            barrier = threading.Barrier(16)
            def start(index):
                barrier.wait()
                if index % 2:
                    try:
                        evaluate_policy(source, policy, context=context)
                        return 1
                    except PolicyError as error:
                        self.assertIn("request-budget", str(error))
                        return 0
                report = run(source, context=context)
                self.assertEqual(verify_report(report), [])
                return report["summary"]["pass"]
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                completed = list(pool.map(start, range(16)))
        self.assertEqual(sum(completed), 3)
        self.assertEqual(len(state["requests"]), 5)
        ledger = context.snapshot()
        self.assertEqual(ledger["dispatched_total"], 5)
        self.assertEqual(ledger["by_kind"]["pdp"], state["requests"].count("/v1/data/authz/allow"))
        self.assertEqual(ledger["by_kind"]["application"], state["requests"].count("/data"))
        self.assertGreaterEqual(ledger["by_kind"]["pdp"], 1)
        self.assertEqual(ledger["reserved_pending"], 0)
        self.assertEqual(context.remaining(), 0)

    def test_cancelled_dag_stops_further_dispatch_and_capture_secrets_stay_transient(self):
        captures = []
        with service() as (target, state):
            context = ExecutionContext(3, [target], 1, 16)
            def capture(value):
                captures.append(value)
                context.cancel()
            result = run(specification(target, 3, dependent=True), context=context, observation_sink=capture)
        self.assertEqual(len(state["requests"]), 1)
        self.assertEqual(result["summary"]["inconclusive"], 2)
        self.assertEqual(captures[0]["complete"], True)
        self.assertEqual([value for key, value in captures[0]["headers"] if key.lower() == "x-proof"], ["first", "second"])
        self.assertIn(b"runtime-only-secret", captures[0]["body"])
        self.assertNotIn("runtime-only-secret", json.dumps(result) + json.dumps(context.snapshot()))
        self.assertEqual(verify_report(result), [])

    def test_context_concurrency_applies_across_concurrent_engine_runs(self):
        with service() as (target, state):
            context = ExecutionContext(6, [target], 2, 1)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                reports = list(pool.map(lambda _: run(specification(target, 3, path="/slow"), context=context), range(2)))
        self.assertEqual(state["peak"], 1)
        self.assertEqual(sum(report["summary"]["pass"] for report in reports), 6)

    def test_transport_failure_is_counted_and_capture_is_incomplete(self):
        captures = []
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            target = "http://127.0.0.1:" + str(sock.getsockname()[1])
            context = ExecutionContext(1, [target], 1, 1)
            result = run(specification(target), context=context, observation_sink=captures.append)
        self.assertEqual(result["summary"]["error"], 1)
        self.assertFalse(captures[0]["complete"])
        self.assertEqual(captures[0]["body"], b"")
        self.assertEqual(context.snapshot()["dispatched_total"], 1)

    def test_watch_shares_one_context_across_all_iterations(self):
        with service() as (target, state):
            context = ExecutionContext(2, [target], 1, 1)
            result = watch(specification(target), max_iterations=4, max_requests_total=10, context=context)
        self.assertEqual(result["completed_iterations"], 2)
        self.assertEqual(result["stop_reason"], "request-budget")
        self.assertEqual(context.snapshot()["dispatched_total"], 2)
        self.assertEqual(len(state["requests"]), 2)

    def test_external_watch_stop_event_cancels_inside_dag_with_provided_context(self):
        event = threading.Event()
        with service() as (target, state):
            context = ExecutionContext(3, [target], 1, 1)
            result = watch(specification(target, 3, dependent=True), max_iterations=2,
                           context=context, stop_event=event, observation_sink=lambda _: event.set())
        self.assertEqual(len(state["requests"]), 1)
        self.assertEqual(result["stop_reason"], "cancelled")
        self.assertEqual(result["execution"]["dispatched_total"], 1)

    def test_observation_callback_failure_is_sanitized(self):
        def broken(_):
            raise ValueError("private-callback-secret")
        with service() as (target, _):
            report = run(specification(target), observation_sink=broken)
        self.assertEqual(report["summary"]["error"], 1)
        self.assertNotIn("private-callback-secret", json.dumps(report))
        self.assertEqual(verify_report(report), [])


if __name__ == "__main__":
    unittest.main()
