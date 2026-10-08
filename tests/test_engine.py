import contextlib
import json
import os
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from authzledger.engine import run
from authzledger.evidence import verify_report
from authzledger.model import ContractError, contract_digest, load_contract


@contextlib.contextmanager
def fixture():
    state = {"requests": [], "active": 0, "peak": 0}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            with lock:
                state["requests"].append((self.path, self.headers.get("Authorization")))
                state["active"] += 1
                state["peak"] = max(state["peak"], state["active"])
            try:
                if self.path == "/slow-headers":
                    self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                    self.wfile.flush()
                    for _ in range(15):
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(0.04)
                    self.wfile.write(b"\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                    return
                if self.path == "/slow":
                    time.sleep(0.2)
                if self.path.startswith("/parallel"):
                    time.sleep(0.06)
                status = 403 if self.path in {"/denied", "/fail-control"} else 200
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/leaked")
                    self.end_headers()
                    return
                if self.path in {"/denied", "/fail-control"}:
                    payload = b'{"error":"denied"}'
                elif self.path == "/large":
                    payload = b"x" * 100
                elif self.path == "/malformed":
                    payload = b"not JSON"
                elif self.path == "/duplicate":
                    payload = b'{"owner":"owner","owner":"peer"}'
                elif self.path == "/nonfinite":
                    payload = b'{"value":NaN}'
                else:
                    payload = json.dumps({"owner": "owner", "flag": True, "amount": 120,
                                          "a/b": {"~value": [1, None]},
                                          "echo": self.headers.get("Authorization")}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload) + (5 if self.path == "/truncated" else 0)))
                if self.path == "/compressed":
                    self.send_header("Content-Encoding", "gzip")
                self.end_headers()
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with lock:
                    state["active"] -= 1

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            state["body"] = body
            self.do_GET()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def case(case_id, path="/success", *, requires=None, expect=None, identity="owner"):
    return {"id": case_id, "identity": identity, "method": "GET", "path": path,
            "requires": requires or [], "expect": expect or {"status": [200], "json": {"/owner": "owner"}}}


def contract(target, cases, **limits):
    return load_contract({"version": 1, "name": "Local fixture", "target": target,
                          "identities": {"owner": {"headers": {"Authorization": {"env": "AUTHZ_TEST_SECRET"}}},
                                         "anonymous": {"headers": {}}}, "cases": cases,
                          "limits": limits})


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {"AUTHZ_TEST_SECRET": "Bearer private-test-secret"})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_success_denial_evidence_and_secret_redaction(self):
        with fixture() as (target, state):
            specification = contract(target, [case("owner"), case("negative", "/denied", requires=["owner"],
                identity="anonymous", expect={"status": [403, 404], "json_absent": ["/amount"]})])
            result = run(specification)
        self.assertEqual(result["summary"], {"pass": 2, "fail": 0, "error": 0, "inconclusive": 0, "total": 2})
        self.assertEqual(verify_report(result), [])
        self.assertEqual(result["contract_sha256"], contract_digest(specification))
        self.assertEqual([item["control_type"] for item in result["results"]], ["positive", "negative"])
        self.assertEqual(state["requests"], [("/success", "Bearer private-test-secret"), ("/denied", None)])
        rendered = json.dumps(result)
        self.assertNotIn("private-test-secret", rendered)
        self.assertNotIn("/amount", rendered)
        self.assertNotIn("Authorization", rendered)

    def test_missing_any_credential_prevents_all_requests(self):
        with fixture() as (target, state):
            specification = contract(target, [case("owner"), case("anon", identity="anonymous")])
            os.environ.pop("AUTHZ_TEST_SECRET", None)
            with self.assertRaises(ContractError):
                run(specification)
            self.assertEqual(state["requests"], [])

    def test_invalid_credential_prevents_all_requests(self):
        with fixture() as (target, state):
            specification = contract(target, [case("owner")])
            os.environ["AUTHZ_TEST_SECRET"] = "secret\r\nInjected: yes"
            with self.assertRaises(ContractError):
                run(specification)
            self.assertEqual(state["requests"], [])

    def test_failed_control_blocks_transitive_requests_and_preserves_order(self):
        with fixture() as (target, state):
            specification = contract(target, [case("grandchild", "/must-not-send-2", requires=["child"]),
                case("child", "/must-not-send", requires=["owner"]), case("owner", "/fail-control"),
                case("independent")])
            report = run(specification)
        self.assertEqual([record["id"] for record in report["results"]], ["grandchild", "child", "owner", "independent"])
        self.assertEqual([record["outcome"] for record in report["results"]], ["inconclusive", "inconclusive", "fail", "pass"])
        self.assertEqual({path for path, _ in state["requests"]}, {"/fail-control", "/success"})
        self.assertIsNone(report["results"][0]["response_sha256"])

    def test_redirect_not_followed_even_when_redirect_is_expected(self):
        with fixture() as (target, state):
            report = run(contract(target, [case("redirect", "/redirect", expect={"status": [302]})]))
        self.assertEqual(report["results"][0]["outcome"], "error")
        self.assertEqual(report["results"][0]["status"], 302)
        self.assertEqual(len(state["requests"]), 1)

    def test_response_size_exact_boundary_and_overflow(self):
        with fixture() as (target, _):
            passing = run(contract(target, [case("bounded", "/large", expect={"status": [200]})], max_response_bytes=100))
            failing = run(contract(target, [case("bounded", "/large", expect={"status": [200]})], max_response_bytes=99))
        self.assertEqual(passing["results"][0]["outcome"], "pass")
        self.assertEqual(failing["results"][0]["outcome"], "error")
        self.assertIsNone(failing["results"][0]["response_sha256"])

    def test_timeout_is_sanitized(self):
        with fixture() as (target, _):
            report = run(contract(target, [case("slow", "/slow")], timeout_seconds=0.1))
        result = report["results"][0]
        self.assertEqual(result["outcome"], "error")
        self.assertEqual(result["reason"], "Request timed out.")
        self.assertLess(result["duration_ms"], 1000)

    def test_total_deadline_interrupts_trickling_headers(self):
        with fixture() as (target, _):
            started = time.monotonic()
            report = run(contract(target, [case("slow-headers", "/slow-headers")], timeout_seconds=0.15))
            elapsed = time.monotonic() - started
        result = report["results"][0]
        self.assertEqual(result["outcome"], "error")
        self.assertEqual(result["reason"], "Request timed out.")
        self.assertLess(elapsed, 0.4)

    def test_invalid_json_never_satisfies_absence_checks(self):
        with fixture() as (target, _):
            for path in ("/malformed", "/duplicate", "/nonfinite"):
                with self.subTest(path=path):
                    report = run(contract(target, [case("check", path, expect={"status": [200], "json_absent": ["/secret"]})]))
                    self.assertEqual(report["results"][0]["outcome"], "fail")
                    self.assertEqual(report["results"][0]["checks"][-1], {"type": "json_absent", "passed": False})

    def test_json_pointer_escapes_array_and_boolean_type(self):
        with fixture() as (target, _):
            report = run(contract(target, [case("pointer", expect={"status": [200],
                "json": {"/a~1b/~0value/0": 1, "/a~1b/~0value/1": None}, "json_absent": ["/a~1b/~0value/01"]}),
                case("typed", expect={"status": [200], "json": {"/flag": 1}})]))
        self.assertEqual([record["outcome"] for record in report["results"]], ["pass", "fail"])

    def test_concurrency_never_exceeds_limit(self):
        with fixture() as (target, state):
            report = run(contract(target, [case(f"case-{index}", f"/parallel/{index}") for index in range(6)], concurrency=2))
        self.assertEqual(report["summary"]["pass"], 6)
        self.assertLessEqual(state["peak"], 2)
        self.assertGreaterEqual(state["peak"], 2)

    def test_ambient_proxy_is_ignored(self):
        with fixture() as (target, _), patch.dict(os.environ, {"http_proxy": "http://127.0.0.1:1", "HTTP_PROXY": "http://127.0.0.1:1", "no_proxy": "", "NO_PROXY": ""}):
            report = run(contract(target, [case("owner")]))
        self.assertEqual(report["summary"]["pass"], 1)

    def test_compressed_and_truncated_responses_are_errors(self):
        with fixture() as (target, _):
            report = run(contract(target, [case("compressed", "/compressed", expect={"status": [200]}),
                                           case("truncated", "/truncated", expect={"status": [200]})]))
        self.assertEqual([record["outcome"] for record in report["results"]], ["error", "error"])

    def test_json_body_for_explicitly_authorized_mutation(self):
        with fixture() as (target, state):
            specification = contract(target, [case("post")])
            specification["cases"][0].update(method="POST", body={"enabled": True})
            specification = load_contract(specification, allow_mutations=True)
            report = run(specification)
        self.assertEqual(report["summary"]["pass"], 1)
        self.assertEqual(json.loads(state["body"]), {"enabled": True})


if __name__ == "__main__":
    unittest.main()


class AddressCandidateDeadlineTests(unittest.TestCase):
    def test_address_candidates_share_one_deadline(self):
        from authzledger.engine import _RequestDeadline
        from unittest.mock import patch
        timeouts = []
        class SlowSocket:
            def settimeout(self, value):
                self.timeout = value
                timeouts.append(value)
            def connect(self, address):
                time.sleep(min(0.12, self.timeout))
                raise TimeoutError()
            def shutdown(self, how):
                pass
            def close(self):
                pass
        import socket
        import time
        candidates = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 1))] * 2
        started = time.monotonic()
        deadline = _RequestDeadline(started + 0.15)
        try:
            with patch('authzledger.engine.socket.getaddrinfo', return_value=candidates), patch('authzledger.engine.socket.socket', side_effect=lambda *a: SlowSocket()):
                with self.assertRaises(TimeoutError):
                    deadline.create_connection(('fixture.invalid', 1), 0.15, None)
        finally:
            deadline.close()
        self.assertLess(time.monotonic() - started, 0.28)
        if len(timeouts) == 2:
            self.assertLess(timeouts[1], 0.08)
