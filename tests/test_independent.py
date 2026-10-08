"""Independent adversarial regression checks; all traffic stays on loopback."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import socketserver
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from authzledger.cli import main, read_json
from authzledger.engine import run
from authzledger.evidence import compare_reports, seal_report, verify_report
from authzledger.model import ContractError, load_contract, plan
from authzledger.reports import render_html, render_junit


@contextlib.contextmanager
def raw_fixture(responder):
    requests = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            received = b""
            while b"\r\n\r\n" not in received and len(received) < 65536:
                part = self.request.recv(4096)
                if not part:
                    break
                received += part
            requests.append(received)
            try:
                responder(self.request, received)
            except (BrokenPipeError, ConnectionResetError):
                pass

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    server = Server(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", requests
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def contract(target, *, expectation=None):
    return {
        "version": 1, "name": "Independent adversarial fixture", "target": target,
        "limits": {"timeout_seconds": 0.15, "concurrency": 1},
        "identities": {"actor": {"headers": {}}},
        "cases": [{"id": "check", "identity": "actor", "method": "GET", "path": "/record",
                   "expect": expectation or {"status": [200], "json": {"/ok": True}}}],
    }


def send_response(sock, body=b'{"ok":true}', *, status=200, advertised_length=None):
    length = len(body) if advertised_length is None else advertised_length
    sock.sendall(f"HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n".encode() + body)


def good_report():
    with raw_fixture(lambda sock, _: send_response(sock)) as (target, _):
        return run(load_contract(contract(target)))


class TransportBoundaryTests(unittest.TestCase):
    def test_content_length_truncation_is_error_even_when_json_prefix_is_complete(self):
        with raw_fixture(lambda sock, _: send_response(sock, advertised_length=4096)) as (target, _):
            report = run(load_contract(contract(target)))
        self.assertEqual(report["results"][0]["outcome"], "error", report["results"])

    def test_total_deadline_covers_slow_trickling_response_headers(self):
        def slow(sock, _):
            sock.sendall(b"HTTP/1.1 200 Fixture\r\nX-Slow: ")
            for _ in range(15):
                sock.sendall(b"x")
                time.sleep(0.04)
            sock.sendall(b"\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}")

        with raw_fixture(slow) as (target, _):
            started = time.monotonic()
            report = run(load_contract(contract(target)))
            elapsed = time.monotonic() - started
        self.assertEqual(report["results"][0]["outcome"], "error")
        self.assertLess(elapsed, 0.40, f"Configured 0.15s total deadline took {elapsed:.3f}s")

    def test_redirect_never_sends_credentials_to_another_origin(self):
        with raw_fixture(lambda sock, _: send_response(sock)) as (sink, sink_requests):
            def redirect(sock, _):
                sock.sendall(f"HTTP/1.1 302 Found\r\nLocation: {sink}/collect\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
            with raw_fixture(redirect) as (target, _), patch.dict(os.environ, {"INDEPENDENT_TOKEN": "Bearer unique-test-only-secret"}):
                value = contract(target)
                value["identities"]["actor"]["headers"] = {"Authorization": {"env": "INDEPENDENT_TOKEN"}}
                report = run(load_contract(value))
            self.assertEqual(report["results"][0]["outcome"], "error")
            self.assertEqual(sink_requests, [])

    def test_nested_percent_delimiter_and_traversal_rejected_before_network(self):
        for path in ("/%252fother", "/%252e%252e/private", "/record%253fsecret=x", "/record?x=%250d%250aHost:test"):
            with self.subTest(path=path):
                value = contract("http://127.0.0.1:1")
                value["cases"][0]["path"] = path
                with self.assertRaises(ContractError):
                    load_contract(value)


class AssertionBoundaryTests(unittest.TestCase):
    def test_failed_positive_control_prevents_denial_request(self):
        with raw_fixture(lambda sock, _: send_response(sock, b'{"error":"expired"}', status=403)) as (target, requests):
            value = contract(target)
            value["cases"].append({"id": "denial", "identity": "actor", "method": "GET", "path": "/sensitive",
                                    "requires": ["check"], "expect": {"status": [403]}})
            report = run(load_contract(value))
        self.assertEqual([r["outcome"] for r in report["results"]], ["fail", "inconclusive"])
        self.assertEqual(len(requests), 1)
        self.assertNotIn(b"/sensitive", requests[0])

    def test_duplicate_json_members_cannot_satisfy_authorization_check(self):
        body = b'{"owner":"attacker","owner":"victim"}'
        with raw_fixture(lambda sock, _: send_response(sock, body)) as (target, _):
            report = run(load_contract(contract(target, expectation={"status": [200], "json": {"/owner": "victim"}})))
        self.assertEqual(report["results"][0]["outcome"], "fail")

    def test_boolean_is_not_equal_to_numeric_permission(self):
        with raw_fixture(lambda sock, _: send_response(sock, b'{"allowed":1}')) as (target, _):
            report = run(load_contract(contract(target, expectation={"status": [200], "json": {"/allowed": True}})))
        self.assertEqual(report["results"][0]["outcome"], "fail")

    def test_credentials_and_reflected_response_never_reach_artifacts(self):
        secret = "Bearer independent-reflected-secret-8492"
        with raw_fixture(lambda sock, _: send_response(sock, json.dumps({"ok": True, "echo": secret}).encode())) as (target, requests), patch.dict(os.environ, {"INDEPENDENT_TOKEN": secret}):
            value = contract(target)
            value["identities"]["actor"]["headers"] = {"Authorization": {"env": "INDEPENDENT_TOKEN"}}
            normalized = load_contract(value)
            report = run(normalized)
            artifacts = json.dumps(plan(normalized)) + json.dumps(report) + render_html(report) + render_junit(report)
        self.assertIn(secret.encode(), requests[0])
        self.assertNotIn(secret, artifacts)


class EvidenceBoundaryTests(unittest.TestCase):
    def test_inconsistent_pass_record_cannot_be_sealed_or_verified(self):
        report = good_report()
        report["results"][0]["checks"][0]["passed"] = False
        try:
            resealed = seal_report(report)
        except ValueError:
            return
        self.assertTrue(verify_report(resealed), "A pass with a failed assertion was accepted as structurally valid evidence")

    def test_same_digest_but_different_target_is_not_a_valid_comparison(self):
        first = good_report()
        second = copy.deepcopy(first)
        second["target"] = "http://127.0.0.1:1"
        second = seal_report(second)
        with self.assertRaises(ValueError):
            compare_reports(first, second)

    def test_duplicate_report_keys_are_not_silently_normalized(self):
        report = good_report()
        text = json.dumps(report)
        text = '{"name":"conflicting-untrusted-name",' + text[1:]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ambiguous.json"
            path.write_text(text)
            with self.assertRaises(ValueError):
                read_json(str(path))

    def test_deep_untrusted_report_returns_controlled_cli_error(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            path = Path(directory) / "deep.json"
            path.write_text('{"untrusted":' + '[' * 2000 + '0' + ']' * 2000 + '}')
            self.assertEqual(main(["verify", str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
