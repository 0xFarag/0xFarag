"""1.0 Studio: domain parity, scoped execution and no browser filesystem authority."""
import copy
import http.client
import io
import json
import shutil
import tempfile
import threading
import time
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from authzledger.history import HistoryStore
from authzledger.signing import generate_keypair, verify_bundle
from authzledger.studio import StudioServer


class StudioV1Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="authzledger-studio-v1-")
        self.root = Path(self.temporary.name)
        self.hits = []
        self.control_valid = True
        test = self

        class Fixture(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                test.hits.append(self.path)
                status = 200 if self.path == "/control" and test.control_valid else 403
                payload = b'{"id":"control"}' if status == 200 else b'{"error":"forbidden"}'
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        self.fixture = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        self.fixture_thread = threading.Thread(target=self.fixture.serve_forever, daemon=True)
        self.fixture_thread.start()
        self.server = None
        self.thread = None
        self.start_server()
        self.contract = {
            "version": 1, "name": "Studio scoped test", "target": f"http://127.0.0.1:{self.fixture.server_port}",
            "identities": {"owner": {"headers": {}}},
            "cases": [
                {"id": "positive", "identity": "owner", "method": "GET", "path": "/control",
                 "expect": {"status": [200], "json": {"/id": "control"}}},
                {"id": "negative", "identity": "owner", "method": "GET", "path": "/private",
                 "requires": ["positive"], "expect": {"status": [403], "json_absent": ["/id"]}},
            ],
        }
        self.policy = {"schema_version": 1, "engine": "local", "default": "deny", "rules": [
            {"id": "control-access", "effect": "allow", "identities": ["owner"], "paths": ["/control"]}]}

    def start_server(self, **options):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join()
        self.server = StudioServer(**options)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join()
        self.fixture.shutdown()
        self.fixture.server_close()
        self.fixture_thread.join()
        self.temporary.cleanup()

    def request(self, path, body=None, *, authorized=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        headers = {"Origin": self.server.origin, "Content-Type": "application/json"}
        if authorized:
            headers["Authorization"] = "Bearer " + self.server.token
        conn.request("POST" if body is not None else "GET", path,
                     json.dumps(body).encode() if body is not None else None, headers)
        response = conn.getresponse()
        code, raw, mime = response.status, response.read(), response.getheader("Content-Type")
        conn.close()
        return code, json.loads(raw) if mime.startswith("application/json") else raw

    def job(self, *, route="/api/run", policy=None, assurance=None, baseline_id=None):
        options = {"contract": self.contract, "policy": policy, "assurance": assurance}
        code, preview = self.request("/api/plan", options)
        self.assertEqual(code, 200, preview)
        code, job = self.request(route, {**options, "review": preview["review"], "authorized": True,
                                        "baseline_id": baseline_id})
        self.assertEqual(code, 200, job)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            _, value = self.request("/api/jobs/" + job["id"])
            if value["state"] != "running":
                self.assertEqual(value["state"], "complete", value)
                return value
            time.sleep(.01)
        self.fail("Bounded Studio job timed out")

    def test_map_layers_are_explicit_offline_and_independent(self):
        code, mapped = self.request("/api/graph", {"contract": self.contract})
        self.assertEqual(code, 200, mapped)
        graph = mapped["graph"]
        self.assertEqual(graph["coverage"]["total"], 2)
        self.assertEqual(graph["coverage"]["policy_known"], 0)
        self.assertEqual(graph["coverage"]["observed_known"], 0)
        self.assertTrue(all(edge["policy"]["decision"] == "unknown" for edge in graph["edges"]))
        code, evaluated = self.request("/api/policy", {"contract": self.contract, "policy": self.policy})
        self.assertEqual(code, 200, evaluated)
        self.assertEqual(evaluated["evaluation"]["decisions"]["positive"]["decision"], "allow")
        self.assertEqual(evaluated["evaluation"]["decisions"]["negative"]["decision"], "deny")
        self.assertEqual(self.hits, [])

    def test_new_routes_require_capability_and_no_filesystem_input(self):
        for route in ("/api/history", "/api/history/1"):
            self.assertEqual(self.request(route, authorized=False)[0], 403)
        for route in ("/api/graph", "/api/plan", "/api/reasoning", "/api/policy"):
            with self.subTest(route=route):
                self.assertEqual(self.request(route, {"contract": "/etc/passwd"})[0], 400)
        self.assertEqual(self.request("/api/graph", {"contract": self.contract, "policy": "/etc/passwd"})[0], 400)
        opa = {"schema_version": 1, "engine": "opa", "endpoint": "http://127.0.0.1:9/v1/data/access",
               "allowed_origins": ["http://127.0.0.1:9"]}
        self.assertEqual(self.request("/api/policy", {"contract": self.contract, "policy": opa})[0], 400)
        self.assertEqual(self.hits, [])

    def test_trusted_startup_policy_engine_is_opt_in_and_budgeted(self):
        decisions = []

        class PDP(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                decisions.append(body)
                raw = json.dumps({"result": body["input"]["path"] == "/control"}).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        pdp = ThreadingHTTPServer(("127.0.0.1", 0), PDP)
        thread = threading.Thread(target=pdp.serve_forever, daemon=True)
        thread.start()
        origin = f"http://127.0.0.1:{pdp.server_port}"
        config = {"schema_version": 1, "engine": "opa", "endpoint": origin + "/v1/data/access",
                  "allowed_origins": [origin]}
        try:
            self.start_server(policy_config=config)
            session = self.request("/api/session")[1]
            self.assertTrue(session["server_policy_available"])
            self.assertEqual(session["server_policy_engine"], "opa")
            self.assertNotIn(origin, json.dumps(session))
            self.assertEqual(decisions, [])
            _, graph = self.request("/api/graph", {"contract": self.contract})
            self.assertEqual(graph["graph"]["coverage"]["policy_known"], 0)
            _, graph = self.request("/api/graph", {"contract": self.contract, "use_server_policy": True})
            self.assertEqual(graph["graph"]["coverage"]["policy_known"], 2)
            self.assertEqual(len(decisions), 2)
            self.assertEqual(self.hits, [])
            _, preview = self.request("/api/plan", {"contract": self.contract, "use_server_policy": True})
            self.assertEqual(preview["assurance"]["maximum_requests"], 4)
            self.assertEqual(len(decisions), 2)
            self.assertEqual(self.request("/api/run", {"contract": self.contract, "review": preview["review"],
                            "authorized": True, "use_server_policy": False})[0], 400)
            self.assertEqual(self.request("/api/graph", {"contract": self.contract,
                            "use_server_policy": True, "policy": self.policy})[0], 400)
        finally:
            pdp.shutdown()
            pdp.server_close()
            thread.join()

    def test_exact_policy_and_assurance_config_are_bound_to_preview(self):
        _, preview = self.request("/api/plan", {"contract": self.contract, "policy": self.policy})
        body = {"contract": self.contract, "policy": self.policy, "authorized": True, "review": preview["review"]}
        body["policy"] = copy.deepcopy(self.policy)
        body["policy"]["default"] = "allow"
        self.assertEqual(self.request("/api/run", body)[0], 400)
        body["policy"] = self.policy
        body["assurance"] = {"cycles": 2, "interval_seconds": 1}
        self.assertEqual(self.request("/api/assurance", body)[0], 400)
        for cycles in (0, 21, True):
            self.assertEqual(self.request("/api/plan", {"contract": self.contract, "assurance": {"cycles": cycles}})[0], 400)
        self.assertEqual(self.hits, [])

    def test_history_evidence_retest_and_persistent_integer_ids(self):
        history = self.root / "history.sqlite3"
        self.start_server(history_path=history)
        result = self.job(policy=self.policy)
        self.assertIs(type(result["history"]["id"]), int)
        self.assertEqual(result["history"]["contract"]["name"], self.contract["name"])
        self.assertEqual(result["graph"]["coverage"]["policy_known"], 2)
        run_id = result["history"]["id"]
        self.assertEqual(self.request("/api/history")[1]["storage"], "persistent")
        self.start_server(history_path=history)
        code, record = self.request("/api/history/" + str(run_id))
        self.assertEqual(code, 200, record)
        self.assertEqual(record["run"]["graph"], result["graph"])
        code, explained = self.request("/api/reasoning", {"history_id": run_id})
        self.assertEqual(code, 200, explained)
        self.assertEqual(explained["ai"]["status"], "disabled")
        retested = self.job(route="/api/retest", policy=self.policy, baseline_id=run_id)
        self.assertEqual(retested["graph_comparison"]["regressions"], [])
        self.assertEqual(len(self.request("/api/history")[1]["runs"]), 2)
        self.assertEqual(HistoryStore(history).verify_chain(), [])

    def test_graph_diff_and_reasoning_refuse_tampered_or_unconfigured_inputs(self):
        result = self.job()
        graph = result["graph"]
        changed = copy.deepcopy(graph)
        changed["edges"][0]["policy"]["decision"] = "allow"
        self.assertEqual(self.request("/api/graph/diff", {"before": graph, "after": changed})[0], 400)
        code, reasoning = self.request("/api/reasoning", {"contract": self.contract, "report": result["report"]})
        self.assertEqual(code, 200, reasoning)
        self.assertEqual(reasoning["ai"]["status"], "disabled")
        self.assertEqual(self.request("/api/reasoning", {"contract": self.contract, "use_local_model": True})[0], 400)
        self.assertEqual(self.request("/api/reasoning", {"contract": self.contract,
                         "model_config": {"origin": "http://127.0.0.1:9", "model": "unsafe"}})[0], 400)

    def test_assurance_is_finite_and_fresh_each_cycle(self):
        result = self.job(route="/api/assurance", policy=self.policy,
                          assurance={"cycles": 2, "interval_seconds": 1})
        self.assertEqual(result["cycles_completed"], 2)
        self.assertEqual(len(self.hits), 4)
        self.assertEqual(len(result["cycle_history"]), 2)

    def test_assurance_stops_on_invalid_control_without_repeating_traffic(self):
        self.control_valid = False
        result = self.job(route="/api/assurance", policy=self.policy,
                          assurance={"cycles": 3, "interval_seconds": 1})
        self.assertEqual(result["cycles_completed"], 1)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["stopped_reason"], "invalid-control")
        self.assertEqual(self.hits, ["/control"])

    def test_direct_run_api_cannot_bypass_repeated_session_stop(self):
        self.control_valid = False
        result = self.job(route="/api/run", assurance={"cycles": 2, "interval_seconds": 1})
        self.assertEqual(result["cycles_completed"], 1)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(self.hits, ["/control"])

    def test_corrupt_history_is_rejected_before_any_application_traffic(self):
        history = self.root / "preflight.sqlite3"
        self.start_server(history_path=history)
        self.job()
        self.hits.clear()
        import sqlite3
        connection = sqlite3.connect(history)
        connection.execute("DROP TRIGGER runs_no_update")
        connection.commit()
        connection.close()
        code, preview = self.request("/api/plan", {"contract": self.contract})
        self.assertEqual(code, 200)
        code, job = self.request("/api/run", {"contract": self.contract, "review": preview["review"], "authorized": True})
        self.assertEqual(code, 200)
        for _ in range(100):
            _, value = self.request("/api/jobs/" + job["id"])
            if value["state"] != "running":
                break
            time.sleep(.01)
        self.assertEqual(value["state"], "error")
        self.assertEqual(self.hits, [])

    def test_signed_proof_requires_startup_keys_and_preserves_original_policy_graph(self):
        if not shutil.which("openssl"):
            self.skipTest("OpenSSL is required for Ed25519 signing")
        result = self.job(policy=self.policy)
        self.assertEqual(self.request("/api/proof", {"history_id": result["history"]["id"]})[0], 400)
        private, public = self.root / "signing.pem", self.root / "public.pem"
        generate_keypair(private, public)
        self.start_server(history_path=self.root / "proof-history.sqlite3", signing_key=private, public_key=public)
        result = self.job(policy=self.policy)
        for forbidden in ("signing_key", "public_key", "attachments", "out"):
            self.assertEqual(self.request("/api/proof", {"history_id": result["history"]["id"], forbidden: "/etc/passwd"})[0], 400)
        code, payload = self.request("/api/proof", {"history_id": result["history"]["id"]})
        self.assertEqual(code, 200)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            contents = {name: archive.read(name) for name in archive.namelist()}
            self.assertEqual(json.loads(contents["attachments/graph.json"]), result["graph"])
            self.assertFalse(any(b"PRIVATE KEY" in raw for raw in contents.values()))
            bundle = self.root / "exported-proof"
            archive.extractall(bundle)
        self.assertEqual(verify_bundle(bundle, public), [])

    def test_cached_graph_proof_and_reasoning_never_requery_policy_engine(self):
        if not shutil.which("openssl"):
            self.skipTest("OpenSSL is required for Ed25519 signing")
        from unittest.mock import patch
        private, public = self.root / "snapshot.pem", self.root / "snapshot-public.pem"
        generate_keypair(private, public)
        # A trusted OPA adapter is represented by its real policy-evaluation
        # output. Subsequent request mocks must never be called during exports.
        self.start_server(signing_key=private, public_key=public,
                          policy_config={"schema_version": 1, "engine": "opa",
                                         "endpoint": "http://127.0.0.1:9/v1/data/access",
                                         "allowed_origins": ["http://127.0.0.1:9"]})
        result = self.job()
        from authzledger.policy import evaluate_policy
        evaluation = evaluate_policy(result["history"]["contract"], self.policy)
        with patch("authzledger.policy.evaluate_policy", return_value=evaluation):
            code, mapped = self.request("/api/graph", {"contract": self.contract,
                              "report": result["report"], "use_server_policy": True})
        self.assertEqual(code, 200, mapped)
        with patch("authzledger.policy.evaluate_policy", side_effect=AssertionError("PDP was queried again")):
            code, explained = self.request("/api/reasoning", {"snapshot_id": mapped["snapshot_id"]})
            self.assertEqual(code, 200, explained)
            code, payload = self.request("/api/proof", {"snapshot_id": mapped["snapshot_id"]})
            self.assertEqual(code, 200)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            self.assertEqual(json.loads(archive.read("attachments/graph.json")), mapped["graph"])
        self.assertEqual(self.request("/api/proof", {"snapshot_id": "forged-id"})[0], 400)


if __name__ == "__main__":
    unittest.main()
