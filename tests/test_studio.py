import copy
import http.client
import json
import os
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from authzledger.evidence import verify_report
from authzledger.studio import MAX_UPLOAD, StudioServer, parse_json
from test_openapi import config, spec


class StudioTests(unittest.TestCase):
    # The eight-scenario corpus took over eight seconds on CI. Allow bounded
    # scheduling headroom without changing the runner's request deadlines.
    JOB_TIMEOUT_SECONDS = 30

    @classmethod
    def setUpClass(cls):
        cls.server = StudioServer()
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.hits = []

        class Fixture(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                cls.hits.append((self.path, self.headers.get("Authorization")))
                payload = b'{"owner":"owner"}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload)

        cls.fixture = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        cls.fixture_thread = threading.Thread(target=cls.fixture.serve_forever, daemon=True)
        cls.fixture_thread.start()

    @classmethod
    def tearDownClass(cls):
        for server in (cls.server, cls.fixture):
            server.shutdown()
            server.server_close()
        cls.thread.join()
        cls.fixture_thread.join()

    def tearDown(self):
        # The server is shared across tests. Even after an assertion failure,
        # drain its worker so an active job does not reject later test jobs.
        deadline = time.monotonic() + self.JOB_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            with self.server.lock:
                if not self.server.active:
                    return
            time.sleep(.01)
        self.fail("Studio job remained active after bounded test cleanup")

    def request(self, path, body=None, headers=None, method=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        values = {"Authorization": "Bearer " + self.server.token, "Origin": self.server.origin,
                  "Content-Type": "application/json"}
        values.update(headers or {})
        values = {k: v for k, v in values.items() if v is not None}
        data = raw if raw is not None else json.dumps(body).encode() if body is not None else None
        conn.request(method or ("POST" if data is not None else "GET"), path, data, values)
        response = conn.getresponse()
        code, payload, response_headers = response.status, response.read(), dict(response.getheaders())
        conn.close()
        if response_headers.get("Content-Type", "").startswith("application/json"):
            payload = json.loads(payload)
        return code, payload, response_headers

    def contract(self):
        conf = config()
        conf["target"] = f"http://127.0.0.1:{self.fixture.server_port}"
        conf["identities"]["owner"]["headers"]["Authorization"] = {"env": "STUDIO_TEST_TOKEN"}
        code, value, _ = self.request("/api/compile", {"document": spec(), "config": conf})
        self.assertEqual(code, 200)
        return value["contract"]

    def wait_job(self, job):
        deadline = time.monotonic() + self.JOB_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            code, value, _ = self.request("/api/jobs/" + job["id"])
            self.assertEqual(code, 200)
            if value["state"] != "running":
                self.assertEqual(value["state"], "complete", value)
                return value
            time.sleep(.01)
        self.fail(f"Studio job did not complete within {self.JOB_TIMEOUT_SECONDS} seconds")

    def test_full_import_preview_run_export_uses_real_http_and_redacts_credentials(self):
        with patch.dict(os.environ, {"STUDIO_TEST_TOKEN": "Bearer local-studio-secret"}):
            contract = self.contract()
            prior = len(self.hits)
            code, preview, _ = self.request("/api/plan", {"contract": contract})
            self.assertEqual(code, 200)
            self.assertEqual(len(self.hits), prior)
            self.assertEqual(preview["credentials"], [{"env": "STUDIO_TEST_TOKEN", "present": True}])
            code, job, _ = self.request("/api/run", {"contract": contract, "review": preview["review"], "authorized": True})
            self.assertEqual(code, 200)
            result = self.wait_job(job)
            self.assertEqual(self.hits[-1], ("/v1/invoices/owner-1?detail=true", "Bearer local-studio-secret"))
            self.assertEqual(result["report"]["summary"]["pass"], 1)
            self.assertEqual(verify_report(result["report"]), [])
            self.assertNotIn("local-studio-secret", json.dumps(result))
            for kind in ("html", "junit"):
                status, payload, headers = self.request("/api/export", {"kind": kind, "report": result["report"]})
                self.assertEqual(status, 200)
                self.assertNotIn(b"local-studio-secret", payload)
                self.assertIn("attachment", headers["Content-Disposition"])
            tampered = copy.deepcopy(result["report"])
            tampered["summary"]["pass"] = 500
            self.assertEqual(self.request("/api/verify", {"report": tampered})[0], 400)
            self.assertEqual(self.request("/api/export", {"report": tampered, "kind": "html"})[0], 400)

    def test_capability_required_even_for_job_and_session_reads(self):
        for token in (None, "Bearer wrong", "Bearer é"):
            self.assertEqual(self.request("/api/session", headers={"Authorization": token})[0], 403)
            self.assertEqual(self.request("/api/jobs/no-such-id", headers={"Authorization": token})[0], 403)

    def test_cross_origin_and_rebinding_host_rejected(self):
        for headers in ({"Host": "attacker.invalid"}, {"Origin": "https://attacker.invalid"}, {"Origin": None}, {"Sec-Fetch-Site": "cross-site"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.request("/api/demo", {}, headers=headers)[0], 403)

    def test_public_shell_contains_no_capability_and_restricts_browser_execution(self):
        code, html, headers = self.request("/", headers={"Authorization": None})
        self.assertEqual(code, 200)
        self.assertNotIn(self.server.token.encode(), html)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("unsafe-inline", headers["Content-Security-Policy"])
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")

    def test_traversal_and_unknown_assets_do_not_read_files(self):
        for path in ("/../../etc/passwd", "/logo.png?../../etc/passwd", "/web/../studio.py", "/api/jobs/../../etc/passwd"):
            self.assertEqual(self.request(path)[0], 404)

    def test_run_requires_exact_recent_plan_and_affirmative_authorization(self):
        contract = self.contract()
        self.assertEqual(self.request("/api/run", {"contract": contract, "authorized": True})[0], 400)
        _, preview, _ = self.request("/api/plan", {"contract": contract})
        body = {"contract": contract, "review": preview["review"]}
        self.assertEqual(self.request("/api/run", body)[0], 400)
        body["authorized"] = "true"
        self.assertEqual(self.request("/api/run", body)[0], 400)
        body["authorized"] = True
        body["contract"]["cases"][0]["path"] = "/changed"
        self.assertEqual(self.request("/api/run", body)[0], 400)
        with self.server.lock:
            digest, allow, _ = self.server.reviews[preview["review"]]
            self.server.reviews[preview["review"]] = digest, allow, 0
        body["contract"] = self.contract()
        self.assertEqual(self.request("/api/run", body)[0], 400)

    def test_duplicate_keys_nonfinite_and_oversized_bodies_fail_closed(self):
        for raw in (b'{"contract": {}, "contract": {}}', b'{"value": NaN}', b'[]', b'{"value": Infinity}'):
            self.assertEqual(self.request("/api/plan", raw=raw)[0], 400)
        self.assertEqual(self.request("/api/parse", {"text": '{"a": 1, "a": 2}'})[0], 400)
        self.assertEqual(self.request("/api/parse", {"text": '[1, true, null]'})[1]["value"], [1, True, None])
        self.assertEqual(self.request("/api/plan", raw=b"{}", headers={"Content-Length": str(MAX_UPLOAD + 1)})[0], 413)
        self.assertEqual(self.request("/api/plan", raw=b"{}", headers={"Content-Type": "text/plain"})[0], 400)

    def test_duplicate_host_and_content_length_headers_are_rejected(self):
        for name in ("Host", "Content-Length"):
            conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
            conn.putrequest("POST", "/api/demo")
            conn.putheader("Authorization", "Bearer " + self.server.token)
            conn.putheader("Origin", self.server.origin)
            conn.putheader("Content-Type", "application/json")
            conn.putheader("Content-Length", "2")
            conn.putheader(name, self.server.origin[7:] if name == "Host" else "2")
            conn.endheaders(b"{}")
            response = conn.getresponse()
            self.assertIn(response.status, (400, 403))
            response.read()
            conn.close()

    def test_browser_import_rejects_silently_rounded_integer_identifiers(self):
        for raw in ('{"id":9007199254740993}', '[{"id":-9007199254740993}]'):
            code, value, _ = self.request('/api/parse', {'text': raw})
            self.assertEqual(code, 400)
            self.assertIn('exact range', value['error'])
        self.assertEqual(self.request('/api/parse', {'text': '{"id":"9007199254740993"}'})[0], 200)

    def test_changed_mutation_setting_requires_new_review(self):
        contract = self.contract()
        _, preview, _ = self.request("/api/plan", {"contract": contract})
        self.assertEqual(self.request("/api/run", {"contract": contract, "review": preview["review"], "authorized": True, "allow_mutations": True})[0], 400)
        self.assertEqual(self.request("/api/plan", {"contract": contract, "allow_mutations": "false"})[0], 400)

    def test_local_demo_returns_actual_before_after_and_retest(self):
        code, job, _ = self.request("/api/demo", {})
        self.assertEqual(code, 200)
        result = self.wait_job(job)
        self.assertEqual(result["baseline"]["summary"]["fail"], 2)
        self.assertEqual(result["report"]["summary"]["pass"], 6)
        self.assertEqual(len(result["comparison"]["resolved"]), 2)
        code, html, _ = self.request("/api/export", {"kind": "comparison", "baseline": result["baseline"], "current": result["report"]})
        self.assertEqual(code, 200)
        self.assertIn(b"peer-cannot-read-owner", html)

    def test_matrix_analysis_is_offline_and_unknown_policy_stays_unresolved(self):
        code, example, _ = self.request('/api/matrix/example')
        self.assertEqual(code, 200)
        before = len(self.hits)
        code, analysis, _ = self.request('/api/matrix/analyze', example)
        self.assertEqual(code, 200)
        self.assertEqual(analysis['manifest']['coverage']['total'], 24)
        self.assertEqual(len(self.hits), before)
        example['project']['decisions']['north_member']['invoice-a'] = 'unknown'
        code, analysis, _ = self.request('/api/matrix/analyze', example)
        self.assertEqual(code, 200)
        self.assertIsNone(analysis['contract'])
        self.assertTrue(analysis['gaps'])

    def test_benchmark_job_and_bound_explanations(self):
        code, job, _ = self.request('/api/benchmark', {})
        self.assertEqual(code, 200)
        result = self.wait_job(job)
        self.assertEqual(result['kind'], 'benchmark')
        self.assertTrue(result['accepted'])
        self.assertEqual(len(result['scenarios']), 8)
        code, explained, _ = self.request('/api/matrix/explain', {'project': result['project'], 'report': result['report']})
        self.assertEqual(code, 200)
        self.assertEqual(len(explained['trace']), 24)
        self.assertTrue(all(x['outcome'] == 'pass' for x in explained['trace']))
        changed = copy.deepcopy(result['project'])
        changed['decisions']['north_member']['invoice-b'] = 'allow'
        self.assertEqual(self.request('/api/matrix/explain', {'project': changed, 'report': result['report']})[0], 400)
        code, migration, _ = self.request('/api/matrix/diff', {'before': result['project'], 'after': changed})
        self.assertEqual(code, 200)
        self.assertEqual(migration['kind'], 'proposed-policy-migration')
        self.assertNotIn('resolved', migration)

    def test_single_active_job_and_bounded_history(self):
        contract = self.contract()
        _, preview, _ = self.request("/api/plan", {"contract": contract})
        body = {"contract": contract, "review": preview["review"], "authorized": True}
        entered, release = threading.Event(), threading.Event()
        from authzledger.engine import run

        def held(value, **options):
            entered.set()
            release.wait(3)
            return run(value, **options)

        with patch.dict(os.environ, {"STUDIO_TEST_TOKEN": "Bearer local-studio-secret"}), patch("authzledger.studio.run", held):
            code, job, _ = self.request("/api/run", body)
            try:
                self.assertEqual(code, 200)
                self.assertTrue(entered.wait(2))
                self.assertEqual(self.request("/api/demo", {})[0], 400)
                self.assertEqual(self.request("/api/run", body)[0], 400)
            finally:
                release.set()
            self.wait_job(job)
        self.assertLessEqual(len(self.server.jobs), 8)


if __name__ == "__main__":
    unittest.main()
