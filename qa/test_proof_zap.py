# © Nasser Aldin Farag (0xFarag). All rights reserved.
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
import tempfile
from contextlib import closing
import unittest
from unittest.mock import patch
from team.proof_zap import ALERT_PATH, read_alerts, ZapImportError


class ZapFixture(unittest.TestCase):
    def setUp(self):
        test = self
        self.status = 200
        self.hits = []
        self.data = {"alerts": [
            {"id": "1", "pluginId": "10010", "method": "GET",
             "url": "https://lab.authz.local/invoices/1042?api_key=private-key#user", "evidence": "secret",
             "description": "raw report", "attack": "private-payload", "cookie": "session=secret"},
            {"id": "2", "pluginId": "10010", "method": "GET", "statusCode": "403",
             "url": "https://outside.test/accounts/private-token"}]}
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                test.hits.append((self.path, self.headers.get("X-ZAP-API-Key")))
                payload = json.dumps(test.data).encode()
                self.send_response(test.status)
                self.send_header("Location", "/other")
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(payload)
            def log_message(self, *args):
                pass
        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = "http://127.0.0.1:" + str(self.http.server_port)
        self.worker = threading.Thread(target=self.http.serve_forever, kwargs={"poll_interval":0.01}, daemon=True)
        self.worker.start()
        self.addCleanup(self.http.server_close)
        self.addCleanup(self.http.shutdown)
        self.env = patch.dict(os.environ, AUTHZLEDGER_ZAP_ORIGIN=self.origin)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_filtered_fixture_shared_engine(self):
        from team.proof_engine import import_source
        rows = read_alerts(self.origin, "session-key")
        self.assertEqual(self.hits, [(ALERT_PATH, "session-key")])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], {"id": "zap-1", "rule": "10010", "host": "lab.authz.local", "method": "GET",
                                   "path": "/invoices/1042", "status": None, "marker": False, "source": "ZAP"})
        self.assertEqual(rows[1]["status"], 403)
        self.assertEqual(rows[1]["host"], "outside.test")
        self.assertRegex(rows[1]["path"], r"^/accounts/redacted-[0-9a-f]{24}$")
        batch = import_source("zap", json.dumps({"observations": rows}).encode())
        self.assertEqual([r["host"] for r in batch["observations"]], ["lab.authz.local", "outside.test"])
        from team.proof_engine import make_scope, evaluate
        scope = make_scope(["lab.authz.local"], "Lokal aufgezeichnete Beobachtungen prüfen", 5)
        report = evaluate(scope, [batch], {key: True for key in ("token", "identity", "owner", "denial")})
        self.assertEqual([f["status"] for f in report["findings"]], ["inconclusive", "out_of_scope"])
        for text in ["private-token", "raw report", "private-key", "session-key", "private-payload", "#user"]:
            self.assertNotIn(text, json.dumps(rows))

    def test_authenticated_workflow_retains_only_metadata(self):
        from team.server import bootstrap, connect, dispatch
        self.data["alerts"][0]["url"] = "https://engagement.example.test/invoices/1042?key=private-query"
        self.data["alerts"][0]["statusCode"] = 403
        with tempfile.TemporaryDirectory() as directory:
            bootstrap(directory, "reviewer@example.test", "fixture-passphrase-123")
            session, cookie = dispatch(directory, "POST", "/api/login",
                                       {"email":"reviewer@example.test", "password":"fixture-passphrase-123"})
            auth = {"token":cookie, "csrf":session["csrf"]}
            base = "/api/teams/" + session["teams"][0]["id"] + "/proof"
            created, _ = dispatch(directory, "POST", base, {"mode":"commercial", "hosts":["engagement.example.test"],
                                                             "roe":"Authorised offline test", "budget":2}, **auth)
            before = created["run"]
            url = base + "/" + before["id"]
            changed, _ = dispatch(directory, "POST", url + "/zap", {"version":before["version"], "apiKey":"fixture-key-123"}, **auth)
            received = changed["run"]
            self.assertEqual([f["status"] for f in received["report"]["findings"]], ["inconclusive", "out_of_scope"])
            reviewed, _ = dispatch(directory, "POST", url + "/controls",
                                   {"version":received["version"], "controls":dict.fromkeys(("token","identity","owner","denial"), True)}, **auth)
            self.assertEqual([f["status"] for f in reviewed["run"]["report"]["findings"]], ["no_marker", "out_of_scope"])
            with closing(connect(directory)) as db:
                stored = "\n".join(db.iterdump())
                for text in ["private-query", "private-token", "fixture-key-123", "private-payload", "raw report"]:
                    self.assertNotIn(text, stored)

    def test_errors(self):
        for status, code in [(401,"zap_denied"),(403,"zap_denied"),(307,"zap_response"),(500,"zap_response")]:
            self.status = status
            with self.assertRaisesRegex(ZapImportError, code):
                read_alerts(self.origin, "test-key")
        self.status = 200
        for body, code in [({"alerts":[]}, "zap_empty"), ({}, "zap_response"),
                           ({"alerts":[{}]}, "zap_response"), ({"alerts":[{}] * 501}, "zap_limit")]:
            self.data = body
            with self.assertRaisesRegex(ZapImportError, code):
                read_alerts(self.origin, "test-key")
        self.assertTrue(all(p == ALERT_PATH for p, _ in self.hits))

    def test_origin_key_and_network(self):
        for value in [self.origin + "/action", self.origin + "?key=a", self.origin + "#",
                      self.origin.replace("127.0.0.1", "localhost"),
                      self.origin.replace("127.0.0.1", "127.0.0.2"), "http://example.test:8080",
                      self.origin.replace("127.0.0.1", "owner@127.0.0.1"), "http://127.0.0.1:65536"]:
            with self.assertRaisesRegex(ZapImportError, "zap_config"):
                read_alerts(value, "test-key")
        with self.assertRaisesRegex(ZapImportError, "zap_credentials"):
            read_alerts(self.origin, "test\r\nHeader: bad")
        self.assertFalse(self.hits)
        self.http.shutdown()
        self.http.server_close()
        with self.assertRaisesRegex(ZapImportError, "zap_unreachable"):
            read_alerts(self.origin, "test-key")
