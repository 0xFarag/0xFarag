import contextlib
import json
import os
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from authzledger.model import load_contract
from authzledger.policy import PolicyError, evaluate_policy, load_policy


def contract():
    return load_contract({"version": 1, "name": "Policy fixture", "target": "https://api.example.test",
                          "identities": {"owner": {"headers": {"Authorization": {"env": "APP_SECRET"}}},
                                         "peer": {"headers": {}}},
                          "cases": [{"id": "owner", "identity": "owner", "method": "GET", "path": "/records/1", "expect": {"status": [200]}},
                                    {"id": "peer", "identity": "peer", "method": "GET", "path": "/records/1", "expect": {"status": [403]}}]})


@contextlib.contextmanager
def opa_fixture(mode="boolean"):
    state = {"requests": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            state["requests"].append({"path": self.path, "body": json.loads(raw), "authorization": self.headers.get("Authorization")})
            if mode == "redirect":
                self.send_response(302)
                self.send_header("Location", "/redirected")
                self.end_headers()
                return
            if mode == "slow":
                time.sleep(0.25)
            body = ({"result": state["requests"][-1]["body"]["input"]["identity"] == "owner"}
                    if mode not in {"undefined", "nonbool", "echo", "large", "duplicate"} else
                    {} if mode == "undefined" else {"result": "true"} if mode == "nonbool" else
                    {"result": True, "decision_id": "private-opa-token"} if mode == "echo" else {"result": True, "padding": "x" * 512})
            payload = b'{"result":true,"result":false}' if mode == "duplicate" else json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            try:
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    try:
        yield {"schema_version": 1, "engine": "opa", "endpoint": origin + "/v1/data/authz/allow", "allowed_origins": [origin]}, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


class PolicyTests(unittest.TestCase):
    def test_intent_does_not_supply_policy_decision(self):
        result = evaluate_policy(contract(), {"schema_version": 1, "engine": "local", "rules": []})
        self.assertEqual([value["decision"] for value in result["decisions"].values()], ["unknown", "unknown"])

    def test_deny_precedence_over_earlier_allow_and_explain_order(self):
        config = {"schema_version": 1, "engine": "local", "rules": [
            {"id": "broad-allow", "effect": "allow"}, {"id": "peer-denied", "effect": "deny", "identities": ["peer"]},
            {"id": "later-deny", "effect": "deny", "identities": ["peer"]}]}
        result = evaluate_policy(contract(), config)
        self.assertEqual(result["decisions"]["owner"]["decision"], "allow")
        peer = result["decisions"]["peer"]
        self.assertEqual(peer["decision"], "deny")
        self.assertEqual(peer["provenance"]["selected_rule"], "peer-denied")
        self.assertEqual(peer["provenance"]["matched_rules"], ["broad-allow", "peer-denied", "later-deny"])
        self.assertEqual(config["rules"][0], {"id": "broad-allow", "effect": "allow"})

    def test_context_is_explicit_case_override_and_type_exact(self):
        config = {"schema_version": 1, "engine": "local", "context": {"tenant": "one", "enabled": 1},
                  "case_context": {"peer": {"tenant": "two", "enabled": True}},
                  "rules": [{"id": "enabled-one", "effect": "allow", "context": {"tenant": "one", "enabled": True}},
                            {"id": "tenant-two", "effect": "deny", "context": {"tenant": "two"}}]}
        result = evaluate_policy(contract(), config)
        self.assertEqual(result["decisions"]["owner"]["decision"], "unknown")
        self.assertEqual(result["decisions"]["peer"]["decision"], "deny")

    def test_scope_unknown_fields_and_ambiguous_inputs_rejected(self):
        bad = [
            {"schema_version": True, "engine": "local", "rules": []},
            {"schema_version": 1, "engine": [], "rules": []},
            {"schema_version": 1, "engine": "local", "rules": [], "default": []},
            {"schema_version": 1, "engine": "local", "rules": [{"id": "a", "effect": "allow"}, {"id": "a", "effect": "deny"}]},
            {"schema_version": 1, "engine": "local", "rules": [], "unknown": True},
            {"schema_version": 1, "engine": "local", "rules": [], "context": {"nested": {1: "bad"}}},
            {"schema_version": 1, "engine": "local", "rules": [], "context": {"nan": float("nan")}},
        ]
        for config in bad:
            with self.subTest(config=config), self.assertRaises(PolicyError):
                load_policy(config)
        with self.assertRaises(PolicyError):
            evaluate_policy(contract(), {"schema_version": 1, "engine": "local", "rules": [], "case_context": {"unknown": {}}})

    def test_opa_scope_requires_explicit_origin(self):
        for config in [
            {"schema_version": 1, "engine": "opa", "endpoint": "https://opa.test/v1/data/authz/allow"},
            {"schema_version": 1, "engine": "opa", "endpoint": "http://169.254.169.254/v1/data/authz/allow", "allowed_origins": ["https://opa.test"]},
            {"schema_version": 1, "engine": "opa", "endpoint": "https://secret@opa.test/v1/data/authz/allow", "allowed_origins": ["https://opa.test"]},
            {"schema_version": 1, "engine": "opa", "endpoint": "https://opa.test/v1/data/../allow", "allowed_origins": ["https://opa.test"]},
        ]:
            with self.subTest(config=config), self.assertRaises(PolicyError):
                load_policy(config)

    def test_opa_real_boolean_api_and_no_app_credentials_or_expectations(self):
        with opa_fixture() as (config, state), patch.dict(os.environ, {"APP_SECRET": "do-not-send", "OPA_SECRET": "private-opa-token"}):
            config["credential_env"] = "OPA_SECRET"
            config["context"] = {"tenant": "explicit"}
            result = evaluate_policy(contract(), config)
        self.assertEqual(result["decisions"]["owner"]["decision"], "allow")
        self.assertEqual(result["decisions"]["peer"]["decision"], "deny")
        self.assertEqual(len(state["requests"]), 2)
        self.assertEqual(state["requests"][0]["authorization"], "Bearer private-opa-token")
        request = state["requests"][0]["body"]["input"]
        self.assertEqual(set(request), {"identity", "method", "path", "context"})
        self.assertNotIn("do-not-send", json.dumps(state))
        self.assertNotIn("private-opa-token", json.dumps(result))
        self.assertEqual(result["decisions"]["owner"]["provenance"]["policy_revision"], "not independently attested")

    def test_opa_undefined_nonboolean_redirect_duplicates_and_bounds_fail_closed(self):
        for mode in ("undefined", "nonbool", "redirect", "large", "duplicate", "slow"):
            with self.subTest(mode=mode), opa_fixture(mode) as (config, state):
                config.update(max_response_bytes=128, timeout_seconds=0.1)
                with self.assertRaises(PolicyError):
                    evaluate_policy(contract(), config)
                self.assertEqual(len(state["requests"]), 1)

    def test_opa_untrusted_response_never_echoes_secret_into_provenance(self):
        with opa_fixture("echo") as (config, state):
            result = evaluate_policy(contract(), config)
        self.assertNotIn("private-opa-token", json.dumps(result))
        self.assertNotIn("decision_id", json.dumps(result))

    def test_policy_validation_does_not_resolve_credential_or_make_request(self):
        with opa_fixture() as (config, state):
            config["credential_env"] = "UNSET_OPA_CREDENTIAL"
            self.assertEqual(load_policy(config)["engine"], "opa")
            self.assertEqual(state["requests"], [])
            with patch.dict(os.environ, {}, clear=True), self.assertRaises(PolicyError):
                evaluate_policy(contract(), config)
            self.assertEqual(state["requests"], [])

    def test_deep_python_input_fails_with_policy_error_before_traffic(self):
        nested = {}
        current = nested
        for _ in range(1500):
            current["nested"] = {}
            current = current["nested"]
        with self.assertRaises(PolicyError):
            load_policy({"schema_version": 1, "engine": "local", "rules": [], "context": nested})

    def test_large_imported_pattern_workload_is_rejected_before_evaluation(self):
        specification = contract()
        specification["limits"]["max_requests"] = 1000
        specification["cases"] = [dict(specification["cases"][0], id=f"case-{index}") for index in range(1000)]
        config = {"schema_version": 1, "engine": "local", "rules": [
            {"id": f"rule-{index}", "effect": "deny", "identities": [f"absent-{number}" for number in range(1000)]}
            for index in range(11)]}
        with self.assertRaisesRegex(PolicyError, "evaluation budget"):
            evaluate_policy(specification, config)


if __name__ == "__main__":
    unittest.main()
