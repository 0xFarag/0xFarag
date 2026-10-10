"""Source-bound, version-aware comparison and hostile-envelope verification."""

import contextlib
import copy
import hashlib
import json
import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from authzledger import engine
from authzledger.assurance import retest_plan
from authzledger.comparison import ComparisonError, create_comparison, verify_comparison
from authzledger.evidence import compare_reports, seal_report
from authzledger.model import contract_digest, load_contract


def contract(target="https://api.example.test"):
    return load_contract({
        "version": 1, "name": "Comparison fixture", "target": target,
        "identities": {"owner": {"headers": {"Authorization": {"env": "COMPARISON_OWNER"}}},
                       "peer": {"headers": {"Authorization": {"env": "COMPARISON_PEER"}}}},
        "cases": [
            {"id": "owner-control", "identity": "owner", "method": "GET", "path": "/owner",
             "expect": {"status": [200], "json": {"/owner": "owner"}}},
            {"id": "peer-control", "identity": "peer", "method": "GET", "path": "/peer",
             "expect": {"status": [200], "json": {"/owner": "peer"}}},
            {"id": "peer-denied", "identity": "peer", "method": "GET", "path": "/owner",
             "requires": ["owner-control", "peer-control"],
             "expect": {"status": [403], "json_absent": ["/owner"]}},
            {"id": "outside", "identity": "owner", "method": "GET", "path": "/outside",
             "expect": {"status": [200], "json": {"/owner": "owner"}}},
        ]})


def reseal(report):
    report["summary"] = {outcome: sum(row["outcome"] == outcome for row in report["results"])
                         for outcome in ("pass", "fail", "error", "inconclusive")}
    report["summary"]["total"] = len(report["results"])
    return seal_report(report)


def report(source, *, leak=False, version="1.0.0", overrides=None):
    results = []
    overrides = overrides or {}
    for case in source["cases"]:
        if case["id"] == "peer-denied":
            status, payload = 403, {"owner": "owner"} if leak else {"error": "denied"}
        else:
            status, payload = 200, {"owner": case["identity"]}
        value = overrides.get(case["id"])
        if value is None:
            value = (status, payload)
        previous = {row["id"]: row for row in results}
        if any(previous[item]["outcome"] != "pass" for item in case["requires"]):
            record = engine._record(case, "inconclusive", "Required control did not pass.")
        elif isinstance(value, str):
            record = engine._record(case, value, "Fixture execution unavailable.")
        else:
            status, payload = value
            raw = json.dumps(payload).encode()
            checks, reason = engine._checks(case, status, raw)
            record = engine._record(case, "pass" if all(check["passed"] for check in checks) else "fail", reason)
            record.update(status=status, checks=checks, response_sha256=hashlib.sha256(raw).hexdigest())
        results.append(record)
    return reseal({"schema_version": 1, "tool": {"name": "AuthzLedger", "version": version},
                   "name": source["name"], "target": source["target"], "contract_sha256": contract_digest(source),
                   "started_at": "2026-10-10T12:00:00Z", "finished_at": "2026-10-10T12:00:01Z", "results": results})


def transition(envelope, identifier="peer-denied"):
    return next(row for row in envelope["transitions"] if row["case_id"] == identifier)


def rehash(envelope):
    body = {key: value for key, value in envelope.items() if key != "comparison_sha256"}
    raw = json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()
    envelope["comparison_sha256"] = hashlib.sha256(b"AuthzLedger:comparison-envelope:v1\n" + raw).hexdigest()
    return envelope


@contextlib.contextmanager
def fixture_service():
    state = {"leak": True, "requests": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            actor = self.headers.get("Authorization")
            state["requests"].append((actor, self.path))
            if actor == "Bearer owner" and self.path in {"/owner", "/outside"}:
                status, payload = 200, {"owner": "owner"}
            elif actor == "Bearer peer" and self.path == "/peer":
                status, payload = 200, {"owner": "peer"}
            else:
                status, payload = 403, {"owner": "owner"} if state["leak"] else {"error": "denied"}
            raw = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.source = contract()
        self.selection = retest_plan(self.source, ["peer-denied"])
        self.before = report(self.source, leak=True)
        self.after = report(self.selection["contract"], version="1.0.5")

    def envelope(self):
        return create_comparison(self.source, self.before, self.after, ["peer-denied"])

    def test_partial_comparison_preserves_originals_and_marks_unselected(self):
        originals = copy.deepcopy((self.source, self.before, self.after))
        envelope = self.envelope()
        self.assertEqual(verify_comparison(envelope), [])
        self.assertEqual((self.source, self.before, self.after), originals)
        self.assertEqual(envelope["baseline_report"], self.before)
        self.assertEqual(envelope["current_report"], self.after)
        self.assertEqual(envelope["dependency_ids"], ["owner-control", "peer-control"])
        self.assertEqual(envelope["coverage"], {"source_cases": 4, "selected_cases": 1,
                         "dependency_cases": 2, "retested_cases": 3, "not_retested_cases": 1})
        self.assertEqual(transition(envelope)["status"], "resolved_check")
        self.assertEqual(transition(envelope, "outside")["status"], "not_retested")
        self.assertIsNone(transition(envelope, "outside")["after"])
        self.assertNotEqual(envelope["bindings"]["source_contract_sha256"], envelope["bindings"]["retest_contract_sha256"])
        with self.assertRaises(ValueError):
            compare_reports(self.before, self.after)

    def test_full_comparison_across_explicit_profiles_without_reseal(self):
        current = report(self.source, version="1.0.5")
        root = current["evidence"]["root_sha256"]
        envelope = create_comparison(self.source, self.before, current)
        self.assertEqual(envelope["coverage"]["not_retested_cases"], 0)
        self.assertEqual(envelope["bindings"]["current_root_sha256"], root)
        self.assertEqual(envelope["profiles"]["baseline"], "authzledger-1.0.0-report-v1-checks-v1")
        self.assertEqual(current["tool"]["version"], "1.0.5")
        with self.assertRaises(ValueError):
            compare_reports(self.before, current)

    def test_deterministic_selection_normalization(self):
        current = report(self.source)
        first = create_comparison(self.source, self.before, current, ["outside", "peer-denied"])
        second = create_comparison(self.source, self.before, current, ["peer-denied", "outside"])
        self.assertEqual(first, second)
        self.assertEqual(verify_comparison(json.loads(json.dumps(first))), [])

    def test_case_transitions_distinguish_errors_and_assertions(self):
        pairs = [("pass", "fail", "regression"), ("fail", "pass", "resolved_check"),
                 ("error", "pass", "testability_restored"), ("pass", "error", "testability_lost"),
                 ("fail", "error", "testability_lost"), ("error", "fail", "inconclusive"),
                 ("error", "error", "inconclusive"), ("inconclusive", "pass", "inconclusive"),
                 ("pass", "pass", "unchanged"), ("fail", "fail", "unchanged")]
        values = {"pass": (403, {"error": "denied"}), "fail": (403, {"owner": "owner"}),
                  "error": "error", "inconclusive": "inconclusive"}
        for old, new, expected in pairs:
            with self.subTest(old=old, new=new):
                before = report(self.source, overrides={"peer-denied": values[old]})
                after = report(self.source, overrides={"peer-denied": values[new]})
                envelope = create_comparison(self.source, before, after)
                self.assertEqual(transition(envelope)["status"], expected)
                self.assertEqual(verify_comparison(envelope), [])

    def test_failed_controls_never_resolve_skipped_case(self):
        for failed_side in ("baseline", "current"):
            failed = report(self.source, overrides={"owner-control": (401, {"error": "expired"})})
            baseline = failed if failed_side == "baseline" else self.before
            current = failed if failed_side == "current" else report(self.source)
            envelope = create_comparison(self.source, baseline, current)
            with self.subTest(side=failed_side):
                self.assertEqual(transition(envelope)["status"], "inconclusive")
                self.assertFalse(transition(envelope)["controls"][failed_side]["valid"])

    def test_status_only_and_unknown_controls_never_resolve(self):
        for expectation in ({"status": [200]}, {"status": [200, 403], "json": {"/owner": "owner"}}):
            source = copy.deepcopy(self.source)
            source["cases"][0]["expect"] = expectation
            source = load_contract(source)
            envelope = create_comparison(source, report(source, leak=True), report(source))
            with self.subTest(expectation=expectation):
                self.assertEqual(transition(envelope)["status"], "inconclusive")
                self.assertFalse(transition(envelope)["controls"]["current"]["valid"])

    def test_unanchored_negative_is_inconclusive(self):
        source = copy.deepcopy(self.source)
        source["cases"][2]["requires"] = []
        envelope = create_comparison(source, report(source, leak=True), report(source))
        self.assertEqual(transition(envelope)["status"], "inconclusive")
        self.assertIn("unanchored_negative_case", transition(envelope)["controls"]["current"]["reasons"])

    def test_transitive_unproven_control_blocks_resolution(self):
        source = copy.deepcopy(self.source)
        source["cases"][1]["requires"] = ["owner-control"]
        source["cases"][0]["expect"] = {"status": [200]}
        source["cases"][2]["requires"] = ["peer-control"]
        envelope = create_comparison(source, report(source, leak=True), report(source))
        self.assertEqual(transition(envelope)["status"], "inconclusive")
        self.assertIn("unproven_positive_control:owner-control", transition(envelope)["controls"]["baseline"]["reasons"])

    def test_exact_context_changes_are_rejected(self):
        for mutation in ("credential", "assertion", "request", "case_headers", "dependencies", "limits", "target", "order"):
            current_source = copy.deepcopy(self.selection["contract"])
            if mutation == "credential":
                current_source["identities"]["peer"]["headers"]["Authorization"]["env"] = "ADMIN_TOKEN"
            elif mutation == "assertion":
                current_source["cases"][2]["expect"]["json_absent"] = []
            elif mutation == "request":
                current_source["cases"][2]["path"] = "/another-owner"
            elif mutation == "case_headers":
                current_source["cases"][2]["headers"] = {"Accept": "application/json"}
            elif mutation == "dependencies":
                current_source["cases"][2]["requires"] = []
            elif mutation == "limits":
                current_source["limits"]["timeout_seconds"] = 2
            elif mutation == "target":
                current_source["target"] = "https://other.example.test"
            else:
                # Keep controls before their dependent for the fixture helper.
                current_source["cases"][0], current_source["cases"][1] = current_source["cases"][1], current_source["cases"][0]
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ComparisonError, "not comparable"):
                create_comparison(self.source, self.before, report(current_source), ["peer-denied"])

    def test_report_record_reorder_is_bound_and_joined_by_stable_id(self):
        current = copy.deepcopy(self.after)
        current["results"].reverse()
        with self.assertRaises(ComparisonError):
            create_comparison(self.source, self.before, current, ["peer-denied"])
        current = reseal(current)
        envelope = create_comparison(self.source, self.before, current, ["peer-denied"])
        self.assertEqual(transition(envelope)["status"], "resolved_check")
        self.assertEqual(envelope["current_report"]["results"][0]["id"], "peer-denied")
        self.assertEqual(verify_comparison(envelope), [])

    def test_current_must_match_exact_dependency_closed_selection(self):
        for selection in (None, ["owner-control"], ["peer-denied", "outside"]):
            with self.subTest(selection=selection), self.assertRaises(ComparisonError):
                create_comparison(self.source, self.before, self.after, selection)
        invalid = copy.deepcopy(self.after)
        invalid["results"] = [row for row in invalid["results"] if row["id"] != "owner-control"]
        for row in invalid["results"]:
            row["requires"] = []
        with self.assertRaises(ComparisonError):
            create_comparison(self.source, self.before, reseal(invalid), ["peer-denied"])

    def test_baseline_must_be_full_and_source_bound(self):
        with self.assertRaises(ComparisonError):
            create_comparison(self.source, self.after, self.after, ["peer-denied"])

    def test_unknown_tool_profiles_and_metadata_are_rejected(self):
        for tool in ({"name": "Other", "version": "1.0.0"}, {"name": "AuthzLedger", "version": "1.0.4"},
                     {"name": "AuthzLedger", "version": "1.1.0"}, {"name": "AuthzLedger", "version": "1.0.5-dev"},
                     {"name": "AuthzLedger", "version": "1.0.0", "build": "unregistered"}):
            current = copy.deepcopy(self.after)
            current["tool"] = tool
            with self.subTest(tool=tool), self.assertRaisesRegex(ComparisonError, "profile"):
                create_comparison(self.source, self.before, reseal(current), ["peer-denied"])

    def test_report_forged_assertion_layout_and_semantics_rejected_even_if_resealed(self):
        for mutation in ("layout", "status", "json_parse", "control_type", "identity", "missing_response"):
            current = copy.deepcopy(self.after)
            record = next(row for row in current["results"] if row["id"] == "peer-denied")
            if mutation == "layout":
                record["checks"].pop()
            elif mutation == "status":
                record["status"] = 200
            elif mutation == "json_parse":
                record["checks"][1]["passed"] = False
                record["outcome"] = "fail"
            elif mutation == "control_type":
                record["control_type"] = "positive"
            elif mutation == "identity":
                record["identity"] = "owner"
            else:
                record["response_sha256"] = None
            with self.subTest(mutation=mutation), self.assertRaises(ComparisonError):
                create_comparison(self.source, self.before, reseal(current), ["peer-denied"])

    def test_duplicate_ids_and_unsealed_tool_change_rejected(self):
        duplicate = copy.deepcopy(self.after)
        duplicate["results"][1]["id"] = duplicate["results"][0]["id"]
        altered_tool = copy.deepcopy(self.after)
        altered_tool["tool"]["version"] = "1.0.0"
        for invalid in (duplicate, altered_tool):
            with self.assertRaises(ComparisonError):
                create_comparison(self.source, self.before, invalid, ["peer-denied"])

    def test_rehashing_derived_claims_cannot_forge_verification(self):
        mutations = [lambda value: value["summary"].update(resolved_check=999),
                     lambda value: value["coverage"].update(not_retested_cases=0),
                     lambda value: transition(value, "outside").update(status="resolved_check"),
                     lambda value: value["bindings"].update(current_tool_sha256="0" * 64),
                     lambda value: value["profiles"].update(current="universal-1.x"),
                     lambda value: value["limitations"].clear(),
                     lambda value: value["policy"].update(status="remediated"),
                     lambda value: value.update(extra_claim="all safe")]
        for mutate in mutations:
            envelope = self.envelope()
            mutate(envelope)
            with self.subTest(mutation=mutate):
                self.assertTrue(verify_comparison(rehash(envelope)))

    def test_rehashing_altered_embedded_sources_cannot_hide_missing_binding(self):
        envelope = self.envelope()
        envelope["source_contract"]["identities"]["peer"]["headers"]["Authorization"]["env"] = "ADMIN_TOKEN"
        self.assertTrue(verify_comparison(rehash(envelope)))
        envelope = self.envelope()
        envelope["current_report"]["results"][0]["response_sha256"] = "f" * 64
        self.assertTrue(verify_comparison(rehash(envelope)))

    def test_malformed_verifier_inputs_fail_closed(self):
        for value in (None, [], {}, {"schema_version": True, "kind": "comparison-envelope"},
                      {"schema_version": 1, "kind": "comparison-envelope"}):
            with self.subTest(value=value):
                self.assertTrue(verify_comparison(value))
        for selection in (None, [], ["missing"], ["peer-denied", "peer-denied"], "peer-denied"):
            envelope = self.envelope()
            envelope["selected_ids"] = selection
            with self.subTest(selection=selection):
                self.assertTrue(verify_comparison(envelope))
        invalid = self.envelope()
        invalid["comparison_sha256"] = float("nan")
        self.assertTrue(verify_comparison(invalid))

    def test_no_network_environment_file_or_policy_io(self):
        with patch("socket.create_connection", side_effect=AssertionError("network I/O")), \
                patch("authzledger.engine._credentials", side_effect=AssertionError("credential I/O")), \
                patch("authzledger.policy.evaluate_policy", side_effect=AssertionError("policy I/O")), \
                patch("builtins.open", side_effect=AssertionError("file I/O")):
            envelope = self.envelope()
            self.assertEqual(verify_comparison(envelope), [])
        with self.assertRaises(ComparisonError):
            create_comparison("/tmp/source.json", self.before, self.after)

    def test_credential_policy_and_time_limits_are_explicit(self):
        envelope = self.envelope()
        self.assertEqual(envelope["bindings"]["runtime_credentials"], "not-attested")
        self.assertEqual(envelope["policy"]["status"], "not_compared")
        text = " ".join(envelope["limitations"])
        self.assertIn("resolved credential values", text)
        self.assertIn("not a trusted ordering", text)
        self.assertIn("does not establish vulnerability remediation", text)

    def test_real_loopback_403_leak_to_scoped_check_recovery(self):
        with fixture_service() as (target, state), patch.dict(os.environ, {
                "COMPARISON_OWNER": "Bearer owner", "COMPARISON_PEER": "Bearer peer"}):
            source = contract(target)
            baseline = engine.run(source)
            self.assertEqual(baseline["summary"]["fail"], 1)
            state["leak"] = False
            state["requests"].clear()
            current = engine.run(retest_plan(source, ["peer-denied"])["contract"])
            self.assertEqual(len(state["requests"]), 3)
            self.assertFalse(any(path == "/outside" for _, path in state["requests"]))
            envelope = create_comparison(source, baseline, current, ["peer-denied"])
        row = transition(envelope)
        self.assertEqual((row["before"]["status"], row["after"]["status"]), (403, 403))
        self.assertEqual(row["before"]["assessment"], "unsafe-denial")
        self.assertEqual(row["status"], "resolved_check")
        self.assertEqual(transition(envelope, "outside")["status"], "not_retested")
        self.assertEqual(verify_comparison(envelope), [])


if __name__ == "__main__":
    unittest.main()
