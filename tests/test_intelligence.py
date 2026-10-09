import copy
import hashlib
import json
import unittest

from authzledger.engine import _checks, _record
from authzledger.evidence import seal_report
from authzledger.intelligence import IntelligenceError, build_graph, differential_graphs, verify_graph
from authzledger.model import contract_digest, load_contract
from authzledger.policy import evaluate_policy


def contract(statuses=None, absent=True):
    return load_contract({"version": 1, "name": "Graph fixture", "target": "https://api.example.test",
                          "identities": {"owner": {"headers": {}}, "peer": {"headers": {}}},
                          "cases": [{"id": "positive", "identity": "owner", "method": "GET", "path": "/records/1",
                                     "expect": {"status": [200], "json": {"/owner": "owner"}}},
                                    {"id": "negative", "identity": "peer", "method": "GET", "path": "/records/1", "requires": ["positive"],
                                     "expect": {"status": statuses or [403, 404], **({"json_absent": ["/owner"]} if absent else {})}}]})


def report(spec, actual_status=403, actual_payload=None):
    results = []
    for case in spec["cases"]:
        status, payload = ((200, {"owner": "owner"}) if case["id"] == "positive"
                           else (actual_status, {"error": "denied"} if actual_payload is None else actual_payload))
        raw = json.dumps(payload).encode()
        checks, reason = _checks(case, status, raw)
        record = _record(case, "pass" if all(check["passed"] for check in checks) else "fail", reason)
        record.update(status=status, checks=checks, response_sha256=hashlib.sha256(raw).hexdigest())
        results.append(record)
    summary = {outcome: sum(item["outcome"] == outcome for item in results) for outcome in ("pass", "fail", "error", "inconclusive")}
    return seal_report({"schema_version": 1, "tool": {"name": "AuthzLedger", "version": "1.0.0"},
                        "name": spec["name"], "target": spec["target"], "contract_sha256": contract_digest(spec),
                        "started_at": "2026-10-09T00:00:00Z", "finished_at": "2026-10-09T00:00:01Z",
                        "summary": {**summary, "total": len(results)}, "results": results})


def policy(effect="deny"):
    return {"schema_version": 1, "engine": "local", "rules": [
        {"id": "owner", "effect": "allow", "identities": ["owner"]},
        {"id": "peer", "effect": effect, "identities": ["peer"]}]}


def edge(graph, case_id="negative"):
    return next(item for item in graph["edges"] if item["case_id"] == case_id)


def reseal_graph(graph):
    graph["graph_sha256"] = contract_digest({key: value for key, value in graph.items() if key != "graph_sha256"})
    return graph


class IntelligenceTests(unittest.TestCase):
    def test_three_layers_independent_unobserved_and_stable(self):
        spec = contract()
        graph = build_graph(spec)
        negative = edge(graph)
        self.assertEqual(negative["intended"]["decision"], "deny")
        self.assertEqual(negative["policy"]["decision"], "unknown")
        self.assertEqual(negative["observed"]["decision"], "unknown")
        self.assertEqual(negative["controls"]["positive"], ["positive"])
        self.assertEqual(graph["coverage"]["unobserved"], 2)
        reordered = copy.deepcopy(spec)
        reordered["cases"].reverse()
        self.assertEqual([item["id"] for item in graph["edges"]], [item["id"] for item in build_graph(reordered)["edges"]])
        self.assertEqual(verify_graph(graph, spec), [])

    def test_status_expectation_mixed_is_unknown_never_observed_inferred(self):
        spec = contract([200, 403])
        graph = build_graph(spec, report(spec, 403))
        self.assertEqual(edge(graph)["intended"]["decision"], "unknown")
        self.assertEqual(edge(graph)["observed"]["decision"], "deny")

    def test_verified_evidence_policy_binding_and_explicit_drift(self):
        spec = contract()
        proof = report(spec)
        graph = build_graph(spec, proof, policy("allow"))
        negative = edge(graph)
        self.assertEqual(negative["policy"]["decision"], "allow")
        self.assertEqual(negative["observed"]["decision"], "deny")
        self.assertEqual(negative["findings"][0]["type"], "policy-intent-drift")
        self.assertEqual(negative["evidence"]["report_root_sha256"], proof["evidence"]["root_sha256"])
        self.assertEqual(verify_graph(graph, spec, proof), [])
        self.assertNotIn("/owner", json.dumps(graph["intended"] if "intended" in graph else negative["intended"]))

    def test_denial_body_leak_is_unsafe_denial_not_safe_deny(self):
        spec = contract()
        graph = build_graph(spec, report(spec, 403, {"owner": "owner"}))
        negative = edge(graph)
        self.assertEqual(negative["observed"]["decision"], "deny")
        self.assertEqual(negative["observed"]["assessment"], "unsafe-denial")
        self.assertEqual(negative["observed"]["outcome"], "fail")
        self.assertIn("denial-body-leak", [finding["type"] for finding in negative["findings"]])

    def test_500_and_200_login_body_never_establish_access_or_escalation(self):
        spec = contract()
        before = build_graph(spec, report(spec))
        for status in (500, 200):
            after = build_graph(spec, report(spec, status, {"error": "login_required"}))
            with self.subTest(status=status):
                self.assertEqual(edge(after)["observed"]["decision"], "unknown")
                self.assertEqual(differential_graphs(before, after)["privilege_escalations"], [])
                self.assertNotIn("unexpected-access", [item["type"] for item in after["findings"]])

    def test_2xx_protected_field_signal_and_retest_resolution(self):
        spec = contract()
        before = build_graph(spec, report(spec, 200, {"owner": "owner"}), policy())
        after = build_graph(spec, report(spec), policy())
        self.assertEqual(edge(before)["observed"]["decision"], "allow")
        self.assertIn("unexpected-access", [item["type"] for item in before["findings"]])
        diff = differential_graphs(before, after)
        self.assertEqual([item["case_id"] for item in diff["resolved"]], ["negative"])
        reverse = differential_graphs(after, before)
        self.assertEqual([item["case_id"] for item in reverse["privilege_escalations"]], ["negative"])
        self.assertEqual([item["case_id"] for item in reverse["regressions"]], ["negative"])

    def test_altered_contract_or_policy_never_becomes_misleading_fix(self):
        spec = contract()
        before = build_graph(spec, report(spec, 200, {"owner": "owner"}), policy())
        changed = contract([200], absent=False)
        after = build_graph(changed, report(changed, 200, {"owner": "owner"}), policy())
        diff = differential_graphs(before, after)
        self.assertEqual(diff["resolved"], [])
        self.assertEqual([item["case_id"] for item in diff["intended_drift"]], ["negative"])
        after = build_graph(spec, report(spec), policy("allow"))
        diff = differential_graphs(before, after)
        self.assertEqual(diff["resolved"], [])
        self.assertEqual([item["case_id"] for item in diff["policy_drift"]], ["negative", "positive"])

    def test_resealed_reports_cannot_claim_wrong_scope_or_checks(self):
        spec = contract()
        mutations = [lambda value: value.update(contract_sha256="0" * 64),
                     lambda value: value.update(target="https://other.test"),
                     lambda value: value["results"][1].update(identity="owner"),
                     lambda value: value["results"][1].update(path="/different"),
                     lambda value: value["results"][1].update(control_type="positive"),
                     lambda value: value["results"][1].update(requires=[]),
                     lambda value: value["results"][1]["checks"].pop(),
                     lambda value: value["results"][1]["checks"][0].update(passed=False)]
        for mutate in mutations:
            value = report(spec)
            mutate(value)
            if value["results"][1]["checks"] and not all(check["passed"] for check in value["results"][1]["checks"]):
                value["results"][1]["outcome"] = "fail"
                value["summary"].update(pass_=0)
                value["summary"] = {"pass": 1, "fail": 1, "error": 0, "inconclusive": 0, "total": 2}
            with self.subTest(mutation=mutate), self.assertRaises(IntelligenceError):
                build_graph(spec, seal_report(value))

    def test_policy_evaluation_rejects_stale_contract_target_case_set_and_provenance(self):
        spec = contract()
        for field in ("contract_sha256", "target", "decisions", "provenance", "engine", "input_sha256"):
            evaluation = evaluate_policy(spec, policy())
            if field == "contract_sha256":
                evaluation[field] = "0" * 64
            elif field == "target":
                evaluation[field] = "https://other.test"
            elif field == "decisions":
                del evaluation[field]["negative"]
            elif field == "provenance":
                evaluation["decisions"]["negative"]["provenance"]["policy_sha256"] = "0" * 64
            elif field == "engine":
                evaluation["engine"] = "opa"
            else:
                evaluation["decisions"]["negative"]["input_sha256"] = "invalid"
            with self.subTest(field=field), self.assertRaises(IntelligenceError):
                build_graph(spec, policy=evaluation)

    def test_graph_tamper_hash_and_resealed_false_findings_rejected(self):
        spec = contract()
        graph = build_graph(spec, report(spec), policy())
        changed = copy.deepcopy(graph)
        edge(changed)["observed"]["decision"] = "allow"
        self.assertTrue(verify_graph(changed))
        self.assertTrue(verify_graph(reseal_graph(changed)))
        changed = copy.deepcopy(graph)
        changed["findings"].append({"type": "fake"})
        self.assertTrue(verify_graph(reseal_graph(changed)))
        changed = copy.deepcopy(graph)
        edge(changed)["intended"]["checks_sha256"] = "0" * 64
        self.assertTrue(verify_graph(reseal_graph(changed), spec, report(spec)))
        changed = copy.deepcopy(graph)
        changed["policy_sha256"] = "invalid-digest"
        for access in changed["edges"]:
            access["policy"]["provenance"]["policy_sha256"] = "invalid-digest"
        self.assertTrue(verify_graph(reseal_graph(changed)))

    def test_added_removed_scope_and_different_target(self):
        spec = contract()
        before = build_graph(spec)
        altered = copy.deepcopy(spec)
        altered["cases"][1]["path"] = "/records/2"
        after = build_graph(altered)
        diff = differential_graphs(before, after)
        self.assertEqual(len(diff["added"]), 1)
        self.assertEqual(len(diff["removed"]), 1)
        self.assertEqual(len(diff["coverage_changes"]), 2)
        altered["target"] = "https://other.test"
        with self.assertRaises(IntelligenceError):
            differential_graphs(before, build_graph(altered))

    def test_status_only_positive_and_missing_observation_never_content_proof(self):
        spec = contract()
        del spec["cases"][0]["expect"]["json"]
        spec = load_contract(spec)
        graph = build_graph(spec, report(spec))
        self.assertEqual(edge(graph, "positive")["observed"]["decision"], "unknown")
        self.assertEqual(edge(graph, "positive")["observed"]["outcome"], "pass")
        self.assertEqual(verify_graph(graph, spec, report(spec)), [])
        diff = differential_graphs(graph, build_graph(spec))
        self.assertEqual(diff["resolved"], [])
        self.assertEqual(len(diff["inconclusive"]), 2)

    def test_changed_identity_or_weakened_prerequisite_never_resolves(self):
        spec = contract()
        spec["identities"]["peer"]["headers"] = {"Authorization": {"env": "PEER_TOKEN"}}
        spec = load_contract(spec)
        before = build_graph(spec, report(spec, 200, {"owner": "owner"}), policy())
        for change in ("identity", "prerequisite"):
            changed = copy.deepcopy(spec)
            if change == "identity":
                changed["identities"]["peer"]["headers"]["Authorization"]["env"] = "ADMIN_TOKEN"
            else:
                del changed["cases"][0]["expect"]["json"]
            changed = load_contract(changed)
            after = build_graph(changed, report(changed), policy())
            diff = differential_graphs(before, after)
            with self.subTest(change=change):
                self.assertEqual(diff["resolved"], [])
                self.assertEqual(diff["regressions"], [])
                self.assertEqual({item["case_id"] for item in diff["context_drift"]}, {"positive", "negative"})

    def test_graph_only_verification_rejects_resealed_dependency_contradictions(self):
        spec = contract()
        original = build_graph(spec, report(spec), policy())
        for mutation in ("failed-control", "undefined-control", "cycle", "false-control-label"):
            graph = copy.deepcopy(original)
            if mutation == "failed-control":
                positive = edge(graph, "positive")
                positive["observed"].update(outcome="fail", decision="unknown", assessment="rejected-control",
                                            content_evidence="not-established")
                positive["observed"]["checks"][-1]["passed"] = False
                from authzledger.intelligence import _findings, _coverage
                positive["findings"] = _findings(positive)
                graph["findings"] = [item for access in graph["edges"] for item in access["findings"]]
                graph["coverage"] = _coverage(graph["edges"])
            elif mutation == "undefined-control":
                edge(graph)["requires"] = ["does-not-exist"]
            elif mutation == "cycle":
                edge(graph, "positive")["requires"] = ["negative"]
                edge(graph, "positive")["controls"].update(negative=["negative"])
            else:
                edge(graph)["controls"]["positive"] = []
            with self.subTest(mutation=mutation):
                self.assertTrue(verify_graph(reseal_graph(graph)))

    def test_legacy_error_without_status_stays_unknown_without_raw_exception(self):
        spec = contract()
        value = report(spec)
        negative = value["results"][1]
        negative.update(outcome="error", checks=[], reason="Request failed.")
        del negative["status"]
        del negative["response_sha256"]
        value["summary"] = {"pass": 1, "fail": 0, "error": 1, "inconclusive": 0, "total": 2}
        value = seal_report(value)
        graph = build_graph(spec, value)
        self.assertEqual(edge(graph)["observed"]["decision"], "unknown")
        self.assertEqual(edge(graph)["observed"]["assessment"], "execution-error")
        self.assertEqual(verify_graph(graph, spec, value), [])


if __name__ == "__main__":
    unittest.main()
