"""Integrity boundaries and semantic comparisons, including dishonest edits."""

import copy
import json
import unittest

from authzledger.evidence import compare_reports, seal_report, verify_report


def report_for(outcomes=None):
    outcomes = outcomes if outcomes is not None else {"owner": "pass", "other-user": "fail"}
    results = [
        {
            "id": case_id, "identity": "owner", "method": "GET", "path": "/invoices/1",
            "outcome": outcome, "status": None if outcome == "inconclusive" else 200,
            "duration_ms": 1.125,
            "checks": [{"type": "status", "passed": outcome == "pass"}] if outcome in ("pass", "fail") else [],
            "reason": "Configured result.", "response_sha256": "b" * 64,
        }
        for case_id, outcome in outcomes.items()
    ]
    return {
        "schema_version": 1, "tool": {"name": "AuthzLedger", "version": "0.1.0"},
        "name": "Invoice authorization", "target": "http://127.0.0.1:8765",
        "contract_sha256": "a" * 64, "started_at": "2026-10-08T00:00:00Z",
        "finished_at": "2026-10-08T00:00:01Z",
        "summary": {**{outcome: sum(r["outcome"] == outcome for r in results)
                        for outcome in ("pass", "fail", "error", "inconclusive")},
                    "total": len(results)},
        "results": results,
    }


class EvidenceTests(unittest.TestCase):
    def test_roundtrip_and_no_input_mutation(self):
        original = report_for()
        frozen = copy.deepcopy(original)
        sealed = seal_report(original)
        self.assertEqual(original, frozen)
        self.assertNotIn("evidence", original)
        self.assertEqual(verify_report(json.loads(json.dumps(sealed))), [])
        sealed["results"][0]["checks"][0]["passed"] = False
        self.assertEqual(original, frozen)

    def test_canonical_mapping_order_does_not_change_root(self):
        source = report_for()
        shuffled = dict(reversed(list(source.items())))
        shuffled["results"] = [dict(reversed(list(item.items()))) for item in source["results"]]
        self.assertEqual(seal_report(source)["evidence"], seal_report(shuffled)["evidence"])

    def test_metadata_fields_and_unknown_metadata_are_bound(self):
        for key, value in (
            ("name", "Changed title"), ("target", "http://127.0.0.1:9999"),
            ("contract_sha256", "c" * 64), ("started_at", "2026-10-09T00:00:00Z"),
            ("finished_at", "2026-10-09T00:00:01Z"),
            ("tool", {"name": "Different", "version": "0.2.0"}),
            ("unexpected_metadata", "replacement"),
        ):
            with self.subTest(key=key):
                report = seal_report(report_for())
                report[key] = value
                self.assertIn("metadata hash mismatch", verify_report(report))

    def test_result_fields_cannot_be_changed_under_existing_seal(self):
        changes = {
            "id": "different-case", "identity": "admin", "method": "POST", "path": "/other",
            "status": 403, "duration_ms": 4.1, "reason": "Falsified claim",
            "checks": [{"type": "json", "passed": True}], "response_sha256": "c" * 64,
            "requires": ["new-prerequisite"], "control_type": "negative",
        }
        for key, value in changes.items():
            with self.subTest(key=key):
                report = seal_report(report_for())
                report["results"][0][key] = value
                self.assertIn("evidence record 1 mismatch", verify_report(report))

    def test_falsified_outcome_and_consistent_summary_still_fail(self):
        report = seal_report(report_for())
        report["results"][1]["outcome"] = "pass"
        report["results"][1]["checks"][0]["passed"] = True
        report["summary"]["pass"] += 1
        report["summary"]["fail"] -= 1
        self.assertIn("metadata hash mismatch", verify_report(report))
        self.assertIn("evidence record 2 mismatch", verify_report(report))

    def test_summary_must_match_actual_results(self):
        report = seal_report(report_for())
        report["summary"]["pass"] = 999
        self.assertIn("summary does not match case outcomes", verify_report(report))
        with self.assertRaises(ValueError):
            seal_report(report)

    def test_case_removal_with_adjusted_summary_is_detected(self):
        report = seal_report(report_for())
        report["results"].pop()
        report["summary"].update({"fail": 0, "total": 1})
        self.assertIn("evidence record count mismatch", verify_report(report))

    def test_removing_result_and_corresponding_chain_record_is_detected(self):
        report = seal_report(report_for())
        report["results"].pop()
        report["evidence"]["records"].pop()
        report["summary"].update({"fail": 0, "total": 1})
        self.assertTrue(verify_report(report))

    def test_result_order_is_bound(self):
        report = seal_report(report_for())
        report["results"].reverse()
        self.assertIn("evidence record 1 mismatch", verify_report(report))

    def test_evidence_order_is_bound(self):
        report = seal_report(report_for())
        report["evidence"]["records"].reverse()
        self.assertIn("evidence record 1 mismatch", verify_report(report))

    def test_algorithm_root_and_evidence_shape_are_checked(self):
        changes = {"algorithm": "md5", "version": True, "root_sha256": "0" * 64,
                   "metadata_sha256": "0" * 64, "records": [], "unknown": "extra"}
        for key, value in changes.items():
            with self.subTest(key=key):
                report = seal_report(report_for())
                report["evidence"][key] = value
                self.assertTrue(verify_report(report))

    def test_missing_evidence_and_malformed_top_level_fail_cleanly(self):
        self.assertTrue(verify_report(report_for()))
        for value in (None, [], "report", {}, {"schema_version": 1, "results": None}):
            with self.subTest(value=value):
                self.assertTrue(verify_report(value))

    def test_non_finite_numbers_and_duplicate_ids_are_rejected(self):
        for invalid in (float("nan"), float("inf"), -1, True):
            report = report_for()
            report["results"][0]["duration_ms"] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                seal_report(report)
        report = report_for()
        report["results"][1]["id"] = report["results"][0]["id"]
        with self.assertRaisesRegex(ValueError, "duplicate stable ID"):
            seal_report(report)

    def test_outcome_assertion_invariants_cannot_be_resealed(self):
        for outcome, checks, expected_error in (
            ("pass", [], "pass requires nonempty, successful checks"),
            ("pass", [{"type": "status", "passed": False}], "pass requires nonempty, successful checks"),
            ("fail", [], "fail requires at least one failed check"),
            ("fail", [{"type": "status", "passed": True}], "fail requires at least one failed check"),
            ("error", [{"type": "status", "passed": True}], "error must not contain assertion results"),
            ("inconclusive", [{"type": "status", "passed": False}], "inconclusive must not contain assertion results"),
        ):
            with self.subTest(outcome=outcome, checks=checks):
                report = seal_report(report_for({"owner": outcome}))
                report["results"][0]["checks"] = checks
                self.assertTrue(any(expected_error in error for error in verify_report(report)))
                with self.assertRaisesRegex(ValueError, expected_error):
                    seal_report(report)

    def test_assessed_outcomes_require_an_http_status(self):
        for outcome in ("pass", "fail"):
            with self.subTest(outcome=outcome):
                report = report_for({"owner": outcome})
                report["results"][0]["status"] = None
                with self.assertRaisesRegex(ValueError, "requires an HTTP status"):
                    seal_report(report)

    def test_empty_report_still_binds_metadata(self):
        report = seal_report(report_for({}))
        self.assertEqual(verify_report(report), [])
        self.assertEqual(report["evidence"]["root_sha256"], report["evidence"]["metadata_sha256"])
        report["name"] = "Changed"
        self.assertTrue(verify_report(report))

    def test_resealing_is_possible_and_changes_external_anchor(self):
        report = seal_report(report_for())
        anchor = report["evidence"]["root_sha256"]
        report["target"] = "http://127.0.0.1:9999"
        altered = seal_report(report)
        # Local consistency alone cannot authenticate the origin of this report.
        self.assertEqual(verify_report(altered), [])
        self.assertNotEqual(altered["evidence"]["root_sha256"], anchor)


class ComparisonTests(unittest.TestCase):
    def test_all_meaningful_transitions(self):
        baseline = seal_report(report_for({
            "regress-fail": "pass", "regress-error": "pass", "resolved-fail": "fail",
            "resolved-error": "error", "still-pass": "pass", "still-fail": "fail",
            "failure-to-error": "fail", "not-resolved": "inconclusive",
            "lost-confidence": "pass",
        }))
        current = seal_report(report_for({
            "regress-fail": "fail", "regress-error": "error", "resolved-fail": "pass",
            "resolved-error": "pass", "still-pass": "pass", "still-fail": "fail",
            "failure-to-error": "error", "not-resolved": "pass",
            "lost-confidence": "inconclusive",
        }))
        diff = compare_reports(baseline, current)
        self.assertEqual(diff["regressions"], ["regress-error", "regress-fail"])
        self.assertEqual(diff["resolved"], ["resolved-error", "resolved-fail"])
        self.assertEqual(diff["unchanged"], ["failure-to-error", "still-fail", "still-pass"])
        self.assertEqual(diff["inconclusive"], ["lost-confidence", "not-resolved"])
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(diff["summary"]["regressions"], 2)
        self.assertEqual(len(diff["transitions"]), 9)

    def test_stable_ids_ignore_case_order(self):
        source = report_for({"z-case": "pass", "a-case": "pass"})
        reversed_source = copy.deepcopy(source)
        reversed_source["results"].reverse()
        diff = compare_reports(seal_report(source), seal_report(reversed_source))
        self.assertEqual(diff["unchanged"], ["a-case", "z-case"])
        self.assertEqual(diff["regressions"], [])

    def test_same_contract_is_required(self):
        source = report_for()
        changed = copy.deepcopy(source)
        changed["contract_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "different contract digests"):
            compare_reports(seal_report(source), seal_report(changed))

    def test_resealed_contradictory_report_metadata_is_refused(self):
        baseline = seal_report(report_for())
        for field, value in (
            ("target", "http://127.0.0.1:9999"), ("name", "Different contract name"),
            ("tool", {"name": "AuthzLedger", "version": "0.2.0"}),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(baseline)
                changed[field] = value
                resealed = seal_report(changed)
                self.assertEqual(verify_report(resealed), [])
                with self.assertRaisesRegex(ValueError, "different " + field):
                    compare_reports(baseline, resealed)

    def test_resealed_changed_case_structure_is_refused(self):
        baseline = seal_report(report_for())
        for field, value in (
            ("identity", "different-identity"), ("method", "POST"), ("path", "/changed"),
            ("requires", ["other-user"]), ("control_type", "negative"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(baseline)
                changed["results"][0][field] = value
                with self.assertRaisesRegex(ValueError, "contradictory"):
                    compare_reports(baseline, seal_report(changed))

    def test_added_removed_and_renamed_ids_contradict_same_contract(self):
        baseline = seal_report(report_for({"owner": "pass", "other-user": "fail"}))
        for case_outcomes in (
            {"owner": "pass"},
            {"owner": "pass", "other-user": "fail", "new-case": "pass"},
            {"owner": "pass", "renamed-case": "fail"},
        ):
            with self.subTest(case_outcomes=case_outcomes):
                changed = seal_report(report_for(case_outcomes))
                with self.assertRaisesRegex(ValueError, "contradictory case-ID sets"):
                    compare_reports(baseline, changed)

    def test_each_input_must_verify_before_comparison(self):
        good = seal_report(report_for())
        bad = copy.deepcopy(good)
        bad["name"] = "Tampered"
        with self.assertRaisesRegex(ValueError, "invalid baseline"):
            compare_reports(bad, good)
        with self.assertRaisesRegex(ValueError, "invalid current"):
            compare_reports(good, bad)


if __name__ == "__main__":
    unittest.main()
