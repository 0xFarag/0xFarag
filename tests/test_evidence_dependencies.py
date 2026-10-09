"""Reject internally hashed evidence that contradicts declared prerequisites."""

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from authzledger.cli import main
from authzledger.evidence import _seal, seal_report, verify_report
from test_evidence import report_for


class DependencyEvidenceTests(unittest.TestCase):
    def assert_rejected_even_if_rehashed(self, report, message):
        with self.assertRaisesRegex(ValueError, message):
            seal_report(report)
        # Model a writer that can recompute hashes but cannot make contradictory
        # prerequisite semantics acceptable to the independent verifier.
        report["evidence"] = _seal(report)
        self.assertTrue(any(message in error for error in verify_report(report)))

    def test_legacy_reports_without_prerequisite_fields_remain_valid(self):
        report = report_for()
        frozen = copy.deepcopy(report)
        self.assertEqual(verify_report(seal_report(report)), [])
        self.assertEqual(report, frozen)

    def test_passed_controls_allow_conclusive_dependents_in_any_record_order(self):
        report = report_for({"denial": "pass", "resource-control": "pass", "actor-control": "pass"})
        report["results"][0]["requires"] = ["actor-control", "resource-control"]
        self.assertEqual(verify_report(seal_report(report)), [])
        report["results"].reverse()
        self.assertEqual(verify_report(seal_report(report)), [])

    def test_unsuccessful_control_blocks_assessed_dependent_outcomes(self):
        for control_outcome in ("fail", "error", "inconclusive"):
            for dependent_outcome in ("pass", "fail", "error"):
                with self.subTest(control=control_outcome, dependent=dependent_outcome):
                    report = report_for({"control": control_outcome, "denial": dependent_outcome})
                    report["results"][1]["requires"] = ["control"]
                    self.assert_rejected_even_if_rehashed(report, "request assessed after a prerequisite did not pass")

    def test_unsuccessful_controls_allow_transitively_inconclusive_dependents(self):
        report = report_for({"control": "fail", "intermediate": "inconclusive", "denial": "inconclusive"})
        report["results"][1]["requires"] = ["control"]
        report["results"][2]["requires"] = ["intermediate"]
        self.assertEqual(verify_report(seal_report(report)), [])

    def test_duplicate_and_undefined_references_are_rejected(self):
        for requires, message in ((["missing"], "undefined prerequisite"),
                                  (["control", "control"], "duplicate prerequisite")):
            with self.subTest(requires=requires):
                report = report_for({"control": "pass", "denial": "pass"})
                report["results"][1]["requires"] = requires
                self.assert_rejected_even_if_rehashed(report, message)

    def test_self_dependency_and_multi_case_cycle_are_rejected(self):
        report = report_for({"control": "pass", "denial": "pass"})
        report["results"][0]["requires"] = ["control"]
        self.assert_rejected_even_if_rehashed(report, "dependency cycle")
        report["results"][0]["requires"] = ["denial"]
        report["results"][1]["requires"] = ["control"]
        self.assert_rejected_even_if_rehashed(report, "dependency cycle")

    def test_long_dependency_chain_is_checked_without_recursion(self):
        report = report_for({f"case-{index}": "pass" for index in range(1200)})
        for index, result in enumerate(report["results"]):
            result["requires"] = [f"case-{index - 1}"] if index else []
        report["results"].reverse()
        self.assertEqual(verify_report(seal_report(report)), [])
        report["results"][-1]["requires"] = ["case-1199"]
        self.assert_rejected_even_if_rehashed(report, "dependency cycle")

    def test_cli_malformed_evidence_and_anchor_returns_controlled_failure(self):
        for evidence in (None, [], "invalid", 42, {}):
            with self.subTest(evidence=evidence), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "report.json"
                report = report_for()
                report["evidence"] = evidence
                path.write_text(json.dumps(report), encoding="utf-8")
                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    self.assertEqual(main(["verify", str(path), "--anchor", "a" * 64]), 2)
                self.assertIn("Integrity check FAILED", stderr.getvalue())
                self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
