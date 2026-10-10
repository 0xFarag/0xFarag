"""Retained-source selective retests use the same envelope service as the CLI."""
import copy
import io
import json
import shutil
import threading
import time
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import test_studio_v1 as fixtures
from authzledger.comparison import create_comparison, verify_comparison
from authzledger.signing import generate_keypair, verify_bundle


class StudioComparisonTests(unittest.TestCase):
    setUp = fixtures.StudioV1Tests.setUp
    tearDown = fixtures.StudioV1Tests.tearDown
    request = fixtures.StudioV1Tests.request
    start_server = fixtures.StudioV1Tests.start_server
    job = fixtures.StudioV1Tests.job

    def baseline(self):
        self.contract["cases"].append({"id": "unselected", "identity": "owner", "method": "GET",
            "path": "/other", "expect": {"status": [403], "json_absent": ["/id"]}, "requires": ["positive"]})
        return self.job()

    def preview(self, baseline):
        body = {"baseline_id": baseline["history"]["id"], "selected_ids": ["negative"]}
        code, preview = self.request("/api/retest/plan", body)
        self.assertEqual(code, 200, preview)
        execution = {**body, "selected_ids": preview["retest"]["selected_ids"],
            "contract": preview["retest"]["contract"], "review": preview["review"], "authorized": True}
        return preview, execution

    def wait_job(self, job):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            code, result = self.request("/api/jobs/" + job["id"])
            self.assertEqual(code, 200)
            if result["state"] != "running":
                self.assertEqual(result["state"], "complete", result)
                return result
            time.sleep(.01)
        self.fail("Selective retest exceeded local deadline")

    def test_preview_adds_controls_offline_and_exposes_source_anchors(self):
        baseline = self.baseline()
        self.hits.clear()
        with patch("authzledger.policy.evaluate_policy", side_effect=AssertionError("preflight must be offline")):
            preview, _ = self.preview(baseline)
        self.assertEqual(self.hits, [])
        self.assertEqual(preview["retest"]["dependency_ids"], ["positive"])
        self.assertEqual(preview["retest"]["not_retested_ids"], ["unselected"])
        self.assertEqual(preview["retest"]["source_contract_sha256"], baseline["report"]["contract_sha256"])
        self.assertEqual(preview["retest"]["baseline_root_sha256"], baseline["report"]["evidence"]["root_sha256"])
        self.assertEqual(preview["assurance"]["maximum_requests"], 2)
        self.assertEqual([item["id"] for item in preview["retest"]["contract"]["cases"]], ["positive", "negative"])

    def test_review_binds_baseline_selection_contract_policy_and_route(self):
        baseline = self.baseline()
        _, body = self.preview(baseline)
        other = self.job()
        self.hits.clear()
        variants = [dict(body, selected_ids=["positive"]), dict(body, baseline_id=other["history"]["id"]),
            dict(body, policy=self.policy), dict(body, assurance={"cycles": 2}), dict(body, authorized=False)]
        changed = copy.deepcopy(body)
        changed["contract"]["cases"][0]["path"] = "/altered"
        variants.append(changed)
        for value in variants:
            with self.subTest(value=value):
                self.assertEqual(self.request("/api/retest", value)[0], 400)
        self.assertEqual(self.request("/api/run", body)[0], 400)
        self.assertEqual(self.hits, [])

    def test_exact_subset_executes_and_omission_is_never_removed_or_resolved(self):
        baseline = self.baseline()
        original = copy.deepcopy(baseline["report"])
        _, body = self.preview(baseline)
        self.hits.clear()
        code, job = self.request("/api/retest", body)
        self.assertEqual(code, 200, job)
        result = self.wait_job(job)
        self.assertEqual(self.hits, ["/control", "/private"])
        envelope = result["comparison_envelope"]
        self.assertEqual(verify_comparison(envelope), [])
        self.assertEqual(envelope["baseline_report"], original)
        self.assertEqual(envelope["current_report"], result["report"])
        self.assertEqual(envelope["summary"]["not_retested"], 1)
        self.assertEqual(next(item for item in envelope["transitions"] if item["case_id"] == "unselected")["status"], "not_retested")
        self.assertIsNone(result["graph_comparison"])
        self.assertEqual(self.request("/api/retest", body)[0], 400, "Consumed review must not restart the job")

    def test_invalid_control_preserves_inconclusive_subset(self):
        baseline = self.baseline()
        _, body = self.preview(baseline)
        self.control_valid = False
        self.hits.clear()
        result = self.wait_job(self.request("/api/retest", body)[1])
        self.assertEqual(self.hits, ["/control"])
        self.assertEqual(result["report"]["summary"]["inconclusive"], 1)
        envelope = result["comparison_envelope"]
        transition = next(item for item in envelope["transitions"] if item["case_id"] == "negative")
        self.assertFalse(transition["controls"]["current"]["valid"])
        self.assertNotEqual(transition["status"], "resolved_check")
        self.assertEqual(envelope["summary"]["not_retested"], 1)

    def test_concurrent_requests_cannot_reuse_a_review_after_fast_dispatch(self):
        baseline = self.baseline()
        _, body = self.preview(baseline)
        self.hits.clear()
        both_validated = threading.Barrier(2)
        dispatches = []
        dispatch_lock = threading.Lock()

        def synchronized_preflight(*args, **kwargs):
            result = create_comparison(*args, **kwargs)
            # Both handlers have already read the same review. Neither can
            # dispatch until the other reaches its final source validation.
            both_validated.wait(timeout=5)
            return result

        def instant_job(*args, **kwargs):
            # Model a job that finishes before the second handler dispatches;
            # the active-job guard cannot provide single-use authorization.
            with dispatch_lock:
                dispatches.append(args)
            return {"id": "instant-job", "state": "running"}

        with patch("authzledger.comparison.create_comparison", side_effect=synchronized_preflight), \
                patch.object(self.server, "start_job", side_effect=instant_job):
            with ThreadPoolExecutor(max_workers=2) as pool:
                requests = [pool.submit(self.request, "/api/retest", body) for _ in range(2)]
                responses = [request.result(timeout=10) for request in requests]
        self.assertEqual(sorted(code for code, _ in responses), [200, 400], responses)
        self.assertEqual(len(dispatches), 1)
        self.assertEqual(self.request("/api/retest", body)[0], 400)
        self.assertEqual(self.hits, [])

    def test_offline_compare_verify_export_and_tamper_rejection(self):
        baseline = self.baseline()
        _, body = self.preview(baseline)
        result = self.wait_job(self.request("/api/retest", body)[1])
        self.hits.clear()
        input_value = {"source_contract": baseline["history"]["contract"], "baseline_report": baseline["report"],
            "current_report": result["report"], "selected_ids": ["negative"]}
        code, compared = self.request("/api/comparison", input_value)
        self.assertEqual(code, 200, compared)
        self.assertEqual(compared["comparison_envelope"], result["comparison_envelope"])
        self.assertEqual(self.request("/api/comparison/verify", compared)[0], 200)
        code, html = self.request("/api/export", {"kind": "comparison-envelope", **compared})
        self.assertEqual(code, 200)
        self.assertIn(b"not_retested", html)
        forged = copy.deepcopy(compared)
        forged["comparison_envelope"]["summary"]["not_retested"] = 0
        self.assertEqual(self.request("/api/comparison/verify", forged)[0], 400)
        self.assertEqual(self.request("/api/export", {"kind": "comparison-envelope", **forged})[0], 400)
        self.assertEqual(self.hits, [])

    def test_selective_proof_binds_comparison_and_readable_export(self):
        if not shutil.which("openssl"):
            self.skipTest("OpenSSL is required for Ed25519 signing")
        private, public = self.root / "private.pem", self.root / "public.pem"
        generate_keypair(private, public)
        self.start_server(signing_key=private, public_key=public)
        baseline = self.baseline()
        _, body = self.preview(baseline)
        result = self.wait_job(self.request("/api/retest", body)[1])
        proof_body = {"history_id": result["history"]["id"], "comparison_envelope": result["comparison_envelope"]}
        self.hits.clear()
        code, raw = self.request("/api/proof", proof_body)
        self.assertEqual(code, 200, raw)
        folder = self.root / "proof"
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            self.assertEqual(json.loads(archive.read("attachments/comparison.json")), result["comparison_envelope"])
            self.assertIn(b"not_retested", archive.read("attachments/comparison.html"))
            archive.extractall(folder)
        self.assertEqual(verify_bundle(folder, public), [])
        self.assertEqual(self.request("/api/proof", dict(proof_body, history_id=baseline["history"]["id"]))[0], 400)
        self.assertEqual(self.hits, [])

    def test_retest_previews_refuse_unknown_sources_and_unsupported_selection(self):
        baseline = self.baseline()
        self.hits.clear()
        for selected in ([], ["missing"], ["negative", "negative"], "negative"):
            self.assertEqual(self.request("/api/retest/plan", {"baseline_id": baseline["history"]["id"],
                "selected_ids": selected})[0], 400)
        self.assertEqual(self.request("/api/retest/plan", {"baseline_id": "0" * 32})[0], 400)
        self.assertEqual(self.request("/api/retest/plan", {"baseline_id": baseline["history"]["id"],
            "selected_ids": ["negative"], "assurance": {"cycles": 2}})[0], 400)
        self.assertEqual(self.request("/api/retest/plan", {"baseline_id": baseline["history"]["id"],
            "selected_ids": ["negative"], "contract": self.contract})[0], 400)
        self.assertEqual(self.hits, [])

    def test_new_routes_keep_session_capability_guard(self):
        for route in ("/api/retest/plan", "/api/comparison", "/api/comparison/verify"):
            self.assertEqual(self.request(route, {}, authorized=False)[0], 403)
        self.assertEqual(self.hits, [])


if __name__ == "__main__":
    unittest.main()
