"""CLI, readable output and signed comparison delivery share source semantics."""

import base64
import contextlib
import copy
import hashlib
import html
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from authzledger.assurance import retest_plan
from authzledger.cli import main
from authzledger.comparison import create_comparison, verify_comparison
from authzledger.reports import render_comparison_html
from authzledger.signing import SIGNING_DOMAIN, create_bundle, generate_keypair, verify_bundle
from test_comparison import contract, rehash, report, reseal


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


class DeliveryFixture:
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="authzledger-comparison-delivery-")
        self.root = Path(self.temporary.name)
        self.source = contract()
        self.selected = retest_plan(self.source, ["peer-denied"])["contract"]
        self.before = report(self.source, leak=True)
        self.after = report(self.selected, version="1.0.5")
        self.envelope = create_comparison(self.source, self.before, self.after, ["peer-denied"])
        self.source_file = self.write("source.json", self.source)
        self.before_file = self.write("baseline.json", self.before)
        self.after_file = self.write("current.json", self.after)
        self.envelope_file = self.write("envelope.json", self.envelope)

    def tearDown(self):
        self.temporary.cleanup()

    def write(self, name, value):
        path = self.root / name
        path.write_bytes(canonical(value))
        return path

    def cli(self, arguments):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = main([str(argument) for argument in arguments])
        return code, output.getvalue() + errors.getvalue()

    def compare_args(self, output):
        return ["compare-retest", self.source_file, self.before_file, self.after_file,
                "--case", "peer-denied", "--out", output]


class ComparisonDeliveryTests(DeliveryFixture, unittest.TestCase):
    def test_cli_roundtrip_is_offline_and_preserves_original_sources(self):
        original_bytes = {path: path.read_bytes() for path in
                          (self.source_file, self.before_file, self.after_file)}
        destination = self.root / "comparison"
        with patch("socket.create_connection", side_effect=AssertionError("comparison must be offline")), \
                patch("authzledger.engine.run", side_effect=AssertionError("comparison must not execute")):
            code, output = self.cli(self.compare_args(destination))
            self.assertEqual(code, 0, output)
            self.assertEqual(self.cli(["verify-comparison", destination / "comparison.json"])[0], 0)
        value = json.loads((destination / "comparison.json").read_bytes())
        self.assertEqual(value, self.envelope)
        self.assertEqual(verify_comparison(value), [])
        self.assertEqual((destination / "comparison.html").read_text(), render_comparison_html(value))
        self.assertIn("1 not retested", output)
        self.assertEqual({path: path.read_bytes() for path in original_bytes}, original_bytes)

    def test_exit_codes_distinguish_regressions_from_unassessed_comparisons(self):
        scenarios = [
            ("restored", self.before, self.after, 0, "resolved_check"),
            ("regressed", report(self.source), report(self.selected, leak=True), 1, "regression"),
            ("invalid-control", report(self.source, overrides={"owner-control": (401, {})}),
             self.after, 2, "inconclusive"),
            ("lost-testability", self.before,
             report(self.selected, overrides={"peer-denied": "error"}), 2, "testability_lost"),
        ]
        for name, before, after, expected, classification in scenarios:
            self.write("baseline.json", before)
            self.write("current.json", after)
            destination = self.root / name
            with self.subTest(name=name):
                code, output = self.cli(self.compare_args(destination))
                self.assertEqual(code, expected, output)
                envelope = json.loads((destination / "comparison.json").read_bytes())
                self.assertGreater(envelope["summary"][classification], 0)
                # A valid comparison can correctly report a regression or uncertainty.
                self.assertEqual(self.cli(["verify-comparison", destination / "comparison.json"])[0], 0)

    def test_existing_destination_is_never_modified(self):
        destination = self.root / "retained"
        destination.mkdir()
        marker = destination / "comparison.json"
        marker.write_bytes(b"independently retained evidence\n")
        code, output = self.cli(self.compare_args(destination))
        self.assertEqual(code, 2)
        self.assertEqual(marker.read_bytes(), b"independently retained evidence\n")
        self.assertEqual(list(destination.iterdir()), [marker])

    def test_strict_cli_inputs_reject_duplicate_keys_and_nonfinite_json(self):
        for path, key in ((self.source_file, "version"), (self.before_file, "schema_version"),
                          (self.after_file, "schema_version")):
            original = path.read_bytes()
            for index, suffix in enumerate((b',"' + key.encode() + b'":1}', b',"untrusted":NaN}')):
                destination = self.root / (path.stem + str(index))
                with self.subTest(path=path.name, suffix=suffix):
                    path.write_bytes(original[:-1] + suffix)
                    code, output = self.cli(self.compare_args(destination))
                    self.assertEqual(code, 2, output)
                    self.assertFalse(destination.exists())
                path.write_bytes(original)
        original = self.envelope_file.read_bytes()
        for suffix in (b',"schema_version":1}', b',"untrusted":NaN}'):
            self.envelope_file.write_bytes(original[:-1] + suffix)
            self.assertEqual(self.cli(["verify-comparison", self.envelope_file])[0], 2)

    def test_reader_rejects_oversize_input_before_creating_output(self):
        destination = self.root / "oversize"
        # Exercise the production bound without allocating a giant fixture.
        with patch("authzledger.signing.MAX_REPORT_BYTES", 32):
            code, output = self.cli(self.compare_args(destination))
        self.assertEqual(code, 2)
        self.assertFalse(destination.exists())

    def test_readable_output_is_identical_after_sorted_json_roundtrip(self):
        roundtrip = json.loads(json.dumps(self.envelope, sort_keys=True))
        self.assertEqual(render_comparison_html(self.envelope), render_comparison_html(roundtrip))

    def test_rehashed_derived_claims_fail_cli_and_renderer_verification(self):
        false = copy.deepcopy(self.envelope)
        false["summary"]["not_retested"] = 0
        rehash(false)
        path = self.write("forged.json", false)
        self.assertEqual(self.cli(["verify-comparison", path])[0], 2)
        with self.assertRaises(ValueError):
            render_comparison_html(false)

    def test_html_escapes_untrusted_contract_text_and_retains_scope_limits(self):
        source = copy.deepcopy(self.source)
        payload = '</title><script>alert("comparison")</script>'
        source["name"] = payload
        selected = retest_plan(source, ["peer-denied"])["contract"]
        envelope = create_comparison(source, report(source, leak=True), report(selected), ["peer-denied"])
        rendered = render_comparison_html(envelope)
        self.assertNotIn(payload, rendered)
        self.assertNotIn("<script>", rendered)
        self.assertIn(html.escape(payload), rendered)
        self.assertIn(envelope["comparison_sha256"], rendered)
        self.assertIn(envelope["baseline_report"]["evidence"]["root_sha256"], rendered)
        self.assertIn("not_retested", rendered)
        self.assertIn("not execution", rendered)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for Ed25519 signing")
class SignedComparisonDeliveryTests(DeliveryFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.private, self.public = self.root / "private.pem", self.root / "public.pem"
        self.bundle = self.root / "proof"
        generate_keypair(self.private, self.public)

    def attachments(self):
        return {"comparison.json": canonical(self.envelope),
                "comparison.html": render_comparison_html(self.envelope).encode("utf-8")}

    def build(self):
        return create_bundle(self.after, self.bundle, self.private, self.attachments())

    def independent(self):
        verifier = Path(__file__).resolve().parents[1] / "tools/verify_bundle.py"
        return subprocess.run([sys.executable, "-I", str(verifier), str(self.bundle),
                               "--public-key", str(self.public)], cwd=self.root, check=False,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=20)

    def resign_existing(self):
        """Model a dishonest authorized signer, beyond accidental hash changes."""
        manifest = json.loads((self.bundle / "manifest.json").read_bytes())
        for record in manifest["files"]:
            raw = (self.bundle / record["path"]).read_bytes()
            record.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        raw = canonical(manifest)
        (self.bundle / "manifest.json").write_bytes(raw)
        message = self.root / "sign-message"
        message.write_bytes(SIGNING_DOMAIN + raw)
        signed = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(self.private),
                                 "-in", str(message)], check=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=20).stdout
        (self.bundle / "signature.base64").write_bytes(base64.b64encode(signed) + b"\n")

    def test_cli_bundle_binds_json_html_and_exact_current_report(self):
        code, output = self.cli(["bundle", self.after_file, "--key", self.private,
                                "--comparison", self.envelope_file, "--out", self.bundle])
        self.assertEqual(code, 0, output)
        self.assertEqual(verify_bundle(self.bundle, self.public), [])
        self.assertEqual(json.loads((self.bundle / "attachments/comparison.json").read_bytes()), self.envelope)
        self.assertEqual((self.bundle / "attachments/comparison.html").read_bytes(),
                         self.attachments()["comparison.html"])
        self.assertEqual(self.cli(["verify-bundle", self.bundle, "--public-key", self.public])[0], 0)
        independent = self.independent()
        self.assertEqual(independent.returncode, 0, independent.stderr)
        self.assertIn("semantics", independent.stdout)
        self.assertEqual(self.cli(["bundle", self.after_file, "--key", self.private,
                                  "--comparison", self.envelope_file, "--out", self.bundle])[0], 2)
        self.assertEqual(verify_bundle(self.bundle, self.public), [])

    def test_different_valid_report_cannot_borrow_comparison_claims(self):
        changed = copy.deepcopy(self.after)
        changed["finished_at"] = "2026-10-11T00:00:00Z"
        changed = reseal(changed)
        self.write("current.json", changed)
        code, output = self.cli(["bundle", self.after_file, "--key", self.private,
                                "--comparison", self.envelope_file, "--out", self.bundle])
        self.assertEqual(code, 2, output)
        self.assertFalse(self.bundle.exists())
        with self.assertRaisesRegex(ValueError, "current report"):
            create_bundle(changed, self.bundle, self.private, self.attachments())
        self.assertFalse(self.bundle.exists())

    def test_html_without_retained_json_and_rehashed_claims_cannot_be_signed(self):
        with self.assertRaisesRegex(ValueError, "requires"):
            create_bundle(self.after, self.bundle, self.private, {"comparison.html": b"All fixed"})
        self.assertFalse(self.bundle.exists())
        false = copy.deepcopy(self.envelope)
        false["summary"]["not_retested"] = 0
        rehash(false)
        with self.assertRaisesRegex(ValueError, "comparison attachment"):
            create_bundle(self.after, self.bundle, self.private, {"comparison.json": canonical(false)})
        self.assertFalse(self.bundle.exists())

    def test_unauthenticated_attachment_tampering_fails_both_verifiers(self):
        self.build()
        path = self.bundle / "attachments/comparison.json"
        path.write_bytes(path.read_bytes() + b" ")
        self.assertTrue(verify_bundle(self.bundle, self.public))
        self.assertNotEqual(self.independent().returncode, 0)

    def test_authorized_resigning_cannot_make_false_html_semantically_valid(self):
        self.build()
        (self.bundle / "attachments/comparison.html").write_bytes(b"<h1>All vulnerabilities fixed</h1>")
        self.resign_existing()
        errors = verify_bundle(self.bundle, self.public)
        self.assertTrue(any("comparison.html" in error for error in errors), errors)
        independent = self.independent()
        self.assertEqual(independent.returncode, 0, independent.stderr)
        self.assertIn("semantics", independent.stdout)

    def test_authorized_rehashed_claims_remain_semantically_invalid(self):
        self.build()
        false = copy.deepcopy(self.envelope)
        false["summary"]["not_retested"] = 0
        rehash(false)
        (self.bundle / "attachments/comparison.json").write_bytes(canonical(false))
        self.resign_existing()
        errors = verify_bundle(self.bundle, self.public)
        self.assertTrue(any("comparison attachment" in error for error in errors), errors)
        independent = self.independent()
        self.assertEqual(independent.returncode, 0, independent.stderr)
        self.assertIn("semantics", independent.stdout)


if __name__ == "__main__":
    unittest.main()
