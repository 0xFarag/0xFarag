"""Trust anchors, dishonest resealing, path boundaries and independent verification."""

import base64
import copy
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

from authzledger.evidence import seal_report, verify_report
from authzledger.intelligence import build_graph, verify_graph
from authzledger.model import contract_digest, load_contract
from authzledger.reasoning import explain_graph
from authzledger.signing import (
    MAX_FILE_BYTES, SIGNING_DOMAIN, create_bundle, generate_keypair, verify_bundle,
)


def report_for():
    return seal_report({
        "schema_version": 1, "tool": {"name": "AuthzLedger", "version": "1.0.0"},
        "name": "Invoice authorization", "target": "http://127.0.0.1:8765",
        "contract_sha256": "a" * 64,
        "started_at": "2026-10-09T00:00:00Z", "finished_at": "2026-10-09T00:00:01Z",
        "summary": {"pass": 1, "fail": 0, "error": 0, "inconclusive": 0, "total": 1},
        "results": [{"id": "owner", "identity": "owner", "method": "GET", "path": "/invoice/1",
                     "outcome": "pass", "status": 200, "duration_ms": 1,
                     "checks": [{"type": "status", "passed": True}], "reason": "Configured result.",
                     "response_sha256": "b" * 64, "control_type": "positive", "requires": []}],
    })


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def intelligence_fixture():
    contract = load_contract({
        "version": 1, "name": "Invoice authorization", "target": "http://127.0.0.1:8765",
        "identities": {"owner": {"headers": {}}},
        "cases": [{"id": "owner", "identity": "owner", "method": "GET", "path": "/invoice/1",
                   "expect": {"status": [200]}}],
    })
    report = report_for()
    report["contract_sha256"] = contract_digest(contract)
    report = seal_report(report)
    return contract, report, build_graph(contract, report)


@unittest.skipUnless(shutil.which("openssl"), "OpenSSL is required for Ed25519 signing")
class SigningTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="authzledger-signing-test-")
        self.root = Path(self.temporary.name)
        self.private = self.root / "private.pem"
        self.public = self.root / "public.pem"
        self.bundle = self.root / "bundle"
        generate_keypair(self.private, self.public)

    def tearDown(self):
        self.temporary.cleanup()

    def build(self, attachments=None):
        return create_bundle(report_for(), self.bundle, self.private, attachments)

    def independent(self):
        script = Path(__file__).resolve().parents[1] / "tools" / "verify_bundle.py"
        # Isolated mode strips PYTHONPATH and the project from the import path.
        return subprocess.run([sys.executable, "-I", str(script), str(self.bundle),
                               "--public-key", str(self.public)], cwd=self.root,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              timeout=20, check=False)

    def rewrite_signed(self, report):
        """Construct an authenticated dishonest runner output, not a hash-only edit."""
        raw = canonical(report)
        (self.bundle / "report.json").write_bytes(raw)
        self.resign_existing()

    def resign_existing(self):
        report = json.loads((self.bundle / "report.json").read_bytes())
        manifest = json.loads((self.bundle / "manifest.json").read_bytes())
        manifest["report"]["root_sha256"] = report["evidence"]["root_sha256"]
        manifest["report"]["contract_sha256"] = report["contract_sha256"]
        for record in manifest["files"]:
            raw = (self.bundle / record["path"]).read_bytes()
            record.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        manifest_raw = canonical(manifest)
        (self.bundle / "manifest.json").write_bytes(manifest_raw)
        message = self.root / "sign-message"
        message.write_bytes(SIGNING_DOMAIN + manifest_raw)
        signed = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(self.private),
                                 "-in", str(message)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=20, check=True).stdout
        (self.bundle / "signature.base64").write_bytes(base64.b64encode(signed) + b"\n")

    def test_roundtrip_attachments_and_isolated_independent_verifier(self):
        source = self.root / "notes.txt"
        source.write_text("Reviewed control ownership.\n")
        report = report_for()
        original = copy.deepcopy(report)
        manifest = create_bundle(report, self.bundle, self.private,
                                 {"notes.txt": source, "contracts/access.json": b'{"scope":"fixture"}'})
        self.assertEqual(report, original)
        self.assertEqual(verify_bundle(self.bundle, self.public), [])
        self.assertEqual(manifest["report"]["root_sha256"], report["evidence"]["root_sha256"])
        result = self.independent()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("VERIFIED", result.stdout)
        self.assertEqual(stat.S_IMODE(self.private.stat().st_mode), 0o600)
        self.assertFalse(any(b"PRIVATE KEY" in path.read_bytes()
                             for path in self.bundle.rglob("*") if path.is_file()))

    def test_key_and_bundle_destinations_cannot_be_overwritten(self):
        original = self.private.read_bytes()
        with self.assertRaisesRegex(ValueError, "already exists"):
            generate_keypair(self.private, self.root / "unused.pem")
        self.assertEqual(self.private.read_bytes(), original)
        self.build()
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.build()
        self.assertEqual(verify_bundle(self.bundle, self.public), [])

    def test_external_trusted_public_key_is_mandatory(self):
        self.build()
        with self.assertRaises(TypeError):
            verify_bundle(self.bundle)
        self.assertTrue(verify_bundle(self.bundle, self.bundle / "public.pem"))
        wrong_private, wrong_public = self.root / "wrong-private.pem", self.root / "wrong-public.pem"
        generate_keypair(wrong_private, wrong_public)
        self.assertIn("trusted public key fingerprint mismatch", verify_bundle(self.bundle, wrong_public))

    def test_tampering_each_authenticated_surface_is_rejected(self):
        self.build({"proof.txt": b"original proof"})
        for name in ("report.json", "public.pem", "attachments/proof.txt", "manifest.json", "signature.base64"):
            path = self.bundle / name
            original = path.read_bytes()
            with self.subTest(name=name):
                path.write_bytes(original + b" ")
                self.assertTrue(verify_bundle(self.bundle, self.public))
                self.assertNotEqual(self.independent().returncode, 0)
            path.write_bytes(original)
        self.assertEqual(verify_bundle(self.bundle, self.public), [])

    def test_resealing_the_report_does_not_recreate_a_trusted_signature(self):
        self.build()
        changed = report_for()
        changed["target"] = "http://127.0.0.1:9999"
        resealed = seal_report(changed)
        self.assertEqual(verify_report(resealed), [])
        (self.bundle / "report.json").write_bytes(canonical(resealed))
        self.assertTrue(verify_bundle(self.bundle, self.public))
        # Even rewriting every unsigned anchor/hash fails against the retained signature.
        manifest = json.loads((self.bundle / "manifest.json").read_bytes())
        raw = canonical(resealed)
        manifest["report"]["root_sha256"] = resealed["evidence"]["root_sha256"]
        for record in manifest["files"]:
            if record["path"] == "report.json":
                record.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        (self.bundle / "manifest.json").write_bytes(canonical(manifest))
        self.assertIn("detached signature verification failed", verify_bundle(self.bundle, self.public))

    def test_semantically_invalid_signed_runner_output_is_rejected(self):
        self.build()
        report = report_for()
        report["results"][0]["checks"] = []
        self.rewrite_signed(report)
        self.assertTrue(any("pass requires" in error for error in verify_bundle(self.bundle, self.public)))
        # This independent tool deliberately verifies authenticity, not report semantics.
        result = self.independent()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("semantics", result.stdout)

    def test_invalid_sealed_report_cannot_be_signed(self):
        bad = report_for()
        bad["summary"]["pass"] = 99
        with self.assertRaisesRegex(ValueError, "invalid sealed report"):
            create_bundle(bad, self.bundle, self.private)
        self.assertFalse(self.bundle.exists())

    def test_traversal_absolute_paths_and_ambiguous_names_are_blocked(self):
        for name in ("../outside.txt", "/outside.txt", "a/../../outside", "a\\outside", "a//b", ".", "C:secret"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.build({name: b"safe"})
            self.assertFalse(self.bundle.exists())
        self.build()
        manifest = json.loads((self.bundle / "manifest.json").read_bytes())
        manifest["files"][0]["path"] = "../outside.txt"
        (self.bundle / "manifest.json").write_bytes(canonical(manifest))
        self.assertTrue(verify_bundle(self.bundle, self.public))

    def test_symlinks_missing_and_extra_files_are_rejected(self):
        self.build({"proof.txt": b"proof"})
        path = self.bundle / "attachments/proof.txt"
        path.unlink()
        self.assertTrue(verify_bundle(self.bundle, self.public))
        path.symlink_to(self.public)
        self.assertTrue(verify_bundle(self.bundle, self.public))
        path.unlink()
        path.write_bytes(b"proof")
        extra = self.bundle / "private.pem"
        extra.write_bytes(b"extra")
        self.assertTrue(verify_bundle(self.bundle, self.public))
        extra.unlink()
        (self.bundle / "unexpected-empty").mkdir()
        self.assertTrue(verify_bundle(self.bundle, self.public))

    def test_symlink_sources_destination_and_trusted_key_are_rejected(self):
        source = self.root / "linked-proof"
        source.symlink_to(self.public)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.build({"proof": source})
        self.bundle.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.build()
        self.bundle.unlink()
        self.build()
        self.assertTrue(verify_bundle(self.bundle, source))

    def test_private_keys_cannot_be_attached(self):
        for value in (self.private, self.private.read_bytes(), b"prefix\n-----BEGIN OPENSSH PRIVATE KEY-----\nsecret"):
            with self.subTest(value_type=type(value)), self.assertRaisesRegex(ValueError, "private key|private signing key"):
                self.build({"secrets.pem": value})
            self.assertFalse(self.bundle.exists())

    def test_duplicate_keys_shape_changes_and_non_finite_manifest_are_rejected(self):
        self.build()
        path = self.bundle / "manifest.json"
        original = path.read_bytes()
        manifest = json.loads(original)
        invalid = [original[:-1] + b',"schema_version":1}',
                   canonical({**manifest, "unexpected": "ignored?"}),
                   original.replace(b'"schema_version":1', b'"schema_version":1e999'),
                   canonical({**manifest, "schema_version": True}),
                   json.dumps(manifest, indent=2).encode()]
        for raw in invalid:
            with self.subTest(raw=raw[:40]):
                path.write_bytes(raw)
                self.assertTrue(verify_bundle(self.bundle, self.public))
                self.assertNotEqual(self.independent().returncode, 0)

    def test_manifest_claimed_sizes_and_sparse_source_abuse_are_bounded(self):
        source = self.root / "too-large"
        with source.open("wb") as handle:
            handle.truncate(MAX_FILE_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "size limit"):
            self.build({"too-large": source})
        self.build()
        manifest = json.loads((self.bundle / "manifest.json").read_bytes())
        manifest["files"][0]["size"] = MAX_FILE_BYTES + 1
        (self.bundle / "manifest.json").write_bytes(canonical(manifest))
        self.assertTrue(verify_bundle(self.bundle, self.public))

    def test_reserved_graph_requires_contract_and_explanation_requires_graph(self):
        contract, report, graph = intelligence_fixture()
        for attachments in ({"graph.json": canonical(graph)},
                            {"explanation.json": canonical(explain_graph(graph))}):
            with self.subTest(names=list(attachments)), self.assertRaisesRegex(ValueError, "requires"):
                create_bundle(report, self.bundle, self.private, attachments)
            self.assertFalse(self.bundle.exists())

    def test_full_source_bundle_reconstructs_graph_and_deterministic_explanation(self):
        contract, report, graph = intelligence_fixture()
        explanation = explain_graph(graph)
        create_bundle(report, self.bundle, self.private, {
            "contract.json": canonical(contract), "graph.json": canonical(graph),
            "explanation.json": canonical(explanation),
        })
        self.assertEqual(verify_bundle(self.bundle, self.public), [])
        result = self.independent()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rehashed_contradictory_graph_cannot_be_signed_or_verified(self):
        contract, report, graph = intelligence_fixture()
        create_bundle(report, self.bundle, self.private, {
            "contract.json": canonical(contract), "graph.json": canonical(graph),
        })
        changed = copy.deepcopy(report)
        changed["results"][0].update(status=403, outcome="fail", checks=[{"type": "status", "passed": False}])
        changed["summary"] = {"pass": 0, "fail": 1, "error": 0, "inconclusive": 0, "total": 1}
        changed = seal_report(changed)
        false_graph = build_graph(contract, changed)
        false_graph["evidence_report_root_sha256"] = report["evidence"]["root_sha256"]
        false_graph["edges"][0]["evidence"]["report_root_sha256"] = report["evidence"]["root_sha256"]
        false_graph["edges"][0]["evidence"]["record_sha256"] = report["evidence"]["records"][0]["sha256"]
        # Match the graph's local hash exactly, preserving plausible source anchors.
        graph_body = {key: value for key, value in false_graph.items() if key != "graph_sha256"}
        false_graph["graph_sha256"] = hashlib.sha256(json.dumps(graph_body, sort_keys=True,
            ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        self.assertEqual(verify_graph(false_graph), [])
        with self.assertRaisesRegex(ValueError, "graph attachment"):
            create_bundle(report, self.root / "false-proof", self.private, {
                "contract.json": canonical(contract), "graph.json": canonical(false_graph),
            })
        (self.bundle / "attachments/graph.json").write_bytes(canonical(false_graph))
        self.resign_existing()
        self.assertTrue(any("graph attachment" in error for error in verify_bundle(self.bundle, self.public)))
        self.assertEqual(self.independent().returncode, 0)

    def test_explanation_binding_authority_citations_and_factual_output_are_checked(self):
        contract, report, graph = intelligence_fixture()
        original = explain_graph(graph)
        variants = []
        for field, value in (("graph_sha256", "0" * 64), ("contract_sha256", "0" * 64),
                             ("decision_authority", "ai"), ("schema_version", True)):
            variant = copy.deepcopy(original)
            variant[field] = value
            variants.append(variant)
        variant = copy.deepcopy(original)
        variant["explanations"][0]["text"] = "All access is verified safe."
        variants.append(variant)
        variant = copy.deepcopy(original)
        variant["ai"]["advisory_only"] = False
        variants.append(variant)
        variant = copy.deepcopy(original)
        variant["ai"].update(status="generated", source="local-ollama", model="test",
                            notes=[{"edge_id": graph["edges"][0]["id"], "text": "Advisory note.",
                                    "citations": ["absent-edge"], "untrusted": True}])
        variants.append(variant)
        for index, explanation in enumerate(variants):
            with self.subTest(index=index), self.assertRaises(ValueError):
                create_bundle(report, self.root / f"invalid-{index}", self.private, {
                    "contract.json": canonical(contract), "graph.json": canonical(graph),
                    "explanation.json": canonical(explanation),
                })
        create_bundle(report, self.bundle, self.private, {
            "contract.json": canonical(contract), "graph.json": canonical(graph),
            "explanation.json": canonical(original),
        })
        (self.bundle / "attachments/explanation.json").write_bytes(canonical(variants[0]))
        self.resign_existing()
        self.assertTrue(verify_bundle(self.bundle, self.public))

    def test_advisory_notes_can_be_signed_without_becoming_decision_authority(self):
        contract, report, graph = intelligence_fixture()
        explanation = explain_graph(graph)
        edge_id = graph["edges"][0]["id"]
        explanation["ai"].update(status="generated", source="local-ollama", model="test",
                                notes=[{"edge_id": edge_id, "text": "An analyst should review the configured scope.",
                                        "citations": [edge_id], "untrusted": True}])
        create_bundle(report, self.bundle, self.private, {
            "contract.json": canonical(contract), "graph.json": canonical(graph),
            "explanation.json": canonical(explanation),
        })
        self.assertEqual(verify_bundle(self.bundle, self.public), [])


if __name__ == "__main__":
    unittest.main()
