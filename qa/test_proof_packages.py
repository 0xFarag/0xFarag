"""© Nasser Aldin Farag (0xFarag). All rights reserved."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from zipfile import ZipFile

from team import keyring, proof_packages as packages, proof_verify as verifier


class ProofSigning(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = sqlite3.connect(self.root / "test.db")
        self.addCleanup(self.db.close)

    def key(self, workspace="alpha"):
        with self.db:
            return packages.key_history(self.db, self.root, workspace)["keys"][0]

    def body(self):
        from team.proof_engine import evaluate, lab_source, make_scope
        return evaluate(make_scope(["lab.authz.local"], "Synthetic workspace", 12), [lab_source()],
                        dict.fromkeys(("token", "identity", "owner", "denial"), True))

    def sign(self, language="de", report=None):
        with self.db:
            return packages.sign_package(self.db, self.root, "alpha", report or self.body(), language)

    def test_manual_rotation_history_rollback_foreign_workspace_and_wrapping(self):
        first = self.key()
        other = self.key("beta")
        self.assertNotEqual(first["keyId"], other["keyId"])
        self.assertEqual(first, self.key())
        self.assertEqual(16, len(first["fingerprint"]))
        self.assertEqual(first["fingerprint"], hashlib.sha256(verifier.pinned_raw(first["jwk"])).hexdigest()[:16])
        self.assertNotIn("d", first["jwk"])
        with self.assertRaises(RuntimeError), self.db:
            packages.rotate_key(self.db, self.root, "alpha")
            raise RuntimeError("simulated audit rollback")
        self.assertEqual(first, self.key())
        with self.db:
            second = packages.rotate_key(self.db, self.root, "alpha")
        self.assertNotEqual(first["keyId"], second["keyId"])
        self.assertEqual(other, self.key("beta"))
        with self.db:
            public_rows = packages.key_history(self.db, self.root, "alpha")["keys"]
        self.assertEqual([True, False], [row["active"] for row in public_rows])
        self.assertEqual(first["jwk"], public_rows[1]["jwk"])
        self.assertIsNone(self.db.execute("SELECT wrapped_seed FROM proof_workspace_keys WHERE key_id=?", (first["keyId"],)).fetchone()[0])
        wrapped = self.db.execute("SELECT wrapped_seed FROM proof_workspace_keys WHERE key_id=?", (second["keyId"],)).fetchone()[0]
        self.assertEqual(len(wrapped), 60)  # nonce, 32-byte encrypted seed, 16-byte authentication tag
        with self.db:
            self.db.execute("UPDATE proof_workspace_keys SET wrapped_seed=? WHERE workspace='beta'", (wrapped,))
        with self.assertRaises(keyring.KeyStoreError), self.db:
            packages._active_signer(self.db, self.root, "beta")
        if os.name == "posix":
            self.assertEqual(0o600, (self.root / packages.MASTER).stat().st_mode & 0o777)
        (self.root / packages.MASTER).unlink()
        with self.assertRaises(keyring.KeyStoreError), self.db:
            packages.rotate_key(self.db, self.root, "alpha")

    def test_concurrent_provision_and_rotation_leave_one_active_key(self):
        def mutate(operation):
            with closing(sqlite3.connect(self.root / "test.db", timeout=5)) as db, db:
                if operation == "read":
                    return packages.key_history(db, self.root, "alpha")["activeKeyId"]
                return packages.rotate_key(db, self.root, "alpha")["keyId"]

        with ThreadPoolExecutor(max_workers=4) as pool:
            first = list(pool.map(mutate, ["read"] * 4))
            rotated = list(pool.map(mutate, ["rotate"] * 4))
        self.assertEqual(len(set(first)), 1)
        self.assertEqual(len(set(rotated)), 4)
        with self.db:
            rows = packages.key_history(self.db, self.root, "alpha")["keys"]
        self.assertEqual(len(rows), 5)
        self.assertEqual(sum(bool(row["active"]) for row in rows), 1)
        with self.db:
            self.db.execute("UPDATE proof_workspace_keys SET public=randomblob(32) WHERE key_id=?", (first[0],))
        with self.assertRaises(keyring.KeyStoreError), self.db:
            packages.key_history(self.db, self.root, "alpha")

    def test_documents_standalone_verifier_tamper_rotation_and_locales(self):
        original = self.sign()
        first = self.key()
        checked = packages.verify_package(original, first["jwk"], "alpha")
        self.assertEqual(4, checked["coverage"]["not_retested"])
        self.assertEqual(original, self.sign())
        with ZipFile(io.BytesIO(original)) as archive:
            parts = {name: archive.read(name) for name in archive.namelist()}
        self.assertIn(b"/FontFile2", parts["report.pdf"])
        self.assertIn(b"/EmbeddedFiles", parts["report.pdf"])
        self.assertEqual(first["keyId"], verifier.inventory_key_id(original))
        self.assertIn(b"Retest-Abdeckung", parts["report.html"])
        self.assertEqual(verifier.canonical(checked), parts["report.json"])
        for name in verifier.FILES:
            with self.subTest(file=name):
                altered = dict(parts)
                altered[name] += b"X"
                with self.assertRaises(ValueError):
                    verifier.verify_bytes(verifier.archive_bytes(altered), first["jwk"])
        with self.assertRaises(ValueError):
            verifier.verify_bytes(original + b"X", first["jwk"])
        flipped = bytearray(original)
        flipped[100] ^= 1
        with self.assertRaises(ValueError):
            verifier.verify_bytes(bytes(flipped), first["jwk"])
        with self.assertRaises(ValueError):
            verifier.verify_bytes(original, first["jwk"], "beta")
        with self.db:
            second = packages.rotate_key(self.db, self.root, "alpha")
        new = self.sign("fr")
        package_file = self.root / "original.zip"
        jwk_file = self.root / "trusted.jwk"
        package_file.write_bytes(original)
        jwk_file.write_text(json.dumps(first["jwk"]))
        runner = [sys.executable, str(Path(verifier.__file__).resolve()), str(package_file), "--key", str(jwk_file)]
        self.assertEqual(0, subprocess.run(runner, cwd=self.root, capture_output=True).returncode)
        self.assertEqual("fr", packages.verify_package(new, second["jwk"])["language"])
        self.assertEqual("en", packages.verify_package(self.sign("en"), second["jwk"])["language"])
        with self.assertRaises(ValueError):
            verifier.verify_bytes(original, second["jwk"])
        with self.assertRaises(ValueError):
            verifier.verify_bytes(new, first["jwk"])
        package_file.write_bytes(new)
        self.assertEqual(1, subprocess.run(runner, cwd=self.root, capture_output=True).returncode)

    def test_baseline_and_retest_are_charged_once_in_all_reports(self):
        from team.proof_engine import lab_after_source, record_retest
        report = self.body()
        selected = [row["id"] for row in report["findings"][:3]]
        intended = {name: value["intended"] for name, value in report["controls"].items()}
        record_retest(report, selected, lab_after_source(), intended)
        archive = self.sign(report=report)
        verified = packages.verify_package(archive, self.key()["jwk"], "alpha")
        self.assertEqual((7, 12), (verified["spent"], verified["budget"]))
        self.assertEqual({"not_retested": 1, "resolved_check": 3}, verified["coverage"])
        with ZipFile(io.BytesIO(archive)) as bundle:
            self.assertIn(b"7 / 12", bundle.read("report.html"))
            self.assertNotIn(b"10 / 12", bundle.read("report.html"))

    def test_primary_verifier_replays_even_a_valid_signature(self):
        original = self.sign()
        pinned = self.key()["jwk"]
        with ZipFile(io.BytesIO(original)) as archive:
            parts = {name: archive.read(name) for name in archive.namelist()}
        body = json.loads(parts["report.json"])
        # Replace a reported outcome, then deliberately sign the inconsistent data with a real workspace key.
        body["retests"][0]["status"] = "resolved_check"
        body["coverage"] = packages._coverage(body)
        with self.assertRaises(ValueError):
            self.sign(report=body)
        parts["report.json"] = verifier.canonical(body)
        parts["report.html"] = packages.render_html(body)
        parts["report.pdf"] = packages.render_pdf(body)
        inventory = json.loads(parts["inventory.json"])
        inventory["files"] = verifier.document_inventory(parts)
        parts["inventory.json"] = verifier.canonical(inventory)
        with self.db:
            key, _ = packages._active_signer(self.db, self.root, "alpha")
            parts["signature.ed25519"] = key.sign(parts["inventory.json"])
        forged = verifier.archive_bytes(parts)
        self.assertEqual(body, verifier.verify_bytes(forged, pinned))
        with self.assertRaises(ValueError):
            packages.verify_package(forged, pinned)


if __name__ == "__main__":
    unittest.main()
