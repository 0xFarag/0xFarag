# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Trust continuity, crash boundaries and independent concurrent signing clients."""
import base64
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from threading import Barrier
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from team import evidence, keyring
from team.documents import build_archive, verify_archive


START = 1800000000


class SigningHistory(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.dbpath = self.root / "team.sqlite3"
        self.db = self.connect()
        self.addCleanup(self.db.close)
        self.db.execute("PRAGMA journal_mode=WAL")
        evidence.init_db(self.db)
        clock_patch = patch.object(keyring, "unix_time", return_value=START)
        self.clock = clock_patch.start()
        self.addCleanup(clock_patch.stop)
        self.case = self.api("POST", ["cases"], {"title": "Evidence", "scope": "example.test"})["case"]

    def connect(self):
        return sqlite3.connect(self.dbpath, timeout=20, isolation_level=None)

    def api(self, method, route, body=None, team="owner", *, db=None):
        conn = self.db if db is None else db
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            return evidence.handle(conn, team, "reviewer", method, route, body or {}, data_dir=self.root)

    def deliver(self, fmt="json", **kwargs):
        response = self.api("POST", ["cases", self.case["id"], "handover"], {"format": fmt}, **kwargs)
        return response["package"] if fmt == "json" else base64.b64decode(response["archive_b64"])

    def test_due_boundary_rotation_historic_archives_and_isolation(self):
        first = self.api("GET", ["trust-key"])
        package = self.deliver()
        archive = self.deliver("html")
        self.clock.return_value = START + keyring.PERIOD - 1
        self.assertEqual(self.deliver()["manifest"]["fingerprint"], first["fingerprint"])
        self.clock.return_value += 1
        self.assertEqual(self.api("GET", ["trust-key"]), first)
        current_archive = self.deliver("html")
        second = self.api("GET", ["trust-key"])
        self.assertNotEqual(first, second)
        keyring.prune_committed(self.db, self.root)
        self.assertFalse((self.root / keyring.SLOTS[0]).exists())
        self.assertTrue(verify_archive(current_archive, second)["valid"])
        self.assertFalse(verify_archive(current_archive, first)["valid"])
        self.clock.return_value += keyring.PERIOD
        current = self.deliver()
        keyring.prune_committed(self.db, self.root)
        history = self.api("GET", ["trust-keys"])
        self.assertEqual(history["rotation_days"], 90)
        self.assertEqual(history["active_fingerprint"], current["manifest"]["fingerprint"])
        active, previous, oldest = history["keys"]
        self.assertEqual([row["status"] for row in (active, previous, oldest)], ["active", "retired", "retired"])
        self.assertIsNone(active["retired_at"])
        self.assertIsNone(oldest["rotate_after"])
        self.assertEqual(oldest["retired_at"], previous["activated_at"])
        self.assertEqual(previous["retired_at"], active["activated_at"])
        self.assertTrue(evidence.verify_package(package, oldest)["valid"])
        self.assertFalse(evidence.verify_package(package, active)["valid"])
        for body in ({"package": package}, {"archive_b64": base64.b64encode(archive).decode()}):
            self.assertTrue(self.api("POST", ["verify"], body)["valid"])
            self.assertFalse(self.api("POST", ["verify"], body, team="stranger")["valid"])
        self.assertFalse((self.root / keyring.SLOTS[1]).exists())

    def test_standalone_signer_accepts_an_uninitialized_database(self):
        with tempfile.TemporaryDirectory() as directory, closing(sqlite3.connect(":memory:")) as db, db:
            key, descriptor = evidence.signer(db, directory)
            self.assertEqual(keyring.key_descriptor(key.public_key()), descriptor)

    def test_storage_failure_preserves_last_committed_key(self):
        first = self.deliver()
        keyring.prune_committed(self.db, self.root)
        self.clock.return_value += keyring.PERIOD
        save = keyring._store
        def fail_before_publication(directory, name, raw):
            if name.endswith(".pub"):
                raise OSError("storage failure")
            save(directory, name, raw)
        with patch.object(keyring, "_store", side_effect=fail_before_publication):
            with self.assertRaises(evidence.WorkflowError):
                self.deliver()
        self.assertEqual(self.api("GET", ["trust-key"])["fingerprint"], first["manifest"]["fingerprint"])
        self.assertTrue(self.api("POST", ["verify"], {"package": first})["valid"])
        retry = self.deliver()
        self.assertNotEqual(retry["manifest"]["fingerprint"], first["manifest"]["fingerprint"])
        self.assertTrue(self.api("POST", ["verify"], {"package": retry})["valid"])

    def test_legacy_pin_and_preexisting_handover(self):
        legacy = Ed25519PrivateKey.generate()
        desc = keyring.key_descriptor(legacy.public_key())
        raw = legacy.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        path = self.root / keyring.SLOTS[0]
        path.write_bytes(raw)
        path.chmod(0o600)
        self.db.execute("INSERT INTO evidence_signer VALUES(1,?)", (desc["fingerprint"],))
        old = evidence.make_package(self.db, "owner", "operator", self.case, "de", self.root, signing=(legacy, desc))
        old_zip = build_archive(old, "html", legacy)
        self.assertEqual(self.api("GET", ["trust-key"]), desc)
        keyring.prune_committed(self.db, self.root)
        self.clock.return_value += keyring.PERIOD
        self.assertNotEqual(self.deliver()["manifest"]["fingerprint"], desc["fingerprint"])
        keyring.prune_committed(self.db, self.root)
        self.assertFalse(path.exists())
        self.assertTrue(self.api("POST", ["verify"], {"archive_b64": base64.b64encode(old_zip).decode()})["valid"])

    def test_missing_legacy_seed_or_missing_pin_does_not_reset_trust(self):
        self.db.execute("INSERT INTO evidence_signer VALUES(1,?)", ("a" * 64,))
        with self.assertRaises(evidence.WorkflowError):
            self.api("GET", ["trust-key"])
        orphan = Ed25519PrivateKey.generate()
        keyring._save_key(self.root, keyring.SLOTS[0], orphan)
        with self.assertRaises(evidence.WorkflowError):
            self.api("GET", ["trust-key"])
        self.db.execute("DELETE FROM evidence_signer")
        with self.assertRaises(evidence.WorkflowError):
            self.api("GET", ["trust-key"])
        self.assertEqual(self.db.execute("SELECT count(*) FROM evidence_key_generations").fetchone()[0], 0)

    def test_absent_current_private_allows_public_verification_only(self):
        first = self.deliver()
        keyring.prune_committed(self.db, self.root)
        (self.root / keyring.SLOTS[0]).unlink()
        self.clock.return_value += keyring.PERIOD
        with self.assertRaises(evidence.WorkflowError):
            self.deliver()
        self.assertTrue(self.api("POST", ["verify"], {"package": first})["valid"])
        self.assertEqual(len(self.api("GET", ["trust-keys"])["keys"]), 1)
        (self.root / (keyring.SLOTS[0] + ".pub")).unlink()
        with self.assertRaises(evidence.WorkflowError):
            self.api("POST", ["verify"], {"package": first})

    def test_modified_signed_history_and_replaced_database_anchor_fail_closed(self):
        original = self.api("GET", ["trust-key"])
        keyring.prune_committed(self.db, self.root)
        self.clock.return_value += keyring.PERIOD
        self.deliver()
        keyring.prune_committed(self.db, self.root)
        self.db.execute("UPDATE evidence_key_generations SET activated_at=0 WHERE generation=1")
        with self.assertRaises(evidence.WorkflowError):
            self.api("GET", ["trust-keys"])
        # A DB-only replacement can create a valid self-signed history with someone else's key.
        fake = Ed25519PrivateKey.generate()
        desc = keyring.key_descriptor(fake.public_key())
        self.db.execute("UPDATE evidence_key_generations SET fingerprint=?,public_key=? WHERE generation=2",
                        (desc["fingerprint"], desc["public_key"]))
        self.db.execute("UPDATE evidence_signer SET fingerprint=?", (desc["fingerprint"],))
        keyring._seal(self.db, fake)
        with self.assertRaises(evidence.WorkflowError):
            self.api("GET", ["trust-keys"])
        self.assertNotEqual(desc["fingerprint"], original["fingerprint"])

    def test_deleted_history_is_not_reinitialized_from_current_slot(self):
        self.deliver()
        keyring.prune_committed(self.db, self.root)
        self.db.execute("DELETE FROM evidence_key_generations")
        self.db.execute("DELETE FROM evidence_key_history_seal")
        with self.assertRaises(evidence.WorkflowError):
            self.api("GET", ["trust-key"])

    def test_interrupted_first_provisioning_reuses_the_staged_identity(self):
        self.db.execute("BEGIN IMMEDIATE")
        _, first = keyring.signer(self.db, self.root)
        self.db.rollback()
        self.assertEqual(self.api("GET", ["trust-key"]), first)
        keyring.prune_committed(self.db, self.root)
        self.assertFalse((self.root / keyring.BOOTSTRAP).exists())

    def test_process_loss_before_and_after_commit(self):
        original = self.deliver()
        keyring.prune_committed(self.db, self.root)
        child = """from pathlib import Path
import os, sqlite3, sys
from team import keyring
p = Path(sys.argv[1])
db = sqlite3.connect(p / 'team.sqlite3', isolation_level=None)
keyring.unix_time = lambda: int(sys.argv[2])
keyring.signer(db, p)
if sys.argv[3] == 'commit':
    db.commit()
os._exit(17)
"""
        self.clock.return_value += keyring.PERIOD
        for point in ("rollback", "commit"):
            run = subprocess.run([sys.executable, "-c", child, str(self.root), str(self.clock.return_value), point],
                                 capture_output=True)
            self.assertEqual(run.returncode, 17, run.stderr.decode())
            history = self.api("GET", ["trust-keys"])["keys"]
            self.assertEqual(len(history), 1 if point == "rollback" else 2)
            self.assertTrue(self.api("POST", ["verify"], {"package": original})["valid"])
            self.assertEqual(self.api("GET", ["trust-key"])["fingerprint"], history[0]["fingerprint"])
            keyring.prune_committed(self.db, self.root)
            self.assertEqual(sum((self.root / name).exists() for name in keyring.SLOTS), 1)

    def test_concurrent_due_handovers_publish_one_generation(self):
        self.deliver()
        keyring.prune_committed(self.db, self.root)
        self.clock.return_value += keyring.PERIOD
        barrier = Barrier(6)
        def sign(_index):
            with closing(self.connect()) as conn:
                barrier.wait(timeout=10)
                package = self.deliver(db=conn)
                keyring.prune_committed(conn, self.root)
                return package
        with ThreadPoolExecutor(max_workers=6) as workers:
            packages = list(workers.map(sign, range(6)))
        history = self.api("GET", ["trust-keys"])["keys"]
        self.assertEqual(len(history), 2)
        for package in packages:
            self.assertTrue(evidence.verify_package(package, history[0])["valid"])

    @unittest.skipUnless(os.name == "posix", "POSIX file modes")
    def test_insecure_or_redirected_private_file_fails_closed(self):
        self.api("GET", ["trust-key"])
        path = self.root / keyring.SLOTS[0]
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        path.chmod(0o644)
        with self.assertRaises(evidence.WorkflowError):
            self.deliver()
        path.chmod(0o600)
        actual = path.rename(self.root / "moved.key")
        path.symlink_to(actual)
        with self.assertRaises(evidence.WorkflowError):
            self.deliver()

    @unittest.skipUnless(os.name == "nt", "Windows DPAPI")
    def test_windows_secret_uses_current_user_dpapi(self):
        self.api("GET", ["trust-key"])
        blob = (self.root / keyring.SLOTS[0]).read_bytes()
        self.assertTrue(blob.startswith(b"AZLDPAPI1"))
        key = Ed25519PrivateKey.from_private_bytes(keyring._dpapi(blob[9:], decrypt=True))
        self.assertEqual(keyring.key_descriptor(key.public_key()), self.api("GET", ["trust-key"]))


if __name__ == "__main__":
    unittest.main()
