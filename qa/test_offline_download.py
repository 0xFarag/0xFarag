"""Exercise the extracted public download. © Nasser Aldin Farag (0xFarag). All rights reserved."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "public" / "downloads" / "pruefwerkzeuge"
PACKAGE = OUT / "AuthzLedger-Offline-Pruefwerkzeuge.zip"


class OfflinePackage(unittest.TestCase):
    def test_rebuild_and_original_sources(self):
        subprocess.run([sys.executable, str(ROOT / "scripts" / "build-pruefwerkzeuge.py"), "--check"], check=True)
        sha = hashlib.sha256(PACKAGE.read_bytes()).hexdigest()
        self.assertEqual((OUT / "SHA256SUMS.txt").read_text(), f"{sha}  {PACKAGE.name}\n")
        with zipfile.ZipFile(PACKAGE) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(set(archive.namelist()), {
                "LICENSE", "README.md", "dateipruefung.py", "file_review.py",
                "rbac/cli.mjs", "rbac/model.mjs", "rbac/retest.mjs", "rbac/README.md"
            })
            self.assertEqual(archive.read("LICENSE"), (ROOT / "LICENSE").read_bytes().replace(b"\r\n", b"\n"))
            for name in ("rbac/cli.mjs", "rbac/model.mjs", "rbac/retest.mjs", "rbac/README.md"):
                self.assertEqual(archive.read(name), (ROOT / "public" / name).read_bytes().replace(b"\r\n", b"\n"))
            self.assertEqual(archive.read("file_review.py"), (ROOT / "tools/pruefwerkzeuge/file_review.py").read_bytes().replace(b"\r\n", b"\n"))

    def test_extracted_rbac_and_hash_cli(self):
        node = shutil.which("node")
        self.assertIsNotNone(node, "Node.js 22+ must be available to exercise the RBAC CLI")
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            with zipfile.ZipFile(PACKAGE) as archive:
                archive.extractall(folder)
            def execute(*args, expected=0, env=None):
                result = subprocess.run(list(args), cwd=folder, text=True, capture_output=True,
                                        env=env, timeout=20, check=False)
                self.assertEqual(result.returncode, expected, result.stderr)
                return json.loads(result.stdout)
            (folder / "case.json").write_text(json.dumps({
                "kind":"User", "name":"test-user", "namespace":"ops",
                "verb":"get", "apiGroup":"", "resource":"pods"
            }), encoding="utf-8")
            (folder / "policy.json").write_bytes(b'{"kind":"List","apiVersion":"v1","items":[]}')
            checked = execute(node, "rbac/cli.mjs", "check", "policy.json", "case.json")
            self.assertEqual(checked["result"]["status"], "no_grant_in_snapshot")
            self.assertEqual(checked["policy_sha256"], hashlib.sha256((folder / "policy.json").read_bytes()).hexdigest())
            contents = b"Public deterministic packaging test.\n"
            (folder / "example.txt").write_bytes(contents)
            hashed = execute(sys.executable,"dateipruefung.py","example.txt")
            self.assertEqual(hashed["file"]["sha256"], hashlib.sha256(contents).hexdigest())
            self.assertEqual(hashed["engine"]["status"], "not_requested")
            missing = execute(sys.executable,"dateipruefung.py","--clamav","example.txt",
                              expected=2,env={**os.environ, "PATH":""})
            self.assertEqual(missing["engine"]["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
