import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from authzledger.cli import main


class EndToEndTests(unittest.TestCase):
    def test_init_requires_both_actors_controls_and_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            path = Path(tmp) / "contract.json"
            argv = ["init", "--target", "http://127.0.0.1:8765", "--out", str(path)]
            self.assertEqual(main(argv), 0)
            initial = path.read_text()
            contract = json.loads(initial)
            self.assertEqual(contract["cases"][-1]["requires"], ["owner-access", "other-access"])
            self.assertEqual(main(argv), 2)
            self.assertEqual(path.read_text(), initial)

    def test_demo_and_cli_integrity_gate(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            root = Path(tmp)
            self.assertEqual(main(["demo", "--out", str(root)]), 0)
            before, after = root / "vulnerable/report.json", root / "fixed/report.json"
            report = json.loads(after.read_text())
            self.assertEqual(report["summary"]["pass"], 6)
            self.assertEqual(main(["verify", str(after), "--anchor", report["evidence"]["root_sha256"]]), 0)
            self.assertEqual(main(["verify", str(after), "--anchor", "0" * 64]), 2)
            self.assertEqual(main(["diff", str(before), str(after), "--out", str(root / "diff")]), 0)
            self.assertEqual(main(["diff", str(after), str(before), "--out", str(root / "regressed")]), 1)
            text = after.read_text()
            self.assertNotIn("Bearer ", text)
            self.assertEqual(main(["plan", str(root / "contract.json")]), 0)
            report["summary"]["pass"] = 999
            after.write_text(json.dumps(report))
            self.assertEqual(main(["verify", str(after)]), 2)

    def test_bad_json_returns_configuration_error(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()):
            path = Path(tmp) / "input.json"
            path.write_text("[1,2,3]")
            self.assertEqual(main(["verify", str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
