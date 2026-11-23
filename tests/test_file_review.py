"""© Nasser Aldin Farag (0xFarag). All rights reserved."""
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from authzledger.cli import main
from authzledger.file_review import _scan_status, review_file


def summary(detected=0):
    return f"Known viruses: 42\nEngine version: 1.4.6\nScanned files: 1\nInfected files: {detected}\n"


class LocalFileReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.source = self.folder / "private ; sample.txt"
        self.source.write_bytes(b"benign sample\r\n")

    def test_hashes_and_missing_engine_return_separate_results(self):
        raw = self.source.read_bytes()
        with patch("authzledger.file_review._engine_path", side_effect=AssertionError("engine")):
            result = review_file(self.source)
        self.assertEqual(result["file"], {"size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                                         "sha1": hashlib.sha1(raw, usedforsecurity=False).hexdigest(),
                                         "md5": hashlib.md5(raw, usedforsecurity=False).hexdigest()})
        self.assertEqual(result["engine"]["status"], "not_requested")
        with patch("authzledger.file_review._engine_path", return_value=None), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["file-review", str(self.source), "--clamav"]), 2)
        self.assertEqual(json.loads(output.getvalue())["engine"]["status"], "unavailable")
        self.assertNotIn("private", output.getvalue())

    def test_file_limits_and_empty_file_keep_correct_hash(self):
        with patch("authzledger.file_review.MAX_SCAN", 2):
            result = review_file(self.source, clamav=True)
        self.assertEqual(result["engine"]["reason"], "input_exceeds_scan_limit")
        self.assertEqual(result["file"]["size_bytes"], self.source.stat().st_size)
        with patch("authzledger.file_review.MAX_FILE", 2), self.assertRaises(ValueError):
            review_file(self.source)
        self.source.write_bytes(b"")
        result = review_file(self.source, clamav=True)
        self.assertEqual(result["file"]["sha256"], hashlib.sha256(b"").hexdigest())
        self.assertEqual(result["engine"]["reason"], "empty_input")

    def test_scanner_contract_with_conservative_evidence_states(self):
        matched = "stdin: Local.Test FOUND\n" + summary(1)
        self.assertEqual(_scan_status(1, matched)["status"], "detection_reported")
        self.assertEqual(_scan_status(1, matched.replace("Scanned files: 1", "Scanned files: 0"))["status"], "detection_reported")
        self.assertEqual(_scan_status(0, "stdin: OK\n" + summary())["status"], "no_detection_reported")
        clean_with_objects = "stdin: OK\n" + summary().replace("Scanned files: 1", "Scanned files: 2")
        self.assertEqual(_scan_status(0, clean_with_objects)["status"], "no_detection_reported")
        for code, message in [(1, matched.replace("Local.Test", "Heuristics.Limits.Exceeded.MaxFileSize")),
                              (1, matched.replace("Local.Test", "Heuristics.Encrypted.Zip")),
                              (0, "stdin: OK\n" + summary().replace("Scanned files: 1", "Scanned files: 0")),
                              (0, "stdin: OK\n" + summary().replace("Known viruses: 42", "Known viruses: 0")),
                              (0, "WARNING: unknown\nstdin: OK\n" + summary()), (0, "stdin: OK"),
                              (0, matched), (1, "stdin: OK\n" + summary())]:
            with self.subTest(code=code, message=message):
                self.assertEqual(_scan_status(code, message)["status"], "incomplete")
        self.assertEqual(_scan_status(2, "database error")["status"], "error")

    @unittest.skipIf(os.name == "nt", "POSIX test fixture executable")
    def test_bounded_process_receives_the_hashed_bytes_only(self):
        fake = self.folder / "clamscan-test-double"
        fake.write_text(
            "#!/usr/bin/env python3\nimport sys,os\n"
            "assert sys.argv[-1] == '-' and '--alert-exceeds-max=yes' in sys.argv\n"
            "assert not any('sample.txt' in arg for arg in sys.argv)\n"
            "assert sys.stdin.buffer.read() == b'benign sample\\r\\n'\n"
            "print(" + repr("stdin: OK\n" + summary()) + ")\n"
        )
        fake.chmod(0o700)
        with patch("authzledger.file_review._engine_path", return_value=str(fake)):
            result = review_file(self.source, clamav=True)
            self.assertEqual(result["engine"], {"name": "ClamAV", "status": "no_detection_reported", "engine_version":"1.4.6"})
            fake.write_text("#!/usr/bin/env python3\nprint('A'*10000)\n")
            with patch("authzledger.file_review.MAX_OUTPUT", 120):
                self.assertEqual(review_file(self.source, clamav=True)["engine"]["reason"], "output_limit")
            fake.write_text("#!/usr/bin/env python3\nimport time\ntime.sleep(2)\n")
            with patch("authzledger.file_review.PROCESS_TIMEOUT", .15):
                self.assertEqual(review_file(self.source, clamav=True)["engine"]["reason"], "timeout")
