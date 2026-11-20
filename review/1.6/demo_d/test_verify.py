import copy
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import verify


class DemoDContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.golden = verify.read_projection(verify.ROOT / "expected" / "projection.json")
        self.actual = copy.deepcopy(self.golden)

    def write(self, name="actual.json", value=None):
        path = self.directory / name
        path.write_text(json.dumps(self.actual if value is None else value), encoding="utf-8")
        return str(path)

    def run_checker(self, *args):
        with redirect_stderr(io.StringIO()) as error, redirect_stdout(io.StringIO()):
            rc = verify.main(list(args))
        return rc, error.getvalue()

    def reject(self, expected_error):
        status, message = self.run_checker(self.write())
        self.assertEqual(1, status)
        self.assertIn(expected_error, message)

    def test_golden_and_reimport(self):
        initial = self.write()
        self.actual["receipts"].reverse()
        self.actual["graph"]["observations"].reverse()
        self.assertEqual((0, ""), self.run_checker(initial, "--reimport", self.write("again.json")))

    def test_original_hash(self):
        self.actual["receipts"][0]["sha256"] = "0" * 64
        self.reject("sha256")

    def test_tampered_source_bytes(self):
        source_dir = self.directory / "sources"
        shutil.copytree(verify.ROOT / "fixtures", source_dir)
        with (source_dir / "ffuf.json").open("ab") as output:
            output.write(b" ")
        code, error = self.run_checker(self.write(), "--sources", str(source_dir))
        self.assertEqual(1, code)
        self.assertIn("SHA-256", error)

    def test_source_locator_and_full_population(self):
        self.actual["graph"]["observations"][0]["record"] = "nmap.xml#/unmapped"
        self.reject("Zeilenmenge")

    def test_duplicate_receipt(self):
        self.actual["receipts"].append(copy.deepcopy(self.actual["receipts"][0]))
        self.reject("doppelte Zeilenidentität")

    def test_duplicate_observation_after_reimport(self):
        initial = self.write()
        row = self.actual["graph"]["observations"][0]
        self.actual["graph"]["observations"].append(copy.deepcopy(row))
        code, error = self.run_checker(initial, "--reimport", self.write("again.json"))
        self.assertEqual(1, code)
        self.assertIn("doppelte Zeilenidentität", error)

    def test_importer_cannot_promote(self):
        for level in ("candidate", "confirmed"):
            with self.subTest(level=level):
                self.actual["graph"]["findings"][0]["evidence_level"] = level
                self.reject("evidence_level")

    def test_out_of_scope_cannot_enter_graph(self):
        self.actual["graph"]["assets"].append("198.51.100.20")
        self.reject("assets")

    def test_out_of_scope_record_must_be_accounted_for(self):
        self.actual["receipts"][1]["records"].pop()
        self.reject("records")

    def test_negative_match_cannot_disappear(self):
        self.actual["graph"]["observations"].pop()
        self.reject("observations")

    def test_negative_match_keeps_boolean(self):
        for wrong in (True, 0, None):
            with self.subTest(wrong=wrong):
                self.actual["graph"]["observations"][3]["asserted"]["matched"] = wrong
                self.reject("matched")

    def test_producer_semantics_retained(self):
        for position, key, wrong in ((0, "method", "probed"), (1, "method", "GET"),
                                     (2, "source_severity", "low")):
            with self.subTest(key=key, position=position):
                self.actual = copy.deepcopy(self.golden)
                self.actual["graph"]["observations"][position]["asserted"][key] = wrong
                self.reject(key)

    def test_same_count_different_finding_provenance(self):
        self.actual["graph"]["findings"][0]["records"][0] = "nuclei.jsonl#line:2"
        self.reject("records")

    def test_duplicate_json_key(self):
        path = self.directory / "invalid.json"
        path.write_text('{"scope":{},"scope":{}}', encoding="utf-8")
        code, error = self.run_checker(str(path))
        self.assertEqual(1, code)
        self.assertIn("Doppelter JSON", error)


if __name__ == "__main__":
    unittest.main()
