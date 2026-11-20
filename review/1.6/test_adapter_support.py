"""Validate the packaged reader matrix offline; --checkout also runs the pinned reader."""

import argparse
import ast
from collections import Counter
import hashlib
import importlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent
CHECKOUT = None


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SupportMatrixTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.matrix = read_json(ROOT / "adapter-support.json")
        evidence = cls.matrix["conformance_evidence"]
        cls.golden = read_json(ROOT / evidence["golden"]["path"])
        cls.profiles = cls.matrix["profiles"]
        cls.evidence = evidence

    def test_profile_ids_and_source_hashes(self):
        self.assertEqual(["nmap", "ffuf", "nuclei"], [row["profile_id"] for row in self.profiles])
        receipts = {r["source"]: r for r in self.golden["receipts"]}
        for row in self.profiles:
            with self.subTest(profile=row["profile_id"]):
                f = row["fixture"]
                self.assertEqual({"nmap": 1, "ffuf": 2, "nuclei": 1}[row["profile_id"]], row["reader_revision"])
                self.assertFalse(row["producer_version_gate"])
                self.assertIsNone(f["producer_version_claimed"])
                self.assertEqual("synthetic", f["origin"])
                self.assertEqual(f["sha256"], sha256(ROOT / f["path"]))
                receipt = receipts[row["logical_source"]]
                self.assertEqual(f["sha256"], receipt["sha256"])
                self.assertEqual(f["records"], dict(Counter(x["disposition"] for x in receipt["records"])))
                self.assertLessEqual(set(f["records"]), set(row["dispositions"]))

    def test_field_matrix_and_levels_match_every_golden_assertion(self):
        for profile in self.profiles:
            source = profile["logical_source"]
            fields = {dst.split(".", 1)[1] for dst in profile["field_map"].values()
                      if dst.startswith("asserted.")}
            observations = [o for o in self.golden["graph"]["observations"]
                            if o["record"].split("#", 1)[0] == source]
            levels = Counter()
            for row in observations:
                self.assertEqual(fields, set(row["asserted"]), source)
                self.assertEqual(profile["record_type"], row["kind"])
                level = row["evidence_level"]
                self.assertIn(level, (None, profile["evidence_ceiling"]))
                levels["null" if level is None else level] += 1
            self.assertEqual(profile["fixture"]["levels"], dict(levels))

    def test_saved_product_projection_and_golden_are_equal(self):
        for key in ("golden", "recorded_product_projection"):
            spec = self.evidence[key]
            path = ROOT / spec["path"]
            self.assertEqual(spec["sha256"], sha256(path), key)
            self.assertEqual(self.golden, read_json(path), key)
        self.assertEqual(self.matrix["projection_format"], self.golden["format"])
        graph = self.golden["graph"]
        rows = [r for src in self.golden["receipts"] for r in src["records"]]
        status = Counter(r["disposition"] for r in rows)
        self.assertEqual(self.evidence["expected"], {
            "sources": len(self.golden["receipts"]), "records": len(rows),
            "accepted": status["accepted"], "out_of_scope": status["out_of_scope"],
            "assets": len(graph["assets"]), "services": len(graph["services"]),
            "endpoints": len(graph["endpoints"]), "observations": len(graph["observations"]),
            "finding_groups": len(graph["findings"]),
            "confirmed": sum(f["evidence_level"] == "confirmed" for f in graph["findings"]),
        })

    def test_references_in_checkout(self):
        if CHECKOUT is None:
            self.skipTest("checkout-dependent test: supply --checkout")
        refs = list(self.evidence["common_tests"]) + [self.matrix["published_reference"]["test"]]
        for p in self.profiles:
            refs.extend(p["tests"])
        by_path = {}
        for ref in refs:
            file, name = ref.split("::")
            if file not in by_path:
                tree = ast.parse((CHECKOUT / file).read_text(encoding="utf-8"))
                by_path[file] = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
            self.assertIn(name, by_path[file], ref)

    def test_pinned_live_reader_and_published_envelope(self):
        if CHECKOUT is None:
            self.skipTest("checkout-dependent test: supply --checkout")
        expected_path = (CHECKOUT / self.matrix["reader_source"]).resolve()
        self.assertEqual(self.matrix["reader_source_sha256"], sha256(expected_path))
        sys.path.insert(0, str(CHECKOUT))
        try:
            reader = importlib.import_module("authzledger.federation_offline")
        finally:
            sys.path.remove(str(CHECKOUT))
        self.assertEqual(expected_path, Path(reader.__file__).resolve())
        self.assertEqual(self.matrix["projection_format"], reader.PROJECTION_FORMAT)
        limits = self.matrix["shared_limits"]
        self.assertEqual(limits["input_bytes_total"], reader.MAX_TOTAL_BYTES)
        self.assertEqual(limits["input_bytes_per_source"], reader.MAX_SOURCE_BYTES)
        self.assertEqual(limits["records_per_source"], reader.MAX_RECORDS)
        allowed = self.golden["scope"]["allowed_services"]
        inputs = [(p["profile_id"], (ROOT / p["fixture"]["path"]).read_bytes()) for p in self.profiles]
        self.assertEqual(self.golden, reader.project_federation(allowed, inputs))
        sample = self.matrix["published_reference"]
        path = CHECKOUT / sample["checkout_path"]
        self.assertEqual(sample["bytes"], path.stat().st_size)
        self.assertEqual(sample["sha256"], sha256(path))
        reference = reader.project_federation(allowed, [("nmap", path.read_bytes())])
        self.assertEqual(sample["expected_federation_records"], len(reference["receipts"][0]["records"]))
        self.assertEqual([], reference["graph"]["observations"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, help="local patched AuthzLedger checkout")
    args = parser.parse_args()
    CHECKOUT = args.checkout.resolve() if args.checkout else None
    unittest.main(argv=[sys.argv[0]], verbosity=2)
