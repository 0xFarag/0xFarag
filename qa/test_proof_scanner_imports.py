# © Nasser Aldin Farag (0xFarag). All rights reserved.
import copy
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from team import proof_packages
from team.evidence_formats import canonical
from team.proof_engine import DEPENDENCIES, evaluate, import_source, make_scope, verify_semantics


FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name):
    return (FIXTURES / name).read_bytes()


class ScannerImports(unittest.TestCase):
    def test_native_reports_remain_unconfirmed_under_fully_effective_controls(self):
        sources = [import_source(fmt, fixture(file)) for fmt, file in (
            ("nessus", "nessus.nessus"), ("nikto", "nikto.xml"), ("cobalt", "cobalt.json"))]
        scope = make_scope(["app.example", "192.0.2.1"], "Offline review", 7)
        report = evaluate(scope, sources, dict.fromkeys(DEPENDENCIES, True))
        self.assertEqual([f["status"] for f in report["findings"]],
                         ["inconclusive", "inconclusive", "out_of_scope", "inconclusive"])
        self.assertTrue(all(f["minimalReproducer"] is None for f in report["findings"]))
        self.assertTrue(verify_semantics(report))
        self.assertEqual(sources[0]["observations"][0]["rule"], "plugin-123-tcp-443")
        self.assertEqual(sources[0]["observations"][0]["severity"], "info")
        self.assertEqual(sources[2]["observations"][0]["rule"], "detection")
        for raw_field in (b"PRIVATE_PAYLOAD", b"private-path", b'"r21"'):
            self.assertNotIn(raw_field, canonical(report))
        for i in range(3):
            for change in ({"marker": True}, {"method": "GET", "status": 403}):
                tampered = copy.deepcopy(sources)
                tampered[i]["observations"][0].update(change)
                with self.subTest(source=i, change=change), self.assertRaises(ValueError):
                    evaluate(scope, tampered, dict.fromkeys(DEPENDENCIES, True))

    def test_new_formats_refuse_alternate_observation_envelopes(self):
        for fmt, label in (("nessus", "Nessus"), ("nikto", "Nikto"), ("cobalt", "Cobalt Strike telemetry")):
            row = {"source": label, "method": "GET", "host": "app.example", "rule": "audit", "path": "/",
                   "status": 403, "marker": True, "id": "assertion"}
            with self.subTest(fmt=fmt), self.assertRaises(ValueError):
                import_source(fmt, canonical({"observations": [row]}))

    def test_invalid_report_or_ambiguous_metadata_fails_closed(self):
        cases = json.loads(fixture("invalid-cases.json"))
        for case in cases:
            if case["source"] in ("nessus", "cobalt"):
                with self.subTest(case=case), self.assertRaises(ValueError):
                    import_source(case["source"], case["text"].encode())
        for fmt, name in (("nessus", "nessus.nessus"), ("nikto", "nikto.xml")):
            with self.subTest(fmt=fmt), self.assertRaises(ValueError):
                import_source(fmt, b"<!DOCTYPE nmaprun>" + fixture(name))
        telemetry = json.loads(fixture("cobalt.json"))
        telemetry["events"] *= 2
        with self.assertRaises(ValueError):
            import_source("cobalt", canonical(telemetry))
        for before, after in ((b'port="443"', b'port="65536"'), (b'"tcp"', b'"ftp"')):
            with self.assertRaises(ValueError):
                import_source("nessus", fixture("nessus.nessus").replace(before, after))

    def test_nuclei_negative_match_is_excluded_from_mixed_jsonl(self):
        match = {"template-id": "positive", "type": "http", "matcher-status": True, "matched-at": "https://app.example/"}
        miss = {**match, "template-id": "negative", "matcher-status": False}
        src = import_source("nuclei", canonical(miss) + b"\n" + canonical(match))
        self.assertEqual([r["rule"] for r in src["observations"]], ["positive"])
        with self.assertRaises(ValueError):
            import_source("nuclei", canonical(miss))

    def test_source_severity_is_optional_and_checked(self):
        match = {"template-id": "audit", "type": "http", "matcher-status": True, "matched-at": "https://app.example/"}
        self.assertNotIn("severity", import_source("nuclei", canonical(match))["observations"][0])
        for severity in ("unknown", "critical"):
            src = import_source("nuclei", canonical({**match, "info": {"severity": severity}}))
            self.assertEqual(severity, src["observations"][0]["severity"])
        with self.assertRaises(ValueError):
            import_source("nuclei", canonical({**match, "info": {"severity": "unexpected"}}))
        for severity, expected in enumerate(("info", "low", "medium", "high", "critical")):
            raw = fixture("nessus.nessus").replace(b'severity="0"', f'severity="{severity}"'.encode())
            self.assertEqual(expected, import_source("nessus", raw)["observations"][0]["severity"])

    def test_signed_scanner_handover_replays_with_pinned_workspace_key(self):
        sources = [import_source(fmt, fixture(name)) for fmt, name in
                   (("nessus", "nessus.nessus"), ("nikto", "nikto.xml"), ("cobalt", "cobalt.json"))]
        match = {"template-id": "audit", "type": "http", "matcher-status": True,
                 "matched-at": "https://app.example/", "info": {"severity": "critical"}}
        sources.append(import_source("nuclei", canonical(match)))
        scope = make_scope(["app.example", "192.0.2.1", "beta.example"], "Offline review", 10)
        report = evaluate(scope, sources, dict.fromkeys(DEPENDENCIES, True))
        with tempfile.TemporaryDirectory() as directory, closing(sqlite3.connect(":memory:")) as db, db:
            pinned = proof_packages.key_history(db, Path(directory), "alpha")["keys"][0]["jwk"]
            archive = proof_packages.sign_package(db, Path(directory), "alpha", report, "en")
            checked = proof_packages.verify_package(archive, pinned, "alpha")
        self.assertEqual(report["source"], checked["source"])
        self.assertEqual(report["evidenceRoot"], checked["evidenceRoot"])
        self.assertEqual({"inconclusive"}, {f["status"] for f in checked["findings"]})

    def test_suite_limits_apply_to_new_import_formats(self):
        item = b'<item id="1"/>'
        raw = b'<niktoscan><scandetails targethostname="app.example">' + item * 1001 + b'</scandetails></niktoscan>'
        with self.assertRaises(ValueError):
            import_source("nikto", raw)
        too_large = fixture("nessus.nessus") + b" " * (1024 * 1024)
        with self.assertRaises(ValueError):
            import_source("nessus", too_large)


if __name__ == "__main__":
    unittest.main()
