# © Nasser Aldin Farag (0xFarag). All rights reserved.
from contextlib import closing
from copy import deepcopy
from pathlib import Path
import sqlite3
import tempfile
import unittest

from team import proof_packages
from team.evidence_formats import MAX_FILE, MAX_ROWS, canonical, sha
from team.proof_engine import DEPENDENCIES, evaluate, import_source, make_scope, verify_semantics

HEADER = b"Target URL,Place,Parameter,Technique(s),Note(s)\r\n"
CSV = HEADER + (
    b'"https://app.example/hidden/path?q=ABC,DEF",GET,customerPrivate,BE,internal-review-note\r\n'
    b'https://app.example/private,POST,sensitiveField,T,false positive or unexploitable\r\n'
    b'https://outside.example/tickets/555,,,,\r\n'
)
CONTROLS = dict.fromkeys(DEPENDENCIES, True)


class SqlmapReport(unittest.TestCase):
    def test_offline_projection_and_signed_replay(self):
        raw = b"\xef\xbb\xbf" + CSV
        source = import_source("sqlmap", raw)
        self.assertEqual(source["sha256"], sha(raw))
        self.assertEqual(["scanner-signal", "tool-disputed", "no-technique-reported"],
                         [row["rule"] for row in source["observations"]])
        for row in source["observations"]:
            self.assertEqual((row["source"], row["method"], row["path"], row["status"], row["marker"]),
                             ("sqlmap", "UNKNOWN", "/", None, False))
        report = evaluate(make_scope(["app.example"], "Approved report review", 1), [source], CONTROLS)
        self.assertEqual(["inconclusive", "budget_blocked", "out_of_scope"],
                         [finding["status"] for finding in report["findings"]])
        self.assertTrue(verify_semantics(report))
        with tempfile.TemporaryDirectory() as tmp, closing(sqlite3.connect(":memory:")) as db, db:
            pinned = proof_packages.key_history(db, Path(tmp), "alpha")["keys"][0]["jwk"]
            archive = proof_packages.sign_package(db, Path(tmp), "alpha", report, "de")
            checked = proof_packages.verify_package(archive, pinned, "alpha")
        self.assertEqual([source], checked["source"])
        for secret in (b"hidden/path", b"ABC,DEF", b"customerPrivate", b"sensitiveField", b"internal-review-note",
                       b"tickets/555", b"https://app.example"):
            self.assertNotIn(secret, canonical(checked))
            self.assertNotIn(secret, archive)

    def test_projected_rows_cannot_establish_an_authorization_finding(self):
        source = import_source("sqlmap", CSV)
        scope = make_scope(["app.example"], "Offline evidence", 10)
        for change in ({"marker": True}, {"status": 403}, {"method": "GET"},
                       {"rule": "private-note"}, {"path": "/admin"}, {"severity": "critical"}):
            corrupt = deepcopy(source)
            corrupt["observations"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                evaluate(scope, [corrupt], CONTROLS)
        with self.assertRaises(ValueError):
            import_source("sqlmap", canonical({"observations": source["observations"]}))

    def test_invalid_or_ambiguous_sources_and_limits(self):
        invalid = [HEADER, HEADER.replace(b"Parameter", b"param"), b"SQL export",
                   HEADER + b'"https://app.example/unterminated,GET,id,B,',
                   HEADER + b"https://app.example/,GET,id,B,note,extra",
                   HEADER + b"https://admin:secret@app.example/,GET,id,B,",
                   HEADER + b"ftp://app.example/,GET,id,B,", HEADER + b"text,GET,id,B,",
                   HEADER + b"https://app.example/,GET,id,X,", HEADER + b"https://app.example/,GET,,B,",
                   HEADER + b"https://app.example/,GET,id,,", CSV + b" " * MAX_FILE,
                   HEADER + b"https://app.example/,,,,\n" * (MAX_ROWS+1)]
        for i, raw in enumerate(invalid):
            with self.subTest(case=i), self.assertRaisesRegex(ValueError, "source"):
                import_source("sqlmap", raw)

    def test_independent_reports_for_same_host_can_coexist_in_one_run(self):
        a = import_source("sqlmap", CSV)
        b = import_source("sqlmap", CSV.replace(b"hidden/path", b"other/path"))
        report = evaluate(make_scope(["app.example"], "Approved evidence", 10), [a,b], CONTROLS)
        self.assertEqual(len(report["findings"]), 6)
        self.assertEqual(len({f["id"] for f in report["findings"]}), 6)
        self.assertEqual({f["status"] for f in report["findings"]}, {"inconclusive","out_of_scope"})


if __name__ == "__main__":
    unittest.main()
