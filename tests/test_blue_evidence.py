"""ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag)."""
import base64
from contextlib import redirect_stderr, redirect_stdout
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from authzledger.blue_evidence import MAX_BYTES, correlate_retest
from authzledger.cli import main
from authzledger.studio_platform import platform_route


FIXTURES = Path(__file__).resolve().parents[1] / "examples" / "blue-evidence"
ANCHOR = FIXTURES / "mixed-c-result.json"
SIGNALS = FIXTURES / "control-lab.json"


class BlueEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.anchor = ANCHOR.read_bytes()
        self.signals = json.loads(SIGNALS.read_bytes())

    def project(self):
        return correlate_retest(self.anchor, json.dumps(self.signals).encode())

    def test_pinned_example_and_coverage(self):
        self.assertEqual(sha256(self.anchor).hexdigest(), "e88fa8b182ad1d7b3477516c1432e24a919d1882a4221bf2cb8e25265cff4bd8")
        result = self.project()
        self.assertEqual({key: sample["status"] for key, sample in result["samples"].items()},
                         {"matched": "observed", "telemetry_only": "telemetry_only", "no_data": "unavailable", "foreign": "incomparable"})
        self.assertEqual(set(result["source_coverage"].values()), {"fix_verified", "not_retested"})
        self.assertTrue(result["synthetic"])
        self.assertFalse(result["signed"])

    def test_changed_original_rejected_even_when_json_is_equivalent(self):
        self.anchor += b"\n"
        with self.assertRaisesRegex(ValueError, "anchor"):
            self.project()

    def test_assessment_scope_and_finding_bound_to_source(self):
        for field in ("assessment", "scope", "finding"):
            with self.subTest(field=field):
                self.signals = json.loads(SIGNALS.read_bytes())
                self.signals["expectation"][field] = "foreign"
                with self.assertRaises(ValueError):
                    self.project()

    def test_matching_requires_all_bindings(self):
        for field in ("assessment", "scope", "finding", "source"):
            with self.subTest(field=field):
                self.signals = json.loads(SIGNALS.read_bytes())
                self.signals["controls"]["matched"]["events"][0][field] = "other"
                self.assertEqual(self.project()["samples"]["matched"]["status"], "incomparable")

    def test_window_inclusive_start_exclusive_end(self):
        event = self.signals["controls"]["matched"]["events"][0]
        for stamp, expected in (("2026-11-20T23:25:41+01:00", "observed"),
                                ("2026-11-20T22:26:03Z", "incomparable")):
            event["at"] = stamp
            self.assertEqual(self.project()["samples"]["matched"]["status"], expected)
        event["at"] = "2026-11-20T22:25:50"
        with self.assertRaises(ValueError):
            self.project()

    def test_alert_rule_and_event_locality(self):
        sample = self.signals["controls"]["matched"]
        sample["alerts"][0]["rule"] = "other.rule"
        self.assertEqual(self.project()["samples"]["matched"]["status"], "telemetry_only")
        sample["events"].clear()
        self.assertEqual(self.project()["samples"]["matched"]["status"], "incomparable")

    def test_duplicate_events_and_ambiguous_retest_rejected(self):
        sample = self.signals["controls"]["matched"]
        sample["events"].append(sample["events"][0])
        with self.assertRaisesRegex(ValueError, "unique"):
            self.project()
        sample["events"].pop()
        anchor = json.loads(self.anchor)
        anchor["transitions"].append(anchor["transitions"][0])
        self.anchor = json.dumps(anchor).encode()
        self.signals["anchor_sha256"] = sha256(self.anchor).hexdigest()
        with self.assertRaisesRegex(ValueError, "Ambiguous"):
            self.project()

    def test_invalid_source_status_and_missing_current_digest_rejected(self):
        for changes in ({"status": "fixed"}, {"current_finding_digest": None}, {"status": "not_retested"}):
            with self.subTest(changes=changes):
                anchor = json.loads(ANCHOR.read_bytes())
                anchor["transitions"][0].update(changes)
                self.anchor = json.dumps(anchor).encode()
                self.signals["anchor_sha256"] = sha256(self.anchor).hexdigest()
                with self.assertRaises(ValueError):
                    self.project()

    def test_bounds_unsupported_profiles_and_duplicate_json_keys(self):
        with self.assertRaises(ValueError):
            correlate_retest(self.anchor, b" " * (MAX_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            correlate_retest(self.anchor, b'{"schema":0,"schema":1}')
        self.signals["schema"] = "other"
        with self.assertRaisesRegex(ValueError, "profile"):
            self.project()
        self.signals.update(schema="authzledger.control-signals.v1", dataset="operator-supplied-signals")
        self.assertFalse(self.project()["synthetic"])

    def test_cli_and_studio_route_match_and_refuse_overwrite(self):
        outputs = []
        handler = SimpleNamespace(path="/api/platform/blue-evidence", server=SimpleNamespace(workbench=None),
                                  respond=lambda code, result: outputs.append((code, result)))
        platform_route(handler, {"anchor_b64": base64.b64encode(self.anchor).decode(),
                                 "signals_b64": base64.b64encode(SIGNALS.read_bytes()).decode()})
        stdout = StringIO()
        args = ["assessment", "blue-evidence", str(ANCHOR), str(SIGNALS)]
        with redirect_stdout(stdout):
            self.assertEqual(main(args), 0)
        self.assertEqual(outputs, [(200, json.loads(stdout.getvalue()))])
        with TemporaryDirectory() as folder, redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            path = Path(folder) / "evidence.json"
            self.assertEqual(main(args + ["--out", str(path)]), 0)
            initial = path.read_bytes()
            self.assertNotEqual(main(args + ["--out", str(path)]), 0)
            self.assertEqual(path.read_bytes(), initial)
