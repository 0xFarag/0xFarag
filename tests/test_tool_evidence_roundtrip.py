"""© Nasser Aldin Farag (0xFarag). All rights reserved."""
import hashlib
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from authzledger.blue_evidence import summarize_telemetry
from authzledger.cli import main
from authzledger.federation_index import build_surface_index
from authzledger.federation_records import validate_federation_receipt
from authzledger.workbench import WorkbenchService, WorkbenchStore
from tests.test_federation_retention import policy


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "offline-tools"
SERVICE = "tcp://192.0.2.10:443"


class ToolEvidenceTests(unittest.TestCase):
    def test_shared_preview_reviewed_retention_and_frozen_index(self):
        files = {"nikto": "nikto.xml", "nessus": "nessus.nessus", "gobuster": "gobuster.txt",
                 "feroxbuster": "feroxbuster.jsonl"}
        args = ["assessment", "federation-preview", "--scope-service", SERVICE]
        for profile, name in files.items():
            args.extend(["--" + profile, str(FIXTURES / name)])
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(args), 0)
        projection = json.loads(output.getvalue())
        self.assertEqual(len(projection["graph"]["observations"]), 4)
        self.assertFalse(projection["graph"]["findings"])
        self.assertNotIn("private-report", output.getvalue())
        with WorkbenchStore(":memory:") as store:
            service = WorkbenchService(store)
            assessment = service.create("Offline inventory", policy([SERVICE]))
            sources = [(profile, (FIXTURES / name).read_bytes()) for profile, name in files.items()]
            result = service.retain_federation(assessment["id"], [SERVICE], sources, expected_revision=1)
            receipt = result["value"]
            self.assertIsNone(validate_federation_receipt(receipt, assessment))
            for source in receipt["sources"]:
                self.assertEqual(source["sha256"], hashlib.sha256(dict(sources)[source["profile"]]).hexdigest())
            index = build_surface_index(service.report(assessment["id"]))
        self.assertEqual(len(index["observations"]), 4)
        self.assertEqual({row["evidence_level"] for row in index["observations"]}, {"hint"})
        self.assertEqual(len(index["services"]), 1)
        self.assertEqual(len(index["endpoints"]), 1)
        self.assertEqual([row["reason"] for row in index["omissions"]], ["unresolved_scope"])
        self.assertNotIn("/docs", json.dumps(receipt))

    def test_telemetry_only_emits_provenance_and_bounded_fields(self):
        raw = (FIXTURES / "telemetry.json").read_bytes()
        with patch("socket.socket", side_effect=AssertionError("network")), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["assessment", "telemetry-summary", str(FIXTURES / "telemetry.json")]), 0)
        summary = json.loads(output.getvalue())
        self.assertEqual(summary, summarize_telemetry(raw))
        self.assertEqual(summary["source_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(summary["counts"], {"detection": 1, "containment": 0, "review": 0})
        self.assertFalse(summary["source_assertions_verified"])
        self.assertNotIn("app.example", output.getvalue())
        self.assertNotIn("r21", output.getvalue())
        self.assertNotIn("retest_status", summary)
        report = json.loads(raw)
        event = report["events"][0]
        for rows in [[event, event], [{**event, "command": "invalid"}], [{**event, "event_type": "unknown"}],
                     [{**event, "observed_at": "2026-02-29T00:00:00Z"}], [{**event, "asset": []}]]:
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                summarize_telemetry(json.dumps({**report, "events": rows}).encode())
