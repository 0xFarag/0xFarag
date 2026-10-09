"""Persistence, source binding, concurrent appends and malicious history edits."""

import copy
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from authzledger.evidence import seal_report
from authzledger.history import HistoryError, HistoryStore
from authzledger.intelligence import build_graph
from authzledger.model import contract_digest, load_contract


def context():
    contract = load_contract({"version": 1, "name": "Retained scope", "target": "http://127.0.0.1:8765",
        "identities": {"owner": {"headers": {"Authorization": {"env": "AUTHZ_HISTORY_SECRET"}}}},
        "cases": [{"id": "owner", "identity": "owner", "method": "GET", "path": "/own", "expect": {"status": [200]}}]})
    report = seal_report({"schema_version": 1, "tool": {"name": "AuthzLedger", "version": "1.0.0"},
        "name": contract["name"], "target": contract["target"], "contract_sha256": contract_digest(contract),
        "started_at": "2026-10-09T00:00:00Z", "finished_at": "2026-10-09T00:00:01Z",
        "summary": {"pass": 1, "fail": 0, "error": 0, "inconclusive": 0, "total": 1},
        "results": [{"id": "owner", "identity": "owner", "method": "GET", "path": "/own", "requires": [],
            "control_type": "positive", "outcome": "pass", "status": 200, "duration_ms": 1,
            "checks": [{"type": "status", "passed": True}], "reason": "Configured checks passed.",
            "response_sha256": hashlib.sha256(b"{}").hexdigest()}]})
    return contract, report, build_graph(contract, report)


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "history.sqlite3"
        self.store = HistoryStore(self.path)
        self.contract, self.report, self.graph = context()

    def test_roundtrip_durable_history_and_external_anchor(self):
        first = self.store.append(self.contract, self.report, self.graph)
        second = self.store.append(dict(reversed(list(self.contract.items()))), self.report, self.graph)
        self.assertEqual(second["previous_sha256"], first["record_sha256"])
        self.store.close()
        with HistoryStore(self.path) as reopened:
            self.assertEqual(reopened.get_run("1")["contract"], self.contract)
            self.assertEqual(reopened.get_run(2)["report"], self.report)
            self.assertEqual(reopened.get_run(2)["graph"], self.graph)
            self.assertEqual([row["id"] for row in reopened.list_runs()], [2, 1])
            self.assertEqual(reopened.verify_chain(expected_root_sha256=second["record_sha256"]), [])
            self.assertTrue(reopened.verify_chain(expected_root_sha256=first["record_sha256"]))
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_report_and_graph_must_bind_to_retained_scope(self):
        report = copy.deepcopy(self.report)
        report["results"][0]["path"] = "/different"
        report = seal_report(report)
        with self.assertRaises(HistoryError):
            self.store.append(self.contract, report, self.graph)
        graph = copy.deepcopy(self.graph)
        graph["coverage"]["assessed"] = 0
        with self.assertRaises(HistoryError):
            self.store.append(self.contract, self.report, graph)
        self.assertEqual(self.store.list_runs(), [])

    def test_resolved_credentials_are_rejected_even_in_sealed_metadata(self):
        with patch.dict(os.environ, {"AUTHZ_HISTORY_SECRET": "Bearer history-private-secret"}):
            report = seal_report(dict(self.report, accidental_metadata="history-private-secret"))
            graph = build_graph(self.contract, report)
            with self.assertRaisesRegex(HistoryError, "resolved identity credential"):
                self.store.append(self.contract, report, graph)
        self.assertEqual(self.store.list_runs(), [])

    def test_sql_update_and_delete_are_blocked(self):
        self.store.append(self.contract, self.report, self.graph)
        with sqlite3.connect(self.path) as connection:
            for statement in ("UPDATE runs SET created_at = 'changed' WHERE id = 1", "DELETE FROM runs"):
                with self.assertRaisesRegex(sqlite3.IntegrityError, "append-only"):
                    connection.execute(statement)
        self.assertEqual(self.store.verify_chain(), [])

    def _tamper(self, statement):
        with sqlite3.connect(self.path) as connection:
            triggers = [row[0] for row in connection.execute("SELECT sql FROM sqlite_master WHERE type = 'trigger'")]
            connection.execute("DROP TRIGGER runs_no_update")
            connection.execute("DROP TRIGGER runs_no_delete")
            connection.execute(statement)
            for trigger in triggers:
                connection.execute(trigger)

    def test_rejects_tampering_before_next_append_or_reopen(self):
        self.store.append(self.contract, self.report, self.graph)
        self._tamper("UPDATE runs SET created_at = 'changed' WHERE id = 1")
        self.assertTrue(self.store.verify_chain())
        with self.assertRaises(HistoryError):
            self.store.append(self.contract, self.report, self.graph)
        with self.assertRaises(HistoryError):
            HistoryStore(self.path)

    def test_deleted_tail_is_detected_even_when_triggers_are_restored(self):
        self.store.append(self.contract, self.report, self.graph)
        self.store.append(self.contract, self.report, self.graph)
        self._tamper("DELETE FROM runs WHERE id = 2")
        self.assertIn("history sequence indicates removed tail records", self.store.verify_chain())

    def test_concurrent_appends_are_transactionally_ordered(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            records = list(pool.map(lambda _: self.store.append(self.contract, self.report, self.graph), range(12)))
        self.assertEqual({row["id"] for row in records}, set(range(1, 13)))
        self.assertEqual(self.store.verify_chain(), [])
        self.assertEqual(len(self.store.list_runs()), 12)

    def test_stale_expected_tail_is_rejected_without_appending(self):
        self.store.append(self.contract, self.report, self.graph)
        with self.assertRaisesRegex(HistoryError, "changed during execution"):
            self.store.append(self.contract, self.report, self.graph, expected_previous_sha256="0" * 64)
        self.assertEqual(len(self.store.list_runs()), 1)

    def test_database_rejects_unsafe_permissions_links_and_bad_ids(self):
        self.path.chmod(0o644)
        with self.assertRaises(HistoryError):
            HistoryStore(self.path)
        self.path.chmod(0o600)
        linked = self.path.parent / "linked.sqlite3"
        linked.symlink_to(self.path)
        with self.assertRaises(HistoryError):
            HistoryStore(linked)
        linked.unlink()
        os.link(self.path, linked)
        with self.assertRaises(HistoryError):
            HistoryStore(linked)
        linked.unlink()
        for run_id in (True, 0, -1, "1; DROP TABLE runs", 2 ** 64):
            with self.subTest(run_id=run_id), self.assertRaises(HistoryError):
                self.store.get_run(run_id)

    def test_limits_and_missing_records_fail_predictably(self):
        for limit in (0, True, -1, 1001):
            with self.assertRaises(HistoryError):
                self.store.list_runs(limit)
        with self.assertRaisesRegex(HistoryError, "not found"):
            self.store.get_run(1)

    def test_malformed_database_schema_is_reported_without_uncaught_errors(self):
        other = self.path.parent / "wrong-schema.sqlite3"
        descriptor = os.open(other, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
        os.close(descriptor)
        with sqlite3.connect(other) as connection:
            connection.execute("PRAGMA user_version = 1")
            connection.execute("CREATE TABLE runs (unrelated TEXT)")
        with self.assertRaisesRegex(HistoryError, "schema is missing or changed"):
            HistoryStore(other)


if __name__ == "__main__":
    unittest.main()
