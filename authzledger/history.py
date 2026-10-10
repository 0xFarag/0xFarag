"""Local, append-only SQLite history bound to the complete evidence context.

Hashes detect changes against retained anchors; an administrator who replaces
the database and every anchor can replace its history. This is not a timestamp
authority, an execution attestation, or an encrypted credential vault.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .evidence import verify_report
from .model import ContractError, contract_digest, load_contract


class HistoryError(ValueError):
    """History is unsafe, inconsistent, or cannot be persisted durably."""


_GENESIS = "0" * 64
_DOMAIN = b"AuthzLedger:history:v1\n"
_MAX_CONTEXT_BYTES = 8 * 1048576
_SCHEMA = """CREATE TABLE runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    previous_sha256 TEXT NOT NULL,
    record_sha256 TEXT NOT NULL UNIQUE,
    context_json TEXT NOT NULL
)"""
_TRIGGERS = {
    "runs_no_update": "CREATE TRIGGER runs_no_update BEFORE UPDATE ON runs BEGIN SELECT RAISE(ABORT, 'history is append-only'); END",
    "runs_no_delete": "CREATE TRIGGER runs_no_delete BEFORE DELETE ON runs BEGIN SELECT RAISE(ABORT, 'history is append-only'); END",
}


def _canonical(value: object) -> str:
    try:
        result = json.dumps(value, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True, allow_nan=False)
        if len(result.encode("utf-8")) > _MAX_CONTEXT_BYTES:
            raise HistoryError("history context exceeds the 8 MiB limit")
        return result
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, HistoryError):
            raise
        raise HistoryError("history requires finite JSON data") from None


def _digest(record: dict) -> str:
    return hashlib.sha256(_DOMAIN + _canonical(record).encode("utf-8")).hexdigest()


def _report_contract_errors(contract: dict, report: dict) -> list[str]:
    errors = verify_report(report)
    if errors:
        return ["invalid report evidence: " + error for error in errors]
    if report["contract_sha256"] != contract_digest(contract):
        errors.append("report contract digest does not match retained contract")
    if report["target"] != contract["target"] or report["name"] != contract["name"]:
        errors.append("report scope does not match retained contract")
    if [item["id"] for item in report["results"]] != [item["id"] for item in contract["cases"]]:
        errors.append("report cases do not match retained contract order")
        return errors
    for case, result in zip(contract["cases"], report["results"]):
        if any(case[key] != result.get(key) for key in ("id", "identity", "method", "path")):
            errors.append("report case definition does not match retained contract")
        if case["requires"] != result.get("requires", []):
            errors.append("report controls do not match retained contract")
    return errors


def _graph_context_errors(contract: dict, report: dict, graph: dict) -> list[str]:
    from .intelligence import verify_graph
    return ["invalid graph context: " + error for error in verify_graph(graph, contract, report)]


def _secret_free(contract: dict, context: dict) -> None:
    """Refuse accidentally copied resolved identity credentials.

    Contract normalization already forbids literal credentials in identity
    headers. Environment references are retained; their values are never added
    to the context. This check also catches accidental values in graph extras.
    Request bodies and fixture assertions must themselves be non-secret.
    """
    values = set()
    for identity in contract["identities"].values():
        for reference in identity["headers"].values():
            if isinstance(reference, dict):
                value = os.environ.get(reference["env"])
                if value:
                    values.add(value)
                    if value.lower().startswith(("bearer ", "basic ")) and len(value.split(" ", 1)[1]) >= 8:
                        values.add(value.split(" ", 1)[1])
    if not values:
        return
    pending = [context]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str) and any(secret == value or len(secret) >= 8 and secret in value for secret in values):
            raise HistoryError("history context contains a resolved identity credential")


class HistoryStore:
    """Persist complete run context with a transactionally linked SHA-256 chain.

    Each operation opens its own connection, making one store safe to use from
    different Studio job threads. A write verifies the whole chain while
    holding BEGIN IMMEDIATE, then commits exactly one immutable record.
    """

    def __init__(self, path: str | Path):
        if str(path) == ":memory:":
            raise HistoryError("history requires a durable filesystem path")
        self.path = Path(path).expanduser().absolute()
        self._closed = False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            descriptor = None
        except OSError:
            raise HistoryError("history database could not be created") from None
        if descriptor is not None:
            os.close(descriptor)
        self._check_file()
        try:
            with self._connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
                if not tables:
                    connection.execute(_SCHEMA)
                    for statement in _TRIGGERS.values():
                        connection.execute(statement)
                    connection.execute("PRAGMA user_version = 1")
                elif version != 1 or "runs" not in tables:
                    raise HistoryError("unsupported history database schema")
                errors = self._verify(connection)
                if errors:
                    raise HistoryError("history integrity check failed: " + "; ".join(errors))
                connection.commit()
        except sqlite3.Error:
            raise HistoryError("history database could not be initialized") from None

    def _check_file(self) -> None:
        try:
            info = self.path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise HistoryError("history must be a regular file without symbolic or hard links")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise HistoryError("history database must be owned by the current user")
            if stat.S_IMODE(info.st_mode) & 0o077:
                raise HistoryError("history database permissions must exclude group and other access (0600)")
        except OSError:
            raise HistoryError("history database is unavailable") from None

    @contextmanager
    def _connection(self, *, read_only: bool = False):
        if self._closed:
            raise HistoryError("history store is closed")
        self._check_file()
        connection = None
        try:
            connection = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            if read_only:
                connection.execute("PRAGMA query_only = ON")
            yield connection
        except sqlite3.Error:
            raise HistoryError("history database operation failed") from None
        finally:
            if connection is not None:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()

    @staticmethod
    def _decode(row: sqlite3.Row) -> dict:
        context = json.loads(row["context_json"])
        return {"id": row["id"], "created_at": row["created_at"],
                "previous_sha256": row["previous_sha256"], "record_sha256": row["record_sha256"],
                **context}

    @staticmethod
    def _summary(record: dict) -> dict:
        report = record["report"]
        return {key: record[key] for key in ("id", "created_at", "previous_sha256", "record_sha256")} | {
            "name": report["name"], "target": report["target"],
            "contract_sha256": report["contract_sha256"],
            "root_sha256": report["evidence"]["root_sha256"],
            "finished_at": report["finished_at"], "summary": dict(report["summary"]),
        }

    @staticmethod
    def _verify(connection: sqlite3.Connection) -> list[str]:
        errors = []
        if connection.execute("PRAGMA user_version").fetchone()[0] != 1:
            return ["unsupported history schema"]
        if [row[0] for row in connection.execute("PRAGMA quick_check")] != ["ok"]:
            return ["SQLite structural integrity failed"]
        columns = [(row["name"], row["type"], row["notnull"], row["dflt_value"], row["pk"])
                   for row in connection.execute("PRAGMA table_info(runs)")]
        expected = [("id", "INTEGER", 0, None, 1), ("created_at", "TEXT", 1, None, 0),
                    ("previous_sha256", "TEXT", 1, None, 0), ("record_sha256", "TEXT", 1, None, 0),
                    ("context_json", "TEXT", 1, None, 0)]
        if columns != expected:
            return ["history record schema is missing or changed"]
        triggers = {row["name"]: row["sql"] for row in connection.execute("SELECT name, sql FROM sqlite_master WHERE type = 'trigger'")}
        for name, sql in _TRIGGERS.items():
            if triggers.get(name) != sql:
                errors.append("append-only trigger missing or changed: " + name)
        previous = _GENESIS
        count = 0
        for row in connection.execute("SELECT * FROM runs ORDER BY id"):
            count += 1
            prefix = "history record " + str(row["id"]) + ": "
            if row["id"] != count:
                errors.append(prefix + "run sequence contains a gap")
            if row["previous_sha256"] != previous:
                errors.append(prefix + "previous hash does not match")
            try:
                context = json.loads(row["context_json"])
                if not isinstance(context, dict) or set(context) != {"schema_version", "contract", "report", "graph"} or type(context["schema_version"]) is not int or context["schema_version"] != 1:
                    raise HistoryError("invalid retained context shape")
                if _canonical(context) != row["context_json"]:
                    raise HistoryError("retained context is not canonical JSON")
                normalized = load_contract(context["contract"], allow_mutations=True)
                if _canonical(normalized) != _canonical(context["contract"]):
                    raise HistoryError("retained contract is not normalized")
                if not isinstance(context["graph"], dict):
                    raise HistoryError("retained graph must be an object")
                errors.extend(prefix + error for error in _report_contract_errors(normalized, context["report"]))
                errors.extend(prefix + error for error in _graph_context_errors(normalized, context["report"], context["graph"]))
                envelope = {"schema_version": 1, "id": row["id"], "created_at": row["created_at"],
                            "previous_sha256": row["previous_sha256"], "context": context}
                if _digest(envelope) != row["record_sha256"]:
                    errors.append(prefix + "record hash does not match")
            except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
                errors.append(prefix + "retained context is invalid")
            previous = row["record_sha256"]
        sequence = connection.execute("SELECT seq FROM sqlite_sequence WHERE name = 'runs'").fetchone()
        if sequence is not None and sequence[0] != count:
            errors.append("history sequence indicates removed tail records")
        errors.extend(_verify_workflow_chain(connection))
        return errors

    def verify_chain(self, *, expected_root_sha256: str | None = None) -> list[str]:
        """Return integrity errors; optionally bind to an independently kept tail."""
        try:
            with self._connection(read_only=True) as connection:
                connection.execute("BEGIN")
                errors = self._verify(connection)
                if expected_root_sha256 is not None:
                    tail = connection.execute("SELECT record_sha256 FROM runs ORDER BY id DESC LIMIT 1").fetchone()
                    if (tail[0] if tail else _GENESIS) != expected_root_sha256:
                        errors.append("history tail does not match independently retained anchor")
                return errors
        except (HistoryError, sqlite3.Error, TypeError, ValueError, KeyError, IndexError):
            return ["history database could not be verified"]

    def append(self, contract: dict, report: dict, graph: dict, *, expected_previous_sha256: str | None = None) -> dict:
        """Append one complete run; refuse corruption, scope mismatch and secrets."""
        try:
            normalized = load_contract(contract, allow_mutations=True)
        except ContractError as exc:
            raise HistoryError("history requires a valid contract") from exc
        errors = _report_contract_errors(normalized, report)
        if errors:
            raise HistoryError("history report rejected: " + "; ".join(errors))
        if not isinstance(graph, dict):
            raise HistoryError("history graph must be an object")
        errors = _graph_context_errors(normalized, report, graph)
        if errors:
            raise HistoryError("history graph rejected: " + "; ".join(errors))
        context = {"schema_version": 1, "contract": normalized, "report": report, "graph": graph}
        context_json = _canonical(context)
        context = json.loads(context_json)
        _secret_free(normalized, context)
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            errors = self._verify(connection)
            if errors:
                raise HistoryError("history integrity check failed: " + "; ".join(errors))
            tail = connection.execute("SELECT id, record_sha256 FROM runs ORDER BY id DESC LIMIT 1").fetchone()
            run_id = tail["id"] + 1 if tail else 1
            previous = tail["record_sha256"] if tail else _GENESIS
            if expected_previous_sha256 is not None and previous != expected_previous_sha256:
                raise HistoryError("history changed during execution; refresh the baseline before rerunning")
            created_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            record_sha256 = _digest({"schema_version": 1, "id": run_id, "created_at": created_at,
                                     "previous_sha256": previous, "context": context})
            connection.execute("INSERT INTO runs (id, created_at, previous_sha256, record_sha256, context_json) VALUES (?, ?, ?, ?, ?)",
                               (run_id, created_at, previous, record_sha256, context_json))
            connection.commit()
        return self._summary({"id": run_id, "created_at": created_at, "previous_sha256": previous,
                              "record_sha256": record_sha256, **context})

    def list_runs(self, limit: int = 100) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise HistoryError("history limit must be an integer between 1 and 1000")
        with self._connection(read_only=True) as connection:
            connection.execute("BEGIN")
            errors = self._verify(connection)
            if errors:
                raise HistoryError("history integrity check failed: " + "; ".join(errors))
            return [self._summary(self._decode(row)) for row in connection.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))]

    def get_run(self, run_id: int | str) -> dict:
        if isinstance(run_id, str) and run_id.isascii() and run_id.isdigit():
            run_id = int(run_id)
        if type(run_id) is not int or not 1 <= run_id <= 9223372036854775807:
            raise HistoryError("history run ID must be a positive integer")
        with self._connection(read_only=True) as connection:
            connection.execute("BEGIN")
            errors = self._verify(connection)
            if errors:
                raise HistoryError("history integrity check failed: " + "; ".join(errors))
            row = connection.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                raise HistoryError("history run was not found")
            record = self._decode(row)
            return {**record, **self._summary(record)}

    def workflow_snapshot(self, scope_key=None):
        """Verify both chains and return workflow history without network access."""
        return _workflow_history_snapshot(self, scope_key)

    def append_workflow(self, trace, *, assurance_plan_digest, scope_key, cycle,
                        expected_previous_sha256=None, expected_runs_root_sha256=None):
        return _append_workflow(self, trace, assurance_plan_digest=assurance_plan_digest,
                                scope_key=scope_key, cycle=cycle,
                                expected_previous_sha256=expected_previous_sha256,
                                expected_runs_root_sha256=expected_runs_root_sha256)

    def close(self) -> None:
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()


# Additive workflow history has an independent, versioned chain. The legacy
# runs table, PRAGMA version, row bytes and retained report roots are unchanged.
_WORKFLOW_DOMAIN = b"AuthzLedger:workflow-history:v1\n"
_WORKFLOW_SCHEMA = """CREATE TABLE workflow_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    previous_sha256 TEXT NOT NULL,
    record_sha256 TEXT NOT NULL UNIQUE,
    context_json TEXT NOT NULL
)"""
_WORKFLOW_TRIGGERS = {
    "workflow_runs_no_update": "CREATE TRIGGER workflow_runs_no_update BEFORE UPDATE ON workflow_runs BEGIN SELECT RAISE(ABORT, 'workflow history is append-only'); END",
    "workflow_runs_no_delete": "CREATE TRIGGER workflow_runs_no_delete BEFORE DELETE ON workflow_runs BEGIN SELECT RAISE(ABORT, 'workflow history is append-only'); END",
}


def _workflow_digest(envelope):
    return hashlib.sha256(_WORKFLOW_DOMAIN + _canonical(envelope).encode()).hexdigest()


def _workflow_tables(connection):
    return {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _workflow_context_errors(context):
    from .workflows import verify_workflow
    if (not isinstance(context, dict) or set(context) != {"schema_version", "kind", "assurance_plan_digest", "scope_key", "cycle", "trace"}
            or type(context["schema_version"]) is not int or context["schema_version"] != 1
            or context["kind"] != "workflow-assurance-cycle" or type(context["cycle"]) is not int or not 1 <= context["cycle"] <= 100):
        return ["invalid workflow history context"]
    for key in ("assurance_plan_digest", "scope_key"):
        value = context[key]
        if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            return ["invalid workflow history digest"]
    return verify_workflow(context["trace"])


def _verify_workflow_chain(connection):
    tables = _workflow_tables(connection)
    if "workflow_runs" not in tables and "workflow_history_schema" not in tables:
        return []
    if not {"workflow_runs", "workflow_history_schema"} <= tables:
        return ["workflow history extension table missing"]
    if [row[0] for row in connection.execute("SELECT version FROM workflow_history_schema")] != [1]:
        return ["unsupported workflow history extension schema"]
    expected = [("id", "INTEGER", 0, None, 1), ("created_at", "TEXT", 1, None, 0),
                ("previous_sha256", "TEXT", 1, None, 0), ("record_sha256", "TEXT", 1, None, 0),
                ("context_json", "TEXT", 1, None, 0)]
    columns = [(r["name"], r["type"], r["notnull"], r["dflt_value"], r["pk"])
               for r in connection.execute("PRAGMA table_info(workflow_runs)")]
    if columns != expected:
        return ["workflow history schema changed"]
    errors = []
    triggers = {r["name"]: r["sql"] for r in connection.execute("SELECT name, sql FROM sqlite_master WHERE type = 'trigger'")}
    for name, statement in _WORKFLOW_TRIGGERS.items():
        if triggers.get(name) != statement:
            errors.append("workflow append-only trigger missing or changed")
    previous = _GENESIS
    count = 0
    for row in connection.execute("SELECT * FROM workflow_runs ORDER BY id"):
        count += 1
        if row["id"] != count or row["previous_sha256"] != previous:
            errors.append("workflow history sequence or previous hash mismatch")
        try:
            context = json.loads(row["context_json"])
            if _canonical(context) != row["context_json"]:
                errors.append("workflow history context is not canonical")
            errors.extend(_workflow_context_errors(context))
            envelope = {"schema_version": 1, "id": row["id"], "created_at": row["created_at"],
                        "previous_sha256": row["previous_sha256"], "context": context}
            if _workflow_digest(envelope) != row["record_sha256"]:
                errors.append("workflow history record hash mismatch")
        except (ValueError, TypeError, KeyError, RecursionError):
            errors.append("workflow history context invalid")
        previous = row["record_sha256"]
    seq = connection.execute("SELECT seq FROM sqlite_sequence WHERE name = 'workflow_runs'").fetchone()
    if seq is not None and seq[0] != count:
        errors.append("workflow history tail removed")
    return errors


def _workflow_history_snapshot(self, scope_key=None):
    """Verify both histories and return immutable workflow records and anchors."""
    with self._connection(read_only=True) as connection:
        connection.execute("BEGIN")
        errors = self._verify(connection)
        if errors:
            raise HistoryError("history integrity check failed before workflow traffic")
        legacy = connection.execute("SELECT record_sha256 FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        rows = list(connection.execute("SELECT * FROM workflow_runs ORDER BY id")) if "workflow_runs" in _workflow_tables(connection) else []
        return {"runs_root_sha256": legacy[0] if legacy else _GENESIS,
                "workflow_root_sha256": rows[-1]["record_sha256"] if rows else _GENESIS,
                "records": [self._decode(row) for row in rows
                            if scope_key is None or json.loads(row["context_json"])["scope_key"] == scope_key]}


def _append_workflow(self, trace, *, assurance_plan_digest, scope_key, cycle,
                     expected_previous_sha256=None, expected_runs_root_sha256=None):
    context = {"schema_version": 1, "kind": "workflow-assurance-cycle", "assurance_plan_digest": assurance_plan_digest,
               "scope_key": scope_key, "cycle": cycle, "trace": trace}
    if _workflow_context_errors(context):
        raise HistoryError("invalid workflow history context")
    context_json = _canonical(context)
    context = json.loads(context_json)
    _secret_free(trace["plan"]["spec"]["contract"], context)
    with self._connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        if self._verify(connection):
            raise HistoryError("history integrity check failed before workflow append")
        legacy = connection.execute("SELECT record_sha256 FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        if expected_runs_root_sha256 is not None and (legacy[0] if legacy else _GENESIS) != expected_runs_root_sha256:
            raise HistoryError("legacy history changed during workflow execution")
        if "workflow_runs" not in _workflow_tables(connection):
            connection.execute(_WORKFLOW_SCHEMA)
            connection.execute("CREATE TABLE workflow_history_schema (version INTEGER PRIMARY KEY CHECK (version = 1))")
            connection.execute("INSERT INTO workflow_history_schema (version) VALUES (1)")
            for statement in _WORKFLOW_TRIGGERS.values():
                connection.execute(statement)
        tail = connection.execute("SELECT id,record_sha256 FROM workflow_runs ORDER BY id DESC LIMIT 1").fetchone()
        previous = tail["record_sha256"] if tail else _GENESIS
        if expected_previous_sha256 is not None and previous != expected_previous_sha256:
            raise HistoryError("workflow history changed during execution")
        row_id = tail["id"] + 1 if tail else 1
        created = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        anchor = _workflow_digest({"schema_version": 1, "id": row_id, "created_at": created,
                                   "previous_sha256": previous, "context": context})
        connection.execute("INSERT INTO workflow_runs (id,created_at,previous_sha256,record_sha256,context_json) VALUES (?,?,?,?,?)",
                           (row_id, created, previous, anchor, context_json))
        connection.commit()
    return {"id": row_id, "created_at": created, "previous_sha256": previous, "record_sha256": anchor,
            "workflow_digest": trace["workflow_digest"], "scope_key": scope_key, "cycle": cycle}
