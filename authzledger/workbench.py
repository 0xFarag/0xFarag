"""Durable local assessment services shared by Studio and CLI.

Editable revisions and immutable evidence are deliberately separate. Credentials
are resolved only by the existing execution services and are never a workspace
setting. Interrupted jobs are not automatically replayed.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .oracles import canonical, digest, seal


class WorkbenchError(ValueError):
    pass


def _now():
    return datetime.now(timezone.utc).isoformat()


def _json(value):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        raise WorkbenchError("workspace_requires_finite_json") from None
    if len(raw.encode()) > 16 * 1024 * 1024:
        raise WorkbenchError("workspace_artifact_size_limit")
    return raw


def _text(value, name, maximum=256):
    if not isinstance(value, str) or not value.strip() or len(value) > maximum or any(ord(c) < 32 or ord(c) == 127 or 0xD800 <= ord(c) <= 0xDFFF for c in value):
        raise WorkbenchError("invalid_" + name)
    return value


def _secret_free(value):
    """Refuse literal credential slots and echoes of referenced env secrets."""
    _json(value)  # Reject cycles, non-finite data and oversized inputs first.
    pending = [value]
    secrets = set()
    strings = []
    sensitive = {"authorization", "proxy-authorization", "cookie", "set-cookie", "password", "passwd", "access_token", "refresh_token", "client_secret", "api_key", "x-api-key"}
    while pending:
        part = pending.pop()
        if isinstance(part, dict):
            if set(part) == {"env"} and isinstance(part["env"], str):
                resolved = os.environ.get(part["env"])
                if resolved:
                    secrets.add(resolved)
                    if " " in resolved:
                        secrets.add(resolved.split(" ", 1)[1])
            for key, item in part.items():
                if str(key).lower() in sensitive:
                    reference = isinstance(item, dict) and set(item) == {"env"} and isinstance(item["env"], str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", item["env"])
                    redacted = item is None or isinstance(item, str) and item in {"", "[REDACTED]", "<redacted>", "redacted"}
                    if not reference and not redacted:
                        raise WorkbenchError("literal_credentials_cannot_be_persisted")
                pending.append(item)
        elif isinstance(part, (list, tuple)):
            pending.extend(part)
        elif isinstance(part, str):
            strings.append(part)
    if any(secret and (secret == text or len(secret) >= 8 and secret in text) for secret in secrets for text in strings):
        raise WorkbenchError("credential_echo_cannot_be_persisted")


def _engagement(value):
    if value is None:
        return {}
    if not isinstance(value, dict) or set(value) - {"reference", "roe_ref", "notes"}:
        raise WorkbenchError("invalid_engagement_metadata")
    _secret_free(value)
    return {key: _text(item, "engagement_" + key, 2000 if key == "notes" else 256) for key, item in value.items()}


class WorkbenchStore:
    def __init__(self, path=":memory:"):
        self.path = str(path)
        self.persistent = self.path != ":memory:"
        self._lock = threading.RLock()
        self._execution_lock = threading.Lock()
        if self.persistent:
            target = Path(self.path).absolute()
            if any(p.is_symlink() for p in (target, *target.parents)):
                raise WorkbenchError("workspace_symlink_refused")
            target.parent.mkdir(parents=True, exist_ok=True)
            if not target.exists():
                fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            self.path = str(target)
            # Both services share the 1.1 database. Let its existing, strict
            # initializer establish/verify that schema before adding tables.
            from .history import HistoryStore
            HistoryStore(self.path).close()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None, timeout=10)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA secure_delete=ON")
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS wb_assessments(id TEXT PRIMARY KEY, revision INTEGER NOT NULL, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS wb_revisions(id TEXT NOT NULL, revision INTEGER NOT NULL, value TEXT NOT NULL, PRIMARY KEY(id,revision));
        CREATE TABLE IF NOT EXISTS wb_artifacts(sequence INTEGER PRIMARY KEY AUTOINCREMENT, artifact_id TEXT NOT NULL UNIQUE, assessment_id TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, FOREIGN KEY(assessment_id) REFERENCES wb_assessments(id));
        CREATE TABLE IF NOT EXISTS wb_jobs(request_id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, plan_id TEXT NOT NULL, state TEXT NOT NULL, artifact_id TEXT, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS wb_schedules(id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, value TEXT NOT NULL);
        CREATE TRIGGER IF NOT EXISTS wb_artifacts_no_update BEFORE UPDATE ON wb_artifacts BEGIN SELECT RAISE(ABORT,'immutable workspace artifact'); END;
        CREATE TRIGGER IF NOT EXISTS wb_artifacts_no_delete BEFORE DELETE ON wb_artifacts BEGIN SELECT RAISE(ABORT,'immutable workspace artifact'); END;
        CREATE TRIGGER IF NOT EXISTS wb_revisions_no_update BEFORE UPDATE ON wb_revisions BEGIN SELECT RAISE(ABORT,'immutable workspace revision'); END;
        CREATE TRIGGER IF NOT EXISTS wb_revisions_no_delete BEFORE DELETE ON wb_revisions BEGIN SELECT RAISE(ABORT,'immutable workspace revision'); END;
        """)
        # Existing running jobs remain ambiguous after a crash. Never claim they
        # completed, resend them, or invalidate another process's active job.

    def close(self):
        with self._lock:
            self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @contextmanager
    def execution_guard(self):
        """Hold one workspace-wide execution capability, released by OS on crash."""
        if not self._execution_lock.acquire(blocking=False):
            raise WorkbenchError("assessment_execution_already_running")
        fd = None
        locked = False
        try:
            if self.persistent:
                try:
                    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
                    fd = os.open(self.path + ".execution.lock", flags, 0o600)
                    if os.name == "nt":
                        import msvcrt
                        if os.fstat(fd).st_size < 1:
                            os.write(fd, b"0")
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                except OSError:
                    raise WorkbenchError("assessment_execution_already_running") from None
            yield
        finally:
            if fd is not None:
                if locked:
                    if os.name == "nt":
                        import msvcrt
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            self._execution_lock.release()

    def _read(self, assessment_id):
        row = self._db.execute("SELECT revision,value FROM wb_assessments WHERE id=?", (assessment_id,)).fetchone()
        if row is None:
            raise WorkbenchError("unknown_assessment")
        try:
            value = json.loads(row["value"])
            unsigned = {k: v for k, v in value.items() if k != "revision_digest"}
            latest = self._db.execute("SELECT revision,value FROM wb_revisions WHERE id=? ORDER BY revision DESC LIMIT 1", (assessment_id,)).fetchone()
            if (value["id"] != assessment_id or value["revision"] != row["revision"] or latest is None
                    or latest["revision"] != row["revision"] or latest["value"] != row["value"]
                    or seal("workbench-revision", unsigned, "revision_digest") != value):
                raise ValueError
        except (TypeError, ValueError, KeyError, AttributeError, RecursionError):
            raise WorkbenchError("workspace_revision_corrupt") from None
        return value

    def _revision(self, value):
        value = copy.deepcopy(value)
        value.pop("revision_digest", None)
        value = seal("workbench-revision", value, "revision_digest")
        raw = _json(value)
        self._db.execute("INSERT INTO wb_revisions VALUES(?,?,?)", (value["id"], value["revision"], raw))
        self._db.execute("INSERT INTO wb_assessments VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,value=excluded.value", (value["id"], value["revision"], raw))
        return value

    def create(self, title, scope, engagement=None):
        from .scope import validate_scope
        _text(title, "assessment_title")
        scope = validate_scope(scope)
        _secret_free(scope)
        value = {"schema_version": 1, "kind": "workbench-assessment", "id": "assessment-" + uuid.uuid4().hex,
                 "title": title, "scope": scope, "revision": 1, "created_at": _now(), "updated_at": _now(),
                 "storage": "persistent" if self.persistent else "session_only", "artifact_head": "0" * 64,
                 "engagement": _engagement(engagement)}
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                result = self._revision(value)
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return result

    def get(self, assessment_id):
        return self.snapshot(assessment_id)[0]

    def list(self):
        with self._lock:
            self._db.execute("BEGIN")
            try:
                ids = [r[0] for r in self._db.execute("SELECT id FROM wb_assessments ORDER BY rowid DESC LIMIT 1000")]
                result = [self._read(aid) for aid in ids]
                self._db.execute("COMMIT")
                return result
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def update(self, assessment_id, patch, expected_revision):
        if not isinstance(patch, dict) or not patch or set(patch) - {"title", "scope", "engagement", "finding_annotations"}:
            raise WorkbenchError("invalid_assessment_patch")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                value = self._read(assessment_id)
                if type(expected_revision) is not int or value["revision"] != expected_revision:
                    raise WorkbenchError("assessment_revision_conflict")
                if "title" in patch:
                    value["title"] = _text(patch["title"], "assessment_title")
                if "engagement" in patch:
                    value["engagement"] = _engagement(patch["engagement"])
                if "scope" in patch:
                    if self._db.execute("SELECT 1 FROM wb_jobs WHERE assessment_id=? AND state='running' LIMIT 1", (assessment_id,)).fetchone():
                        raise WorkbenchError("scope_change_requires_stopped_execution")
                    from .scope import validate_scope
                    value["scope"] = validate_scope(patch["scope"])
                    _secret_free(value["scope"])
                if "finding_annotations" in patch:
                    from .platform_reports import freeze_platform
                    value["finding_annotations"] = copy.deepcopy(patch["finding_annotations"])
                    records = self._artifacts(value)
                    _secret_free({"assessment": value, "artifacts": records})
                    freeze_platform(value, records)
                value["revision"] += 1
                value["updated_at"] = _now()
                result = self._revision(value)
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return result

    def add_artifact(self, assessment_id, kind, value, expected_revision=None, *, deduplicate=False):
        _text(kind, "artifact_kind", 80)
        if not isinstance(value, dict):
            raise WorkbenchError("artifact_requires_object")
        _secret_free(value)
        _json(value)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                current = self._read(assessment_id)
                records = self._artifacts(current)
                if expected_revision is not None and (type(expected_revision) is not int or current["revision"] != expected_revision):
                    raise WorkbenchError("assessment_revision_conflict")
                if deduplicate:
                    prior = next((item for item in records if item["kind"] == kind and item["value"] == value), None)
                    if prior is not None:
                        self._db.execute("COMMIT")
                        return prior
                previous = current["artifact_head"]
                artifact = seal("workbench-artifact", {"artifact_id": "artifact-" + uuid.uuid4().hex,
                    "assessment_id": assessment_id, "kind": kind, "created_at": _now(), "assessment_revision": current["revision"],
                    "scope_digest": current["scope"].get("scope_digest"), "previous_digest": previous, "value": copy.deepcopy(value)}, "artifact_digest")
                self._db.execute("INSERT INTO wb_artifacts(artifact_id,assessment_id,kind,value) VALUES(?,?,?,?)", (artifact["artifact_id"], assessment_id, kind, _json(artifact)))
                current["artifact_head"] = artifact["artifact_digest"]
                current["revision"] += 1
                current["updated_at"] = _now()
                self._revision(current)
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return artifact

    def _artifacts(self, current):
        records = self._db.execute("SELECT artifact_id,assessment_id,kind,value FROM wb_artifacts WHERE assessment_id=? ORDER BY sequence", (current["id"],)).fetchall()
        previous = "0" * 64
        values = []
        try:
            for row in records:
                item = json.loads(row["value"])
                unsigned = {k: v for k, v in item.items() if k != "artifact_digest"}
                if (item["assessment_id"] != current["id"] or item["artifact_id"] != row["artifact_id"] or item["kind"] != row["kind"]
                        or item["previous_digest"] != previous or seal("workbench-artifact", unsigned, "artifact_digest") != item):
                    raise ValueError
                previous = item["artifact_digest"]
                values.append(item)
            if current.get("artifact_head", "0" * 64) != previous:
                raise ValueError
        except (TypeError, ValueError, KeyError, AttributeError, RecursionError):
            raise WorkbenchError("workspace_evidence_chain_corrupt") from None
        return values

    def snapshot(self, assessment_id):
        """Read revision and complete evidence chain from one SQLite snapshot."""
        with self._lock:
            self._db.execute("BEGIN")
            try:
                current = self._read(assessment_id)
                artifacts = self._artifacts(current)
                self._db.execute("COMMIT")
                return copy.deepcopy(current), artifacts
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def artifacts(self, assessment_id, kind=None):
        _, records = self.snapshot(assessment_id)
        return records if kind is None else [v for v in records if v["kind"] == kind]

    def artifact(self, assessment_id, artifact_id):
        values = [v for v in self.artifacts(assessment_id) if v["artifact_id"] == artifact_id]
        if len(values) != 1:
            raise WorkbenchError("unknown_assessment_artifact")
        return values[0]


class WorkbenchService:
    def __init__(self, store):
        self.store = store

    def capabilities(self):
        from .detectors import catalog
        return {"schema_version": 1, "checks": catalog(), "persistent": self.store.persistent,
                "workflow": ["discover", "assess", "investigate", "retest", "report", "proof"],
                "scheduling": "bounded_local_runner", "credentials": "runtime_only",
                "unknown_surface": "unknown", "network_engine": "shared_execution_context",
                "import_adapters": ["nmap-xml-v1", "nuclei-jsonl-v1"],
                "playbooks": "static_preapproved_shared_budget", "finding_reviews": "source_bound_annotations"}

    def create(self, title, scope, engagement=None):
        return self.store.create(title, scope, engagement)

    def list(self):
        return self.store.list()

    def update(self, assessment_id, patch, expected_revision):
        return self.store.update(assessment_id, patch, expected_revision)

    def annotate(self, assessment_id, annotations, expected_revision):
        return self.store.update(assessment_id, {"finding_annotations": annotations}, expected_revision)

    def get(self, assessment_id):
        assessment, artifacts = self.store.snapshot(assessment_id)
        return {"assessment": assessment, "artifacts": artifacts, "coverage": self.coverage(artifacts),
                "schedules": self.schedules(assessment_id), "jobs": self.jobs(assessment_id)}

    def jobs(self, assessment_id):
        with self.store._lock:
            return [dict(row) for row in self.store._db.execute("SELECT request_id,plan_id,state,artifact_id,created_at FROM wb_jobs WHERE assessment_id=? ORDER BY rowid", (assessment_id,))]

    def recover_interrupted(self, assessment_id):
        """Explicitly classify abandoned claims; never repeat their requests."""
        with self.store.execution_guard(), self.store._lock:
            self.store._db.execute("BEGIN IMMEDIATE")
            try:
                self.store._read(assessment_id)
                self.store._db.execute("UPDATE wb_jobs SET state='interrupted' WHERE assessment_id=? AND state='running'", (assessment_id,))
                rows = self.store._db.execute("SELECT id,value FROM wb_schedules WHERE assessment_id=?", (assessment_id,)).fetchall()
                for row in rows:
                    value = json.loads(row["value"])
                    if value["state"] == "running":
                        value.update(state="blocked", reason="interrupted_execution_requires_review")
                        self.store._db.execute("UPDATE wb_schedules SET value=? WHERE id=?", (_json(value), row["id"]))
                self.store._db.execute("COMMIT")
            except BaseException:
                self.store._db.execute("ROLLBACK")
                raise
        return {"jobs": self.jobs(assessment_id), "schedules": self.schedules(assessment_id)}

    @staticmethod
    def coverage(artifacts):
        plans = [a for a in artifacts if a["kind"] in {"check-plan", "retest-plan", "discovery-plan", "playbook-plan"}]
        executions = [a for a in artifacts if a["kind"] in {"check-execution", "retest-execution", "discovery-execution", "playbook-execution"}]
        findings = [f for a in executions for f in a["value"].get("findings", [])]
        findings.extend(f for a in executions if a["kind"] == "playbook-execution" for step in a["value"]["steps"]
                        for f in (step.get("execution") or {}).get("findings", []))
        return {"plans": len(plans), "executions": len(executions), "confirmed": sum(f.get("status", f.get("evidence_level")) == "confirmed" for f in findings),
                "inconclusive": sum(f.get("status", f.get("evidence_level")) == "inconclusive" for f in findings),
                "unknown_surface": "unknown", "denominator": "retained explicit plans; not total application security"}

    def import_source(self, assessment_id, raw, profile, *, source_origin=None, response_bytes=None, expected_revision=None):
        from .imports import parse_import
        current = self.store.get(assessment_id)
        if profile in {"nmap-xml-v1", "nuclei-jsonl-v1"}:
            from .adapters import import_adapter
            if source_origin is not None or response_bytes is not None:
                raise WorkbenchError("adapter_does_not_accept_http_pair_options")
            batch = import_adapter(raw, profile, scope=current["scope"])
            kind = "adapter-receipt"
        else:
            batch = parse_import(raw, profile, source_origin=source_origin, response_bytes=response_bytes)
            kind = "import-batch"
        record = self.store.add_artifact(assessment_id, kind, batch, expected_revision=expected_revision if expected_revision is not None else current["revision"])
        self.refresh_catalog(assessment_id)
        return record

    def refresh_catalog(self, assessment_id, declarations=None):
        from .surface import build_catalog, merge_catalogs
        current, records = self.store.snapshot(assessment_id)
        imports = [a["value"] for a in records if a["kind"] == "import-batch"]
        catalog = build_catalog(imports, declarations=declarations, scope=current["scope"])
        previous = next((i for i in range(len(records)-1, -1, -1) if records[i]["kind"] == "surface-catalog"), -1)
        if previous >= 0:
            catalog = merge_catalogs([records[previous]["value"], catalog], scope=current["scope"])
        for item in records[previous+1:]:
            if item["kind"] in {"discovery-execution", "adapter-receipt"}:
                catalog = merge_catalogs([catalog, item["value"]["catalog"]], scope=current["scope"])
            elif item["kind"] == "playbook-execution":
                for step in item["value"]["steps"]:
                    executed = step.get("execution")
                    if isinstance(executed, dict) and executed.get("kind") == "discovery-execution":
                        catalog = merge_catalogs([catalog, executed["catalog"]], scope=current["scope"])
        return self.store.add_artifact(assessment_id, "surface-catalog", catalog, expected_revision=current["revision"])

    def delta(self, assessment_id, baseline_catalog_id, current_catalog_id, checks=None):
        from .surface import diff_catalogs, plan_delta_checks
        sources = [self.store.artifact(assessment_id, value) for value in (baseline_catalog_id, current_catalog_id)]
        if any(value["kind"] != "surface-catalog" for value in sources):
            raise WorkbenchError("surface_catalog_required")
        delta = diff_catalogs(*(value["value"] for value in sources))
        plan = plan_delta_checks(delta, checks) if checks is not None else None
        result = {"delta": self.store.add_artifact(assessment_id, "surface-delta", delta), "check_plan": None}
        if plan is not None:
            result["check_plan"] = self.store.add_artifact(assessment_id, "delta-check-plan", plan)
        return result

    def knowledge(self, assessment_id, observations, pack=None):
        from .knowledge import match_cve_candidates
        result = match_cve_candidates(observations, pack)
        return self.store.add_artifact(assessment_id, "knowledge-result", result)

    def discover_plan(self, assessment_id, seeds):
        from .discovery import plan_discovery
        current = self.store.get(assessment_id)
        plan = plan_discovery(current["scope"], seeds)
        return self.store.add_artifact(assessment_id, "discovery-plan", plan, expected_revision=current["revision"])

    def check_plan(self, assessment_id, spec):
        from .detectors import compile_check
        current = self.store.get(assessment_id)
        plan = compile_check(spec, current["scope"])
        return self.store.add_artifact(assessment_id, "check-plan", plan, expected_revision=current["revision"])

    def playbook_plan(self, assessment_id, steps):
        from .playbooks import plan_playbook
        current, records = self.store.snapshot(assessment_id)
        if not isinstance(steps, list) or not 1 <= len(steps) <= 100:
            raise WorkbenchError("invalid_playbook_steps")
        index = {item["artifact_id"]: item for item in records}
        resolved = []
        for step in steps:
            if not isinstance(step, dict) or set(step) != {"id", "plan_id", "requires"}:
                raise WorkbenchError("invalid_playbook_step")
            source = index.get(step["plan_id"])
            if source is None or source["kind"] not in {"discovery-plan", "check-plan", "retest-plan"}:
                raise WorkbenchError("playbook_requires_existing_plan")
            resolved.append({"id": step["id"], "plan": source["value"], "requires": step["requires"]})
        plan = plan_playbook(current["scope"], resolved)
        return self.store.add_artifact(assessment_id, "playbook-plan", plan, expected_revision=current["revision"])

    def _execute(self, assessment_id, plan_id, approval, *, expected_kind, execute, result_kind, credential_resolver=None, stop_event=None, request_id=None, _schedule_claim=None):
        from .scope import context_for_scope
        plan_record = self.store.artifact(assessment_id, plan_id)
        plan = plan_record["value"]
        if plan_record["kind"] != expected_kind or not isinstance(approval, str) or approval != plan.get("plan_digest"):
            raise WorkbenchError("exact_plan_approval_required")
        request_id = _text(request_id or plan_id, "request_id", 256)
        with self.store.execution_guard():
            with self.store._lock:
                # Owning the OS guard proves that another conforming process has
                # no live execution. Retained running jobs are now ambiguous,
                # never replayed or retroactively called successful.
                self.store._db.execute("UPDATE wb_jobs SET state='interrupted' WHERE state='running'")
                self.store._db.execute("BEGIN IMMEDIATE")
                try:
                    current = self.store._read(assessment_id)
                    if plan_record["scope_digest"] != current["scope"].get("scope_digest"):
                        raise WorkbenchError("scope_changed_replan_required")
                    if _schedule_claim is not None:
                        claim_id, claim_value = _schedule_claim
                        claimed = self.store._db.execute("SELECT value FROM wb_schedules WHERE id=? AND assessment_id=?", (claim_id, assessment_id)).fetchone()
                        if claimed is None or claimed["value"] != claim_value:
                            raise WorkbenchError("schedule_claim_lost")
                    previous = self.store._db.execute("SELECT * FROM wb_jobs WHERE request_id=?", (request_id,)).fetchone()
                    if previous:
                        if previous["assessment_id"] != assessment_id or previous["plan_id"] != plan_id:
                            raise WorkbenchError("idempotency_context_conflict")
                        if previous["state"] != "completed":
                            raise WorkbenchError("prior_execution_" + previous["state"] + "_new_plan_required")
                        artifact_id = previous["artifact_id"]
                        self.store._db.execute("COMMIT")
                        return self.store.artifact(assessment_id, artifact_id)
                    self.store._db.execute("INSERT INTO wb_jobs VALUES(?,?,?,?,?,?)", (request_id, assessment_id, plan_id, "running", None, _now()))
                    self.store._db.execute("COMMIT")
                except BaseException:
                    if self.store._db.in_transaction:
                        self.store._db.execute("ROLLBACK")
                    raise
            try:
                cleanup = plan.get("adapter_plan", {}).get("cleanup_reserve", 0) if plan.get("check", {}).get("adapter") == "workflow" else 0
                maximum = None
                if plan.get("kind") == "playbook-plan":
                    cleanup = plan["cleanup_reserve"]
                    maximum = plan["request_upper_bound"]
                context = context_for_scope(current["scope"], max_requests=maximum, cleanup_reserve=cleanup, allow_cleanup_after_cancel=bool(cleanup))
                if stop_event is not None:
                    context.add_stop_event(stop_event)
                result = execute(plan, context=context, credential_resolver=credential_resolver)
                artifact = self.store.add_artifact(assessment_id, result_kind, result)
            except BaseException:
                with self.store._lock:
                    self.store._db.execute("UPDATE wb_jobs SET state='interrupted' WHERE request_id=?", (request_id,))
                raise
            with self.store._lock:
                self.store._db.execute("UPDATE wb_jobs SET state='completed',artifact_id=? WHERE request_id=?", (artifact["artifact_id"], request_id))
            return artifact

    def discover_execute(self, assessment_id, plan_id, approval, **kwargs):
        from .discovery import execute_discovery
        return self._execute(assessment_id, plan_id, approval, expected_kind="discovery-plan", execute=execute_discovery, result_kind="discovery-execution", **kwargs)

    def check_execute(self, assessment_id, plan_id, approval, **kwargs):
        from .detectors import execute_check
        return self._execute(assessment_id, plan_id, approval, expected_kind="check-plan", execute=execute_check, result_kind="check-execution", **kwargs)

    def playbook_execute(self, assessment_id, plan_id, approval, **kwargs):
        from .playbooks import execute_playbook
        return self._execute(assessment_id, plan_id, approval, expected_kind="playbook-plan", execute=execute_playbook, result_kind="playbook-execution", **kwargs)

    def retest_plan(self, assessment_id, execution_id, selection=None):
        from .detectors import plan_check_retest
        current = self.store.get(assessment_id)
        source = self.store.artifact(assessment_id, execution_id)
        if source["kind"] not in {"check-execution", "retest-execution"}:
            raise WorkbenchError("check_execution_required")
        plan = plan_check_retest(source["value"], selection, scope=current["scope"])
        return self.store.add_artifact(assessment_id, "retest-plan", plan, expected_revision=current["revision"])

    def retest_execute(self, assessment_id, plan_id, approval, **kwargs):
        from .detectors import execute_check, compare_check_executions
        artifact = self._execute(assessment_id, plan_id, approval, expected_kind="retest-plan", execute=execute_check, result_kind="retest-execution", **kwargs)
        records = self.store.artifacts(assessment_id)
        result = artifact["value"]
        source_digest = result["plan"]["spec"]["retest_of"]["execution_digest"]
        baseline = next((item["value"] for item in records if item["kind"] in {"check-execution", "retest-execution"}
                         and item["value"].get("execution_digest") == source_digest), None)
        if baseline is None:
            raise WorkbenchError("source_execution_missing")
        comparison = compare_check_executions(baseline, result)
        if not any(item["kind"] == "check-comparison" and item["value"].get("comparison_digest") == comparison["comparison_digest"] for item in records):
            self.store.add_artifact(assessment_id, "check-comparison", comparison, deduplicate=True)
        return artifact

    def report(self, assessment_id, *, out=None, formats=("json", "html", "pdf"), key=None):
        from .platform_reports import freeze_platform, export_platform, create_platform_bundle
        assessment, artifacts = self.store.snapshot(assessment_id)
        snapshot = freeze_platform(assessment, artifacts)
        if out is None:
            return snapshot
        if key is not None:
            return create_platform_bundle(snapshot, out, key, formats=formats)
        return export_platform(snapshot, out, formats=formats)

    def schedule(self, assessment_id, plan_id, approval, interval_seconds, iterations, request_budget):
        artifact = self.store.artifact(assessment_id, plan_id)
        if artifact["kind"] not in {"check-plan", "discovery-plan", "retest-plan", "playbook-plan"} or artifact["value"].get("plan_digest") != approval:
            raise WorkbenchError("exact_plan_approval_required")
        if type(iterations) is not int or not 1 <= iterations <= 1000 or type(interval_seconds) is not int or not 1 <= interval_seconds <= 86400 * 30:
            raise WorkbenchError("bounded_schedule_required")
        if type(request_budget) is not int or not 1 <= request_budget <= 1000000:
            raise WorkbenchError("bounded_schedule_budget_required")
        value = {"schema_version": 1, "kind": "assessment-schedule", "id": "schedule-" + uuid.uuid4().hex,
                 "assessment_id": assessment_id, "plan_id": plan_id, "approval": approval,
                 "interval_seconds": interval_seconds, "iterations": iterations, "completed_iterations": 0,
                 "request_budget": request_budget, "reserved_requests": 0, "state": "scheduled", "next_due": _now(),
                 "limitations": ["Requires a running local scheduler invocation; no daemon is installed.", "Credentials are resolved afresh at each run.", "Interrupted executions are not automatically retried."]}
        with self.store._lock:
            self.store._db.execute("BEGIN IMMEDIATE")
            try:
                current = self.store._read(assessment_id)
                if artifact["scope_digest"] != current["scope"]["scope_digest"]:
                    raise WorkbenchError("scope_changed_replan_required")
                self.store._db.execute("INSERT INTO wb_schedules VALUES(?,?,?)", (value["id"], assessment_id, _json(value)))
                self.store._db.execute("COMMIT")
            except BaseException:
                self.store._db.execute("ROLLBACK")
                raise
        return value

    def schedules(self, assessment_id):
        with self.store._lock:
            return [json.loads(row[0]) for row in self.store._db.execute("SELECT value FROM wb_schedules WHERE assessment_id=? ORDER BY rowid", (assessment_id,))]

    def run_due(self, assessment_id=None, *, credential_resolver=None, stop_event=None):
        import time
        with self.store._lock:
            rows = self.store._db.execute("SELECT value FROM wb_schedules" + (" WHERE assessment_id=?" if assessment_id else ""), (assessment_id,) if assessment_id else ()).fetchall()
        outcomes = []
        for row in rows:
            schedule = json.loads(row[0])
            if schedule["state"] != "scheduled" or datetime.fromisoformat(schedule["next_due"]).timestamp() > time.time():
                continue
            aid = schedule["assessment_id"]
            artifact = self.store.artifact(aid, schedule["plan_id"])
            # Conservatively reserve the full scope budget per cycle. Unused
            # reservations are not made available to uncertain/crashed runs.
            maximum = self.store.get(aid)["scope"]["limits"]["max_requests"]
            if schedule["reserved_requests"] + maximum > schedule["request_budget"]:
                schedule["state"] = "budget_exhausted"
                with self.store._lock:
                    changed = self.store._db.execute("UPDATE wb_schedules SET value=? WHERE id=? AND value=?", (_json(schedule), schedule["id"], row[0])).rowcount
                if changed:
                    outcomes.append(schedule)
                continue
            old_raw = row[0]
            schedule["state"] = "running"
            schedule["reserved_requests"] += maximum
            with self.store._lock:
                changed = self.store._db.execute("UPDATE wb_schedules SET value=? WHERE id=? AND value=?", (_json(schedule), schedule["id"], old_raw)).rowcount
            if not changed:
                continue
            try:
                execute = {"check-plan": self.check_execute, "discovery-plan": self.discover_execute, "retest-plan": self.retest_execute,
                           "playbook-plan": self.playbook_execute}[artifact["kind"]]
                result = execute(aid, schedule["plan_id"], schedule["approval"], credential_resolver=credential_resolver, stop_event=stop_event,
                                 request_id=schedule["id"] + ":" + str(schedule["completed_iterations"]),
                                 _schedule_claim=(schedule["id"], _json(schedule)))
                schedule["last_artifact_id"] = result["artifact_id"]
                schedule["completed_iterations"] += 1
                schedule["state"] = "completed" if schedule["completed_iterations"] >= schedule["iterations"] else "scheduled"
                schedule["next_due"] = datetime.fromtimestamp(time.time() + schedule["interval_seconds"], timezone.utc).isoformat()
            except (ValueError, OSError):
                schedule["state"] = "blocked"
                schedule["reason"] = "execution_requires_review"
            with self.store._lock:
                self.store._db.execute("UPDATE wb_schedules SET value=? WHERE id=?", (_json(schedule), schedule["id"]))
            outcomes.append(schedule)
        return outcomes
