"""Loopback-only workbench. Not a hosted service or multi-user server."""
from __future__ import annotations

import hmac
import hashlib
import copy
import json
import os
import secrets
import tempfile
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path

from . import __version__
from .engine import run
from .evidence import compare_reports, verify_report
from .model import ContractError, contract_digest, load_contract, plan
from .openapi import catalog, compile_contract
from .matrix import compile_matrix, explain_report, policy_diff
from .reports import render_diff_html, render_html, render_junit

MAX_UPLOAD = 4 * 1048576


def browser_numbers(value):
    """Refuse integers that the browser would silently round during JSON parsing."""
    pending = [value]
    while pending:
        item = pending.pop()
        if type(item) is int and abs(item) > 9007199254740991:
            raise ContractError("JSON integer exceeds the browser's exact range. Use a string identifier or the CLI for this input.")
        if isinstance(item, dict):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return value


def parse_json(raw: bytes, *, object_only=True):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("Duplicate JSON keys")
            value[key] = item
        return value

    def reject(_):
        raise ValueError("Non-finite JSON number")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=reject)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid UTF-8 JSON document") from exc
    if object_only and not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def studio_contract(value, allow=False):
    if not isinstance(value, dict):
        raise ContractError("Import a contract JSON object. Browser file paths are not accepted.")
    return load_contract(value, allow_mutations=allow)


def studio_policy(value):
    """Browser policy editing is local; remote adapters are a CLI capability."""
    if value is None:
        return None
    if not isinstance(value, dict) or value.get("engine") != "local":
        raise ContractError("Studio accepts local policy JSON only. Use the CLI for explicitly scoped OPA adapters.")
    from .policy import load_policy
    return load_policy(value)


def assurance_settings(value, request_count):
    value = {} if value is None else value
    if not isinstance(value, dict) or set(value) - {"cycles", "interval_seconds"}:
        raise ContractError("Assurance settings accept cycles and interval_seconds only.")
    cycles = value.get("cycles", 1)
    interval = value.get("interval_seconds", 1)
    if type(cycles) is not int or not 1 <= cycles <= 20:
        raise ContractError("Choose between 1 and 20 assurance cycles.")
    if type(interval) is not int or not 1 <= interval <= 3600:
        raise ContractError("Choose an interval between 1 and 3600 seconds.")
    if cycles * request_count > 1000:
        raise ContractError("This assurance session exceeds the 1,000-request bound.")
    return {"cycles": cycles, "interval_seconds": interval}


def settings_digest(policy, assurance):
    return hashlib.sha256(json.dumps({"policy": policy, "assurance": assurance}, sort_keys=True,
                                     ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def history_identifier(value):
    if type(value) is int and 1 <= value <= 9007199254740991:
        return str(value)
    if isinstance(value, str) and 1 <= len(value) <= 96 and all(char in "0123456789abcdef-" for char in value):
        return value
    raise ContractError("Choose an existing history record.")


class StudioServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 16

    def __init__(self, port=0, *, history_path=None, signing_key=None, public_key=None, reasoning_config=None, policy_config=None):
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.history_lock = threading.Lock()
        self.jobs = {}
        self.reviews = {}
        self.review_settings = {}
        self.retest_reviews = {}
        self.graph_snapshots = {}
        self.history = None
        if history_path is not None:
            from .history import HistoryStore
            self.history = HistoryStore(history_path)
        self.memory_history = {}
        self.signing_key = Path(signing_key) if signing_key else None
        self.public_key = Path(public_key) if public_key else None
        self.reasoning_config = reasoning_config
        self.policy_config = None
        if policy_config is not None:
            from .policy import load_policy
            self.policy_config = load_policy(policy_config)
        self.stopping = threading.Event()
        self.cancellations = {}
        self.active = False
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(("127.0.0.1", port), StudioHandler)
        self.origin = f"http://127.0.0.1:{self.server_port}"

    @property
    def url(self):
        return self.origin + "/#" + self.token

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(10)
        return sock, addr

    def resolve_policy(self, body):
        selected = body.get("use_server_policy", False)
        if type(selected) is not bool:
            raise ContractError("use_server_policy must be boolean.")
        if selected:
            if self.policy_config is None:
                raise ContractError("No policy engine was configured when Studio started.")
            if body.get("policy") is not None:
                raise ContractError("Choose the configured policy engine or a local policy, one at a time.")
            return self.policy_config
        return studio_policy(body.get("policy"))

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def record_run(self, contract, report, graph, *, previous_sha256=None):
        """Store only normalized contracts and verified, secret-free results."""
        with self.history_lock:
            if self.history is not None:
                record = self.history.append(contract, report, graph, expected_previous_sha256=previous_sha256)
                return self.history.get_run(record["id"])
            run_id = secrets.token_hex(16)
            record = {"id": run_id, "name": report["name"], "target": report["target"],
                      "finished_at": report["finished_at"], "summary": report["summary"],
                      "contract": contract, "report": report, "graph": graph}
            while len(self.memory_history) >= 200:
                del self.memory_history[next(iter(self.memory_history))]
            self.memory_history[run_id] = record
            return record

    def list_runs(self):
        with self.history_lock:
            if self.history is not None:
                return self.history.list_runs()
            return [{key: value for key, value in item.items() if key not in {"contract", "report", "graph"}}
                    for item in reversed(list(self.memory_history.values()))]

    def get_run(self, run_id):
        with self.history_lock:
            if self.history is not None:
                return self.history.get_run(run_id)
            return self.memory_history.get(run_id)

    def retain_graph(self, contract, report, graph):
        snapshot_id = secrets.token_urlsafe(24)
        with self.lock:
            while len(self.graph_snapshots) >= 16:
                del self.graph_snapshots[next(iter(self.graph_snapshots))]
            self.graph_snapshots[snapshot_id] = {"contract": contract, "report": report, "graph": graph}
        return snapshot_id

    def graph_snapshot(self, value):
        if not isinstance(value, str) or not 1 <= len(value) <= 100:
            raise ContractError("Build the authorization graph again; its retained snapshot is unavailable.")
        with self.lock:
            record = self.graph_snapshots.get(value)
        if record is None:
            raise ContractError("Build the authorization graph again; its retained snapshot is unavailable.")
        return record

    def start_job(self, kind, contract=None, *, policy=None, assurance=None, baseline=None, selected_ids=None):
        with self.lock:
            if self.active:
                raise ContractError("A job is already running. Wait for its result.")
            self.active = True
            while len(self.jobs) >= 8:
                del self.jobs[next(iter(self.jobs))]
            job_id = secrets.token_hex(12)
            self.jobs[job_id] = {"id": job_id, "kind": kind, "state": "running"}
            cancel = threading.Event()
            self.cancellations[job_id] = cancel

        def execute():
            try:
                if kind == "benchmark":
                    from .benchmark import run_benchmark
                    result = run_benchmark()
                    if not result["accepted"]:
                        raise ValueError("Corpus acceptance failed")
                    result["corpus_kind"] = result.pop("kind")
                    from .intelligence import build_graph, differential_graphs
                    corpus_contract = compile_matrix(result["project"])["contract"]
                    before = build_graph(corpus_contract, result["baseline"])
                    after = build_graph(corpus_contract, result["report"])
                    self.record_run(corpus_contract, result["baseline"], before)
                    result.update(graph=after, graph_comparison=differential_graphs(before, after),
                                  history=self.record_run(corpus_contract, result["report"], after))
                elif kind == "demo":
                    from .demo import run_demo
                    with tempfile.TemporaryDirectory(prefix="authzledger-demo-") as directory:
                        out = Path(directory)
                        if run_demo(out) != 0:
                            raise ValueError("Demo verification failed")
                        demo_contract = load_contract(parse_json((out / "contract.json").read_bytes()))
                        result = {"baseline": parse_json((out / "vulnerable/report.json").read_bytes()),
                                  "report": parse_json((out / "fixed/report.json").read_bytes()),
                                  "comparison": parse_json((out / "diff.json").read_bytes())}
                        from .intelligence import build_graph, differential_graphs
                        before = build_graph(demo_contract, result["baseline"])
                        after = build_graph(demo_contract, result["report"])
                        self.record_run(demo_contract, result["baseline"], before)
                        result.update(graph=after, graph_comparison=differential_graphs(before, after),
                                      history=self.record_run(demo_contract, result["report"], after))
                else:
                    from .intelligence import build_graph, differential_graphs
                    from .assurance import assessment_status, history_snapshot
                    from .engine import _credentials
                    cycles = (assurance or {}).get("cycles", 1)
                    interval = (assurance or {}).get("interval_seconds", 1)
                    records = []
                    previous = baseline
                    for cycle in range(cycles):
                        if cancel.is_set() or self.stopping.is_set():
                            break
                        with self.history_lock:
                            if self.history is not None:
                                retained, tail = history_snapshot(self.history, contract)
                            else:
                                retained = next((item for item in reversed(list(self.memory_history.values()))
                                                 if item["target"] == contract["target"] and item["name"] == contract["name"]), None)
                                tail = None
                        if previous is None:
                            previous = retained
                        _credentials(contract)
                        from .policy import evaluate_policy
                        evaluated = evaluate_policy(contract, policy) if policy is not None else None
                        report = run(contract)
                        graph = build_graph(contract, report, evaluated)
                        # A strict subset is not graph removal. Its retained full
                        # source is compared by ComparisonEnvelope instead.
                        comparison = differential_graphs(previous["graph"], graph) if previous and selected_ids is None else None
                        status, exit_code, stop_reason = assessment_status(report, graph, comparison)
                        current = self.record_run(contract, report, graph, previous_sha256=tail)
                        result = {"report": report, "graph": graph, "history": current,
                                  "graph_comparison": comparison, "cycles_completed": cycle + 1,
                                  "cycles_requested": cycles, "assurance_status": status,
                                  "exit_code": exit_code, "stopped_reason": stop_reason}
                        if baseline is not None:
                            from .comparison import create_comparison
                            result["comparison_envelope"] = create_comparison(
                                baseline["contract"], baseline["report"], report, selected_ids)
                            result["baseline"] = baseline["report"]
                        records.append({"id": current.get("id", current.get("run_id")),
                                        "finished_at": report["finished_at"], "summary": report["summary"]})
                        previous = {"graph": graph}
                        with self.lock:
                            self.jobs[job_id].update(cycles_completed=cycle + 1, cycles_requested=cycles)
                        if status != "pass":
                            break
                        if cycle + 1 < cycles and (cancel.wait(interval) or self.stopping.is_set()):
                            break
                    if not records:
                        with self.lock:
                            self.jobs[job_id].update(state="cancelled")
                        return
                    result.update(cycle_history=records, cancelled=cancel.is_set())
                with self.lock:
                    self.jobs[job_id].update(state="complete", **result)
            except Exception:
                # Do not return exceptions which may contain credentials or response data.
                with self.lock:
                    self.jobs[job_id].update(state="error", error="Execution failed. Check the contract and credential environment.")
            finally:
                with self.lock:
                    self.active = False
                    self.cancellations.pop(job_id, None)

        threading.Thread(target=execute, daemon=True, name="authzledger-job").start()
        return {"id": job_id, "state": "running"}

    def server_close(self):
        self.stopping.set()
        with self.lock:
            for cancel in self.cancellations.values():
                cancel.set()
        super().server_close()


class StudioHandler(BaseHTTPRequestHandler):
    server_version = "AuthzLedger"
    sys_version = ""

    def log_message(self, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        self.respond(code, {"error": "Request rejected."})

    def respond(self, code, value, content_type="application/json; charset=utf-8", filename=None):
        data = json.dumps(value, ensure_ascii=True, allow_nan=False).encode() if isinstance(value, dict) else value
        if isinstance(data, str):
            data = data.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def permitted(self, *, api=False, post=False):
        if self.headers.get_all("Host", []) != [self.server.origin[7:]]:
            self.respond(403, {"error": "Loopback Host required."})
            return False
        origins = self.headers.get_all("Origin", [])
        if (post and origins != [self.server.origin]) or (origins and origins != [self.server.origin]):
            self.respond(403, {"error": "Same-origin request required."})
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            self.respond(403, {"error": "Cross-site request rejected."})
            return False
        auth = self.headers.get_all("Authorization", [])
        if api and (len(auth) != 1 or not hmac.compare_digest(auth[0].encode("utf-8"), ("Bearer " + self.server.token).encode("ascii"))):
            self.respond(403, {"error": "Open the complete session URL printed by the CLI."})
            return False
        return True

    def do_GET(self):
        if not self.permitted(api=self.path.startswith("/api/")):
            return
        assets = {"/": ("web/index.html", "text/html; charset=utf-8"),
                  "/app.js": ("web/app.js", "text/javascript; charset=utf-8"),
                  "/style.css": ("web/style.css", "text/css; charset=utf-8"),
                  "/logo.png": ("brand_logo.png", "image/png")}
        if self.path in assets:
            resource, mime = assets[self.path]
            self.respond(200, files("authzledger").joinpath(resource).read_bytes(), mime)
        elif self.path == "/api/session":
            self.respond(200, {"version": __version__, "storage": "persistent" if self.server.history else "memory",
                               "max_upload_bytes": MAX_UPLOAD,
                               "signed_proof": bool(self.server.signing_key and self.server.public_key),
                               "local_ai": self.server.reasoning_config is not None,
                               "server_policy_available": self.server.policy_config is not None,
                               "server_policy_engine": self.server.policy_config["engine"] if self.server.policy_config else None,
                               "assurance": {"max_cycles": 20, "max_total_requests": 1000}})
        elif self.path == "/api/history":
            try:
                self.respond(200, {"runs": self.server.list_runs(),
                                   "storage": "persistent" if self.server.history else "memory"})
            except (ValueError, OSError):
                self.respond(400, {"error": "History integrity validation failed."})
        elif self.path.startswith("/api/history/"):
            run_id = self.path.removeprefix("/api/history/")
            if not run_id or len(run_id) > 96 or any(char not in "0123456789abcdef-" for char in run_id):
                self.respond(404, {"error": "Unknown history record."})
                return
            try:
                record = self.server.get_run(run_id)
                self.respond(200, {"run": record}) if record else self.respond(404, {"error": "Unknown history record."})
            except (ValueError, OSError):
                self.respond(400, {"error": "History integrity validation failed."})
        elif self.path == "/api/plans":
            self.respond(200, files("authzledger").joinpath("web/plans.json").read_bytes())
        elif self.path == "/api/matrix/example":
            from .benchmark import sample_project
            self.respond(200, {"project": sample_project()})
        elif self.path.startswith("/api/jobs/"):
            with self.server.lock:
                job = self.server.jobs.get(self.path.removeprefix("/api/jobs/"))
                # Serialize while holding the lock; worker may otherwise update this object.
                payload = json.dumps(job).encode() if job else None
            self.respond(200, payload) if payload else self.respond(404, {"error": "Job is no longer available."})
        else:
            self.respond(404, {"error": "Unknown route."})

    def do_POST(self):
        if not self.permitted(api=True, post=True):
            return
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if (len(lengths) != 1 or not lengths[0].isdigit() or "Transfer-Encoding" in self.headers
                    or self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json"):
                self.respond(400, {"error": "A single bounded JSON body is required."})
                return
            length = int(lengths[0])
            if not 0 < length <= MAX_UPLOAD:
                self.respond(413, {"error": "Request exceeds the 4 MiB upload limit."})
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("Incomplete body")
            body = parse_json(raw)
            allow = body.get("allow_mutations", False)
            if type(allow) is not bool:
                raise ValueError("allow_mutations must be boolean")
            if self.path == "/api/parse":
                source = body.get("text")
                if not isinstance(source, str):
                    raise ValueError("JSON text is required")
                result = {"value": browser_numbers(parse_json(source.encode("utf-8"), object_only=False))}
            elif self.path == "/api/catalog":
                result = catalog(body.get("document"))
            elif self.path == "/api/compile":
                result = {"contract": compile_contract(body.get("document"), body.get("config"), allow_mutations=allow)}
            elif self.path == "/api/matrix/analyze":
                result = compile_matrix(body.get("project"), require_complete=False)
            elif self.path == "/api/matrix/explain":
                result = explain_report(body.get("project"), body.get("report"))
            elif self.path == "/api/matrix/diff":
                result = policy_diff(body.get("before"), body.get("after"))
            elif self.path in {"/api/graph", "/api/policy", "/api/reasoning"}:
                from .intelligence import build_graph, verify_graph
                from .policy import evaluate_policy
                if self.path == "/api/reasoning" and (body.get("history_id") is not None or body.get("snapshot_id") is not None):
                    record = (self.server.get_run(history_identifier(body["history_id"]))
                              if body.get("history_id") is not None else self.server.graph_snapshot(body["snapshot_id"]))
                    if record is None or verify_graph(record["graph"], record["contract"], record["report"]):
                        raise ContractError("Verified history record required.")
                    graph = record["graph"]
                else:
                    contract = studio_contract(body.get("contract"), allow)
                    config = self.server.resolve_policy(body)
                    evaluated = evaluate_policy(contract, config) if config is not None else None
                    report = body.get("report")
                    if report is not None and (not isinstance(report, dict) or verify_report(report)):
                        raise ContractError("Report integrity validation failed.")
                    graph = build_graph(contract, report, evaluated)
                if self.path == "/api/reasoning":
                    from .reasoning import explain_graph
                    if set(body) - {"contract", "report", "policy", "allow_mutations", "use_local_model", "history_id", "snapshot_id", "use_server_policy"}:
                        raise ContractError("Model origin and configuration cannot be supplied through the browser.")
                    if type(body.get("use_local_model", False)) is not bool:
                        raise ContractError("use_local_model must be boolean.")
                    use_model = body.get("use_local_model", False)
                    if use_model and self.server.reasoning_config is None:
                        raise ContractError("Start Studio with an explicit local reasoning configuration first.")
                    result = explain_graph(graph, self.server.reasoning_config if use_model else None)
                elif self.path == "/api/policy":
                    result = {"policy": None if body.get("use_server_policy") else config,
                              "evaluation": evaluated, "graph": graph,
                              "snapshot_id": self.server.retain_graph(contract, report, graph)}
                else:
                    result = {"graph": graph, "snapshot_id": self.server.retain_graph(contract, report, graph)}
            elif self.path == "/api/graph/diff":
                from .intelligence import differential_graphs
                if not isinstance(body.get("before"), dict) or not isinstance(body.get("after"), dict):
                    raise ContractError("Two verified graph JSON objects are required.")
                result = {"comparison": differential_graphs(body["before"], body["after"])}
            elif self.path in {"/api/plan", "/api/retest/plan"}:
                retained = None
                selection = None
                if self.path == "/api/retest/plan":
                    if set(body) - {"baseline_id", "selected_ids", "allow_mutations", "policy", "use_server_policy", "assurance"}:
                        raise ContractError("Retest previews use only the retained source and explicit case selection.")
                    from .assurance import retest_plan
                    from .comparison import create_comparison
                    baseline_id = history_identifier(body.get("baseline_id"))
                    retained = self.server.get_run(baseline_id)
                    if retained is None:
                        raise ContractError("Select an existing retained baseline.")
                    # This validates source binding and supported semantics
                    # before any application or remote policy request.
                    create_comparison(retained["contract"], retained["report"], retained["report"])
                    selection = retest_plan(retained["contract"], body.get("selected_ids"), allow_mutations=allow)
                    contract = selection["contract"]
                else:
                    contract = studio_contract(body.get("contract"), allow)
                config = self.server.resolve_policy(body)
                request_count = len(contract["cases"]) * (2 if config and config["engine"] == "opa" else 1)
                settings = assurance_settings(body.get("assurance"), request_count)
                if retained is not None and settings["cycles"] != 1:
                    raise ContractError("A source-bound selective retest executes exactly one reviewed cycle.")
                review = secrets.token_urlsafe(24)
                with self.server.lock:
                    self.server.reviews = {key: value for key, value in self.server.reviews.items() if value[2] > time.monotonic()}
                    self.server.review_settings = {key: value for key, value in self.server.review_settings.items()
                                                  if key in self.server.reviews}
                    if len(self.server.reviews) >= 16:
                        del self.server.reviews[next(iter(self.server.reviews))]
                    self.server.retest_reviews = {key: value for key, value in self.server.retest_reviews.items()
                                                  if key in self.server.reviews}
                    self.server.reviews[review] = (contract_digest(contract), allow, time.monotonic() + 600)
                    self.server.review_settings[review] = settings_digest(config, settings)
                    if retained is not None:
                        self.server.retest_reviews[review] = {"baseline_id": baseline_id,
                            "baseline": copy.deepcopy(retained), "contract": copy.deepcopy(contract),
                            "selected_ids": selection["selected_ids"]}
                environment = sorted({v["env"] for i in contract["identities"].values() for v in i["headers"].values() if isinstance(v, dict)})
                result = {"plan": plan(contract), "review": review,
                          "assurance": {**settings, "maximum_requests": request_count * settings["cycles"],
                                        "policy_engine": config["engine"] if config else None},
                          "credentials": [{"env": name, "present": bool(os.environ.get(name))} for name in environment]}
                if selection is not None:
                    result["retest"] = {"baseline_id": baseline_id, "contract": contract,
                        "source_contract_sha256": selection["source_contract_sha256"],
                        "baseline_root_sha256": retained["report"]["evidence"]["root_sha256"],
                        "selected_ids": selection["selected_ids"], "dependency_ids": selection["dependency_ids"],
                        "not_retested_ids": [case["id"] for case in retained["contract"]["cases"]
                                              if case["id"] not in {item["id"] for item in contract["cases"]}]}
            elif self.path in {"/api/run", "/api/retest", "/api/assurance"}:
                contract = studio_contract(body.get("contract"), allow)
                config = self.server.resolve_policy(body)
                request_count = len(contract["cases"]) * (2 if config and config["engine"] == "opa" else 1)
                settings = assurance_settings(body.get("assurance"), request_count)
                with self.server.lock:
                    reviewed = self.server.reviews.get(str(body.get("review", "")))
                    reviewed_settings = self.server.review_settings.get(str(body.get("review", "")))
                    retest_review = self.server.retest_reviews.get(str(body.get("review", "")))
                if (not reviewed or reviewed[:2] != (contract_digest(contract), allow)
                        or reviewed[2] <= time.monotonic() or reviewed_settings != settings_digest(config, settings)):
                    raise ContractError("Preview this exact contract before running it. Plans expire after ten minutes.")
                if body.get("authorized") is not True:
                    raise ContractError("Confirm authorization for the displayed target before execution.")
                baseline = None
                selected_ids = None
                if retest_review is not None and self.path != "/api/retest":
                    raise ContractError("This review is bound to a retained-baseline retest.")
                if self.path == "/api/retest":
                    from .comparison import create_comparison
                    run_id = history_identifier(body.get("baseline_id"))
                    if retest_review is not None:
                        if (run_id != retest_review["baseline_id"]
                                or body.get("selected_ids") != retest_review["selected_ids"]):
                            raise ContractError("Preview this exact baseline and case selection again.")
                        baseline = retest_review["baseline"]
                        selected_ids = retest_review["selected_ids"]
                    else:
                        if body.get("selected_ids") is not None:
                            raise ContractError("Preview a selective retest before executing selected cases.")
                        baseline = self.server.get_run(run_id)
                    if not baseline or baseline["contract"]["target"] != contract["target"]:
                        raise ContractError("Retests require an existing baseline for the exact target origin.")
                    if retest_review is None and contract_digest(baseline["contract"]) != contract_digest(contract):
                        raise ContractError("A full retest must preserve the retained source contract. Use the selective retest preview.")
                    create_comparison(baseline["contract"], baseline["report"], baseline["report"])
                kind = "assurance" if self.path == "/api/assurance" else "retest" if baseline else "run"
                if retest_review is not None:
                    with self.server.lock:
                        # Claim before dispatch. Two requests can have read the
                        # same valid review above while the first fast job has
                        # already finished. The retained object identity makes
                        # the authorization single-use across that race.
                        if (self.server.retest_reviews.get(body["review"]) is not retest_review
                                or self.server.reviews.get(body["review"]) != reviewed
                                or reviewed[2] <= time.monotonic()):
                            raise ContractError("This retest review was already consumed or expired. Preview again.")
                        self.server.reviews.pop(body["review"], None)
                        self.server.review_settings.pop(body["review"], None)
                        self.server.retest_reviews.pop(body["review"], None)
                # A concurrently started job can still reject dispatch. A
                # consumed retest review is deliberately never restored.
                result = self.server.start_job(kind, contract, policy=config, assurance=settings, baseline=baseline,
                                               selected_ids=selected_ids)
            elif self.path == "/api/cancel":
                with self.server.lock:
                    cancel = self.server.cancellations.get(body.get("id"))
                    if cancel is None:
                        raise ContractError("This job is not active.")
                    cancel.set()
                result = {"state": "cancelling", "message": "The current bounded execution cycle completes; no further cycle starts."}
            elif self.path == "/api/demo":
                result = self.server.start_job("demo")
            elif self.path == "/api/benchmark":
                result = self.server.start_job("benchmark")
            elif self.path == "/api/compare":
                result = {"comparison": compare_reports(body.get("baseline"), body.get("current"))}
            elif self.path == "/api/comparison":
                from .comparison import create_comparison
                result = {"comparison_envelope": create_comparison(body.get("source_contract"),
                    body.get("baseline_report"), body.get("current_report"), body.get("selected_ids"))}
            elif self.path == "/api/comparison/verify":
                from .comparison import verify_comparison
                envelope = body.get("comparison_envelope")
                if verify_comparison(envelope):
                    raise ContractError("Comparison integrity and source binding validation failed.")
                result = {"comparison_envelope": envelope}
            elif self.path == "/api/verify":
                report = body.get("report")
                if not isinstance(report, dict) or verify_report(report):
                    raise ValueError("Report integrity validation failed")
                result = {"report": report}
            elif self.path == "/api/proof":
                if set(body) - {"report", "contract", "policy", "allow_mutations", "history_id", "snapshot_id", "use_server_policy", "comparison_envelope"}:
                    raise ContractError("Signing keys and filesystem paths cannot be supplied through the browser.")
                if not self.server.signing_key or not self.server.public_key:
                    raise ContractError("Start Studio with --signing-key and --public-key to export signed proof.")
                from .intelligence import build_graph, verify_graph
                from .policy import evaluate_policy
                from .signing import create_bundle, verify_bundle
                record = None
                if body.get("history_id") is not None:
                    run_id = history_identifier(body["history_id"])
                    record = self.server.get_run(run_id)
                    if record is None:
                        raise ContractError("This history record is not available.")
                elif body.get("snapshot_id") is not None:
                    record = self.server.graph_snapshot(body["snapshot_id"])
                report = record["report"] if record else body.get("report")
                if not isinstance(report, dict) or verify_report(report):
                    raise ContractError("Report integrity validation failed.")
                contract = studio_contract(record["contract"] if record else body.get("contract"), True if record else allow)
                if record:
                    graph = record["graph"]
                    if verify_graph(graph, contract, report):
                        raise ContractError("History graph integrity validation failed.")
                else:
                    config = self.server.resolve_policy(body)
                    if config and config["engine"] == "opa":
                        raise ContractError("Build the graph and export its retained snapshot. Proof export never re-queries OPA.")
                    evaluated = evaluate_policy(contract, config) if config is not None else None
                    graph = build_graph(contract, report, evaluated)
                with tempfile.TemporaryDirectory(prefix="authzledger-proof-") as directory:
                    folder = Path(directory)
                    graph_path = folder / "graph.json"
                    graph_path.write_text(json.dumps(graph, sort_keys=True, ensure_ascii=True), encoding="utf-8")
                    contract_path = folder / "contract.json"
                    contract_path.write_text(json.dumps(contract, sort_keys=True, ensure_ascii=True), encoding="utf-8")
                    bundle = folder / "proof"
                    attachments = {"graph.json": graph_path, "contract.json": contract_path}
                    if body.get("comparison_envelope") is not None:
                        from .comparison import verify_comparison
                        from .reports import render_comparison_html
                        envelope = body["comparison_envelope"]
                        if verify_comparison(envelope) or envelope["current_report"] != report:
                            raise ContractError("The comparison must verify and bind this exact proof report.")
                        attachments["comparison.json"] = json.dumps(envelope, sort_keys=True,
                            ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
                        attachments["comparison.html"] = render_comparison_html(envelope).encode("utf-8")
                    create_bundle(report, bundle, self.server.signing_key,
                                  attachments=attachments)
                    errors = verify_bundle(bundle, self.server.public_key)
                    if errors:
                        raise ContractError("Independent signature verification failed; no package exported.")
                    archive = folder / "authzledger-proof.zip"
                    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
                        for item in sorted(bundle.rglob("*")):
                            if item.is_file():
                                zipped.write(item, str(item.relative_to(bundle)))
                    self.respond(200, archive.read_bytes(), "application/zip", "authzledger-proof.zip")
                return
            elif self.path == "/api/export":
                kind = body.get("kind")
                if kind == "comparison-envelope":
                    from .reports import render_comparison_html
                    self.respond(200, render_comparison_html(body.get("comparison_envelope")),
                                 "text/html; charset=utf-8", "authzledger-comparison.html")
                    return
                if kind == "comparison":
                    comparison = compare_reports(body.get("baseline"), body.get("current"))
                    self.respond(200, render_diff_html(comparison), "text/html; charset=utf-8", "authzledger-retest.html")
                    return
                report = body.get("report")
                if not isinstance(report, dict) or verify_report(report):
                    raise ValueError("Report integrity validation failed")
                formats = {"html": (render_html, "text/html; charset=utf-8", "authzledger-report.html"),
                           "junit": (render_junit, "application/xml; charset=utf-8", "authzledger-junit.xml")}
                if kind not in formats:
                    raise ValueError("Unknown export format")
                renderer, mime, name = formats[kind]
                self.respond(200, renderer(report), mime, name)
                return
            else:
                self.respond(404, {"error": "Unknown route."})
                return
            self.respond(200, result)
        except ContractError as exc:
            self.respond(400, {"error": str(exc)})
        except (ValueError, TypeError, KeyError, AttributeError, RecursionError, OSError):
            self.respond(400, {"error": "Input could not be processed. Check its JSON structure and supported format."})


def serve(port=0, *, open_browser=False, history_path=None, signing_key=None, public_key=None, reasoning_config=None, policy_config=None):
    server = StudioServer(port, history_path=history_path, signing_key=signing_key,
                          public_key=public_key, reasoning_config=reasoning_config, policy_config=policy_config)
    print(f"AuthzLedger Studio {__version__} · local workbench", flush=True)
    print(server.url, flush=True)
    storage = "retained in the configured local history" if server.history else "held in memory; export before closing"
    print(f"Keep this session URL private. Results are {storage}.", flush=True)
    if open_browser:
        import webbrowser
        webbrowser.open(server.url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
