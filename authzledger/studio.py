"""Loopback-only workbench. Not a hosted service or multi-user server."""
from __future__ import annotations

import hmac
import json
import os
import secrets
import tempfile
import threading
import time
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


class StudioServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 16

    def __init__(self, port=0):
        self.token = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.jobs = {}
        self.reviews = {}
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

    def start_job(self, kind, contract=None):
        with self.lock:
            if self.active:
                raise ContractError("A job is already running. Wait for its result.")
            self.active = True
            while len(self.jobs) >= 8:
                del self.jobs[next(iter(self.jobs))]
            job_id = secrets.token_hex(12)
            self.jobs[job_id] = {"id": job_id, "kind": kind, "state": "running"}

        def execute():
            try:
                if kind == "benchmark":
                    from .benchmark import run_benchmark
                    result = run_benchmark()
                    if not result["accepted"]:
                        raise ValueError("Corpus acceptance failed")
                    result["corpus_kind"] = result.pop("kind")
                elif kind == "demo":
                    from .demo import run_demo
                    with tempfile.TemporaryDirectory(prefix="authzledger-demo-") as directory:
                        out = Path(directory)
                        if run_demo(out) != 0:
                            raise ValueError("Demo verification failed")
                        result = {"baseline": parse_json((out / "vulnerable/report.json").read_bytes()),
                                  "report": parse_json((out / "fixed/report.json").read_bytes()),
                                  "comparison": parse_json((out / "diff.json").read_bytes())}
                else:
                    result = {"report": run(contract)}
                with self.lock:
                    self.jobs[job_id].update(state="complete", **result)
            except Exception:
                # Do not return exceptions which may contain credentials or response data.
                with self.lock:
                    self.jobs[job_id].update(state="error", error="Execution failed. Check the contract and credential environment.")
            finally:
                with self.lock:
                    self.active = False

        threading.Thread(target=execute, daemon=True, name="authzledger-job").start()
        return {"id": job_id, "state": "running"}


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
            self.respond(200, {"version": __version__, "storage": "memory", "max_upload_bytes": MAX_UPLOAD})
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
            elif self.path == "/api/plan":
                contract = load_contract(body.get("contract"), allow_mutations=allow)
                review = secrets.token_urlsafe(24)
                with self.server.lock:
                    self.server.reviews = {key: value for key, value in self.server.reviews.items() if value[2] > time.monotonic()}
                    if len(self.server.reviews) >= 16:
                        del self.server.reviews[next(iter(self.server.reviews))]
                    self.server.reviews[review] = (contract_digest(contract), allow, time.monotonic() + 600)
                environment = sorted({v["env"] for i in contract["identities"].values() for v in i["headers"].values() if isinstance(v, dict)})
                result = {"plan": plan(contract), "review": review,
                          "credentials": [{"env": name, "present": bool(os.environ.get(name))} for name in environment]}
            elif self.path == "/api/run":
                contract = load_contract(body.get("contract"), allow_mutations=allow)
                with self.server.lock:
                    reviewed = self.server.reviews.get(str(body.get("review", "")))
                if (not reviewed or reviewed[:2] != (contract_digest(contract), allow)
                        or reviewed[2] <= time.monotonic()):
                    raise ContractError("Preview this exact contract before running it. Plans expire after ten minutes.")
                if body.get("authorized") is not True:
                    raise ContractError("Confirm authorization for the displayed target before execution.")
                result = self.server.start_job("run", contract)
            elif self.path == "/api/demo":
                result = self.server.start_job("demo")
            elif self.path == "/api/benchmark":
                result = self.server.start_job("benchmark")
            elif self.path == "/api/compare":
                result = {"comparison": compare_reports(body.get("baseline"), body.get("current"))}
            elif self.path == "/api/verify":
                report = body.get("report")
                if not isinstance(report, dict) or verify_report(report):
                    raise ValueError("Report integrity validation failed")
                result = {"report": report}
            elif self.path == "/api/export":
                kind = body.get("kind")
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


def serve(port=0, *, open_browser=False):
    server = StudioServer(port)
    print(f"AuthzLedger Studio {__version__} · local workbench", flush=True)
    print(server.url, flush=True)
    print("Keep this session URL private. Export results before closing; history is held in memory.", flush=True)
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
