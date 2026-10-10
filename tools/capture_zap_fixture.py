#!/usr/bin/env python3
"""Capture an unchanged ZAP JSON+ export from one public loopback request.

Requires an independently downloaded ZAP 2.17.0 Linux distribution. This is
an exporter harness, never a handwritten replacement for an exported report.
Existing outputs are refused; use a fresh directory for each capture.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, build_opener

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from authzledger.experiments import compile_imported_experiment, execute_experiment, verify_execution
from authzledger.imports import parse_import

ARCHIVE_SHA256 = "efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a"


def bindings(entry):
    return {
        "id": "zap-export-acceptance", "title": "Native ZAP export acceptance",
        "target": entry["origin"],
        "identities": {
            "owner": {"headers": {"Authorization": {"env": "AUTHZ_ZAP_LAB_OWNER"}}},
            "peer": {"headers": {"Authorization": {"env": "AUTHZ_ZAP_LAB_PEER"}}},
        },
        "actor_identity": "peer", "owner_identity": "owner",
        "identity_probe": {"path": "/me", "expect": {"status": [200], "json": {"/principal": "peer", "/tenant": "B"}}},
        "negative_probe": {"path": "/known-denial", "expect": {"status": [403], "json_absent": ["/marker"]}},
        "rule": {"id": "tenant-isolation", "resource_id": "invoice-A", "kind": "forbid_field_equal", "pointer": "/marker", "value": "synthetic-A"},
        "omitted_secret_slots": [slot["id"] for slot in entry["secret_slots"]],
        "capture_mode": "safe_values", "limits": {"max_requests": 4, "concurrency": 1},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zap-dir", required=True, type=Path)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if hashlib.sha256(args.archive.read_bytes()).hexdigest() != ARCHIVE_SHA256:
        raise SystemExit("ZAP distribution does not match the pinned official SHA256")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    names = ("zap-real.json", "zap-real.provenance.json", "zap-real.execution.json")
    if any((out / name).exists() for name in names):
        raise SystemExit("Refusing to overwrite an existing capture")
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if len(observed) >= 5:
                self.send_error(429, "Fixture request budget exhausted")
                return
            observed.append({"method": "GET", "path": self.path})
            actor = self.headers.get("Authorization")
            if self.path == "/me":
                status, body = 200, {"principal": "peer" if actor == "Bearer public-lab-peer" else "unknown", "tenant": "B"}
            elif self.path == "/known-denial":
                status, body = 403, {"error": "denied"}
            elif self.path == "/invoice/A":
                status = 200 if actor in (None, "Bearer public-lab-owner") else 403
                body = {"marker": "synthetic-A", "notice": "Public synthetic lab object"}
            else:
                status, body = 404, {"error": "not found"}
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    with socket.socket() as temporary:
        temporary.bind(("127.0.0.1", 0))
        port = temporary.getsockname()[1]
    opener = build_opener(ProxyHandler({}))
    api_key = secrets.token_hex(24)

    def api(component, kind, name, **params):
        url = f"http://127.0.0.1:{port}/JSON/{component}/{kind}/{name}/?" + urlencode(dict(apikey=api_key, **params))
        with opener.open(url, timeout=10) as response:
            value = json.load(response)
        if isinstance(value, dict) and "code" in value:
            raise RuntimeError("ZAP API failed: " + str(value["code"]))
        return value

    try:
        with tempfile.TemporaryDirectory(prefix="authzledger-zap-") as temporary:
            temp = Path(temporary)
            config = temp / "api.properties"
            config.write_text("api.key=" + api_key + "\n", encoding="utf-8")
            config.chmod(0o600)
            command = [str(args.zap_dir.resolve() / "zap.sh"), "-daemon", "-silent", "-notel", "-host", "127.0.0.1", "-port", str(port), "-dir", str(temp / "home"), "-configfile", str(config)]
            with (temp / "startup.log").open("wb") as logfile:
                process = subprocess.Popen(command, stdout=logfile, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 90
                    while True:
                        try:
                            version = api("core", "view", "version")["version"]
                            break
                        except (URLError, TimeoutError):
                            if process.poll() is not None or time.monotonic() >= deadline:
                                raise RuntimeError("ZAP did not become ready")
                            time.sleep(0.25)
                    if version != "2.17.0":
                        raise RuntimeError("Unexpected ZAP version")
                    installed = api("autoupdate", "view", "installedAddons")["installedAddons"]
                    producer_addons = [{key: addon[key] for key in ("id", "version")} for addon in installed if addon["id"] in {"reports", "pscan", "pscanrules", "network"}]
                    api("pscan", "action", "disableAllScanners")
                    api("pscan", "action", "enableScanners", ids="10021")
                    api("core", "action", "accessUrl", url=origin + "/invoice/A", followRedirects="false")
                    deadline = time.monotonic() + 30
                    while int(api("pscan", "view", "recordsToScan")["recordsToScan"]):
                        if time.monotonic() >= deadline:
                            raise RuntimeError("Passive scan timeout")
                        time.sleep(0.1)
                    alerts = api("core", "view", "alerts", baseurl=origin)["alerts"]
                    if not alerts or any(alert["pluginId"] != "10021" for alert in alerts):
                        raise RuntimeError("Expected native passive header alert was not emitted")
                    api("reports", "action", "generate", title="AuthzLedger public loopback exporter fixture", template="traditional-json-plus", sites=origin, reportDir=str(out), reportFileName="zap-real.json", display="false")
                    raw = (out / "zap-real.json").read_bytes()
                    fixture_digest = hashlib.sha256(raw).hexdigest()
                    native_report = json.loads(raw)
                    batch = parse_import(raw, "zap-json-plus")
                    if len(batch["entries"]) != 1 or len(observed) != 1:
                        raise RuntimeError("Capture must contain one entry and one target request")
                    entry = batch["entries"][0]
                    plan = compile_imported_experiment(entry, bindings(entry))
                    old = {key: os.environ.get(key) for key in ("AUTHZ_ZAP_LAB_OWNER", "AUTHZ_ZAP_LAB_PEER")}
                    os.environ.update(AUTHZ_ZAP_LAB_OWNER="Bearer public-lab-owner", AUTHZ_ZAP_LAB_PEER="Bearer public-lab-peer")
                    try:
                        execution = execute_experiment(plan)
                    finally:
                        for key, value in old.items():
                            if value is None:
                                os.environ.pop(key, None)
                            else:
                                os.environ[key] = value
                    errors = verify_execution(execution)
                    if errors or execution["findings"][0]["status"] != "confirmed" or len(observed) != 5:
                        raise RuntimeError("Controlled execution acceptance failed")
                    execution_path = out / "zap-real.execution.json"
                    execution_path.write_text(json.dumps(execution, indent=2) + "\n", encoding="utf-8")
                    provenance = {
                        "schema_version": 1, "kind": "tool-generated-zap-fixture-provenance",
                        "generated_at": datetime.now(timezone.utc).isoformat(), "fixture": "zap-real.json",
                        "producer": {"tool": "ZAP", "version": version, "exporter": "reports.generate", "profile": "traditional-json-plus", "addons": producer_addons},
                        "producer_diagnostics": {key: value for key, value in native_report.get("statistics", {}).items() if key.startswith("stats.log.")},
                        "distribution": {"url": "https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz", "sha256": ARCHIVE_SHA256, "checksum_source": "https://github.com/zaproxy/zaproxy/releases/tag/v2.17.0"},
                        "authenticity": "Unmodified report bytes written directly by the installed ZAP Report Generation add-on after actual loopback HTTP traffic and native passive rule 10021.",
                        "source_scope": {"origin": origin, "external_targets": False, "authentication": False, "response_data": "Public authored synthetic lab object; no customer data."},
                        "capture_request_count": 1, "controlled_execution_request_count": 4,
                        "observed_requests": observed, "sha256": fixture_digest,
                        "execution": {"fixture": execution_path.name, "sha256": hashlib.sha256(execution_path.read_bytes()).hexdigest(), "execution_digest": execution["execution_digest"], "finding_status": execution["findings"][0]["status"], "verification_errors": errors},
                        "reproduction": "python3 tools/capture_zap_fixture.py --zap-dir /path/to/ZAP_2.17.0 --archive /path/to/ZAP_2.17.0_Linux.tar.gz --output /new/capture/directory",
                        "hash_note": "Raw-byte hashing applies only to this deliberate public credential-free fixture. Production imports hash the redacted projection.",
                        "limitations": ["The captured alert is ZAP's missing-header assertion, retained as unverified source data. The separate AuthzLedger run confirms only the configured synthetic authorization marker rule.", "This capture closes the ZAP component of F01-01 only. It is not a Burp export.", "ZAP API calls and the one export-capture request are counted separately from the four-request AuthzLedger execution budget.", "The native report retains ZAP startup diagnostics; this fixture verifies the HTTP/passive-scan/report path, not every installed ZAP add-on or browser integration."],
                        "license": "Public lab payload and harness: repository license. ZAP-generated report descriptions: upstream ZAP Apache-2.0; see https://github.com/zaproxy/zap-extensions/blob/main/LICENSE."
                    }
                    if hashlib.sha256((out / "zap-real.json").read_bytes()).hexdigest() != fixture_digest:
                        raise RuntimeError("Original native export changed")
                    (out / "zap-real.provenance.json").write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
                    print(json.dumps({"fixture_sha256": fixture_digest, "capture_requests": 1, "controlled_requests": 4, "finding": "confirmed", "verification_errors": errors}))
                finally:
                    try:
                        api("core", "action", "shutdown")
                    except (URLError, RuntimeError, TimeoutError):
                        pass
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        process.wait(timeout=10)
                    # Diagnostic copy is explicitly redacted; native JSON report is not.
                    logfile.flush()
                    diagnostics = (temp / "startup.log").read_text(errors="replace")
                    (out / "zap-startup.redacted.log").write_text(diagnostics.replace(api_key, "[API_KEY_REDACTED]").replace(str(temp), "[TEMP_DIRECTORY]"), encoding="utf-8")
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)


if __name__ == "__main__":
    main()
