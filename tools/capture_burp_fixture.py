#!/usr/bin/env python3
"""Capture genuine Burp Copy-to-file messages, then verify a separate local run.

This tool supplies the public fixture and checks files saved by the native Burp
UI. It never serializes, rewrites or substitutes the exported HTTP messages.
Use a fresh output directory; see capture-instructions.json after startup.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

BURP_VERSION = "2026.9.2"
BURP_JAR_SHA256 = "3571f8cadbfd65b0b090d2753735c40b76ad7fdde0b927df2b22ec46ea09693a"
BURP_DOWNLOAD = "https://portswigger.net/burp/releases/startdownload?product=desktop&type=jar&version=2026.9.2"


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--burp-jar", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--wait-seconds", type=int, default=900)
    args = parser.parse_args()
    if not 1 <= args.wait_seconds <= 1800:
        parser.error("wait-seconds must be between 1 and 1800")
    if digest(args.burp_jar) != BURP_JAR_SHA256:
        parser.error("Burp JAR does not match the pinned official SHA256")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    observed = []
    phase = {"name": "native_capture"}

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def do_GET(self):
            if len(observed) >= 8:
                self.send_error(429, "Public fixture budget exhausted")
                return
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
            observed.append({"phase": phase["name"], "method": "GET", "path": self.path,
                             "status": status, "request_line_hex": self.raw_requestline.hex(),
                             "headers": list(self.headers.raw_items())})
            raw = json.dumps(body).encode("ascii")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    instructions = {
        "origin": origin, "url": origin + "/invoice/A",
        "native_action": "Burp message editor Raw tab: Copy to file with no text selected",
        "request_file": "burp-request.http", "response_file": "burp-response.http",
        "xml_file_optional": "burp-http-messages.xml",
        "completion": "After both native files exist, write capture-ready.json with edition, native_action and screenshot filenames.",
        "public_fixture": "Owned loopback, public synthetic marker, no real credentials or customer data.",
    }
    save(out / "capture-instructions.json", instructions)
    print(json.dumps(instructions), flush=True)
    try:
        deadline = time.monotonic() + args.wait_seconds
        while not (out / "capture-ready.json").is_file():
            if time.monotonic() >= deadline:
                raise RuntimeError("Native export was not supplied before the deadline")
            time.sleep(0.25)
        receipt = json.loads((out / "capture-ready.json").read_text())
        if receipt.get("native_action") != instructions["native_action"] or receipt.get("edition") != "Community":
            raise RuntimeError("Native capture action/edition receipt is missing")
        screenshots = receipt.get("screenshots")
        if not isinstance(screenshots, list) or not screenshots:
            raise RuntimeError("Native UI screenshot evidence is required")
        screenshot_hashes = {}
        for name in screenshots:
            if not isinstance(name, str) or Path(name).name != name or not name.endswith(".png"):
                raise RuntimeError("Screenshot must be a local PNG filename")
            screenshot_hashes[name] = digest(out / name)
        request_path, response_path = out / "burp-request.http", out / "burp-response.http"
        before = {p.name: digest(p) for p in (request_path, response_path)}
        from authzledger.imports import ImportError, parse_import
        from authzledger.experiments import compile_imported_experiment, execute_experiment, verify_execution
        from authzledger.credentials import CredentialResolver
        batch = parse_import(request_path.read_bytes(), "burp-http-pair-v1", source_origin=origin,
                             response_bytes=response_path.read_bytes())
        entry = batch["entries"][0]
        if (entry["method"], entry["origin"], entry["path"], entry["response"]["status"]) != ("GET", origin, "/invoice/A", 200):
            raise RuntimeError("Native export does not match the public captured request")
        if entry["execution_blockers"]:
            raise RuntimeError("Native request has execution blockers")
        native_requests = list(observed)
        if len(native_requests) != 1 or native_requests[0]["path"] != "/invoice/A":
            raise RuntimeError("Native capture must contain exactly one public fixture request")
        bindings = {
            "id": "burp-native-export-acceptance", "title": "Native Burp Copy-to-file acceptance",
            "target": origin,
            "identities": {
                "owner": {"headers": {"Authorization": {"env": "AUTHZ_BURP_LAB_OWNER"}}},
                "peer": {"headers": {"Authorization": {"env": "AUTHZ_BURP_LAB_PEER"}}},
            },
            "actor_identity": "peer", "owner_identity": "owner",
            "identity_probe": {"path": "/me", "expect": {"status": [200], "json": {"/principal": "peer", "/tenant": "B"}}},
            "negative_probe": {"path": "/known-denial", "expect": {"status": [403], "json_absent": ["/marker"]}},
            "rule": {"id": "tenant-isolation", "resource_id": "invoice-A", "kind": "forbid_field_equal", "pointer": "/marker", "value": "synthetic-A"},
            "omitted_secret_slots": [slot["id"] for slot in entry["secret_slots"]],
            "capture_mode": "safe_values", "limits": {"max_requests": 4, "concurrency": 1},
        }
        plan = compile_imported_experiment(entry, bindings)
        phase["name"] = "controlled_execution"
        resolver = CredentialResolver()
        resolver.bind_session("AUTHZ_BURP_LAB_OWNER", "Bearer public-lab-owner", identity="owner", target_origin=origin)
        resolver.bind_session("AUTHZ_BURP_LAB_PEER", "Bearer public-lab-peer", identity="peer", target_origin=origin)
        result = execute_experiment(plan, credential_resolver=resolver)
        if verify_execution(result):
            raise RuntimeError("Controlled execution did not verify")
        if len(observed) != 5:
            raise RuntimeError("Expected one native capture plus four controlled requests")
        if not any(f.get("status") == "confirmed" for f in result.get("findings", [])):
            raise RuntimeError("Expected the controlled public marker violation")
        xml_receipt = None
        xml = out / "burp-http-messages.xml"
        if xml.is_file():
            try:
                parse_import(xml.read_bytes(), "burp-xml")
            except ImportError as exc:
                xml_receipt = {"sha256": digest(xml), "import_result": str(exc), "accepted": False}
            else:
                xml_receipt = {"sha256": digest(xml), "import_result": "accepted", "accepted": True}
        if before != {p.name: digest(p) for p in (request_path, response_path)}:
            raise RuntimeError("Native export bytes changed during verification")
        save(out / "burp-real.import.json", batch)
        save(out / "burp-real.execution.json", result)
        save(out / "request-receipts.json", observed)
        save(out / "burp-real.provenance.json", {
            "producer": "Burp Suite", "edition": "Community", "version": BURP_VERSION,
            "distribution_url": BURP_DOWNLOAD, "distribution_sha256": BURP_JAR_SHA256,
            "capture_time": datetime.now(timezone.utc).isoformat(), "native_action": instructions["native_action"],
            "profile": "burp-http-pair-v1", "source_origin": origin, "native_files_sha256": before,
            "native_capture_requests": len(native_requests), "controlled_execution_requests": len(observed) - len(native_requests),
            "screenshots_sha256": screenshot_hashes, "xml_export": xml_receipt,
            "public_synthetic_fixture": True, "native_files_unchanged": True,
            "provenance_level": "Observed native UI action, pinned producer binary and unchanged export bytes; not a vendor attestation.",
            "harness_sha256": digest(Path(__file__)),
        })
        print("Native Burp capture and separate four-request controlled execution verified.", flush=True)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=5)


if __name__ == "__main__":
    main()
