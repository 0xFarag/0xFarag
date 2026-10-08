"""A real, entirely loopback fixture demonstrating vulnerable and fixed authorization."""
from __future__ import annotations

import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .engine import run
from .evidence import compare_reports
from .model import load_contract, plan
from .reports import render_diff_html


def demo_contract(target: str, env_names: dict[str, str]) -> dict:
    return {
        "version": 1, "name": "Invoice API · local authorization fixture", "target": target,
        "limits": {"max_requests": 20, "timeout_seconds": 3, "max_response_bytes": 16384, "concurrency": 3},
        "identities": {**{name: {"headers": {"Authorization": {"env": env}}} for name, env in env_names.items()}, "anonymous": {"headers": {}}},
        "cases": [
            {"id": "owner-own-invoice", "identity": "owner", "method": "GET", "path": "/invoices/owner-1", "expect": {"status": [200], "json": {"/owner": "owner", "/amount": 120}}},
            {"id": "peer-own-invoice", "identity": "peer", "method": "GET", "path": "/invoices/peer-1", "expect": {"status": [200], "json": {"/owner": "peer", "/amount": 240}}},
            {"id": "peer-cannot-read-owner", "identity": "peer", "method": "GET", "path": "/invoices/owner-1", "requires": ["owner-own-invoice", "peer-own-invoice"], "expect": {"status": [403, 404], "json_absent": ["/amount", "/owner"]}},
            {"id": "anonymous-cannot-read", "identity": "anonymous", "method": "GET", "path": "/invoices/owner-1", "requires": ["owner-own-invoice"], "expect": {"status": [401, 403], "json_absent": ["/amount"]}},
            {"id": "admin-can-read-audit", "identity": "admin", "method": "GET", "path": "/admin/audit", "expect": {"status": [200], "json": {"/access": "admin"}}},
            {"id": "owner-cannot-read-audit", "identity": "owner", "method": "GET", "path": "/admin/audit", "requires": ["admin-can-read-audit", "owner-own-invoice"], "expect": {"status": [403], "json_absent": ["/access"]}},
        ],
    }


def run_demo(out: Path) -> int:
    from .cli import print_summary, save_report, write_json
    tokens = {"Bearer " + secrets.token_hex(24): name for name in ("owner", "peer", "admin")}
    env_names = {name: "AUTHZLEDGER_DEMO_" + name.upper() + "_TOKEN" for name in tokens.values()}
    prior = {env: os.environ.get(env) for env in env_names.values()}
    mode = {"fixed": False}

    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def do_GET(self) -> None:
            actor = tokens.get(self.headers.get("Authorization", ""))
            status, payload = 404, {"error": "not_found"}
            if actor is None:
                status, payload = 401, {"error": "authentication_required"}
            elif self.path in ("/invoices/owner-1", "/invoices/peer-1"):
                owner = self.path.split("/")[-1].split("-")[0]
                if mode["fixed"] and actor not in (owner, "admin"):
                    status, payload = 403, {"error": "forbidden"}
                else:
                    status, payload = 200, {"owner": owner, "amount": 120 if owner == "owner" else 240}
            elif self.path == "/admin/audit":
                if mode["fixed"] and actor != "admin":
                    status, payload = 403, {"error": "forbidden"}
                else:
                    status, payload = 200, {"access": "admin"}
            body = json.dumps(payload, sort_keys=True).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for token, name in tokens.items():
            os.environ[env_names[name]] = token
        contract = load_contract(demo_contract(f"http://127.0.0.1:{server.server_port}", env_names))
        out.mkdir(parents=True, exist_ok=True)
        write_json(out / "contract.json", contract)
        write_json(out / "plan.json", plan(contract))
        before = run(contract)
        save_report(before, out / "vulnerable")
        print("\nBEFORE · vulnerable local fixture")
        print_summary(before)
        mode["fixed"] = True
        after = run(contract)
        save_report(after, out / "fixed")
        print("\nAFTER · fixed local fixture")
        print_summary(after)
        comparison = compare_reports(before, after)
        write_json(out / "diff.json", comparison)
        (out / "diff.html").write_text(render_diff_html(comparison), encoding="utf-8")
        expected = {"peer-cannot-read-owner", "owner-cannot-read-audit"}
        detected = {case["id"] for case in before["results"] if case["outcome"] == "fail"}
        passed = detected == expected and after["summary"]["pass"] == 6 and after["summary"]["total"] == 6
        print(f"\nDemo {'verified' if passed else 'FAILED'}: {len(comparison['resolved'])} resolved; synthetic loopback fixture only.")
        print(f"Reports: {out}")
        return 0 if passed else 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        for env, previous in prior.items():
            if previous is None:
                os.environ.pop(env, None)
            else:
                os.environ[env] = previous
