"""Bounded local fault corpus: actual HTTP observations, explicit expected detections."""
from __future__ import annotations

import copy
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .engine import run
from .evidence import compare_reports
from .matrix import compile_matrix, explain_report
from .model import load_contract

ACTORS = {"north_member": ("north", "member"), "north_admin": ("north", "admin"),
          "south_member": ("south", "member"), "south_admin": ("south", "admin")}
RESOURCES = {"invoice-a": ("north_member", "north", "invoice"), "invoice-b": ("north_admin", "north", "invoice"),
             "invoice-c": ("south_member", "south", "invoice"), "invoice-d": ("south_admin", "south", "invoice"),
             "audit-north": ("north_admin", "north", "audit"), "audit-south": ("south_admin", "south", "audit")}
ALLOW = {"north_member": {"invoice-a"}, "north_admin": {"invoice-a", "invoice-b", "audit-north"},
         "south_member": {"invoice-c"}, "south_admin": {"invoice-c", "invoice-d", "audit-south"}}
FAULTS = {
    "owner-bypass": {"m:north_member:invoice-b", "m:south_member:invoice-d"},
    "tenant-bypass": {"m:north_admin:invoice-c", "m:north_admin:invoice-d", "m:south_admin:invoice-a", "m:south_admin:invoice-b"},
    "role-bypass": {"m:north_member:audit-north", "m:south_member:audit-south"},
    "denial-leak": {"m:north_member:invoice-b"},
}


def sample_project(target="http://127.0.0.1:8080", env_names=None):
    env_names = env_names or {name: "AUTHZ_" + name.upper() + "_TOKEN" for name in ACTORS}
    return {"version": 1, "name": "Tenant boundaries · invoice and audit API", "target": target,
            "actors": [{"id": name, "label": tenant.title() + " · " + role.title(), "tenant": tenant, "role": role,
                        "env": env_names[name]} for name, (tenant, role) in ACTORS.items()],
            "resources": [{"id": rid, "label": rid.replace("-", " ").title(), "path": "/" + kind + "/" + rid,
                           "owner": owner, "tenant": tenant, "assertions": {"/id": rid, "/tenant": tenant},
                           "absent": ["/id", "/tenant", "/amount"]}
                          for rid, (owner, tenant, kind) in RESOURCES.items()],
            "decisions": {a: {r: "allow" if r in ALLOW[a] else "deny" for r in RESOURCES} for a in ACTORS},
            "limits": {"max_requests": 32, "timeout_seconds": 3, "max_response_bytes": 16384, "concurrency": 4}}


def run_benchmark(out: Path | None = None):
    suffix = secrets.token_hex(8).upper()
    envs = {a: "AUTHZ_CORPUS_" + suffix + "_" + a.upper() for a in ACTORS}
    tokens = {"Bearer " + secrets.token_hex(24): a for a in ACTORS}
    mode = {"name": "clean"}
    requests = []

    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            actor = tokens.get(self.headers.get("Authorization", ""))
            rid = self.path.rsplit("/", 1)[-1]
            requests.append((actor, self.path))
            status, payload = 404, {"error": "not_found"}
            if actor is None or (mode["name"] == "expired-credential" and actor == "north_member"):
                # A broken middleware that hides invalid sessions behind 403 is a false-pass trap.
                status, payload = 403, {"error": "invalid_session"}
            elif rid in RESOURCES and self.path == "/" + RESOURCES[rid][2] + "/" + rid:
                owner, tenant, kind = RESOURCES[rid]
                actor_tenant, role = ACTORS[actor]
                permitted = actor_tenant == tenant and ((kind == "invoice" and actor == owner) or role == "admin")
                if mode["name"] == "owner-bypass" and kind == "invoice" and actor_tenant == tenant:
                    permitted = True
                if mode["name"] == "tenant-bypass" and kind == "invoice" and role == "admin":
                    permitted = True
                if mode["name"] == "role-bypass" and kind == "audit" and actor_tenant == tenant:
                    permitted = True
                if mode["name"] == "missing-resource" and rid == "invoice-a":
                    status, payload = 404, {"error": "not_found"}
                elif permitted:
                    status, payload = 200, {"id": rid, "tenant": tenant, "amount": 120}
                    if mode["name"] == "wrong-object" and rid == "invoice-a":
                        payload["id"] = "unrelated-fallback-object"
                elif mode["name"] == "denial-leak" and actor == "north_member" and rid == "invoice-b":
                    status, payload = 403, {"error": "forbidden", "amount": 120}
                else:
                    status, payload = 403, {"error": "forbidden"}
            data = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        for token, name in tokens.items():
            os.environ[envs[name]] = token
        project = sample_project(f"http://127.0.0.1:{server.server_port}", envs)
        compiled = compile_matrix(project)
        contract = compiled["contract"]
        naive = copy.deepcopy(contract)
        for case in naive["cases"]:
            case["requires"] = []
            case["expect"] = {"status": case["expect"]["status"]}
        naive = load_contract(naive)
        evidence, rows = {}, []
        for name in ["clean", *FAULTS, "expired-credential", "missing-resource", "wrong-object"]:
            mode["name"] = name
            requests.clear()
            report = run(contract)
            observed_requests = len(requests)
            baseline = run(naive)
            explained = explain_report(project, report)
            failed_denials = {x["case_id"] for x in explained["trace"] if x["decision"] == "deny" and x["outcome"] == "fail"}
            unresolved = {x["case_id"] for x in explained["trace"] if x["outcome"] == "inconclusive"}
            naive_map = {x["id"]: x for x in baseline["results"]}
            masked = sum(naive_map[k]["outcome"] == "pass" for k in unresolved)
            expected = FAULTS.get(name, set())
            if name == "expired-credential":
                expected_unresolved = {"m:north_member:" + r for r in RESOURCES if r != "invoice-a"} | {"m:south_member:invoice-a", "m:south_admin:invoice-a"}
            elif name in {"missing-resource", "wrong-object"}:
                expected_unresolved = {"m:north_member:" + r for r in RESOURCES if r != "invoice-a"} | {"m:south_member:invoice-a", "m:south_admin:invoice-a"}
            else:
                expected_unresolved = set()
            expected_control_failures = {"m:north_member:invoice-a"} if name == "expired-credential" else {"m:north_member:invoice-a", "m:north_admin:invoice-a"} if name in {"missing-resource", "wrong-object"} else set()
            actual_control_failures = {x["case_id"] for x in explained["trace"] if x["decision"] == "allow" and x["outcome"] == "fail"}
            accepted = (failed_denials == expected and unresolved == expected_unresolved and
                        actual_control_failures == expected_control_failures and report["summary"]["error"] == 0)
            rows.append({"scenario": name, "accepted": accepted, "summary": report["summary"],
                         "expected_denial_violations": sorted(expected), "detected_denial_violations": sorted(failed_denials),
                         "expected_inconclusive": sorted(expected_unresolved), "observed_requests": observed_requests,
                         "naive_status_only_false_passes_on_unresolved": masked,
                         "status_only_missed_denial_violations": sum(naive_map[k]["outcome"] == "pass" for k in expected)})
            evidence[name] = {"report": report, "status_only_report": baseline}
        # Finish with an actual clean retest after the faulty implementations.
        mode["name"] = "clean"
        repaired = run(contract)
        if repaired["summary"]["pass"] != 24:
            raise ValueError("Clean retest failed")
        evidence["clean"]["report"] = repaired
        result = {"schema_version": 1, "kind": "local-synthetic-fault-corpus", "scenarios": rows,
                  "accepted": all(r["accepted"] for r in rows), "project": project,
                  "manifest": compiled["manifest"], "evidence": evidence,
                  "baseline": evidence["owner-bypass"]["report"], "report": evidence["clean"]["report"],
                  "comparison": compare_reports(evidence["owner-bypass"]["report"], evidence["clean"]["report"]),
                  "limitation": "Eight authored local scenarios, not an independent tool comparison, field study or market-superiority proof."}
        if out is not None:
            from .cli import write_json, save_report
            from .reports import render_diff_html
            out.mkdir(parents=True, exist_ok=True)
            write_json(out / "benchmark.json", result)
            write_json(out / "matrix.json", project)
            write_json(out / "manifest.json", compiled["manifest"])
            write_json(out / "contract.json", contract)
            for name, item in evidence.items():
                save_report(item["report"], out / name)
                save_report(item["status_only_report"], out / name / "status-only")
            (out / "retest.html").write_text(render_diff_html(result["comparison"]), encoding="utf-8")
        return result
    finally:
        server.shutdown()
        server.server_close()
        for env in envs.values():
            os.environ.pop(env, None)
