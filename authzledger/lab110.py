"""Explicit loopback-only workflow lab for reproducible state/replay evidence.

The deliberately vulnerable fixture uses synthetic disposable objects only.
It is never bound to a public interface and does not contact another service.
"""
from __future__ import annotations
import argparse
import contextlib
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

@contextlib.contextmanager
def workflow_lab(*, port=0):
    state = {"objects": {}, "next": 0, "vulnerable": True, "replay": False, "control": True,
             "cleanup": True, "duplicate": False, "reuse": False, "bad_id": False, "requests": []}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def send(self, status, body):
            payload = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(status); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload))); self.end_headers(); self.wfile.write(payload)
        def do_GET(self):
            state["requests"].append(("GET", self.path))
            if self.path == "/control":
                return self.send(200, {"principal": "operator" if state["control"] else "wrong"})
            key = self.path.split("/")[-1]
            if key not in state["objects"]: return self.send(404, {})
            self.send(200, dict(state["objects"][key], id=key))
        def do_POST(self):
            state["requests"].append(("POST", self.path))
            raw = self.rfile.read(min(65537, int(self.headers.get("Content-Length", "0"))))
            if len(raw) > 65536: return self.send(413, {})
            try: request_body = json.loads(raw) if raw else {}
            except (ValueError, UnicodeError): return self.send(400, {})
            if self.path == "/objects":
                state["next"] += 1
                key = "fixed" if state["reuse"] else str(state["next"])
                if state["bad_id"]: key = "../outside"
                state["objects"][key] = {"state": "draft", "effects": 0, "operations": []}
                if state["duplicate"]: return self.send(201, b'{"id":"1","id":"2"}')
                return self.send(201, {"id": key})
            _, _, key, action = self.path.split("/")
            obj = state["objects"][key]
            if action == "approve": obj["state"] = "approved"
            if action == "complete":
                if not state["vulnerable"] and obj["state"] not in {"approved", "completed"}:
                    return self.send(403, {})
                obj["state"] = "completed"
                operation = request_body.get("operation_id")
                if not isinstance(operation, str) or operation != key:
                    return self.send(400, {"error": "operation identifier required"})
                if state["replay"] or operation not in obj["operations"]:
                    obj["effects"] += 1
                    obj["operations"].append(operation)
            self.send(200, {})
        def do_DELETE(self):
            state["requests"].append(("DELETE", self.path))
            if not state["cleanup"]: return self.send(500, {})
            state["objects"].pop(self.path.split("/")[-1], None)
            self.send(200, {})
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
    try: yield "http://127.0.0.1:" + str(server.server_port), state
    finally: server.shutdown(); server.server_close(); worker.join()


def workflow_spec(origin):
    def op(id, method, path, expect):
        return {"id": id, "identity": "operator", "method": method, "path": path, "expect": expect}
    def step(id, case_id, bind=True):
        result = {"id": id, "case_id": case_id, "bindings": []}
        if bind:
            result["bindings"] = [{"source_step": "create", "pointer": "/id", "type": "string", "target": {"kind": "path_segment", "index": 2}}]
        return result
    result = {"schema_version": 1, "kind": "workflow-spec", "id": "approval", "title": "Approval must precede completion",
            "contract": {"version": 1, "name": "Workflow fixture", "target": origin, "identities": {"operator": {"headers": {}}},
                         "limits": {"max_requests": 100, "concurrency": 1}, "cases": [
                op("control", "GET", "/control", {"status": [200], "json": {"/principal": "operator"}}),
                op("create", "POST", "/objects", {"status": [201]}),
                op("before", "GET", "/objects/placeholder", {"status": [200], "json": {"/state": "draft", "/effects": 0}}),
                op("approve", "POST", "/objects/placeholder/approve", {"status": [200]}),
                op("complete", "POST", "/objects/placeholder/complete", {"status": [200, 403]}),
                op("after", "GET", "/objects/placeholder", {"status": [200]}),
                op("delete", "DELETE", "/objects/placeholder", {"status": [200]})]},
            "controls": ["control"], "setup": step("create", "create", False), "precondition": step("before", "before"),
            "steps": [step("approve", "approve"), step("complete", "complete")], "postcondition": step("after", "after"),
            "cleanup": [step("delete", "delete")], "fixture": {"source_step": "create", "pointer": "/id", "type": "string", "read_pointer": "/id"},
            "rule": {"id": "approval", "kind": "forbidden_state", "pointer": "/state", "value": "completed"},
            "variants": [{"id": "skip-approval", "omit": ["approve"]}], "mutation_approval": ["create", "approve", "complete", "delete"]}
    result["contract"]["cases"][4]["body"] = {"operation_id": "placeholder"}
    result["steps"][1]["bindings"].append({"source_step": "create", "pointer": "/id", "type": "string", "target": {"kind": "json", "pointer": "/operation_id"}})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run AuthzLedger's synthetic workflow lab on loopback")
    parser.add_argument("--port", type=int, default=8768)
    parser.add_argument("--safe", action="store_true", help="Enforce approval and idempotency")
    parser.add_argument("--replay-vulnerable", action="store_true", help="Allow repeated side effects for the same explicit operation identifier")
    args = parser.parse_args(argv)
    if not 0 <= args.port <= 65535:
        parser.error("port must be 0..65535")
    with workflow_lab(port=args.port) as (origin, state):
        state["vulnerable"] = not args.safe
        state["replay"] = args.replay_vulnerable
        print("Synthetic workflow lab: " + origin, flush=True)
        print("Bound to 127.0.0.1; Ctrl+C stops and discards synthetic objects.", flush=True)
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            pass
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
