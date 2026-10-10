#!/usr/bin/env python3
"""Exercise the source-bound comparison slice with real loopback requests.

Usage: python tools/check_comparison.py --out NEW_DIRECTORY

Only a synthetic HTTP service bound to 127.0.0.1 is contacted. Its temporary
credentials and the temporary private signing key are never saved in the output.
The service is stopped before offline comparison/signing/verification begins.
The standalone verifier checks signature and bytes, not comparison semantics;
the main verifier separately checks the source-bound comparison and HTML.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from authzledger import engine
from authzledger.assurance import retest_plan
from authzledger.comparison import create_comparison, verify_comparison
from authzledger.evidence import verify_report
from authzledger.intelligence import build_graph
from authzledger.model import load_contract
from authzledger.reports import render_comparison_html
from authzledger.signing import create_bundle, generate_keypair, verify_bundle


def require(condition, message):
    """Keep acceptance checks active even when Python is invoked with -O."""
    if not condition:
        raise AssertionError(message)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True,
                       allow_nan=False) + "\n").encode("utf-8")


@contextlib.contextmanager
def credentials(values):
    previous = {name: os.environ.get(name) for name in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


@contextlib.contextmanager
def fixture(values):
    state = {"leak": True, "requests": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            token = self.headers.get("Authorization")
            actor = ("owner" if token == values["AUTHZ_COMPARISON_OWNER"] else
                     "peer" if token == values["AUTHZ_COMPARISON_PEER"] else "unknown")
            # Record identities, never raw credentials or headers.
            state["requests"].append({"method": "GET", "path": self.path, "identity": actor})
            if actor == "owner" and self.path == "/invoices/owner-1":
                status, body = 200, {"record_id": "owner-1", "owner": "owner", "protected_marker": "invoice-proof"}
            elif actor == "peer" and self.path == "/invoices/peer-1":
                status, body = 200, {"record_id": "peer-1", "owner": "peer"}
            elif actor == "owner" and self.path == "/unselected-control":
                status, body = 200, {"owner": "owner", "scope": "separate-resource"}
            elif actor == "peer" and self.path == "/invoices/owner-1":
                status, body = 403, {"error": "forbidden"}
                if state["leak"]:
                    body["protected_marker"] = "invoice-proof"
            else:
                status, body = 401, {"error": "authentication-required"}
            raw = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
        require(not worker.is_alive(), "loopback fixture did not stop")


def specification(target):
    return load_contract({
        "version": 1, "name": "403 disclosure: source-bound selective retest", "target": target,
        "limits": {"max_requests": 4, "timeout_seconds": 2, "concurrency": 1, "max_response_bytes": 4096},
        "identities": {
            "owner": {"headers": {"Authorization": {"env": "AUTHZ_COMPARISON_OWNER"}}},
            "peer": {"headers": {"Authorization": {"env": "AUTHZ_COMPARISON_PEER"}}},
        },
        "cases": [
            {"id": "owner-positive", "identity": "owner", "method": "GET", "path": "/invoices/owner-1",
             "expect": {"status": [200], "json": {"/record_id": "owner-1", "/owner": "owner", "/protected_marker": "invoice-proof"}}},
            {"id": "peer-positive", "identity": "peer", "method": "GET", "path": "/invoices/peer-1",
             "expect": {"status": [200], "json": {"/record_id": "peer-1", "/owner": "peer"}}},
            {"id": "peer-denied-owner", "identity": "peer", "method": "GET", "path": "/invoices/owner-1",
             "requires": ["owner-positive", "peer-positive"],
             "expect": {"status": [403], "json_absent": ["/protected_marker"]}},
            {"id": "unselected-control", "identity": "owner", "method": "GET", "path": "/unselected-control",
             "expect": {"status": [200], "json": {"/owner": "owner", "/scope": "separate-resource"}}},
        ],
    })


def check(out):
    out = Path(out).absolute()
    out.mkdir(parents=True, exist_ok=False)
    values = {"AUTHZ_COMPARISON_OWNER": "Bearer " + secrets.token_urlsafe(32),
              "AUTHZ_COMPARISON_PEER": "Bearer " + secrets.token_urlsafe(32)}
    with credentials(values), fixture(values) as (target, state):
        source = specification(target)
        baseline = engine.run(source)
        require(not verify_report(baseline), "baseline evidence invalid")
        require(baseline["summary"]["fail"] == 1, "baseline must contain exactly the 403 disclosure")
        baseline_requests = list(state["requests"])
        require(len(baseline_requests) == 4, "baseline must execute four scoped requests")
        selection = retest_plan(source, ["peer-denied-owner"])
        require(selection["dependency_ids"] == ["owner-positive", "peer-positive"], "retest omitted its positive controls")
        state["leak"] = False
        state["requests"].clear()
        current = engine.run(selection["contract"])
        require(not verify_report(current), "current evidence invalid")
        retest_requests = list(state["requests"])
        require(len(retest_requests) == 3, "retest must execute precisely three requests")
        require(all(row["path"] != "/unselected-control" for row in retest_requests), "unselected resource was retested")

    # All operations below run after the application server and credentials are
    # removed. They use retained evidence, never fresh application observations.
    envelope = create_comparison(source, baseline, current, selection["selected_ids"])
    require(not verify_comparison(envelope), "offline comparison verification failed")
    transitions = {row["case_id"]: row for row in envelope["transitions"]}
    negative = transitions["peer-denied-owner"]
    require(negative["status"] == "resolved_check", "expected a restored configured assertion")
    require(negative["before"]["status"] == negative["after"]["status"] == 403, "both observations must retain HTTP 403")
    require(negative["before"]["assessment"] == "unsafe-denial", "the baseline must detect the leaking denial body")
    require(transitions["unselected-control"]["status"] == "not_retested", "unselected case was misclassified")
    require(envelope["coverage"]["retested_cases"] == 3 and envelope["coverage"]["not_retested_cases"] == 1,
            "selective coverage is inconsistent")
    html = render_comparison_html(envelope)
    graph = build_graph(selection["contract"], current)
    documents = {
        "source.json": source, "baseline.json": baseline,
        "retest-contract.json": selection["contract"], "retest-plan.json": selection,
        "current.json": current, "comparison.json": envelope, "current-graph.json": graph,
    }
    for name, document in documents.items():
        (out / name).write_bytes(json_bytes(document))
    (out / "comparison.html").write_text(html, encoding="utf-8")
    proof, public_key = out / "proof", out / "trusted-public.pem"
    with tempfile.TemporaryDirectory(prefix="authzledger-comparison-key-") as temporary:
        private_key = Path(temporary) / "private.pem"
        generate_keypair(private_key, public_key)
        manifest = create_bundle(current, proof, private_key, {
            "contract.json": json_bytes(selection["contract"]),
            "graph.json": json_bytes(graph),
            "comparison.json": json_bytes(envelope),
            "comparison.html": html.encode("utf-8"),
        })
    require(not verify_bundle(proof, public_key), "main semantic/signature bundle verification failed")

    # ZIP is a transport archive. Both verifiers consume its extracted package;
    # no archive-extraction support is attributed to the standalone verifier.
    archive_path = out / "proof.zip"
    with zipfile.ZipFile(archive_path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(proof.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(proof).as_posix())
    with tempfile.TemporaryDirectory(prefix="authzledger-comparison-verify-") as temporary:
        extracted = Path(temporary) / "proof"
        extracted.mkdir()
        with zipfile.ZipFile(archive_path) as archive:
            # Only this tool's freshly created inventory is extracted here.
            archive.extractall(extracted)
        require(not verify_bundle(extracted, public_key), "main verification of archived package failed")
        standalone = subprocess.run(
            [sys.executable, "-I", str(ROOT / "tools/verify_bundle.py"), str(extracted),
             "--public-key", str(public_key)],
            cwd=temporary, capture_output=True, text=True, check=True, timeout=30,
        )
    result = {
        "passed": True,
        "scope": "Synthetic loopback fixture; comparison implementation slice, not a 1.0.5 release declaration.",
        "runtime_version": current["tool"]["version"],
        "baseline_requests": len(baseline_requests), "retest_requests": len(retest_requests),
        "comparison_sha256": envelope["comparison_sha256"],
        "summary": envelope["summary"], "coverage": envelope["coverage"],
        "proof_zip_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        "signer_public_key_sha256": manifest["signer"]["public_key_sha256"],
        "main_verifier": "Passed: report chain, source-bound comparison, derived HTML, inventory and Ed25519 signature.",
        "standalone_verifier": "Passed with python -I: signature, inventory, hashes and report anchors; comparison semantics are not evaluated.",
        "standalone_stdout": standalone.stdout.strip(),
        "trust": "The generated public key is a demonstration trust anchor, not an independently authenticated producer identity.",
        "private_key": "Created temporarily for this fixture and removed after signing.",
        "meaning": "resolved_check records restored configured assertions; it is not an independent vulnerability-remediation attestation.",
    }
    (out / "acceptance.json").write_bytes(json_bytes(result))
    credential_bytes = [value.encode("ascii") for value in values.values()]
    for path in out.rglob("*"):
        if path.is_file():
            raw = path.read_bytes()
            require(not any(value in raw for value in credential_bytes), "credential material persisted in output")
            require(b"PRIVATE KEY-----" not in raw, "private signing key persisted in output")
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="New output directory; existing paths are refused")
    check(parser.parse_args().out)
