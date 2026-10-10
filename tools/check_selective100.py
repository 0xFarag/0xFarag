#!/usr/bin/env python3
"""Demo C: 100 baseline cases -> 7 selected + 3 controls -> 90 not_retested.

Run: python3 tools/check_selective100.py --out NEW_DIRECTORY
Only a synthetic 127.0.0.1 service is contacted. Main and isolated standalone
verification run after that service stops and the temporary signing key is gone.
No tests module, external target, persistent credential or private key is used.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from authzledger.assessment_reports import assessment_attachments, freeze_assessment, verify_assessment
from authzledger.execution import REQUEST_KINDS
from authzledger.experiments import (compile_experiment, execute_experiment,
    verify_execution, plan_experiment_retest, compare_executions)
from authzledger.reports import render_comparison_html
from authzledger.signing import create_bundle, generate_keypair, verify_bundle


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True,
                       allow_nan=False) + "\n").encode("utf-8")


def write_new(path, raw):
    with path.open("xb") as handle:
        handle.write(raw)


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
    state = {"leak": True, "requests": [], "stopped": False}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            token = self.headers.get("Authorization")
            actor = ("owner" if token == values["SELECTIVE_OWNER"] else
                     "peer" if token == values["SELECTIVE_PEER"] else "unknown")
            route = urlsplit(self.path).path
            if actor == "peer" and route == "/me":
                status, body, kind = 200, {"principal": "peer", "tenant": "B"}, "identity_control"
            elif actor == "owner" and route == "/invoice/A":
                status, body, kind = 200, {"marker": "synthetic-A"}, "object_control"
            elif actor == "peer" and route == "/known-denial":
                status, body, kind = 403, {"error": "denied"}, "negative_control"
            elif actor == "peer" and route == "/invoice/A":
                status, body, kind = 403, {"error": "denied"}, "application"
                if state["leak"]:
                    body["marker"] = "synthetic-A"
            elif actor == "owner" and route.startswith("/historical/"):
                status, body, kind = 200, {"scope": "historical-control"}, "application"
            else:
                status, body, kind = 401, {"error": "authentication-required"}, "application"
            # Capture the server-observed request category and synthetic identity;
            # never copy Authorization or any raw request header to evidence.
            state["requests"].append({"method": "GET", "path": self.path,
                                      "identity": actor, "kind": kind, "status": status})
            raw = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    worker = threading.Thread(target=server.serve_forever,
                              kwargs={"poll_interval": 0.01}, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=3)
        require(not worker.is_alive(), "loopback fixture did not stop")
        state["stopped"] = True


def specification(target):
    controls = [
        {"id": "actor", "identity": "peer", "method": "GET", "path": "/me",
         "expect": {"status": [200], "json": {"/principal": "peer", "/tenant": "B"}}},
        {"id": "owner", "identity": "owner", "method": "GET", "path": "/invoice/A",
         "expect": {"status": [200], "json": {"/marker": "synthetic-A"}}},
        {"id": "negative", "identity": "peer", "method": "GET", "path": "/known-denial",
         "requires": ["actor", "owner"],
         "expect": {"status": [403], "json_absent": ["/marker"]}},
    ]
    selected = [{"id": f"target-{i}", "identity": "peer", "method": "GET",
                 "path": f"/invoice/A?view={i}", "requires": ["actor", "owner", "negative"],
                 "expect": {"status": [403], "json_absent": ["/marker"]}}
                for i in range(7)]
    outside = [{"id": f"outside-{i:02}", "identity": "owner", "method": "GET",
                "path": f"/historical/{i:02}",
                "expect": {"status": [200], "json": {"/scope": "historical-control"}}}
               for i in range(90)]
    return {
        "schema_version": 1, "kind": "experiment-spec", "id": "selective100",
        "title": "Selective retest: seven declared views of one synthetic resource",
        "contract": {
            "version": 1, "name": "Demo C: bounded 100-case baseline", "target": target,
            "limits": {"max_requests": 100, "timeout_seconds": 2,
                       "concurrency": 1, "max_response_bytes": 4096},
            "identities": {
                "owner": {"headers": {"Authorization": {"env": "SELECTIVE_OWNER"}}},
                "peer": {"headers": {"Authorization": {"env": "SELECTIVE_PEER"}}},
            }, "cases": controls + selected + outside,
        },
        "rule": {"id": "tenant-isolation", "resource_id": "invoice-A",
                 "kind": "forbid_field_equal", "pointer": "/marker", "value": "synthetic-A"},
        "variants": [{"id": f"variant-{i}", "case_id": f"target-{i}",
                      "identity_control": "actor", "object_control": "owner",
                      "negative_control": "negative"} for i in range(7)],
        "capture_mode": "safe_values",
    }


def receipt(execution, requests):
    counts = {kind: sum(row["kind"] == kind for row in requests)
              for kind in sorted(REQUEST_KINDS)}
    ledger = execution["budget_ledger"]
    require(counts == ledger["by_kind"], "server and execution request categories differ")
    require(len(requests) == ledger["dispatched_total"], "server and ledger totals differ")
    require(sum(counts.values()) == len(requests), "request category missing from accounting")
    return {"report_root_sha256": execution["report"]["evidence"]["root_sha256"],
            "execution_digest": execution["execution_digest"],
            "approved_requests": ledger["approved_total"],
            "dispatched_requests": len(requests), "by_kind": counts,
            "server_observed_requests": requests}


def check(out):
    out = Path(out).absolute()
    out.mkdir(parents=True, exist_ok=False)
    values = {name: "Bearer " + secrets.token_urlsafe(32)
              for name in ("SELECTIVE_OWNER", "SELECTIVE_PEER")}
    baseline_path = out / "baseline-execution.json"
    with credentials(values), fixture(values) as (target, state):
        spec = specification(target)
        baseline = execute_experiment(compile_experiment(spec))
        require(not verify_execution(baseline), "baseline execution is invalid")
        require(len(baseline["report"]["results"]) == 100, "expected 100 baseline cases")
        require(len(baseline["findings"]) == 7 and
                all(f["status"] == "confirmed" for f in baseline["findings"]),
                "all seven synthetic denial disclosures must be confirmed")
        baseline_bytes = json_bytes(baseline)
        write_new(baseline_path, baseline_bytes)
        baseline_receipt = receipt(baseline, list(state["requests"]))
        require(baseline_receipt["dispatched_requests"] == 100, "expected 100 baseline dispatches")
        retest_plan = plan_experiment_retest(baseline, [v["id"] for v in spec["variants"]])
        require(len(retest_plan["contract"]["cases"]) == 10, "retest must include 7 targets + 3 controls")
        state["leak"] = False
        state["requests"].clear()
        current = execute_experiment(retest_plan)
        require(not verify_execution(current), "current execution is invalid")
        current_receipt = receipt(current, list(state["requests"]))
        require(current_receipt["dispatched_requests"] == 10, "expected exactly 10 retest dispatches")
        require(not any(r["path"].startswith("/historical/") for r in state["requests"]),
                "unselected baseline resource was dispatched again")

    # Application fixture is closed before every comparison/signature/verification.
    require(state["stopped"], "offline verification requires the fixture to be stopped")
    comparison = compare_executions(baseline, current)
    require(len(comparison["transitions"]) == 7 and
            all(t["status"] == "fix_verified" for t in comparison["transitions"]),
            "only selected rule/resource/identity bindings may be marked fix_verified")
    envelope = comparison["comparison_envelope"]
    require(envelope["coverage"]["retested_cases"] == 10 and
            envelope["coverage"]["not_retested_cases"] == 90, "coverage must retain 90 historical cases")
    outside = [t for t in envelope["transitions"] if t["case_id"].startswith("outside-")]
    require(len(outside) == 90 and all(t["status"] == "not_retested" for t in outside),
            "historical cases must never be promoted to fixed")
    require(baseline_path.read_bytes() == baseline_bytes == json_bytes(baseline),
            "baseline bytes or original evidence root changed")

    signed_receipt = {
        "schema_version": 1, "demo": "C", "scope": "synthetic-loopback-selective-retest",
        "tool_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "baseline": baseline_receipt, "current": current_receipt,
        "total_network_requests": 110,
        "total_by_kind": {kind: baseline_receipt["by_kind"][kind] + current_receipt["by_kind"][kind]
                          for kind in sorted(REQUEST_KINDS)},
        "selected_cases": 7, "required_control_cases": 3, "not_retested_cases": 90,
        "fixture_stopped_before_verification": True,
        "baseline_bytes_unchanged": True,
        "baseline_file_sha256": hashlib.sha256(baseline_bytes).hexdigest(),
        "scope_limits": [
            "Seven explicit query variants share one synthetic resource, identity and rule.",
            "The 90 remaining baseline cases are historical, not evidence of a current fix.",
            "100 to 10 compares dispatched requests within this fixture; it is not a general speedup benchmark.",
            "Server receipts are local measurements by this runner, not third-party execution attestations.",
            "Setup, cleanup, replay, reduction, PDP, advisory and state probes make no HTTP requests here.",
        ],
    }
    snapshot = freeze_assessment([baseline, current], {
        "assessment_id": "demo-c-selective100", "title": "AuthzLedger / selective retest evidence",
        "reviewer": "Synthetic demonstration runner",
        "executive_summary": "100 baseline requests; 7 selected checks plus 3 fresh prerequisite controls; 90 cases remain not_retested.",
        "scope": [target], "limitations": signed_receipt["scope_limits"],
    }, [comparison])
    require(not verify_assessment(snapshot), "assessment cannot be independently reconstructed")
    attachments = assessment_attachments(snapshot)
    attachments.update({"comparison.json": json_bytes(envelope),
                        "comparison.html": render_comparison_html(envelope).encode("utf-8"),
                        "request-receipts.json": json_bytes(signed_receipt)})
    documents = {"specification.json": spec, "retest-plan.json": retest_plan,
                 "current-execution.json": current, "experiment-comparison.json": comparison,
                 "request-receipts.json": signed_receipt}
    for name, document in documents.items():
        write_new(out / name, json_bytes(document))
    for name, raw in attachments.items():
        if name != "request-receipts.json":
            write_new(out / name, raw)

    proof, public_key = out / "proof", out / "trusted-public.pem"
    with tempfile.TemporaryDirectory(prefix="authzledger-selective100-key-") as temporary:
        private_key = Path(temporary) / "private.pem"
        generate_keypair(private_key, public_key)
        manifest = create_bundle(current["report"], proof, private_key, attachments)
    require(not private_key.exists(), "temporary private signing key still exists")
    require(not verify_bundle(proof, public_key), "main semantic/signature verification failed")
    shutil.copyfile(ROOT / "tools/verify_bundle.py", out / "verify_bundle.py")
    archive_path = out / "proof.zip"
    with zipfile.ZipFile(archive_path, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(proof.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(proof).as_posix())
    with tempfile.TemporaryDirectory(prefix="authzledger-selective100-verify-") as temporary:
        extracted = Path(temporary) / "proof"
        extracted.mkdir()
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(extracted)  # Only this runner's newly created inventory.
        require(not verify_bundle(extracted, public_key), "archived package semantic verification failed")
        standalone = subprocess.run(
            [sys.executable, "-I", str(out / "verify_bundle.py"), str(extracted),
             "--public-key", str(public_key)], cwd=temporary,
            capture_output=True, text=True, check=True, timeout=30)
    result = {
        "passed": True, "runtime_version": current["report"]["tool"]["version"],
        "baseline_requests": 100, "retest_requests": 10, "total_network_requests": 110,
        "selected_cases": 7, "required_control_cases": 3, "not_retested_cases": 90,
        "coverage": envelope["coverage"],
        "baseline_root_sha256": baseline["report"]["evidence"]["root_sha256"],
        "current_root_sha256": current["report"]["evidence"]["root_sha256"],
        "comparison_sha256": envelope["comparison_sha256"],
        "proof_zip_sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        "signer_public_key_sha256": manifest["signer"]["public_key_sha256"],
        "main_verifier": "Passed: signature, inventory, report chain, retained execution/finding semantics, comparison and exact report renderings.",
        "standalone_verifier": "Passed under python -I outside checkout: signature, inventory, hashes and report anchors; no oracle/finding/comparison semantic replay.",
        "standalone_stdout": standalone.stdout.strip(),
        "fixture_stopped_before_verification": True, "private_key_removed": True,
        "trust": "Fresh demonstration key; distribute its fingerprint separately. The signature does not authenticate producer identity or remote execution truth.",
        "meaning": "fix_verified is scoped to selected rule/resource/identity bindings with fresh valid controls; 90 other cases remain historical.",
    }
    write_new(out / "acceptance.json", json_bytes(result))
    readme = f"""# Demo C: selective retest and independent package\n\n100 baseline cases were executed against a synthetic loopback fixture. Seven\nexplicit query variants of one protected resource were selected for retest.\nThe retest executed those seven cases plus three fresh prerequisite controls.\nThe other 90 cases remain `not_retested`. Total HTTP dispatches: 110.\n\nThe fixture stopped before offline comparison, signing and both verifier runs.\nThe temporary private signing key was removed. All request categories, including\nzero-count categories, are retained in `request-receipts.json` and signed in\n`proof/attachments/request-receipts.json`.\n\n## Verify retained evidence\n\nFrom this directory, with Python 3.10+ and OpenSSL available:\n\n```sh\npython3 -I verify_bundle.py proof --public-key trusted-public.pem\npython3 -m authzledger verify-bundle proof --public-key trusted-public.pem\n```\n\nThe second command requires AuthzLedger installed. The first checks inventory,\nhashes, report anchors and signature; the second also reconstructs the retained\nassessment, oracle/finding/fix semantics and exact HTML/PDF outputs. No application\nservice is required. `proof.zip` contains the same package for transport; extract\nit into a new directory before verification.\n\nDemonstration signer fingerprint (SHA-256 of DER public key):\n`{manifest['signer']['public_key_sha256']}`\n\nThis newly generated key is a demonstration trust anchor, not authenticated\nproducer identity. Obtain a producer key fingerprint through a separate trusted\nchannel for real assessments. Signed bytes do not establish remote execution truth.\n\n## Reproduce\n\nFrom the matching source checkout, choose a new output directory:\n\n```sh\npython3 tools/check_selective100.py --out /tmp/authzledger-selective100-new\n```\n\nExisting output directories are refused. Each run uses a random port, fresh\ncredentials and a fresh signing key, so hashes and roots differ between runs.\nThe measured counts and scoped status transitions are reproducible. The baseline\nfile is written once before retest and checked unchanged afterward. This does not\nclaim an immutable filesystem or a general tenfold speedup.\n\nOpen `assessment.html` or `assessment.pdf` for findings and limitations; open\n`comparison.html` to inspect all 100 case transitions and the 90 historical cases.\n\nAll rights reserved: Nasser Aldin Farag / 0xFarag.\n"""
    write_new(out / "README.md", readme.encode("utf-8"))
    forbidden = [value.encode("ascii") for value in values.values()]
    forbidden += [value.split(" ", 1)[1].encode("ascii") for value in values.values()]
    for path in out.rglob("*"):
        if path.is_file():
            raw = path.read_bytes()
            require(not any(value in raw for value in forbidden), "credential persisted in output")
            # A verifier source contains the private-key rejection regex; only
            # actual PEM begin delimiters indicate secret material here.
            require(b"-----BEGIN PRIVATE KEY-----" not in raw, "private signing key persisted")
    checksums = "".join(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(out).as_posix()}\n"
                        for path in sorted(out.rglob("*")) if path.is_file())
    write_new(out / "SHA256SUMS", checksums.encode("ascii"))
    print(json.dumps(result, indent=2))
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="New output directory; existing paths are refused")
    check(parser.parse_args().out)
