"""Reproduce the packaged three-file offline workflow in a fresh directory."""
import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "demo_d" / "fixtures"
SERVICE = "tcp://192.0.2.10:443"


def run(argv, cwd):
    result = subprocess.run([str(a) for a in argv], cwd=cwd, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "Command failed")
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True, help="Working tree with the supplied patch applied")
    parser.add_argument("--out", type=Path, required=True, help="New output directory, which must not already exist")
    args = parser.parse_args()
    checkout = args.checkout.resolve()
    out = args.out.resolve()
    if not (checkout / "authzledger" / "federation_offline.py").is_file():
        parser.error("The supplied checkout lacks the federation patch")
    if out.exists():
        parser.error("Choose a new output directory")
    out.mkdir(parents=True, mode=0o700)
    def cli(*argv):
        return run([sys.executable, "-B", "-m", "authzledger", *argv], checkout)
    scope = dict(schema_version=1, kind="assessment-scope", id="offline-fixture",
                 authorization_ref="synthetic offline fixture", origins=[SERVICE],
                 operations=[dict(origin=SERVICE, method="CONNECT", path="/", purpose="service")],
                 allowed_networks=["192.0.2.10/32"], expires_at="2099-01-01T00:00:00Z",
                 allowed_effects=["read"], limits=dict(max_requests=1, concurrency=1,
                 timeout_seconds=1, max_response_bytes=100))
    (out / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    projection, repeat = out / "projection.json", out / "repeat.json"
    sources = ["--scope-service", SERVICE, "--nmap", FIXTURES / "nmap.xml",
               "--ffuf", FIXTURES / "ffuf.json", "--nuclei", FIXTURES / "nuclei.jsonl"]
    for path in (projection, repeat):
        cli("assessment", "federation-preview", *sources, "--out", path)
    print(run([sys.executable, ROOT / "demo_d" / "verify.py", projection, "--reimport", repeat], ROOT).strip())
    store = out / "assessment.sqlite"
    asm = json.loads(cli("assessment", "create", "--store", store, "--title",
                         "Synthetic offline federation", "--scope", out / "scope.json"))
    retain = ["assessment", "federation-retain", asm["id"], "--store", store, "--expected-revision",
              str(asm["revision"]), "--reviewed-projection", projection, "--release-sources", *sources]
    first, second = json.loads(cli(*retain)), json.loads(cli(*retain))
    reopened = json.loads(cli("assessment", "show", asm["id"], "--store", store))
    if (first["artifact_digest"] != second["artifact_digest"] or len(reopened["artifacts"]) != 1
        or reopened["assessment"]["revision"] != asm["revision"] + 1):
        raise ValueError("Persisted reimport did not retain exactly one artifact and one revision")
    snapshot = out / "snapshot.json"
    cli("assessment", "freeze", asm["id"], "--store", store, "--out", snapshot)
    cli("assessment", "verify", snapshot)
    cli("assessment", "report", snapshot, "--out", out / "reports")
    public, proof = out / "trusted-demo-public.pem", out / "proof"
    with tempfile.TemporaryDirectory(prefix="authzledger-demo-key-") as key_dir:
        key = Path(key_dir) / "private.pem"
        cli("keygen", "--private", key, "--public", public)
        cli("assessment", "bundle", snapshot, "--key", key, "--out", proof)
    standalone = ROOT / "demo-d-proof" / "verify_bundle.py"
    print(cli("verify-bundle", proof, "--public-key", public).strip())
    print(run([sys.executable, "-I", standalone, proof, "--public-key", public], ROOT).strip())
    with tempfile.TemporaryDirectory(prefix="authzledger-demo-copy-") as temp:
        broken = Path(temp) / "proof"
        shutil.copytree(proof, broken)
        victim = broken / "report.json"
        data = victim.read_bytes()
        victim.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
        cases = ([sys.executable, "-B", "-m", "authzledger", "verify-bundle", broken, "--public-key", public],
                 [sys.executable, "-I", standalone, broken, "--public-key", public])
        exits = []
        for argv in cases:
            result = subprocess.run([str(v) for v in argv], cwd=checkout, capture_output=True, text=True)
            if result.returncode == 0 or "hash mismatch: report.json" not in (result.stdout + result.stderr):
                raise ValueError("Tampered payload was not rejected for its digest mismatch")
            exits.append(result.returncode)
    summary = dict(fixture="demo-d", accepted_records=first["value"]["catalog"]["accepted_records"],
                   omitted_records=first["value"]["catalog"]["omitted_records"],
                   retained_artifacts=len(reopened["artifacts"]), snapshot_verified=True,
                   valid_package_exitcodes=[0,0], one_byte_tamper_exitcodes=exits)
    (out / "results.json").write_text(json.dumps(summary, indent=2)+"\n", encoding="utf-8")
    print(json.dumps(summary))

if __name__ == "__main__":
    main()
