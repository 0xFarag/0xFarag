# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Compare the recipient executable and original verifier on a pinned proof ZIP."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
from zipfile import ZipFile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROOF_SHA = "54b21858a89d498ba3b5050ad85f5969068bf79bcf5a07467297b3c3d1d5e817"
HERE = Path(__file__).resolve().parent


def run_cases(executable, bundle, key):
    results = {}
    def verify(name, target, trusted, code, needle):
        # The new binary must run without a discoverable Python or OpenSSL.
        env = os.environ.copy()
        if executable and os.name == "nt":
            env["PATH"] = str(Path(os.environ["SystemRoot"], "System32"))
        for label, command in [
            ("upstream", [sys.executable, str(HERE / "upstream_verifier.py")]),
            ("packaged", [str(executable)] if executable else [sys.executable, str(HERE / "verifier.py")]),
        ]:
            result = subprocess.run([*command, str(target), "--public-key", str(trusted)],
                                    capture_output=True, text=True, timeout=90,
                                    env=env if label == "packaged" else None)
            output = (result.stdout + result.stderr).strip()
            if result.returncode != code or needle.lower() not in output.lower():
                raise RuntimeError(f"{name}/{label}: exit {result.returncode}: {output}")
            results[f"{name}/{label}"] = {"exit": result.returncode, "message": output}

    with TemporaryDirectory(prefix="receipt-check-") as temp:
        work = Path(temp)
        proof = work / "signed"
        shutil.copytree(bundle, proof)
        verify("authentic", proof, key, 0, "VERIFIED")
        verify("self_trust", proof, proof / "public.pem", 1, "outside the bundle")
        foreign = Ed25519PrivateKey.generate().public_key()
        foreign_key = work / "other.pem"
        foreign_key.write_bytes(foreign.public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo))
        verify("wrong_key", proof, foreign_key, 1, "fingerprint")
        payload = next(p for p in (proof / "attachments").iterdir() if p.is_file() and p.stat().st_size)
        original = payload.read_bytes()
        payload.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        verify("one_byte", proof, key, 1, "hash mismatch")
        payload.write_bytes(original)
        extra = proof / "unlisted.txt"
        extra.write_text("not signed")
        verify("unlisted_file", proof, key, 1, "extra bundle files")
        extra.unlink()
        signature = proof / "signature.base64"
        raw = bytearray(base64.b64decode(signature.read_bytes()))
        raw[0] ^= 1
        signature.write_bytes(base64.b64encode(raw) + b"\n")
        verify("bad_signature", proof, key, 1, "signature verification failed")
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()
    if hashlib.sha256(args.archive.read_bytes()).hexdigest() != PROOF_SHA:
        raise ValueError("wrong official proof archive")
    with TemporaryDirectory(prefix="release-proof-") as name:
        with ZipFile(args.archive) as z:
            z.extractall(name)
        proof_root = Path(name, "authzledger-proof")
        results = run_cases(args.exe.resolve(), proof_root / "C-retest-proof" / "proof",
                            proof_root / "trusted-public.pem")
    args.receipt.write_text(json.dumps({"version": "recipient-studio-preview3", "source_proof_sha256": PROOF_SHA,
        "binary_sha256": hashlib.sha256(args.exe.read_bytes()).hexdigest(),
        "github_run_id": os.environ.get("GITHUB_RUN_ID"), "commit": os.environ.get("GITHUB_SHA"),
        "tests": results}, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
