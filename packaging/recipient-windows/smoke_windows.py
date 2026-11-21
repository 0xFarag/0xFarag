# ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
"""Run a local Windows smoke test against the pinned upstream demo ZIP.
Use the default disposable CI account or a fresh Windows user profile.
"""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent
DEMO_HASH = "54b21858a89d498ba3b5050ad85f5969068bf79bcf5a07467297b3c3d1d5e817"

def verify(exe, bundle, key, wanted_code, wanted_text):
    result = subprocess.run([exe, bundle, "--public-key", key], capture_output=True, text=True, timeout=60)
    output = (result.stdout + result.stderr).strip()
    print(f"exit {result.returncode}: {output}", flush=True)
    if result.returncode != wanted_code or wanted_text not in output:
        raise RuntimeError("Unexpected verifier result")

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("archive", type=Path)
    args = ap.parse_args()
    if os.name != "nt" or hashlib.sha256(args.archive.read_bytes()).hexdigest() != DEMO_HASH:
        raise SystemExit("A Windows host and the pinned release archive are required.")
    installed = Path(os.environ["LOCALAPPDATA"]) / "Programs" / "AuthzLedgerRecipientVerifierPreview"
    if installed.exists():
        raise SystemExit("The preview directory already exists. Run this test under a fresh profile.")
    with tempfile.TemporaryDirectory(prefix="authzledger-smoke-") as scratch:
        work = Path(scratch)
        with zipfile.ZipFile(args.archive) as archive:
            archive.extractall(work)
        proof = work / "authzledger-proof" / "C-retest-proof" / "proof"
        trusted = work / "authzledger-proof" / "trusted-public.pem"
        changed = work / "changed"
        shutil.copytree(proof, changed)
        target = changed / "attachments" / "platform.pdf"
        content = bytearray(target.read_bytes())
        content[0] ^= 1
        target.write_bytes(content)
        openssl = os.environ["AUTHZLEDGER_OPENSSL"]
        private = work / "unrelated-private.pem"
        public = work / "unrelated-public.pem"
        subprocess.run([openssl, "genpkey", "-algorithm", "Ed25519", "-out", private], check=True)
        subprocess.run([openssl, "pkey", "-in", private, "-pubout", "-out", public], check=True)
        private.unlink()
        exe = ROOT / "AuthzLedgerVerify-x64.exe"
        for binary in (exe, installed / exe.name):
            if binary != exe:
                subprocess.run([ROOT / "AuthzLedgerVerify-Setup.exe", "/S"], check=True, timeout=90)
                if hashlib.sha256(binary.read_bytes()).digest() != hashlib.sha256(exe.read_bytes()).digest():
                    raise RuntimeError("Installed payload differs")
            verify(binary, proof, trusted, 0, "VERIFIED: Ed25519")
            verify(binary, changed, trusted, 1, "file size or hash mismatch")
            verify(binary, proof, public, 1, "trusted public key fingerprint mismatch")
        state = installed / "user-evidence-keep.txt"
        state.write_text("retained", encoding="utf-8")
        # Running /S with _?= prevents a forked background uninstaller copy.
        subprocess.run([installed / "Uninstall.exe", "/S", "_?=" + str(installed)], check=True, timeout=90)
        if (installed / exe.name).exists() or state.read_text(encoding="utf-8") != "retained":
            raise RuntimeError("Removal or evidence retention failed")
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Uninstall\AuthzLedgerRecipientVerifierPreview"):
                raise RuntimeError("Uninstall metadata remains")
        except FileNotFoundError:
            pass
        print("Installer, installed payload and uninstaller passed; user file retained.")
        # Only our initially nonexistent directory in this disposable test profile.
        shutil.rmtree(installed)

if __name__ == "__main__":
    main()
