# ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
"""Build a Windows x64 recipient launcher and per-user NSIS installer."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "src"
EXPECTED = "afe47e30606d61f09025fa8b2703d7446b08cc0a3093e4b82eace355bfba5303"

def main():
    if hashlib.sha256((SOURCE / "verify_bundle.py").read_bytes()).hexdigest() != EXPECTED:
        raise SystemExit("Historical verifier hash mismatch.")
    go = shutil.which("go")
    nsis = shutil.which("makensis")
    if not nsis and os.name == "nt":
        candidate = Path(os.environ["ProgramFiles(x86)"]) / "NSIS" / "makensis.exe"
        if candidate.is_file():
            nsis = str(candidate)
    if not go or not nsis:
        raise SystemExit("Install Go 1.24+ and NSIS 3 or set their executable directories on PATH.")
    env = dict(os.environ, GOOS="windows", GOARCH="amd64", CGO_ENABLED="0", GO111MODULE="off", GOTOOLCHAIN="local")
    subprocess.run([go, "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=",
                    "-o", str(ROOT / "AuthzLedgerVerify-x64.exe"), "main.go"], cwd=SOURCE, env=env, check=True)
    payload = ROOT / "AuthzLedgerVerify-x64.exe"
    if not payload.is_file() or payload.stat().st_size < 4096:
        raise SystemExit("Missing compiled Windows payload.")
    option = "/" if os.name == "nt" else "-"
    subprocess.run([nsis, option + "NOCD", option + "INPUTCHARSET", "UTF8",
                    str(SOURCE / "installer.nsi")], cwd=ROOT, check=True)

if __name__ == "__main__":
    main()
