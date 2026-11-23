"""Test a real local clamscan with a private, harmless fixture signature. No public signature feed or service.
© Nasser Aldin Farag (0xFarag). All rights reserved.
"""
from hashlib import md5
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    # The CI launcher supplies the exact official-distribution binary and its libraries.
    real_scanner = str(Path(sys.argv[1]).resolve(strict=True))
    with tempfile.TemporaryDirectory() as folder:
        root = Path(folder)
        bindir = root / "bin"
        bindir.mkdir()
        # This POSIX-only fixture delegates scanning to the real installed binary.
        # Only the database option is supplied by the fixture to avoid a remote signature feed.
        wrapper = bindir / "clamscan"
        wrapper.write_text('#!/bin/sh\nexec "$AUTHZ_CI_CLAMSCAN" --database="$AUTHZ_CI_SIGNATURE" "$@"\n')
        wrapper.chmod(0o700)
        test_bytes = b"AuthzLedger harmless local file; synthetic CI marker 3459.\n"
        digest = md5(test_bytes, usedforsecurity=False).hexdigest()
        database = root / "local.hdb"
        database.write_text(f"{digest}:{len(test_bytes)}:AuthzLedger.Benign.LocalMarker\n")
        env = {**os.environ, "PATH": os.pathsep.join([str(bindir), os.environ["PATH"]]),
               "AUTHZ_CI_CLAMSCAN": real_scanner, "AUTHZ_CI_SIGNATURE": str(database)}
        for content, expected, exitcode in [(test_bytes, "detection_reported", 1),
                                             (b"Ordinary project note with no configured marker.\n", "no_detection_reported", 0)]:
            sample = root / "input"
            sample.write_bytes(content)
            proc = subprocess.run([sys.executable, "-m", "authzledger", "file-review", str(sample), "--clamav"],
                                  env=env, capture_output=True, timeout=85)
            engine = json.loads(proc.stdout)["engine"]
            if proc.returncode != exitcode or engine["status"] != expected or not engine["engine_version"]:
                raise SystemExit(f"Real ClamAV integration failed: {proc.returncode} / {engine}")
            print(f"Real ClamAV {engine['engine_version']}: {engine['status']}")


if __name__ == "__main__":
    main()
