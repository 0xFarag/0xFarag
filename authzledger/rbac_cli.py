"""Launch the shipped offline RBAC evaluator. © Nasser Aldin Farag (0xFarag). All rights reserved."""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


def run(arguments: list[str]) -> int:
    node = shutil.which("node.exe" if os.name == "nt" else "node")
    if node is None:
        print("The offline RBAC command requires Node.js 22 or newer on PATH.", file=sys.stderr)
        return 2
    environment = os.environ.copy()
    environment.pop("NODE_OPTIONS", None)
    try:
        version = subprocess.run([node, "--version"], env=environment, capture_output=True, timeout=5, check=True)
        major = re.fullmatch(rb"v([0-9]+)\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?", version.stdout.strip())
        if major is None or int(major[1]) < 22:
            print("The offline RBAC command requires Node.js 22 or newer on PATH.", file=sys.stderr)
            return 2
        entry = Path(__file__).resolve().parent / "rbac" / "cli.mjs"
        if not entry.is_file():
            print("RBAC assets are missing. Reinstall this AuthzLedger review package.", file=sys.stderr)
            return 2
        return subprocess.run([node, str(entry), *arguments], env=environment, check=False).returncode
    except (OSError, subprocess.SubprocessError):
        print("Could not start the local Node.js runtime for RBAC.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
