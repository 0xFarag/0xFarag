# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Add the local Tk desktop to the digest-pinned original recipient DEB."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

BASE_DIGEST = "d6d6541ddd03069d0f3cfb7554944f6f17ebb38ceef4c567aa63d2eec2ae632a"
RIGHTS = "© Nasser Aldin Farag (0xFarag). All rights reserved."
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("base", type=Path)
parser.add_argument("output_dir", type=Path)
args = parser.parse_args()
if hashlib.sha256(args.base.read_bytes()).hexdigest() != BASE_DIGEST:
    raise SystemExit("Unexpected base Debian verifier checksum")
args.output_dir.mkdir(exist_ok=True, parents=True)
output = args.output_dir / "authzledger-verifier_1.5.0-preview3_all.deb"
here = Path(__file__).resolve().parent
with tempfile.TemporaryDirectory() as temp:
    root = Path(temp, "root")
    subprocess.run(["dpkg-deb", "--raw-extract", args.base, root], check=True)
    control = root / "DEBIAN/control"
    fields = control.read_text()
    for old, new in {
        "Version: 1.5.0-0~preview1": "Version: 1.5.0-0~preview3",
        "Depends: python3 (>= 3.10), openssl (>= 3.0.0)": "Depends: python3 (>= 3.10), openssl (>= 3.0.0), python3-tk",
        "Homepage: https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0": "Homepage: https://authzledger.vercel.app/",
        "verifier (packaging preview)": "verifier with graphical desktop (preview 3)",
    }.items():
        if fields.count(old) != 1:
            raise ValueError("unexpected Debian metadata")
        fields = fields.replace(old, new)
    control.write_text(fields)
    gui = root / "usr/bin/authzledger-studio"
    shutil.copyfile(here.parent / "windows/evidence_studio.py", gui)
    gui.chmod(0o755)
    entry = root / "usr/share/applications/authzledger-recipient-studio.desktop"
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text(f"# {RIGHTS}\n[Desktop Entry]\nType=Application\nVersion=1.0\nName=AuthzLedger Recipient Studio\nComment=Verify a signed evidence handover offline\nExec=/usr/bin/authzledger-studio\nTryExec=/usr/bin/authzledger-studio\nTerminal=false\nCategories=Utility;Security;\n")
    shutil.copyfile(here.parent / "INSTALL-Studio.md", root / "usr/share/doc/authzledger-verifier/INSTALL-Studio.md")
    epoch = 1795392000
    for path in [*root.rglob("*"), root]:
        os.utime(path, (epoch, epoch), follow_symlinks=False)
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(epoch))
    subprocess.run(["dpkg-deb", "--build", "--root-owner-group", root, output], env=env, check=True)
print(hashlib.sha256(output.read_bytes()).hexdigest(), output.name)
