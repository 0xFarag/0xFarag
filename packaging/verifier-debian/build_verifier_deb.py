#!/usr/bin/env python3
"""Build the AuthzLedger offline verifier preview using the two pinned release assets."""
# ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
from zipfile import ZipFile

VERSION = '1.5.0-0~preview1'
PACKAGE = 'authzledger-verifier'
EPOCH = 1795219200
ASSETS = {
    'verify_bundle.py': 'afe47e30606d61f09025fa8b2703d7446b08cc0a3093e4b82eace355bfba5303',
    'authzledger-1.5.0-proof.zip': '54b21858a89d498ba3b5050ad85f5969068bf79bcf5a07467297b3c3d1d5e817',
}
WRAPPER = """#!/usr/bin/python3 -I
# ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
import os
from pathlib import Path
import runpy

os.environ["PATH"] = "/usr/bin:/bin"
script = Path(__file__).resolve().parents[1] / "share/authzledger-verifier/verify_bundle.py"
runpy.run_path(str(script), run_name="__main__")
"""
CONTROL = f"""Package: {PACKAGE}
Version: {VERSION}
Architecture: all
Maintainer: Nasser Aldin Farag (0xFarag) <174953727+0xFarag@users.noreply.github.com>
Section: utils
Priority: optional
Depends: python3 (>= 3.10), openssl (>= 3.0.0)
Homepage: https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0
Description: AuthzLedger offline evidence-bundle verifier (packaging preview)
 Checks an Ed25519 evidence inventory using an independently trusted public key.
 Runs locally and requires no AuthzLedger installation or network service.
"""
def put(root, name, data, mode=0o644):
    target = root / name
    target.parent.mkdir(exist_ok=True, parents=True)
    target.write_bytes(data)
    target.chmod(mode)

def build(assets_dir, out_dir):
    for name, digest in ASSETS.items():
        if hashlib.sha256((assets_dir / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"Unexpected release input: {name}")
    out_dir.mkdir(exist_ok=True, parents=True)
    dest = out_dir / f'{PACKAGE}_{VERSION}_all.deb'
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / 'root'
        put(root, 'DEBIAN/control', CONTROL.encode())
        put(root, 'usr/bin/authzledger-verify', WRAPPER.encode(), 0o755)
        put(root, 'usr/share/authzledger-verifier/verify_bundle.py', (assets_dir / 'verify_bundle.py').read_bytes())
        with ZipFile(assets_dir / 'authzledger-1.5.0-proof.zip') as archive:
            license_text = archive.read('authzledger-proof/LICENSE')
            copyright_notice = 'ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).\n\n'.encode()
            put(root, 'usr/share/doc/authzledger-verifier/copyright', copyright_notice + license_text)
            put(root, 'usr/share/doc/authzledger-verifier/NOTICE.txt', archive.read('authzledger-proof/NOTICE.txt'))
        for path in [root, *root.rglob('*')]:
            if path.is_dir():
                path.chmod(0o755)
            os.utime(path, (EPOCH, EPOCH))
        subprocess.run(['dpkg-deb', '--root-owner-group', '-Zxz', '-z6', '--build', str(root), str(dest)],
                       env={**os.environ, 'SOURCE_DATE_EPOCH': str(EPOCH), 'TZ':'UTC', 'LC_ALL':'C'}, check=True)
    return dest

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('assets', type=Path, help='Directory containing v1.5.0 verify_bundle.py and authzledger-1.5.0-proof.zip')
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    print(build(args.assets, args.output))
