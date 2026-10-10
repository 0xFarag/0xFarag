"""Build public distribution assets from explicit, secret-free allowlists.

This packages bytes; it does not bypass the separate stable publication gate.
Proof inputs must be synthetic public demos already checked by both verifiers.
"""
from pathlib import Path
import argparse
import base64
import hashlib
import re
import shutil
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'
DIST.mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT))
from authzledger import __version__ as VERSION

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--proof-source', type=Path, default=ROOT / 'evidence/1.1.0-release-review',
                    help='Public synthetic proof root containing assessment-demos and selective100')
args = parser.parse_args()
PRIVATE_PEM = re.compile(rb'^-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----', re.M)
ED25519_DER_PREFIX = bytes.fromhex('302a300506032b6570032100')


def validate_public_pem(path):
    """Permit public Ed25519 SubjectPublicKeyInfo only; never trust by filename."""
    raw = path.read_bytes()
    lines = raw.strip().splitlines()
    if (len(lines) < 3 or lines[0] != b'-----BEGIN PUBLIC KEY-----'
            or lines[-1] != b'-----END PUBLIC KEY-----'):
        raise SystemExit('Refusing non-public PEM in public proof: ' + str(path))
    try:
        der = base64.b64decode(b''.join(lines[1:-1]), validate=True)
    except (ValueError, base64.binascii.Error):
        raise SystemExit('Refusing malformed public PEM in public proof: ' + str(path))
    if len(der) != len(ED25519_DER_PREFIX) + 32 or not der.startswith(ED25519_DER_PREFIX):
        raise SystemExit('Refusing non-Ed25519 public key in public proof: ' + str(path))


def permitted(path, *, public_proof=False):
    if not path.is_file() or path.is_symlink() or '__pycache__' in path.parts:
        return False
    if path.suffix in {'.pyc', '.sqlite3', '.db'} or path.name.endswith(('-wal', '-shm')):
        return False
    if path.suffix == '.pem':
        if not public_proof:
            return False
        validate_public_pem(path)
    if public_proof and PRIVATE_PEM.search(path.read_bytes()):
        raise SystemExit('Refusing private key content in public proof: ' + str(path))
    return True


def add_zip_file(output, path, name):
    item = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
    item.compress_type = zipfile.ZIP_DEFLATED
    item.create_system = 3
    item.external_attr = (stat.S_IMODE(path.stat().st_mode) | stat.S_IFREG) << 16
    output.writestr(item, path.read_bytes())


files = []
for name in ['README.md', 'INSTALL.md', 'RELEASE_NOTES.md', 'RELEASE.json', 'CHANGELOG.md', 'LICENSE', 'NOTICE.txt', 'SECURITY.md', 'CONTRIBUTING.md', 'pyproject.toml', 'MANIFEST.in', 'start.sh', '.gitignore']:
    path = ROOT / name
    if path.is_file():
        files.append(path)
for name in ['authzledger', 'docs', 'examples', 'fixtures', 'tests', 'tools', 'brand', '.github', 'evidence/1.0.0', 'evidence/1.1.0-dev0', 'evidence/1.1.0-release-review']:
    directory = ROOT / name
    if directory.is_dir():
        files.extend(path for path in directory.rglob('*')
                     if permitted(path, public_proof=name == 'evidence/1.1.0-release-review'))
archive = DIST / f'authzledger-{VERSION}-source.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as output:
    for path in sorted(set(files)):
        add_zip_file(output, path, f'authzledger/{path.relative_to(ROOT).as_posix()}')
shutil.copyfile(ROOT / 'tools/verify_bundle.py', DIST / 'verify_bundle.py')
assets = [archive, DIST / f'authzledger-{VERSION}-py3-none-any.whl']

if VERSION in {'1.1.0.dev0', '1.1.0'}:
    proof_files = []
    required = [('assessment-demos', 'results.json'), ('selective100', 'acceptance.json')]
    for directory_name, receipt_name in required:
        directory = args.proof_source / directory_name
        for required_name in [receipt_name, 'trusted-public.pem', 'proof/manifest.json', 'proof/signature.base64', 'proof/report.json', 'proof/public.pem']:
            required_path = directory / required_name
            if not required_path.is_file() or required_path.is_symlink():
                raise SystemExit('Required public proof is missing: ' + str(required_path))
        proof_files.extend(path for path in directory.rglob('*') if permitted(path, public_proof=True))
    proof_archive = DIST / f'authzledger-{VERSION}-proof.zip'
    with zipfile.ZipFile(proof_archive, 'w', zipfile.ZIP_DEFLATED) as output:
        for path in sorted(proof_files):
            add_zip_file(output, path, f'authzledger-proof/{path.relative_to(args.proof_source).as_posix()}')
        for name in ['INSTALL.md', 'RELEASE_NOTES.md', 'LICENSE', 'NOTICE.txt', 'tools/verify_bundle.py', 'tools/check_selective100.py']:
            path = ROOT / name
            if not path.is_file():
                raise SystemExit('Required proof guide or reproducer missing: ' + name)
            add_zip_file(output, path, f'authzledger-proof/{name}')
        readme = '''# AuthzLedger public synthetic proof

This archive contains the three assessment demonstrations and the separate
100-case selective-retest measurement. These are authored local fixtures;
they do not certify third-party exporters or production efficiency.

Install the matching wheel plus reportlab==4.4.9; see INSTALL.md. From this
extracted directory, with the fixture servers already stopped:

    python -I -m authzledger verify-bundle assessment-demos/proof --public-key assessment-demos/trusted-public.pem
    python -I tools/verify_bundle.py assessment-demos/proof --public-key assessment-demos/trusted-public.pem

    python -I -m authzledger verify-bundle selective100/proof --public-key selective100/trusted-public.pem
    python -I tools/verify_bundle.py selective100/proof --public-key selective100/trusted-public.pem

Consult selective100/acceptance.json and request-receipts.json for exact counts.
Reproduce the three demonstrations into a NEW directory:

    python -I -m authzledger assessment demo --out fresh-assessment-demos

The public keys in this archive are demo trust anchors only, not independent
publisher authentication. Authenticate the trusted public key separately for
real handover. The main verifier checks supported evidence semantics; the
standalone verifier checks signature, inventory, hashes and report anchors.
Neither proves remote execution truth. No private signing keys are retained.
'''
        item = zipfile.ZipInfo('authzledger-proof/README.md', (2026, 1, 1, 0, 0, 0))
        item.compress_type = zipfile.ZIP_DEFLATED
        output.writestr(item, readme)
    assets.append(proof_archive)
assets.append(DIST / 'verify_bundle.py')
for filename in (['AuthzLedger_1.0_Release_wide.mp4', 'AuthzLedger_1.0_Release_vertical.mp4', 'AuthzLedger_1.0_en.srt'] if VERSION == '1.0.0' else []):
    source = ROOT / 'media' / filename
    if not source.is_file():
        raise SystemExit('Verified launch media are required before packaging')
    shutil.copyfile(source, DIST / filename)
    assets.append(DIST / filename)
if any(not path.is_file() for path in assets):
    raise SystemExit('Build the wheel first')
(DIST / 'SHA256SUMS.txt').write_text(''.join(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n' for path in assets))
print('Source, wheel, public proof, independent verifier and checksums prepared; publication gate remains separate.')
