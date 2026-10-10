"""Build the public distribution from an explicit, secret-free source allowlist."""
from pathlib import Path
import hashlib
import shutil
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'
DIST.mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT))
from authzledger import __version__ as VERSION
files = []
for name in ['README.md', 'INSTALL.md', 'RELEASE_NOTES.md', 'RELEASE.json', 'CHANGELOG.md', 'LICENSE', 'NOTICE.txt', 'SECURITY.md', 'CONTRIBUTING.md', 'pyproject.toml', 'MANIFEST.in', 'start.sh', '.gitignore']:
    path = ROOT / name
    if path.is_file():
        files.append(path)
for name in ['authzledger', 'docs', 'examples', 'fixtures', 'tests', 'tools', 'brand', '.github', 'evidence/1.0.0', 'evidence/1.1.0-dev0']:
    directory = ROOT / name
    if directory.is_dir():
        files.extend(path for path in directory.rglob('*') if path.is_file() and not path.is_symlink()
                     and '__pycache__' not in path.parts and path.suffix not in {'.pyc', '.pem', '.sqlite3', '.db'})
archive = DIST / f'authzledger-{VERSION}-source.zip'
with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as output:
    for path in sorted(set(files)):
        item = zipfile.ZipInfo(f'authzledger/{path.relative_to(ROOT).as_posix()}', (2026, 1, 1, 0, 0, 0))
        item.compress_type = zipfile.ZIP_DEFLATED
        item.create_system = 3
        item.external_attr = (stat.S_IMODE(path.stat().st_mode) | stat.S_IFREG) << 16
        output.writestr(item, path.read_bytes())
shutil.copyfile(ROOT / 'tools/verify_bundle.py', DIST / 'verify_bundle.py')
assets = [archive, DIST / f'authzledger-{VERSION}-py3-none-any.whl', DIST / 'verify_bundle.py']
for filename in (['AuthzLedger_1.0_Release_wide.mp4', 'AuthzLedger_1.0_Release_vertical.mp4', 'AuthzLedger_1.0_en.srt'] if VERSION == '1.0.0' else []):
    source = ROOT / 'media' / filename
    if not source.is_file():
        raise SystemExit('Verified launch media are required before packaging')
    shutil.copyfile(source, DIST / filename)
    assets.append(DIST / filename)
if any(not path.is_file() for path in assets):
    raise SystemExit('Build the wheel first')
(DIST / 'SHA256SUMS.txt').write_text(''.join(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n' for path in assets))
print('Release source, wheel, independent verifier and checksums prepared.')
