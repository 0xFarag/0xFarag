# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Build native Team application packages from an allowlist of release sources."""
import argparse
import gzip
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / 'packaging' / 'team'
VERSION = (PACK / 'VERSION').read_text().strip()
NAME = 'authzledger-team'
STEM = NAME + '-' + VERSION
FILES = [f'AuthzLedger-Team-{VERSION}-Windows-x64.exe', f'{NAME}_{VERSION}-1_all.deb',
         STEM + '-1-any.pkg.tar.zst', 'PKGBUILD', STEM + '.tar.gz',
         STEM + '-linux-amd64.docker.tar.gz', STEM + '-linux-amd64.oci.tar',
         f'AuthzLedger-Burp-Export-{VERSION}.jar']


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def members():
    fixed = [ROOT / name for name in ['LICENSE', 'NOTICE.txt', 'public/assets/authzledger-logo.png', 'team/requirements.txt',
             'scripts/build-team-release.py', 'docs/Team-Login-RBAC.md', 'docs/Key-Rotation.md', 'docs/ZAP-API-Scan-Import.md',
             'integrations/burp/README.md', 'integrations/burp-handoff/README.md', 'docs/Proof-Studio-Betrieb.md',
             'docs/ZAP-Ergebnisimport.md']]
    scripts = list((ROOT / 'team').glob('*.py'))
    web = [p for p in (ROOT / 'team/static').rglob('*') if p.suffix.lower() in
           {'.html', '.js', '.mjs', '.css', '.json', '.png', '.svg', '.ico', '.woff', '.woff2', '.ttf'}]
    web.extend([ROOT / 'team/static/pdf/FONT-LICENSE.txt',
                ROOT / 'team/static/fonts/Outfit-OFL.txt', ROOT / 'team/static/fonts/Fraunces-OFL.txt'])
    packaging = [p for p in PACK.iterdir() if p.is_file()]
    for required in ['team/server.py', 'team/evidence.py', 'team/report_pdf.py', 'team/static/index.html',
                     'team/static/pdf/ReportSans.ttf', 'team/static/pdf/FONT-LICENSE.txt', 'team/static/pdf/arabic-lines.json']:
        if not (ROOT / required).is_file():
            raise SystemExit('Incomplete Team application: ' + required)
    files = sorted(set(fixed + scripts + web + packaging))
    if any(p.is_symlink() or not p.is_file() for p in files):
        raise SystemExit('A release source is missing or is a symlink')
    return files


def stage(directory):
    for p in members():
        target = directory / p.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, target)
        target.chmod(0o644)


def source_package(output, epoch):
    archive = output / (STEM + '.tar.gz')
    with archive.open('wb') as raw:
        with gzip.GzipFile(fileobj=raw, filename='', mode='wb', mtime=epoch) as gz:
            with tarfile.open(fileobj=gz, mode='w', format=tarfile.GNU_FORMAT) as bundle:
                for p in members():
                    info = tarfile.TarInfo(STEM + '/' + p.relative_to(ROOT).as_posix())
                    info.size, info.mode, info.mtime = p.stat().st_size, 0o644, epoch
                    with p.open('rb') as body:
                        bundle.addfile(info, body)
    template = (PACK / 'PKGBUILD.in').read_text()
    (output / 'PKGBUILD').write_text(template.replace('@VERSION@', VERSION).replace('@SHA256@', digest(archive)), encoding='utf-8')


def deb(output, epoch):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        clean = root / 'source'
        staging = root / 'package'
        stage(clean)
        subprocess.run([sys.executable, str(clean / 'packaging/team/install.py'), str(staging)], check=True)
        meta = staging / 'DEBIAN'
        meta.mkdir(mode=0o755)
        (meta / 'control').write_text(f'Package: {NAME}\nVersion: {VERSION}-1\nArchitecture: all\nSection: utils\n'
            'Priority: optional\nMaintainer: Nasser Aldin Farag (0xFarag)\n'
            'Depends: python3 (>= 3.10), python3-cryptography, python3-reportlab, python3-tk\nHomepage: https://authzledger.com\n'
            'Description: Local AuthzLedger Team evidence workspace\n'
            ' Includes a Python service, a graphical launcher and a desktop menu entry.\n', encoding='utf-8')
        for path in sorted(staging.rglob('*'), reverse=True):
            os.utime(path, (epoch,epoch))
        env = {**os.environ, 'SOURCE_DATE_EPOCH': str(epoch), 'TZ': 'UTC'}
        subprocess.run(['dpkg-deb', '--root-owner-group', '-Zxz', '--build', str(staging), str(output / FILES[1])], env=env, check=True)


def windows(output):
    if sys.platform != 'win32':
        raise SystemExit('Build the Windows executable using a Windows Python interpreter.')
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        src = directory / 'src'
        stage(src)
        legal = directory / 'legal'
        legal.mkdir()
        for source in [src / 'LICENSE', src / 'NOTICE.txt', src / 'packaging/team/THIRD-PARTY.md']:
            shutil.copyfile(source, legal / source.name)
        subprocess.run([sys.executable, str(src / 'packaging/team/collect_notices.py'), str(legal / 'third-party'), '--windows'], check=True)
        parts = tuple(int(x) for x in VERSION.split('.'))
        if len(parts) != 4 or any(n < 0 or n > 65535 for n in parts):
            raise ValueError('Expected four Windows version components (0 to 65535)')
        version_file = directory / 'windows-version.txt'
        template = (src / 'packaging/team/windows-version.txt.in').read_text(encoding='utf-8')
        version_file.write_text(template.replace('@PARTS@', str(parts)).replace('@VERSION@', VERSION), encoding='utf-8')
        guides = src / 'docs'
        shutil.copyfile(src / 'integrations/burp/README.md', guides / 'Burp-Export.md')
        shutil.copyfile(src / 'integrations/burp-handoff/README.md', guides / 'Burp-Handoff.md')
        for notice in (src / 'team/static/fonts').glob('*-OFL.txt'):
            shutil.copyfile(notice, legal / notice.name)
        shutil.copyfile(src / 'team/static/pdf/FONT-LICENSE.txt', legal / 'FONT-LICENSE.txt')
        subprocess.run([sys.executable, '-m', 'PyInstaller', '--clean', '--noconfirm', '--onefile', '--windowed',
            '--name', FILES[0][:-4], '--icon', str(src / 'packaging/team/authzledger-team.ico'),
            '--version-file', str(version_file), '--collect-submodules', 'reportlab.pdfbase',
            '--paths', str(src), '--add-data', f'{src / "team/static"};team/static', '--add-data', f'{legal};legal',
            '--add-data', f'{guides};docs', '--workpath', str(directory / 'work'), '--specpath', str(directory / 'spec'),
            '--distpath', str(output), str(src / 'packaging/team/launcher.py')], check=True)
    for flag in ['--self-test', '--gui-self-test']:
        subprocess.run([str(output / FILES[0]), flag], check=True, timeout=90)


def checksums(output):
    actual = {p.name for p in output.iterdir() if p.is_file() and p.name != 'SHA256SUMS'}
    if actual != set(FILES) or any((output / name).is_symlink() or (output / name).stat().st_size < 1 for name in FILES):
        raise SystemExit(f'Release inventory mismatch: missing {set(FILES) - actual}, unexpected {actual - set(FILES)}')
    (output / 'SHA256SUMS').write_text(''.join(f'{digest(output / name)}  {name}\n' for name in sorted(FILES)), encoding='ascii')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('format', choices=['source', 'deb', 'windows', 'context', 'verify'])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    dest = args.output.resolve()
    dest.mkdir(parents=True, exist_ok=True)
    epoch = int(os.environ.get('SOURCE_DATE_EPOCH', '0'))
    if args.format == 'context':
        if any(dest.iterdir()):
            raise SystemExit('Use an empty directory for the Docker build context.')
        stage(dest)
    elif args.format == 'source':
        source_package(dest, epoch)
    elif args.format == 'deb':
        deb(dest, epoch)
    elif args.format == 'windows':
        windows(dest)
    else:
        checksums(dest)
