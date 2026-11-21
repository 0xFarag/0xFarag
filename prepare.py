"""Assemble offline recipient verifier packages from individually pinned, pretested inputs."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'out'
REPOSITORY = '0xFarag/0xFarag'
ASSETS = json.loads((ROOT / 'expected.json').read_text())
SOURCES = json.loads((ROOT / 'sources.json').read_text())

def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def github(path):
    return json.loads(subprocess.check_output(['gh', 'api', 'repos/' + REPOSITORY + '/' + path]))

def fetch_tested_artifact(name):
    source = SOURCES[name]
    run = github('actions/runs/' + str(source['run']))
    assert run['conclusion'] == 'success'
    assert run['head_sha'] == source['commit']
    assert run['repository']['full_name'] == REPOSITORY
    asset = github('actions/artifacts/' + str(source['id']))
    assert asset['workflow_run']['id'] == source['run']
    assert asset['digest'] == 'sha256:' + source['sha256']
    assert not asset['expired']
    result = ROOT / (name + '.zip')
    with result.open('xb') as sink:
        subprocess.run(['gh','api',f"repos/{REPOSITORY}/actions/artifacts/{source['id']}/zip"],stdout=sink,check=True)
    assert digest(result) == source['sha256']
    return result

def copy_members(archive, names):
    with zipfile.ZipFile(archive) as package:
        for name in names:
            assert package.namelist().count(name) == 1 and Path(name).name == name
            (OUT / name).write_bytes(package.read(name))

def assemble_legacy(source, result):
    ordered_names = ['AuthzLedgerVerify-x64.exe','AuthzLedgerVerify-Setup.exe','LESEMICH.md',
                     'Go-LICENSE.txt','NSIS-LICENSE.txt','upstream-LICENSE','upstream-NOTICE.txt',
                     'NOTICE.txt','verification.json','windows-smoke.txt','native-SHA256SUMS']
    with zipfile.ZipFile(source) as built, zipfile.ZipFile(result, 'x') as target:
        for name in ordered_names:
            data = built.read(name) if name in built.namelist() else (ROOT / 'legacy' / name).read_bytes()
            info = zipfile.ZipInfo(name, (2026,11,21,0,0,0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            target.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)

def main():
    OUT.mkdir()
    for path in (ROOT / 'inputs').iterdir():
        assert path.is_file() and path.name in ASSETS
        shutil.copy2(path, OUT / path.name)
    new_windows = fetch_tested_artifact('windows')
    shutil.copy2(new_windows, OUT / 'AuthzLedger-Windows-x64-SelfContained.zip')
    assemble_legacy(fetch_tested_artifact('windows-legacy'), OUT / 'AuthzLedger-Windows-x64-Pruefer-Preview.zip')
    linux = fetch_tested_artifact('linux')
    copy_members(linux,SOURCES['linux']['members'])
    assert sorted(p.name for p in OUT.iterdir()) == sorted(ASSETS)
    for name, expected in ASSETS.items():
        assert digest(OUT / name) == expected, name
    (OUT / 'SHA256SUMS.txt').write_text(''.join(f'{ASSETS[name]}  {name}\n' for name in sorted(ASSETS)))

if __name__ == '__main__':
    main()
