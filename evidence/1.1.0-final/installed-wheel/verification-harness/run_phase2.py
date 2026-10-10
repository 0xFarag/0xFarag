#!/usr/bin/env python3
"""Run only after the final 1.1.0 Phase1 freeze has been explicitly authorized."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import time
import tomllib
import zipfile


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def require(value, message):
    if not value:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--freeze-confirmed', action='store_true', required=True)
    parser.add_argument('--run-name', default='run', help='New task-local run directory; never overwrites prior evidence.')
    args = parser.parse_args()
    source = args.source.resolve()
    work = Path(__file__).resolve().parent
    if not re.fullmatch('[a-zA-Z0-9-]+', args.run_name):
        parser.error('run-name must contain only letters, digits and hyphens')
    run = work/args.run_name
    run.mkdir()
    logs = run/'logs'
    logs.mkdir()
    commands = []
    env = {k:v for k,v in os.environ.items() if k not in {'PYTHONPATH','PYTHONHOME','VIRTUAL_ENV'}}
    env.update(SOURCE_DATE_EPOCH='1767225600', PYTHONHASHSEED='0', PYTHONDONTWRITEBYTECODE='1', TZ='UTC', LC_ALL='C.UTF-8', PIP_NO_INDEX='1', PIP_FIND_LINKS=str(work/'dependency-wheels'), PIP_DISABLE_PIP_VERSION_CHECK='1')

    def command(name, argv, cwd=run):
        print(f'START {name}', flush=True)
        started=time.time()
        with (logs/f'{name}.log').open('w') as handle:
            p = subprocess.run([str(x) for x in argv], stdout=handle, stderr=subprocess.STDOUT, cwd=cwd, env=env)
        commands.append({'name':name, 'argv':[str(x) for x in argv], 'cwd':str(cwd), 'exit_code':p.returncode, 'seconds':round(time.time()-started,3), 'log':str(logs/f'{name}.log')})
        dump(run/'commands.json', commands)
        print(f'END {name} exit={p.returncode}', flush=True)
        if p.returncode:
            raise RuntimeError(f'{name} failed; inspect {logs/name}.log')

    project = tomllib.loads((source/'pyproject.toml').read_text())
    require(project['project']['version'] == '1.1.0', 'source version is not stable1.1.0')
    require(project['build-system']['requires'] == ['setuptools==84.0.0','wheel==0.48.0'], 'unpinned build dependencies')
    require(project['project']['optional-dependencies']['reports'] == ['reportlab==4.4.9'], 'wrong reports extra')
    names = ['pyproject.toml','MANIFEST.in','README.md','LICENSE','NOTICE','INSTALL.md','CHANGELOG.md','SECURITY.md','CONTRIBUTING.md']
    files = [source/n for n in names if (source/n).is_file()]
    files += [p for p in sorted((source/'authzledger').rglob('*')) if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc']
    source_files = {p.relative_to(source).as_posix():sha(p) for p in files}
    core_files = {n:h for n,h in source_files.items() if n.startswith('authzledger/') or n in ('pyproject.toml','MANIFEST.in')}
    dump(run/'source-build-inputs.json', source_files)
    dump(run/'environment.json', {k:env[k] for k in ('SOURCE_DATE_EPOCH','PYTHONHASHSEED','PYTHONDONTWRITEBYTECODE','TZ','LC_ALL','PIP_NO_INDEX','PIP_FIND_LINKS')})
    dump(run/'dependency-wheels.json', {p.name:sha(p) for p in sorted((work/'dependency-wheels').glob('*.whl'))})
    buildvenv=run/'build-venv'
    command('01-build-venv', [sys.executable,'-m','venv',buildvenv])
    buildpython=buildvenv/'bin/python'
    command('02-build-dependencies', [buildpython,'-m','pip','install','setuptools==84.0.0','wheel==0.48.0'])
    wheels=[]
    for index in (1,2):
        checkout=run/f'build-source-{index}'
        checkout.mkdir()
        for p in files:
            dst=checkout/p.relative_to(source)
            dst.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(p,dst)
            require(sha(dst)==source_files[p.relative_to(source).as_posix()], 'build input changed while copying')
        destination=run/f'wheel-{index}'
        command(f'03-build-wheel-{index}', [buildpython,'-m','pip','wheel','--no-deps','--no-build-isolation','--wheel-dir',destination,checkout])
        wheel=destination/'authzledger-1.1.0-py3-none-any.whl'
        require(wheel.is_file(), 'expected wheel absent')
        wheels.append(wheel)
    require(sha(wheels[0])==sha(wheels[1]), 'two independent wheel builds differ')
    with zipfile.ZipFile(wheels[0]) as archive:
        metadata=archive.read('authzledger-1.1.0.dist-info/METADATA').decode()
        require('Provides-Extra: reports' in metadata and 'reportlab==4.4.9' in metadata, 'reports extra missing from wheel metadata')
        require(all(n in archive.namelist() for n in ('authzledger/fonts/DejaVuSans.ttf','authzledger/fonts/DejaVuSans-Bold.ttf')), 'bundled fonts absent')
        dump(run/'wheel-inventory.json', [{'path':i.filename,'size':i.file_size,'timestamp':i.date_time,'sha256':hashlib.sha256(archive.read(i.filename)).hexdigest()} for i in archive.infolist()])
    dump(run/'deterministic-wheel.json', {'passed':True,'source_date_epoch':1767225600,'build_backend':{'setuptools':'84.0.0','wheel':'0.48.0'},'wheels':[str(p) for p in wheels],'sha256':sha(wheels[0]),'bytes':wheels[0].stat().st_size})
    venv=run/'installed-venv'
    command('04-clean-install-venv',[sys.executable,'-m','venv',venv])
    python=venv/'bin/python'
    command('05-install-wheel-reports',[python,'-m','pip','install',str(wheels[0])+'[reports]','pypdf==6.10.0','pillow==12.3.0'])
    command('06-installed-pip-check',[python,'-m','pip','check'])
    command('07-installed-pip-freeze',[python,'-m','pip','freeze','--all'])
    harness=run/'harness'
    (harness/'tools').mkdir(parents=True)
    toolhashes={}
    for name in ('verify_bundle.py','check_assessment.py','check_selective100.py','check_workflows110.py'):
        src=source/'tools'/name
        shutil.copyfile(src,harness/'tools'/name)
        toolhashes[name]=sha(src)
    shutil.copyfile(work/'proof_qa.py',harness/'proof_qa.py')
    toolhashes['custom/proof_qa.py']=sha(harness/'proof_qa.py')
    toolhashes['custom/run_phase2.py']=sha(Path(__file__).resolve())
    dump(run/'harness-source-sha256.json', toolhashes)
    require(not (harness/'authzledger').exists(), 'harness contains checkout package')
    anchors=run/'trust-anchors'
    anchors.mkdir()
    standalone=harness/'tools/verify_bundle.py'
    # Product exports are the subject of acceptance; no hand-authored PDF assets.
    command('08-assessment-demos',[python,'-I',harness/'tools/check_assessment.py','--out',run/'assessment-demos'])
    command('09-selective-100',[python,'-I',harness/'tools/check_selective100.py','--out',run/'selective100'])
    command('10-workflows',[python,'-I',harness/'tools/check_workflows110.py','--out',run/'workflows110'])
    for name in ('assessment-demos','selective100'):
        key=anchors/f'{name}-public.pem'
        shutil.copyfile(run/name/'trusted-public.pem',key)
        command(f'11-verify-{name}',[python,'-I',harness/'proof_qa.py','verify','--bundle',run/name/'proof','--public-key',key,'--standalone',standalone,'--out',run/f'{name}-verification.json'])
    command('12-report-and-assurance-qa',[python,'-I',harness/'proof_qa.py','run','--out',run/'report-qa','--anchors',anchors,'--standalone',standalone])
    after={n:sha(source/n) for n in core_files}
    require(after==core_files, 'product core changed during Phase2')
    require(sha(Path(__file__).resolve()) == toolhashes['custom/run_phase2.py'], 'driver changed during Phase2')
    dump(run/'source-core-unchanged.json', {'passed':True, 'sha256':after})
    dump(run/'acceptance.json', {'passed':True,'version':'1.1.0','wheel_sha256':sha(wheels[0]),'commands':len(commands),'all_commands_exit_zero':True,'source_core_unchanged':True,'visual_review':'pending external raster review','key_scope':'Ephemeral demo/acceptance anchors explicitly supplied outside bundles; not publisher identity attestation.'})
    print('PHASE2 COMPUTATIONAL ACCEPTANCE PASSED',flush=True)


if __name__=='__main__':
    main()
