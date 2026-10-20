#!/usr/bin/env python3
"""Execute all 1.5 release gates; retain measured logs, never infer success."""
from pathlib import Path
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from authzledger import __version__
from tools.release_gate150 import BROWSERS, source_digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    environment = dict(os.environ, SOURCE_DATE_EPOCH='1767225600', PYTHON=sys.executable)
    receipt = {'schema_version': 1, 'kind': 'release-verification150', 'producer_version': __version__,
               'source_digest': source_digest(), 'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
               'started_at': datetime.now(timezone.utc).isoformat(), 'completed': False,
               'runtime': {'python': platform.python_version(), 'platform': platform.platform()}, 'commands': []}

    def save():
        (out / 'verification.json').write_text(json.dumps(receipt, indent=2) + '\n')

    def run(identifier, command, *, cwd=ROOT, timeout=900, env=None):
        print(identifier + ': running', flush=True)
        started = time.monotonic()
        log = out / (identifier + '.log')
        with log.open('wb') as handle:
            try:
                process = subprocess.run(command, cwd=cwd, env=env or environment, stdout=handle,
                                         stderr=subprocess.STDOUT, timeout=timeout, check=False)
                code = process.returncode
            except subprocess.TimeoutExpired:
                handle.write(b'\nRelease verification timeout.\n')
                code = 124
        receipt['commands'].append({'id': identifier, 'argv': [str(x) for x in command], 'returncode': code,
                                    'elapsed_seconds': round(time.monotonic() - started, 3),
                                    'log': log.name, 'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()})
        save()
        print(identifier + ': ' + ('passed' if code == 0 else 'FAILED; ' + str(log)), flush=True)
        if code:
            raise SystemExit(code)

    save()
    run('unit', [sys.executable, str(ROOT / 'tools/run_tests150.py'), '--out', str(out / 'unit-results.json')])
    receipt['unit_results'] = json.loads((out / 'unit-results.json').read_text())
    measured = receipt['unit_results']
    if (measured.get('producer_version') != __version__ or measured.get('executed', 0) < 530
            or measured.get('executed') != measured.get('discovered')
            or not measured.get('successful') or any(measured.get(k) != 0 for k in ('failures', 'errors', 'skipped', 'unexpected_successes'))):
        raise SystemExit('Unit completion receipt does not establish the complete successful suite.')
    save()
    for identifier, script in [('core', 'release_check.py'), ('comparison', 'check_comparison.py'),
                               ('assessment', 'check_assessment.py'), ('selective100', 'check_selective100.py'),
                               ('workflow110', 'check_workflows110.py'), ('platform150', 'check_platform150.py')]:
        run(identifier, [sys.executable, str(ROOT / 'tools' / script), '--out', str(out / identifier)])
    run('native_burp', [sys.executable, '-I', str(ROOT / 'tools/check_native_burp.py')])
    for browser in BROWSERS:
        run('browser_' + browser, ['node', str(ROOT / 'tests' / ('browser_' + browser + '.cjs'))], timeout=300)
    wheel_name = 'authzledger-' + __version__ + '-py3-none-any.whl'
    first, second = out / 'wheel-first', out / 'wheel-second'
    for identifier, destination in [('wheel_first', first), ('wheel_second', second)]:
        run(identifier, [sys.executable, '-m', 'pip', 'wheel', '--no-deps', '--no-build-isolation', '--wheel-dir', str(destination), str(ROOT)])
    run('wheel_equal', [sys.executable, '-c', 'from pathlib import Path; import sys; assert Path(sys.argv[1]).read_bytes()==Path(sys.argv[2]).read_bytes()', str(first / wheel_name), str(second / wheel_name)])
    # No checkout imports are permitted. Both installed demos run in a new directory,
    # and a copied independent verifier operates only on the resulting artifacts.
    with tempfile.TemporaryDirectory(prefix='authzledger-installed150-') as temporary:
        isolated = Path(temporary)
        shutil.copyfile(ROOT / 'tools/verify_bundle.py', isolated / 'verify_bundle.py')
        installed_script = '''from pathlib import Path
import json, subprocess, sys, venv
root=Path.cwd(); venv.EnvBuilder(with_pip=True).create(root/'venv')
python=root/'venv'/('Scripts/python.exe' if sys.platform=='win32' else 'bin/python')
def run(*args): subprocess.run([str(python), *map(str,args)],check=True)
run('-m','pip','install','--no-index','--no-deps',sys.argv[1])
run('-m','pip','install','reportlab==4.4.9')
run('-I','-c',"import authzledger,pathlib,sys; p=pathlib.Path(authzledger.__file__).resolve(); assert str(p).startswith(str(pathlib.Path(sys.prefix).resolve())); assert authzledger.__version__ == "+repr(sys.argv[2])+"; print(authzledger.__version__,p)")
run('-I','-m','authzledger','assessment','demo','--out',root/'legacy-demo')
run('-I','-m','authzledger','verify-bundle',root/'legacy-demo/proof','--public-key',root/'legacy-demo/trusted-public.pem')
run('-I',root/'verify_bundle.py',root/'legacy-demo/proof','--public-key',root/'legacy-demo/trusted-public.pem')
run('-I','-m','authzledger','assessment','demo150','--out',root/'suite-demo','--standalone-verifier',root/'verify_bundle.py')
run('-I','-m','authzledger','verify-bundle',root/'suite-demo/C-retest-proof/proof','--public-key',root/'suite-demo/trusted-public.pem')
run('-I',root/'verify_bundle.py',root/'suite-demo/C-retest-proof/proof','--public-key',root/'suite-demo/trusted-public.pem')
print(json.dumps({'isolated':True,'version':sys.argv[2],'legacy_and_suite_demos':True}))
'''
        run('installed_wheel', [sys.executable, '-c', installed_script, str(first / wheel_name), __version__], cwd=isolated, timeout=900)
    (ROOT / 'dist').mkdir(exist_ok=True)
    shutil.copyfile(first / wheel_name, ROOT / 'dist' / wheel_name)
    run('package', [sys.executable, str(ROOT / 'tools/package_release.py'), '--proof-source', str(out / 'platform150')])
    if source_digest() != receipt['source_digest']:
        print('Sources changed during verification; receipt cannot be completed.', flush=True)
        return 2
    receipt['completed'] = True
    receipt['completed_at'] = datetime.now(timezone.utc).isoformat()
    save()
    shutil.copyfile(out / 'verification.json', ROOT / 'dist/verification.json')
    with (ROOT / 'dist/SHA256SUMS.txt').open('a') as checksums:
        checksums.write(hashlib.sha256((out / 'verification.json').read_bytes()).hexdigest() + '  verification.json\n')
    print('All release executions passed: ' + str(out / 'verification.json'), flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
