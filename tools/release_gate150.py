#!/usr/bin/env python3
"""Guard the 1.5 publication stage using same-source execution receipts.

This is a release process guard, not an independent attestation that an operator
or CI host is honest. Publication also requires successful exact-commit CI.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from authzledger import __version__
from tools.check_native_burp import check_native_burp

BROWSERS = ('acceptance', 'v1', 'comparison', 'assessments',
            'assessment_security', 'retest_freshness', 'feature_coverage', 'platform150')
REQUIRED = {'unit', 'core', 'comparison', 'assessment', 'selective100', 'workflow110',
            'native_burp', 'platform150', 'wheel_first', 'wheel_second',
            'wheel_equal', 'installed_wheel', 'package'} | {'browser_' + b for b in BROWSERS}


def source_files(root=ROOT):
    files = []
    for name in ('authzledger', 'tools', 'tests', 'fixtures', 'examples', 'docs', '.github', 'brand'):
        folder = root / name
        if folder.is_symlink():
            raise ValueError('Symlink in release sources: ' + name)
        if folder.exists():
            for path in folder.rglob('*'):
                if '__pycache__' in path.parts or path.suffix == '.pyc':
                    continue
                if path.is_symlink():
                    raise ValueError('Symlink in release sources: ' + str(path.relative_to(root)))
                if path.is_file():
                    files.append(path)
    for name in ('README.md', 'INSTALL.md', 'RELEASE_NOTES.md',
                 'RELEASE.json', 'CHANGELOG.md', 'LICENSE', 'NOTICE.txt', 'SECURITY.md',
                 'CONTRIBUTING.md', 'pyproject.toml', 'MANIFEST.in', 'start.sh', '.gitignore'):
        path = root / name
        if path.is_symlink():
            raise ValueError('Symlink in release sources: ' + name)
        if path.is_file():
            files.append(path)
    return sorted(set(files))


def source_digest(root=ROOT):
    """Bind product code, fixtures, tests, docs and build/release machinery."""
    hasher = hashlib.sha256()
    for path in source_files(root):
        hasher.update(path.relative_to(root).as_posix().encode() + b'\0')
        hasher.update(hashlib.sha256(path.read_bytes()).digest())
    return hasher.hexdigest()


def blockers(receipt_dir=None, *, allow_development=False, publication=False):
    errors = []
    allowed = {'1.5.0'} | ({'1.5.0.dev0'} if allow_development and not publication else set())
    if __version__ not in allowed:
        errors.append('Producer must be exactly 1.5.0 for publication.')
    package = re.search(r'^version = "([^"]+)"$', (ROOT / 'pyproject.toml').read_text(), re.M)
    metadata = json.loads((ROOT / 'RELEASE.json').read_text())
    if not package or package[1] != __version__ or metadata.get('version') != __version__:
        errors.append('Producer, wheel metadata and RELEASE.json versions must agree.')
    if metadata.get('target_version') != '1.5.0':
        errors.append('Target release must remain 1.5.0.')
    rows = re.findall(r'^\| (F\d{2}-\d{2}) \| [^\n]*? \| (Verifiziert|Teilweise verifiziert|Offenes Abnahmegate) \|',
                      (ROOT / 'docs/acceptance-1.1.0.md').read_text(), re.M)
    if len(rows) != 88 or any(status != 'Verifiziert' for _, status in rows):
        errors.append('Historical 1.1 acceptance ledger must retain its 88 verified scenarios.')
    try:
        check_native_burp()
    except ValueError as exc:
        errors.append('Native Burp evidence: ' + str(exc))
    if receipt_dir is None:
        errors.append('Executed release verification receipt is required.')
        return errors
    receipt_dir = Path(receipt_dir)
    try:
        receipt = json.loads((receipt_dir / 'verification.json').read_text())
        if receipt.get('kind') != 'release-verification150' or receipt.get('producer_version') != __version__:
            errors.append('Receipt producer/profile differs from current release.')
        if receipt.get('source_digest') != source_digest():
            errors.append('Sources changed since verification; rerun the complete gate.')
        commands = receipt.get('commands', [])
        identifiers = [row.get('id') for row in commands]
        if len(identifiers) != len(set(identifiers)) or not REQUIRED.issubset(identifiers):
            errors.append('Required test, browser, demo, package or installation executions are missing.')
        for row in commands:
            if row.get('returncode') != 0:
                errors.append('Execution failed: ' + str(row.get('id')))
            log = receipt_dir / row.get('log', '')
            if not log.is_file() or log.is_symlink() or log.parent != receipt_dir:
                errors.append('Invalid execution log: ' + str(row.get('id')))
            elif hashlib.sha256(log.read_bytes()).hexdigest() != row.get('log_sha256'):
                errors.append('Execution log changed: ' + str(row.get('id')))
        if not receipt.get('completed'):
            errors.append('Verification did not complete.')
        unit = receipt.get('unit_results', {})
        if (unit.get('kind') != 'unit-completion150' or unit.get('producer_version') != __version__
                or unit.get('executed', 0) < 530 or unit.get('executed') != unit.get('discovered')
                or not unit.get('successful') or any(unit.get(k) != 0 for k in ('failures', 'errors', 'skipped', 'unexpected_successes'))):
            errors.append('Complete unit execution counts with zero failures, errors and skips are required.')
        if publication:
            commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
            if receipt.get('commit') != commit or (os.environ.get('GITHUB_SHA') and os.environ['GITHUB_SHA'] != commit):
                errors.append('Publication commit does not match the verified commit.')
            if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT, text=True).strip():
                errors.append('Tracked source changes exist after verification.')
            tracked = set(subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT, text=True).split('\0'))
            if any(path.relative_to(ROOT).as_posix() not in tracked for path in source_files(ROOT)):
                errors.append('Untracked release sources cannot be published under this commit.')
    except (OSError, ValueError, TypeError, KeyError) as exc:
        errors.append('Invalid release receipt: ' + str(exc))
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--receipt-dir', type=Path, required=True)
    parser.add_argument('--allow-development', action='store_true')
    parser.add_argument('--publication', action='store_true')
    args = parser.parse_args()
    errors = blockers(args.receipt_dir, allow_development=args.allow_development, publication=args.publication)
    if errors:
        print('1.5.0 publication blocked:\n' + '\n'.join('- ' + e for e in errors))
        return 2
    print('Complete same-source release receipts verified' + ('; exact publication commit verified.' if args.publication else '.'))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
