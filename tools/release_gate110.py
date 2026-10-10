#!/usr/bin/env python3
"""Fail closed until the exact 1.1.0 contract acceptance ledger is complete.

This is a publication guard, not an independent certification of test receipts.
Run the documented unit, browser, distribution and proof checks on the same
commit before publishing. A development version can never pass this guard.
"""
from pathlib import Path
import json
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from authzledger import __version__
from tools.check_native_burp import check_native_burp

EXPECTED = {f'F{feature:02}-{number:02}' for feature, count in
            [(1, 10), (2, 12), (3, 10), (4, 10), (5, 12), (6, 12), (7, 12), (8, 10)]
            for number in range(1, count + 1)}


def blockers():
    rows = re.findall(r'^\| (F\d{2}-\d{2}) \| [^\n]*? \| (Verifiziert|Teilweise verifiziert|Offenes Abnahmegate) \|',
                      (ROOT / 'docs/acceptance-1.1.0.md').read_text(), re.M)
    errors = []
    if len(rows) != 88 or {identifier for identifier, _ in rows} != EXPECTED:
        errors.append('Acceptance ledger must contain exactly the 88 contractual scenarios.')
    errors.extend(identifier + ': ' + status for identifier, status in rows if status != 'Verifiziert')
    if __version__ != '1.1.0':
        errors.append('Producer version is ' + __version__ + '; production 1.1.0 is not enabled.')
    package_version = re.search(r'^version = "([^"]+)"$', (ROOT / 'pyproject.toml').read_text(), re.M)
    metadata = json.loads((ROOT / 'RELEASE.json').read_text())
    if not package_version or package_version[1] != __version__ or metadata.get('version') != __version__:
        errors.append('Producer, wheel metadata and RELEASE.json versions must agree.')
    try:
        check_native_burp()
    except ValueError as exc:
        errors.append('Native Burp evidence: ' + str(exc))
    return errors


if __name__ == '__main__':
    errors = blockers()
    if errors:
        print('1.1.0 publication blocked:')
        print('\n'.join('- ' + error for error in errors))
        raise SystemExit(2)
    print('Version, complete acceptance ledger and pinned native Burp evidence permit the 1.1.0 publication stage.')
