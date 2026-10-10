#!/usr/bin/env python3
"""Fail closed until the exact 1.1.0 contract acceptance ledger is complete.

This is a publication guard, not an independent certification of test receipts.
Run the documented unit, browser, distribution and proof checks on the same
commit before publishing. A development version can never pass this guard.
"""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from authzledger import __version__

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
    return errors


if __name__ == '__main__':
    errors = blockers()
    if errors:
        print('1.1.0 publication blocked:')
        print('\n'.join('- ' + error for error in errors))
        raise SystemExit(2)
    print('Version and complete acceptance ledger permit the 1.1.0 publication stage.')
