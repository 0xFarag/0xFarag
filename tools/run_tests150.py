#!/usr/bin/env python3
"""Run the complete discovered suite and retain an explicit completion record."""
from pathlib import Path
import argparse
import json
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from authzledger import __version__


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists():
        raise ValueError('Test completion output already exists')
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
    expected = suite.countTestCases()
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    receipt = {'kind': 'unit-completion150', 'producer_version': __version__,
               'discovered': expected, 'executed': result.testsRun,
               'failures': len(result.failures), 'errors': len(result.errors),
               'skipped': len(result.skipped), 'unexpected_successes': len(result.unexpectedSuccesses),
               'successful': result.wasSuccessful(), 'elapsed_seconds': round(time.monotonic() - started, 3)}
    args.out.write_text(json.dumps(receipt, indent=2) + '\n')
    return 0 if result.wasSuccessful() and result.testsRun == expected and expected >= 530 and not result.skipped else 1


if __name__ == '__main__':
    raise SystemExit(main())
