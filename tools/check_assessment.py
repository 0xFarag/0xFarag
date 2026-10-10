#!/usr/bin/env python3
"""Run all three synthetic assessment demonstrations and an isolated verifier."""
import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from authzledger.assessment_demo import run_demos

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    result = run_demos(args.out)
    subprocess.run([sys.executable, '-I', str(ROOT / 'tools/verify_bundle.py'), str(args.out.resolve() / 'proof'),
                    '--public-key', str(args.out.resolve() / 'trusted-public.pem')], check=True)
    print('Three controlled demonstrations verified: import/reproducer, denial/controls, selective retest/proof.')
    print('Request count:', result['network_requests'])
