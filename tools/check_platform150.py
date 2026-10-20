#!/usr/bin/env python3
"""Run three real loopback platform demos and verify the signed handover offline."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from authzledger.demo150 import run_demos


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--standalone-verifier', type=Path, default=ROOT / 'tools' / 'verify_bundle.py')
    parser.add_argument('--formats', default='json,html,pdf', help='Comma-separated verified report formats')
    args = parser.parse_args()
    result = run_demos(args.out, standalone_verifier=args.standalone_verifier, formats=tuple(args.formats.split(',')))
    print(json.dumps({'result': 'verified', 'producer_version': result['producer_version'],
                      'http_requests': result['total_http_requests_observed'],
                      'service_connections': result['total_service_connections_observed'],
                      'tamper_rejected': bool(result['tamper']['main_errors']),
                      'receipt': str(args.out.resolve() / 'results.json')}, sort_keys=True))


if __name__ == '__main__':
    main()
