"""Exercise the complete local evidence workflow; CI must pass before publishing."""
from __future__ import annotations
import argparse
import contextlib
import io
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from authzledger.cli import main
from authzledger.history import HistoryStore
from authzledger.assurance import retest_plan


def invoke(*argv):
    result = main(list(map(str, argv)))
    if result != 0:
        raise AssertionError(f'Acceptance command {argv[0]} failed with {result}')


def check(out):
    out.mkdir(parents=True, exist_ok=False)
    invoke('demo', '--out', out / 'demo')
    contract = json.loads((out / 'demo/contract.json').read_text())
    policy = {'schema_version': 1, 'engine': 'local', 'default': 'deny', 'rules': [
        {'id': 'owner-own', 'effect': 'allow', 'identities': ['owner'], 'methods': ['GET'], 'paths': ['/invoices/owner-1']},
        {'id': 'peer-own', 'effect': 'allow', 'identities': ['peer'], 'methods': ['GET'], 'paths': ['/invoices/peer-1']},
        {'id': 'admin-audit', 'effect': 'allow', 'identities': ['admin'], 'methods': ['GET'], 'paths': ['/admin/audit']}]}
    policy_path = out / 'policy.json'
    policy_path.write_text(json.dumps(policy))
    for name, report in [('before', 'vulnerable'), ('after', 'fixed')]:
        invoke('graph', out / 'demo/contract.json', '--report', out / f'demo/{report}/report.json', '--policy', policy_path, '--out', out / f'{name}-graph.json')
    invoke('intelligence-diff', out / 'before-graph.json', out / 'after-graph.json', '--out', out / 'differential.json')
    diff = json.loads((out / 'differential.json').read_text())
    assert len(diff['resolved']) == 2, diff
    invoke('explain', out / 'after-graph.json', '--out', out / 'explanation.json')
    invoke('keygen', '--private', out / 'private.pem', '--public', out / 'trusted-public.pem')
    invoke('bundle', out / 'demo/fixed/report.json', '--key', out / 'private.pem', '--contract', out / 'demo/contract.json', '--graph', out / 'after-graph.json', '--explanation', out / 'explanation.json', '--out', out / 'proof')
    invoke('verify-bundle', out / 'proof', '--public-key', out / 'trusted-public.pem')
    subprocess.run([sys.executable, str(ROOT / 'tools/verify_bundle.py'), str(out / 'proof'), '--public-key', str(out / 'trusted-public.pem')], check=True, cwd=out)
    with HistoryStore(out / 'history.sqlite3') as history:
        for name, report in [('before', 'vulnerable'), ('after', 'fixed')]:
            history.append(contract, json.loads((out / f'demo/{report}/report.json').read_text()), json.loads((out / f'{name}-graph.json').read_text()))
        assert len(history.list_runs()) == 2
        assert not history.verify_chain()
    invoke('history', out / 'history.sqlite3', '--out', out / 'history-index.json')
    invoke('retest', out / 'demo/contract.json', '--case', 'peer-cannot-read-owner', '--out', out / 'retest.json')
    retest = json.loads((out / 'retest.json').read_text())
    assert set(retest['dependency_ids']) == {'owner-own-invoice', 'peer-own-invoice'}
    invoke('benchmark', '--out', out / 'corpus')
    result = {'passed': True, 'scope': 'synthetic loopback fixtures', 'resolved': len(diff['resolved']), 'history_records': 2,
              'workflows': ['three-layer graph', 'independent local policy', 'differential retest', 'grounded explanation', 'Ed25519 signing', 'externally trusted verification', 'standalone verifier', 'durable history', 'dependency-closed retest', 'eight-scenario corpus']}
    (out / 'acceptance.json').write_text(json.dumps(result, indent=2) + '\n')
    print('AuthzLedger 1.0 complete local evidence workflow passed.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    check(parser.parse_args().out.absolute())
