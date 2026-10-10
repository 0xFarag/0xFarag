#!/usr/bin/env python3
"""External installed-wheel acceptance; never imports checkout/test modules."""
from __future__ import annotations
import argparse
import copy
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def require(value, message):
    if not value:
        raise AssertionError(message)


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inventory(root):
    return {p.relative_to(root).as_posix(): {'bytes': p.stat().st_size, 'sha256': digest(p)}
            for p in sorted(root.rglob('*')) if p.is_file()}


def verify_pair(bundle, key, standalone, log):
    from authzledger.signing import verify_bundle
    require(bundle not in key.parents and key != bundle, 'trust anchor is inside bundle')
    errors = verify_bundle(bundle, key)
    require(not errors, f'main verifier rejected {bundle}: {errors}')
    result = subprocess.run([sys.executable, '-I', str(standalone), str(bundle), '--public-key', str(key)],
                            capture_output=True, text=True, check=False, cwd=key.parent)
    dump(log, {'bundle': str(bundle), 'external_public_key': str(key), 'public_key_file_sha256': digest(key),
               'main_errors': errors, 'standalone_exit_code': result.returncode,
               'standalone_stdout': result.stdout, 'standalone_stderr': result.stderr})
    require(result.returncode == 0, result.stderr + result.stdout)


def render(snapshot_path, out):
    from authzledger.assessment_reports import export_assessment, verify_assessment
    snapshot = json.loads(snapshot_path.read_text())
    require(not verify_assessment(snapshot), 'invalid frozen assessment')
    export_assessment(snapshot, out)


def run(args):
    import authzledger
    from authzledger.assessment_demo import assessment_lab, imported_plan
    from authzledger.assessment_reports import freeze_assessment, verify_assessment, create_assessment_bundle, RENDERER_PROFILE
    from authzledger.experiments import compile_experiment, execute_experiment, verify_execution
    from authzledger.signing import generate_keypair
    from authzledger.history import HistoryStore
    from authzledger.lab110 import workflow_lab, workflow_spec
    from authzledger.workflow_assurance import compile_workflow_assurance, run_workflow_assurance, verify_workflow_assurance
    from pypdf import PdfReader

    out = args.out
    out.mkdir()
    anchors = args.anchors
    anchors.mkdir(exist_ok=True)
    package = Path(authzledger.__file__).resolve().parent
    require('site-packages' in package.parts, f'checkout import: {package}')
    require(authzledger.__version__ == '1.1.0', 'nonrelease installed package')
    require(importlib.metadata.version('reportlab') == '4.4.9', 'wrong reportlab')
    expected_fonts = {'DejaVuSans.ttf': 'ae7b7855e115a5966d8b1b3f80f254ccc117ec86f9965e202ee2940453837280',
                      'DejaVuSans-Bold.ttf': '5c1247acef7f2b8522a31742c76d6adcb5569bacc0be7ceaa4dc39dd252ce895'}
    fonts = {name: digest(package/'fonts'/name) for name in expected_fonts}
    require(fonts == expected_fonts, 'bundled DejaVu2.37 hash mismatch')
    dump(out/'installed-provenance.json', {'module_path': str(package), 'version': authzledger.__version__,
         'python': sys.version, 'prefix': sys.prefix, 'renderer_profile': RENDERER_PROFILE,
         'versions': {n: importlib.metadata.version(n) for n in ('authzledger','reportlab','pillow','pypdf')},
         'font_sha256': fonts, 'trust_scope': 'Ephemeral acceptance keys; independently supplied outside every bundle. No publisher identity attestation.'})

    executions = []
    with assessment_lab() as (origin, state, resolver, values):
        template = imported_plan(origin)[2]['spec']
        for i in range(50):
            spec = copy.deepcopy(template)
            spec['rule']['id'] = f'isolated-rule-{i:02d}'
            spec['title'] = f'Finding {i:02d}: Überprüfung von Mandantengrenzen αβγ - ' + 'long context '*10
            execution = execute_experiment(compile_experiment(spec), credential_resolver=resolver)
            require(not verify_execution(execution), 'invalid 50-finding source execution')
            require(execution['findings'][0]['status'] == 'confirmed', 'missing controlled finding')
            executions.append(execution)
        receipts = copy.deepcopy(state['requests'])
        secrets_used = tuple(values.values())
    require(len(receipts) == 200, '50 findings require exactly 200 controlled requests')
    snapshot = freeze_assessment(executions, {'title': '50 findings / Unicode Zürich αβγ',
        'limitations': ['Synthetic controlled loopback evidence; not a claim about a remote production system.',
                       'https://example.invalid/' + 'path-segment/'*40]})
    require(not verify_assessment(snapshot), 'invalid 50-finding assessment')
    require(len(snapshot['findings']) == 50 and sum(snapshot['summary'].values()) == 50, 'wrong finding count')
    snapshot_path = out/'snapshot-50.json'
    dump(snapshot_path, snapshot)
    dump(out/'request-receipts-50.json', receipts)
    render_environments = {'render-a': None, 'render-b': '1767225600',
                           'render-epoch-zero': '0', 'render-epoch-invalid': 'invalid'}
    for name, epoch in render_environments.items():
        child_env = os.environ.copy()
        if epoch is None:
            child_env.pop('SOURCE_DATE_EPOCH', None)
        else:
            child_env['SOURCE_DATE_EPOCH'] = epoch
        subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()), 'render',
                        '--snapshot', str(snapshot_path), '--out', str(out/name)], check=True, cwd=out, env=child_env)
    first, second = inventory(out/'render-a'), inventory(out/'render-b')
    require(first == second, 'JSON/HTML/PDF bytes differ across independent render processes')
    for name in render_environments:
        require(inventory(out/name) == first, f'reports depend on SOURCE_DATE_EPOCH: {name}')
    pdf = PdfReader(out/'render-a'/'assessment.pdf')
    text = '\n'.join(page.extract_text() for page in pdf.pages)
    html = (out/'render-a'/'assessment.html').read_text()
    for row in snapshot['findings']:
        for value in (row['id'], *row['record']['evidence_refs']):
            require(value in text, 'PDF missing retained finding or evidence reference')
            require(value in html, 'HTML missing retained finding or evidence reference')
    for value in ('Finding 49', 'Zürich αβγ', 'Überprüfung'):
        require(value in text, 'PDF Unicode/long-title text missing')
    with tempfile.TemporaryDirectory(prefix='authzledger-phase2-private-') as temp:
        private = Path(temp)/'private.pem'
        public = anchors/'report-50-public.pem'
        generate_keypair(private, public)
        pinned_key_sha = digest(public)
        for name in ('proof-a', 'proof-b'):
            create_assessment_bundle(snapshot, out/name, private)
    require(digest(public) == pinned_key_sha, 'external trust anchor changed')
    require(inventory(out/'proof-a') == inventory(out/'proof-b'), 'signed inventory/proof bytes are not repeatable')
    manifest = json.loads((out/'proof-a'/'manifest.json').read_text())
    for record in manifest['files']:
        p = out/'proof-a'/record['path']
        require(record['sha256'] == digest(p) and record['size'] == p.stat().st_size, 'manifest does not bind actual bytes')
    require({'attachments/assessment.json','attachments/assessment.html','attachments/assessment.pdf'} <=
            {r['path'] for r in manifest['files']}, 'all report formats must be signed')
    verify_pair(out/'proof-a', public, args.standalone, out/'report-proof-verification.json')
    for name, epoch in render_environments.items():
        child_env = os.environ.copy()
        if epoch is None:
            child_env.pop('SOURCE_DATE_EPOCH', None)
        else:
            child_env['SOURCE_DATE_EPOCH'] = epoch
        subprocess.run([sys.executable, '-I', str(Path(__file__).resolve()), 'verify',
                        '--bundle', str(out/'proof-a'), '--public-key', str(public),
                        '--standalone', str(args.standalone), '--out', str(out/f'verification-{name}.json')],
                       check=True, cwd=anchors, env=child_env)
    # Verify that both verifiers fail on bytes not present in the signed inventory.
    with tempfile.TemporaryDirectory(prefix='authzledger-phase2-tamper-') as temp:
        tampered = Path(temp)/'proof'
        shutil.copytree(out/'proof-a', tampered)
        with (tampered/'attachments'/'assessment.pdf').open('ab') as handle:
            handle.write(b'\n% unsigned modification\n')
        from authzledger.signing import verify_bundle
        require(verify_bundle(tampered, public), 'main accepted unsigned PDF modification')
        p = subprocess.run([sys.executable, '-I', str(args.standalone), str(tampered), '--public-key', str(public)], capture_output=True, text=True)
        require(p.returncode != 0, 'standalone accepted unsigned PDF modification')
        dump(out/'unsigned-modification-rejected.json', {'main_rejected': True, 'standalone_exit_code': p.returncode, 'standalone_stdout': p.stdout, 'standalone_stderr': p.stderr})

    assurance_receipts = {}
    for case, vulnerable, expected_cycles, expected_requests, expected_status in (
        ('safe', False, 2, 12, 'satisfied'), ('violation', True, 1, 6, 'violation')):
        case_out = out/f'workflow-assurance-{case}'
        case_out.mkdir()
        with workflow_lab() as (origin, state), HistoryStore(case_out/'history.sqlite3') as history:
            state['vulnerable'] = vulnerable
            plan = compile_workflow_assurance({'schema_version': 1, 'kind': 'workflow-assurance-spec',
                'workflow': workflow_spec(origin), 'max_cycles': 2, 'interval_seconds': 0,
                'max_requests_total': 12, 'max_history_age_seconds': 300})
            result = run_workflow_assurance(plan, history=history)
            require(result['completed_cycles'] == expected_cycles, 'wrong assurance cycle count')
            require(result['status'] == expected_status, 'wrong assurance status')
            require(result['budget_ledger']['dispatched_total'] == expected_requests == len(state['requests']), 'wrong assurance request count')
            require(not state['objects'], 'workflow fixture cleanup incomplete')
            require(not history.verify_chain(), 'invalid durable history')
            request_receipts = copy.deepcopy(state['requests'])
        require(not verify_workflow_assurance(result), 'offline assurance verification failed')
        with HistoryStore(case_out/'history.sqlite3') as history:
            require(not history.verify_chain(), 'history changed after reopen')
            require(len(history.workflow_snapshot()['records']) == expected_cycles, 'durable trace count mismatch')
        dump(case_out/'assurance.json', result)
        dump(case_out/'request-receipts.json', request_receipts)
        frozen = freeze_assessment([], {'title': 'Finite workflow assurance: '+case}, assurances=[result])
        dump(case_out/'snapshot.json', frozen)
        render(case_out/'snapshot.json', case_out/'reports')
        with tempfile.TemporaryDirectory(prefix='authzledger-phase2-private-') as temp:
            private = Path(temp)/'private.pem'
            public = anchors/f'workflow-{case}-public.pem'
            generate_keypair(private, public)
            create_assessment_bundle(frozen, case_out/'proof', private)
        verify_pair(case_out/'proof', public, args.standalone, case_out/'verification.json')
        assurance_receipts[case] = {'cycles': expected_cycles, 'requests': expected_requests, 'status': expected_status,
            'objects_cleaned': True, 'history_reopened_verified': True, 'offline_verification': True}
    for p in out.rglob('*'):
        if p.is_file() and p.suffix != '.sqlite3':
            raw = p.read_bytes()
            require(all(value.encode() not in raw for value in secrets_used), f'credential leaked: {p}')
            require(b'-----BEGIN PRIVATE KEY-----' not in raw, f'private signing key leaked: {p}')
    dump(out/'acceptance.json', {'passed': True, 'findings': 50, 'network_requests_50': 200,
        'pdf_pages': len(pdf.pages), 'unicode_and_all_evidence_refs_present': True,
        'independent_process_render_byte_equality': first, 'repeat_signed_bundle_byte_equality': True,
        'source_date_epoch_independent_render_and_verification': render_environments,
        'signed_inventory_covers_json_html_pdf': True, 'unsigned_pdf_modification_rejected': True,
        'private_keys_retained': False, 'workflow_assurance': assurance_receipts,
        'visual_review': 'pending raster inspection', 'network': 'controlled synthetic loopback only'})
    print(json.dumps({'passed': True, 'findings': 50, 'pdf_pages': len(pdf.pages), 'out': str(out)}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=['run','render','verify'])
    parser.add_argument('--out', type=Path)
    parser.add_argument('--snapshot', type=Path)
    parser.add_argument('--anchors', type=Path)
    parser.add_argument('--standalone', type=Path)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--public-key', type=Path)
    args = parser.parse_args()
    if args.mode == 'render':
        render(args.snapshot, args.out)
    elif args.mode == 'verify':
        verify_pair(args.bundle, args.public_key, args.standalone, args.out)
    else:
        run(args)


if __name__ == '__main__':
    main()
