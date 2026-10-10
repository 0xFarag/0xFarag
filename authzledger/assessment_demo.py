"""Three reproducible assessment proofs against a synthetic loopback service.

No external system is contacted. Credentials and the private signing key exist
only for this run. Imported material is authored fixture data, not a claim of
compatibility certification by Burp or any other third-party product.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import json
from pathlib import Path
import secrets
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def write_json(path, value):
    with Path(path).open('x', encoding='utf-8') as output:
        json.dump(value, output, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False)
        output.write('\n')


@contextlib.contextmanager
def assessment_lab():
    """An authenticated two-tenant fixture; its tokens never enter recorded data."""
    from .credentials import CredentialResolver
    values = {'owner': 'Bearer ' + secrets.token_urlsafe(24), 'peer': 'Bearer ' + secrets.token_urlsafe(24)}
    state = {'mode': 'bola', 'requests': []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            actor = next((name for name, value in values.items() if self.headers.get('Authorization') == value), 'unknown')
            path = urlsplit(self.path).path
            state['requests'].append({'identity': actor, 'method': 'GET', 'path': path})
            if actor == 'unknown':
                status, body = 401, {'error': 'credentials required'}
            elif path == '/me':
                principal = 'owner' if state['mode'] == 'invalid_controls' else actor
                status, body = 200, {'principal': principal, 'tenant': 'A' if principal == 'owner' else 'B'}
            elif path == '/known-denial':
                status, body = 403, {'error': 'denied'}
            elif path == '/invoices/a' and actor == 'owner':
                status, body = 200, {'id': 'invoice-a', 'tenant': 'A', 'protected_marker': 'SYNTHETIC-INVOICE-A'}
            elif path == '/invoices/a' and state['mode'] in {'bola', 'leak', 'invalid_controls'}:
                status = 200 if state['mode'] == 'bola' else 403
                body = {'id': 'invoice-a', 'tenant': 'A', 'protected_marker': 'SYNTHETIC-INVOICE-A'}
            elif path == '/invoices/a':
                status, body = (200 if state['mode'] == '200error' else 403), {'error': 'denied'}
            else:
                status, body = 404, {'error': 'missing'}
            raw = json.dumps(body).encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
    worker.start()
    target = 'http://127.0.0.1:' + str(server.server_port)
    resolver = CredentialResolver()
    for identity, value in values.items():
        resolver.bind_session('DEMO_' + identity.upper(), value, identity=identity, target_origin=target)
    try:
        yield target, state, resolver, values
    finally:
        resolver.clear()
        server.shutdown()
        server.server_close()
        worker.join(2)


def imported_plan(target, *, variants=1):
    from .imports import parse_import
    from .experiments import compile_imported_experiment
    request = ('GET /invoices/a HTTP/1.1\r\nHost: ' + urlsplit(target).netloc
               + '\r\nAccept: application/json\r\nAccept-Language: en\r\nPragma: no-cache\r\n\r\n').encode()
    raw = ('<items><item><url>' + target + '/invoices/a</url><method>GET</method><path>/invoices/a</path>'
           + '<request base64="true">' + base64.b64encode(request).decode() + '</request>'
           + '<status>200</status></item></items>').encode()
    batch = parse_import(raw, 'burp-xml')
    entry = batch['entries'][0]
    bindings = {
        'id': 'invoice-isolation', 'title': 'Tenant B must not receive Tenant A invoice content',
        'target': target,
        'identities': {name: {'headers': {'Authorization': {'env': 'DEMO_' + name.upper()}}} for name in ('owner', 'peer')},
        'actor_identity': 'peer', 'owner_identity': 'owner',
        'identity_probe': {'path': '/me', 'expect': {'status': [200], 'json': {'/principal': 'peer', '/tenant': 'B'}}},
        'negative_probe': {'path': '/known-denial', 'expect': {'status': [403], 'json_absent': ['/protected_marker']}},
        'rule': {'id': 'tenant-isolation', 'kind': 'forbid_field_equal', 'pointer': '/protected_marker',
                 'value': 'SYNTHETIC-INVOICE-A', 'resource_id': 'invoice-a',
                 'resource_pointer': '/id', 'resource_value': 'invoice-a'},
        'capture_mode': 'safe_values',
        'selected_variants': [{'id': 'peer-' + str(index + 1), 'identity': 'peer', 'path': '/invoices/a'} for index in range(variants)]}
    return batch, bindings, compile_imported_experiment(entry, bindings)


def run_demos(out):
    from .experiments import execute_experiment, verify_execution, plan_experiment_retest, compare_executions
    from .minimize import removable_units, plan_reduction, execute_reduction, verify_reduction
    from .assessment_reports import freeze_assessment, export_assessment, create_assessment_bundle
    from .signing import generate_keypair, verify_bundle
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    outputs = {}
    with assessment_lab() as (target, state, resolver, values):
        batch, bindings, plan = imported_plan(target)
        require(imported_plan(target)[2] == plan, 'Plan must be deterministic')
        imported = execute_experiment(plan, credential_resolver=resolver)
        require(not verify_execution(imported), 'Imported experiment must verify')
        require(imported['findings'][0]['status'] == 'confirmed', 'BOLA fixture must be confirmed')
        reduction_plan = plan_reduction(imported, removable_units(imported), max_requests=40)
        reduced = execute_reduction(reduction_plan, credential_resolver=resolver)
        require(not verify_reduction(reduced), 'Every accepted reduction must verify')
        require(reduced['one_minimal'] and reduced['accepted_removed'], 'Fixture must reduce with the bounded final gate')
        outputs['01-import-to-reproducer'] = {'import': batch, 'bindings': bindings, 'plan': plan,
                                             'execution': imported, 'reduction': reduced}
        state['mode'] = 'leak'
        leakage = execute_experiment(plan, credential_resolver=resolver)
        require(leakage['findings'][0]['category'] == 'denial_data_disclosure', '403 marker must be treated as disclosure')
        state['mode'] = 'invalid_controls'
        invalid = execute_experiment(plan, credential_resolver=resolver)
        require(invalid['findings'][0]['interpretation'] == 'inconclusive', 'Invalid controls cannot confirm')
        state['mode'] = '200error'
        error200 = execute_experiment(plan, credential_resolver=resolver)
        require(error200['findings'][0]['status'] == 'rejected', 'A 200 error object must not be called BOLA')
        outputs['02-denial-and-controls'] = {'leakage': leakage, 'invalid-controls': invalid, '200-error': error200}
        state['mode'] = 'leak'
        full = execute_experiment(imported_plan(target, variants=2)[2], credential_resolver=resolver)
        baseline_before = copy.deepcopy(full)
        retest = plan_experiment_retest(full, ['peer-1'])
        state['mode'] = 'fixed'
        current = execute_experiment(retest, credential_resolver=resolver)
        comparison = compare_executions(full, current)
        require([t['status'] for t in comparison['transitions']] == ['fix_verified', 'not_retested'], 'Partial fix must not update the omitted finding')
        require(full == baseline_before, 'Retest must preserve original evidence')
        outputs['03-selective-retest-proof'] = {'baseline': full, 'current': current, 'comparison': comparison}
        network_count = len(state['requests'])
        forbidden_values = tuple(values.values())
    # All reporting, signing and verification now run with the fixture stopped.
    for name, documents in outputs.items():
        directory = out / name
        directory.mkdir()
        for label, value in documents.items():
            write_json(directory / (label + '.json'), value)
    metadata = {'assessment_id': 'reproducible-local-assessment', 'title': 'Controlled proof and selective fix verification',
                'reviewer': 'AuthzLedger synthetic fixture', 'scope': [target],
                'limitations': ['Authored synthetic import fixture; this run is not a third-party exporter certification.',
                                'A selected fix proves only the retained rule, identity, object and configured controls.']}
    first_snapshot = freeze_assessment([imported], {**metadata, 'assessment_id': 'import-to-reproducer'}, reductions=[reduced])
    snapshot = freeze_assessment([full, current], metadata, comparisons=[comparison])
    write_json(out / '01-import-to-reproducer' / 'snapshot.json', first_snapshot)
    write_json(out / '03-selective-retest-proof' / 'snapshot.json', snapshot)
    export_assessment(snapshot, out / 'reports')
    with tempfile.TemporaryDirectory(prefix='authzledger-demo-key-') as temporary:
        private = Path(temporary) / 'private.pem'
        public = out / 'trusted-public.pem'
        generate_keypair(private, public)
        create_assessment_bundle(snapshot, out / 'proof', private)
        verification = verify_bundle(out / 'proof', public)
        require(not verification, 'Signed bundle and report semantics must verify')
    for path in out.rglob('*'):
        if path.is_file():
            raw = path.read_bytes()
            require(all(value.encode() not in raw for value in forbidden_values), 'Credentials must not be exported')
    summary = {'kind': 'assessment-demo-results', 'schema_version': 1,
               'fixture': 'synthetic-loopback-only', 'network_requests': network_count,
               'import_to_finding': imported['findings'][0]['status'],
               'reduction': {'removed_units': len(reduced['accepted_removed']), 'requests': reduced['requests_used'], 'label': reduced['label']},
               'denial_leakage': leakage['findings'][0]['category'], 'invalid_controls': invalid['findings'][0]['interpretation'],
               'error_200': error200['findings'][0]['status'], 'retest': comparison['transitions'],
               'baseline_cases': len(full['report']['results']), 'retest_cases': len(current['report']['results']),
               'package_semantics_verified': True, 'private_key_retained': False,
               'offline_standalone_command': 'python tools/verify_bundle.py OUTPUT/proof --public-key OUTPUT/trusted-public.pem'}
    write_json(out / 'results.json', summary)
    return summary
