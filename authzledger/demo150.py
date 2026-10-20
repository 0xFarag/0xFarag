"""Real, bounded loopback demonstrations for the integrated assessment platform.

These authored fixtures are not captures from customer systems or comparative
scanner benchmarks. Every result is produced by the shared product services.
"""
from __future__ import annotations

import contextlib
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .assessment_demo import assessment_lab, imported_plan, require, write_json


def _scope(identifier, operations, *, max_requests=64):
    from .scope import validate_scope
    return validate_scope({
        'schema_version': 1, 'kind': 'assessment-scope', 'id': identifier,
        'authorization_ref': 'AuthzLedger-owned disposable loopback fixtures',
        'origins': sorted({op['origin'] for op in operations}),
        'operations': [dict(op, effect='read') for op in operations],
        'allowed_networks': ['127.0.0.0/8'],
        'expires_at': (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
        'limits': {'max_requests': max_requests, 'concurrency': 1,
                   'timeout_seconds': 2, 'max_response_bytes': 65536},
        'allowed_effects': ['read']})


def _contrast_scope(plan, identifier, *, max_requests=64):
    kinds = {case['id']: 'application' for case in plan['contract']['cases']}
    for variant in plan['variants']:
        kinds[variant['identity_control']] = 'identity_control'
        kinds[variant['object_control']] = 'object_control'
        kinds[variant['negative_control']] = 'negative_control'
    operations = [{'origin': plan['contract']['target'], 'method': case['method'],
                   'path': case['path'], 'purpose': kinds[case['id']]}
                  for case in plan['contract']['cases']]
    return _scope(identifier, operations, max_requests=max_requests)


def _persist(store, title, scope, documents):
    assessment = store.create(title, scope)
    for label, value in documents.items():
        store.add_artifact(assessment['id'], value['kind'], value)
    return store.get(assessment['id']), store.artifacts(assessment['id'])


def _write_documents(out, documents):
    out.mkdir()
    for label, value in documents.items():
        write_json(out / (label + '.json'), value)


def demo_authorization(out, store):
    """A: valid controls, protected content, reduction and honest counterexamples."""
    from .experiments import execute_experiment, verify_execution
    from .minimize import removable_units, plan_reduction, execute_reduction, verify_reduction
    from .scope import context_for_scope
    started = time.monotonic()
    with assessment_lab() as (target, state, resolver, values):
        batch, bindings, plan = imported_plan(target)
        scope = _contrast_scope(plan, 'demo-a-authorization')
        context = context_for_scope(scope)
        confirmed = execute_experiment(plan, context=context, credential_resolver=resolver)
        require(not verify_execution(confirmed), 'A: execution must verify')
        require(confirmed['findings'][0]['status'] == 'confirmed', 'A: BOLA fixture must confirm')
        reduced = execute_reduction(plan_reduction(confirmed, removable_units(confirmed), max_requests=40),
                                    context=context, credential_resolver=resolver)
        require(not verify_reduction(reduced), 'A: reduction must verify')
        require(reduced['one_minimal'] and reduced['accepted_removed'], 'A: bounded reduction must remove unnecessary units')
        observations = {}
        for mode in ('leak', 'invalid_controls', '200error'):
            state['mode'] = mode
            run = execute_experiment(plan, context=context, credential_resolver=resolver)
            require(not verify_execution(run), 'A: counterexample execution must verify')
            observations[mode] = run
        require(observations['leak']['findings'][0]['category'] == 'denial_data_disclosure', 'A: 403 content remains disclosure')
        require(observations['invalid_controls']['findings'][0]['interpretation'] == 'inconclusive', 'A: invalid controls must block confirmation')
        require(observations['200error']['findings'][0]['status'] == 'rejected', 'A: HTTP 200 alone is not a finding')
        requests = copy.deepcopy(state['requests'])
        ledger = context.snapshot()
        require(ledger['dispatched_total'] == len(requests), 'A: actual HTTP counter must match dispatch ledger')
        secrets = tuple(values.values())
    documents = {'import': batch, 'plan': plan, 'confirmed': confirmed, 'reduction': reduced,
                 'denial-disclosure': observations['leak'], 'invalid-controls': observations['invalid_controls'],
                 '200-error': observations['200error']}
    assessment, artifacts = _persist(store, 'A — Controlled authorization finding', scope, documents)
    _write_documents(out, documents)
    receipt = {'demo': 'A', 'assessment_id': assessment['id'], 'fixture': 'authored-loopback-two-tenant',
               'http_requests_observed': len(requests), 'network_operations_observed': len(requests),
               'execution_ledger': ledger, 'limits': scope['limits'],
               'confirmed': confirmed['findings'][0]['status'],
               'denial_disclosure': observations['leak']['findings'][0]['category'],
               'invalid_controls': observations['invalid_controls']['findings'][0]['interpretation'],
               'error_200': observations['200error']['findings'][0]['status'],
               'reduction': {'requests_used': reduced['requests_used'], 'removed_units': len(reduced['accepted_removed']),
                             'one_minimal': reduced['one_minimal'], 'label': reduced['label']},
               'elapsed_ms': round((time.monotonic() - started) * 1000, 3)}
    write_json(out / 'receipt.json', receipt)
    return receipt, assessment, artifacts, secrets


@contextlib.contextmanager
def discovery_lab():
    """Separate HTTP and banner sockets; both bind only IPv4 loopback."""
    state = {'http_requests': [], 'service_connections': 0}
    lock = threading.Lock()

    class HTTPHandler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            with lock:
                state['http_requests'].append({'method': 'GET', 'path': self.path})
            if self.path == '/':
                raw = b'<html><a href="/api/status">Status</a><a href="https://outside.invalid/private">Excluded</a></html>'
                status, kind = 200, 'text/html'
            elif self.path == '/api/status':
                raw = b'{"service":"authzledger-owned-demo","ready":true}'
                status, kind = 200, 'application/json'
            else:
                raw, status, kind = b'{"error":"missing"}', 404, 'application/json'
            self.send_response(status)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(raw)))
            # Deliberately omit the exact operator-required header in the fixture.
            self.end_headers()
            self.wfile.write(raw)

    class BannerHandler(socketserver.BaseRequestHandler):
        def handle(self):
            with lock:
                state['service_connections'] += 1
            self.request.sendall(b'SSH-2.0-AuthzLedgerFixture\r\n')

    http = ThreadingHTTPServer(('127.0.0.1', 0), HTTPHandler)
    service = socketserver.ThreadingTCPServer(('127.0.0.1', 0), BannerHandler)
    service.daemon_threads = True
    workers = [threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
               for server in (http, service)]
    for worker in workers:
        worker.start()
    try:
        yield 'http://127.0.0.1:' + str(http.server_port), service.server_address[1], state
    finally:
        for server in (http, service):
            server.shutdown()
            server.server_close()
        for worker in workers:
            worker.join(2)


def demo_discovery(out, store):
    """B: scoped service and HTTP discovery lead to a controlled profile check."""
    from .discovery import plan_discovery, execute_discovery, verify_discovery
    from .detectors import catalog, compile_check, execute_check, verify_check_execution
    from .scope import context_for_scope
    started = time.monotonic()
    with discovery_lab() as (origin, service_port, state):
        operations = [{'origin': origin, 'method': 'GET', 'path': path, 'purpose': 'discovery'}
                      for path in ('/', '/api/status')]
        operations += [{'origin': origin, 'method': 'GET', 'path': '/api/status', 'purpose': purpose}
                       for purpose in ('object_control', 'application')]
        operations += [{'origin': 'tcp://127.0.0.1:' + str(service_port), 'method': 'CONNECT', 'path': '/', 'purpose': 'service'}]
        scope = _scope('demo-b-discovery', operations, max_requests=12)
        context = context_for_scope(scope)
        plan = plan_discovery(scope, [{'kind': 'http', 'origin': origin, 'paths': ['/'], 'follow_links': True, 'max_depth': 1},
                                      {'kind': 'service', 'host': '127.0.0.1', 'ports': [service_port]}])
        require(not state['http_requests'] and state['service_connections'] == 0, 'B: planning must be offline')
        discovery = execute_discovery(plan, context=context)
        require(not verify_discovery(discovery), 'B: discovery must verify')
        require(any(o['path'] == '/api/status' and o['state'] == 'responded' for o in discovery['observations']), 'B: scoped link must actually be visited')
        require(any(o['purpose'] == 'service' and o['state'] == 'open' for o in discovery['observations']), 'B: service must actually be connected')
        registry = catalog()
        check_id = 'misconfig.security_headers'
        require(check_id in registry['profiles']['web-quick'], 'B: selected check must belong to declared profile')
        spec = {'schema_version': 1, 'kind': 'check-spec', 'id': 'demo-b-required-headers',
                'check_id': check_id, 'version': '1.0.0', 'source_refs': [discovery['execution_digest']],
                'contract': {'version': 1, 'name': 'Explicit response header requirement', 'target': origin,
                             'identities': {'anonymous': {'headers': {}}},
                             'limits': {'max_requests': 2, 'concurrency': 1, 'timeout_seconds': 2, 'max_response_bytes': 65536},
                             'cases': [{'id': 'baseline', 'identity': 'anonymous', 'method': 'GET', 'path': '/api/status', 'expect': {'status': [200]}},
                                       {'id': 'probe', 'identity': 'anonymous', 'method': 'GET', 'path': '/api/status', 'requires': ['baseline'], 'expect': {'status': [200]}}]},
                'controls': ['baseline'], 'target_case': 'probe', 'params': {'required_headers': ['x-content-type-options']}}
        check_plan = compile_check(spec, scope)
        execution = execute_check(check_plan, context=context)
        require(not verify_check_execution(execution), 'B: controlled check must verify')
        require(execution['findings'][0]['status'] == 'confirmed', 'B: exact configured header omission must confirm')
        http_count, service_count = len(state['http_requests']), state['service_connections']
        ledger = context.snapshot()
        require(ledger['dispatched_total'] == http_count + service_count, 'B: service plus HTTP counters must match shared ledger')
        require(all(row['path'] in {'/', '/api/status'} for row in state['http_requests']), 'B: no unapproved link may be fetched')
    documents = {'discovery-plan': plan, 'discovery': discovery, 'check-plan': check_plan, 'check-execution': execution}
    assessment, artifacts = _persist(store, 'B — Discovery to controlled configuration evidence', scope, documents)
    _write_documents(out, documents)
    receipt = {'demo': 'B', 'assessment_id': assessment['id'], 'fixture': 'authored-loopback-http-and-banner',
               'http_requests_observed': http_count, 'service_connections_observed': service_count,
               'network_operations_observed': http_count + service_count,
               'execution_ledger': ledger, 'limits': scope['limits'], 'profile': 'web-quick',
               'selected_checks': [check_id], 'profile_registry_digest': registry['registry_digest'],
               'discovery_coverage': discovery['coverage'], 'finding_status': execution['findings'][0]['status'],
               'finding_claim': 'The explicitly required response header is absent; no exploitability claim.',
               'elapsed_ms': round((time.monotonic() - started) * 1000, 3)}
    write_json(out / 'receipt.json', receipt)
    return receipt, assessment, artifacts


def demo_retest(out, store):
    """C: preserve the original source while proving only the selected fix."""
    from .experiments import execute_experiment, verify_execution, plan_experiment_retest, compare_executions
    from .scope import context_for_scope
    started = time.monotonic()
    with assessment_lab() as (target, state, resolver, values):
        plan = imported_plan(target, variants=2)[2]
        scope = _contrast_scope(plan, 'demo-c-selective-retest', max_requests=20)
        context = context_for_scope(scope)
        state['mode'] = 'leak'
        baseline = execute_experiment(plan, context=context, credential_resolver=resolver)
        before = copy.deepcopy(baseline)
        retest_plan = plan_experiment_retest(baseline, ['peer-1'])
        state['mode'] = 'fixed'
        current = execute_experiment(retest_plan, context=context, credential_resolver=resolver)
        require(not verify_execution(baseline) and not verify_execution(current), 'C: both original and new executions must verify')
        comparison = compare_executions(baseline, current)
        require([t['status'] for t in comparison['transitions']] == ['fix_verified', 'not_retested'], 'C: omitted finding must remain not_retested')
        require(baseline == before, 'C: original evidence must not change')
        observed = len(state['requests'])
        ledger = context.snapshot()
        require(ledger['dispatched_total'] == observed, 'C: actual counter must match shared budget')
        secrets = tuple(values.values())
    documents = {'baseline': baseline, 'retest-plan': retest_plan, 'current': current, 'comparison': comparison}
    assessment, artifacts = _persist(store, 'C — Selective fix proof with explicit omitted coverage', scope, documents)
    _write_documents(out, documents)
    receipt = {'demo': 'C', 'assessment_id': assessment['id'], 'fixture': 'authored-loopback-two-tenant',
               'http_requests_observed': observed, 'network_operations_observed': observed,
               'execution_ledger': ledger, 'limits': scope['limits'],
               'baseline_cases': len(baseline['report']['results']), 'current_cases': len(current['report']['results']),
               'transitions': comparison['transitions'], 'original_evidence_preserved': baseline == before,
               'elapsed_ms': round((time.monotonic() - started) * 1000, 3)}
    write_json(out / 'receipt.json', receipt)
    return receipt, assessment, artifacts, comparison, secrets


def _standalone_script(explicit):
    candidates = [Path(explicit)] if explicit is not None else [
        Path(__file__).with_name('verify_bundle_standalone.py'),
        Path(__file__).resolve().parents[1] / 'tools' / 'verify_bundle.py']
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return candidate.resolve()
    raise ValueError('Independent verifier file required; pass standalone_verifier explicitly.')


def _standalone(verifier, bundle, public):
    result = subprocess.run([sys.executable, '-I', str(verifier), str(bundle.resolve()), '--public-key', str(public.resolve())],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    return {'returncode': result.returncode, 'stdout': result.stdout.decode('utf-8', 'replace')[-4000:],
            'stderr': result.stderr.decode('utf-8', 'replace')[-4000:]}


def run_demos(out, *, standalone_verifier=None, formats=('json', 'html', 'pdf')):
    """Run all real fixtures, then verify original and byte-tampered packages offline."""
    from . import __version__
    from .workbench import WorkbenchStore
    from .platform_reports import freeze_platform, verify_platform, export_platform, create_platform_bundle
    from .signing import generate_keypair, verify_bundle
    verifier = _standalone_script(standalone_verifier)
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    started_at = datetime.now(timezone.utc).isoformat()
    started = time.monotonic()
    database = out / 'assessment-workspace.sqlite3'
    with WorkbenchStore(database) as store:
        a, assessment_a, artifacts_a, secrets_a = demo_authorization(out / 'A-authorization', store)
        b, assessment_b, artifacts_b = demo_discovery(out / 'B-discovery-detect', store)
        c, assessment_c, artifacts_c, comparison, secrets_c = demo_retest(out / 'C-retest-proof', store)
        saved_ids = sorted(item['id'] for item in store.list())
    with WorkbenchStore(database) as reopened:
        require(sorted(item['id'] for item in reopened.list()) == saved_ids, 'Assessments must persist across close/reopen')
        require(all(reopened.artifacts(aid) for aid in saved_ids), 'Persisted evidence chain must verify after reopen')
    # All fixture listeners have stopped before freezing, signing or verifying.
    snapshots = {
        'A-authorization': freeze_platform(assessment_a, artifacts_a),
        'B-discovery-detect': freeze_platform(assessment_b, artifacts_b),
        'C-retest-proof': freeze_platform(assessment_c, artifacts_c)}
    for name, snapshot in snapshots.items():
        require(not verify_platform(snapshot), name + ': platform snapshot must verify')
        write_json(out / name / 'snapshot.json', snapshot)
        export_platform(snapshot, out / name / 'reports', formats=formats)
    public = out / 'trusted-public.pem'
    proof = out / 'C-retest-proof' / 'proof'
    with tempfile.TemporaryDirectory(prefix='authzledger-platform-demo-key-') as temporary:
        private = Path(temporary) / 'operator-private.pem'
        generate_keypair(private, public)
        create_platform_bundle(snapshots['C-retest-proof'], proof, private, formats=formats)
        main_errors = verify_bundle(proof, public)
        require(not main_errors, 'C: main package verifier must pass')
        standalone = _standalone(verifier, proof, public)
        require(standalone['returncode'] == 0, 'C: isolated standalone verifier must pass')
    tampered = out / 'C-retest-proof' / 'tampered-proof'
    shutil.copytree(proof, tampered)
    victim = tampered / 'report.json'
    original = victim.read_bytes()
    require(bool(original), 'C: tamper target must contain signed bytes')
    mutated = bytearray(original)
    mutated[-1] ^= 1
    victim.write_bytes(mutated)
    require(sum(a != b for a, b in zip(original, mutated)) == 1, 'C: exactly one byte must change')
    tamper_errors = verify_bundle(tampered, public)
    tamper_standalone = _standalone(verifier, tampered, public)
    require(bool(tamper_errors) and tamper_standalone['returncode'] != 0, 'C: both verifiers must reject changed bytes')
    require(not verify_bundle(proof, public), 'C: untampered original must remain valid')
    for path in out.rglob('*'):
        if path.is_file():
            raw = path.read_bytes()
            require(all(secret.encode() not in raw for secret in (*secrets_a, *secrets_c)), 'Runtime credentials must not be persisted or exported')
            require(b'PRIVATE KEY-----' not in raw, 'Private signing key must not be retained')
    receipt = {'schema_version': 1, 'kind': 'platform-demo-results', 'producer_version': __version__,
               'started_at': started_at, 'completed_at': datetime.now(timezone.utc).isoformat(),
               'elapsed_ms': round((time.monotonic() - started) * 1000, 3),
               'runtime': {'python': platform.python_version(), 'implementation': platform.python_implementation(), 'system': platform.system()},
               'fixture': 'authored-loopback-only', 'demos': {'A': a, 'B': b, 'C': c},
               'total_http_requests_observed': sum(item['http_requests_observed'] for item in (a, b, c)),
               'total_service_connections_observed': b['service_connections_observed'],
               'total_network_operations_observed': sum(item['network_operations_observed'] for item in (a, b, c)),
               'workspace_reopened': True, 'fixture_stopped_before_export': True,
               'main_verifier_errors': main_errors, 'standalone_verification': standalone,
               'standalone_verifier_sha256': hashlib.sha256(verifier.read_bytes()).hexdigest(),
               'tamper': {'changed_bytes': 1, 'relative_path': 'report.json',
                          'original_sha256': hashlib.sha256(original).hexdigest(), 'tampered_sha256': hashlib.sha256(mutated).hexdigest(),
                          'main_errors': tamper_errors, 'standalone': tamper_standalone},
               'private_key_retained': False,
               'limitations': ['Authored synthetic fixtures are not native exporter certification or production findings.',
                               'Measured timings describe this runtime only; no competing-product benchmark was run.',
                               'A missing configured header is a narrow configuration finding, not proof of exploitability.',
                               'Signatures establish byte integrity and key possession, not remote execution truth.']}
    write_json(out / 'results.json', receipt)
    return receipt
