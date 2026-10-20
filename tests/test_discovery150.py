"""Real loopback discovery, explicit boundaries and honest passive evidence."""
import copy
import json
import socket
import threading
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from authzledger.discovery import (DiscoveryError, execute_discovery, plan_discovery,
                                   verify_discovery, verify_discovery_plan)
from authzledger.imports import parse_import
from authzledger.oracles import seal
from authzledger.scope import context_for_scope
from authzledger.surface import (SurfaceError, build_catalog, candidate_experiments,
    diff_catalogs, merge_catalogs, plan_delta_checks, verify_candidates, verify_catalog,
    verify_surface_delta, verify_delta_check_plan)


def scope(origins, operations, budget=20):
    return {'schema_version': 1, 'kind': 'assessment-scope', 'id': 'lab',
        'authorization_ref': 'owned-loopback-fixture', 'origins': origins,
        'operations': operations, 'allowed_networks': ['127.0.0.0/8'],
        'expires_at': (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        'allowed_effects': ['read'], 'limits': {'max_requests': budget, 'concurrency': 2,
        'timeout_seconds': 1, 'max_response_bytes': 4096}}


def batch(path='/objects/12', label='one'):
    return parse_import(json.dumps({'log': {'version': '1.2', 'entries': [{
        'request': {'method': 'GET', 'url': 'https://api.example.test' + path,
                    'httpVersion': 'HTTP/1.1', 'headers': [{'name': 'Authorization', 'value': 'Bearer ' + label}]},
        'response': {'status': 200}}]}}).encode(), 'har-1.2')


@contextmanager
def webfixture():
    requests = []
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            requests.append(self.path)
            body = (b'<a href="/api">API</a><a href="/never?token=DO_NOT_RETAIN">x</a>'
                    b'<a href="http://outside.invalid/private">outside</a> BODY_PRIVATE_SECRET') if self.path == '/' else b'{"public":true}'
            self.send_response(200)
            self.send_header('Server', 'nginx/1.24.0 private-secret')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield 'http://127.0.0.1:' + str(server.server_port), requests
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)


class SurfaceTests(unittest.TestCase):
    def test_offline_import_dedup_provenance_and_no_identity_inference(self):
        first = batch()
        second = copy.deepcopy(first)
        # Another supported exporter records the same operation independently.
        second = parse_import(b'GET /objects/12 HTTP/1.1\r\nHost: api.example.test\r\n\r\n',
                              'burp-http-pair-v1', source_origin='https://api.example.test')
        with patch.object(socket, 'socket', side_effect=AssertionError('network')), patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS')):
            catalog = build_catalog([first, second, first])
        self.assertEqual(len(catalog['endpoints']), 1)
        ep = catalog['endpoints'][0]
        self.assertEqual(len(ep['source_refs']), 2)
        self.assertEqual(ep['owner'], 'unknown')
        self.assertEqual(ep['identity'], 'unknown')
        self.assertEqual(ep['coverage'], 'not_tested')
        self.assertEqual(verify_catalog(catalog), [])
        candidates = candidate_experiments(catalog)
        self.assertEqual(verify_candidates(candidates), [])
        self.assertTrue(all(not c['executable'] and c['evidence_level'] == 'hint' for c in candidates['candidates']))
        self.assertIn('owner_binding_required', next(c for c in candidates['candidates'] if c['family'] == 'authz')['blockers'])
        self.assertNotIn('Bearer', json.dumps(catalog))

    def test_openapi_is_declaration_without_server_authorization_or_raw_examples(self):
        document = {'openapi': '3.0.3', 'info': {'title': 'PRIVATE_LABEL', 'version': '1'},
            'servers': [{'url': 'http://outside.invalid'}], 'paths': {'/items/{id}': {
            'get': {'parameters': [{'name': 'id', 'in': 'path', 'required': True, 'schema': {'type': 'integer'}}]}}}}
        c = build_catalog([], declarations=[{'origin': 'https://api.example.test', 'openapi': document}])
        serialized = json.dumps(c)
        self.assertNotIn('outside.invalid', serialized)
        self.assertNotIn('PRIVATE_LABEL', serialized)
        self.assertIn('explicit_fixture_values_required', c['endpoints'][0]['execution_blockers'])
        self.assertEqual(verify_catalog(c), [])

    def test_forged_import_and_catalog_projection_rejected(self):
        source = batch()
        source['entries'][0]['origin'] = 'https://other.example.test'
        with self.assertRaisesRegex(SurfaceError, 'import_digest_mismatch'):
            build_catalog([source])
        c = build_catalog([batch()])
        c['endpoints'][0]['owner'] = 'guessed'
        c = seal('surface-catalog', c, 'catalog_digest')
        self.assertTrue(verify_catalog(c))

    def test_delta_missing_is_not_observed_and_never_fixed(self):
        before = build_catalog([batch()]); after = build_catalog([])
        result = diff_catalogs(before, after)
        self.assertEqual(result['transitions'][0]['transition'], 'not_observed')
        self.assertEqual(result['transitions'][0]['retest_status'], 'not_retested')
        self.assertEqual(verify_surface_delta(result), [])

    def test_merge_retains_exact_source_refs_without_refreshing_them(self):
        a, b = build_catalog([batch()]), build_catalog([batch('/other')])
        merged = merge_catalogs([a, b, a])
        self.assertEqual(len(merged['endpoints']), 2)
        self.assertEqual(verify_catalog(merged), [])
        self.assertEqual(merged['observations'], sorted(a['observations'] + b['observations'], key=lambda value: json.dumps(value,sort_keys=True,separators=(',',':'))))

    def test_delta_selection_closure_and_unknown_fallback(self):
        before = build_catalog([batch()]); after = build_catalog([])
        delta = diff_catalogs(before, after)
        eid = before['endpoints'][0]['endpoint_id']; aid = before['assets'][0]['asset_id']
        checks = [{'check_id': 'check', 'endpoint_ids': [eid], 'asset_ids': [aid], 'requires': ['control'], 'dependencies_complete': True},
                  {'check_id': 'control', 'endpoint_ids': [eid], 'asset_ids': [aid], 'requires': [], 'dependencies_complete': True}]
        plan = plan_delta_checks(delta, checks)
        self.assertEqual(plan['selected_check_ids'], ['check', 'control'])
        self.assertEqual(plan['all_checks_current_retest_status'], 'not_retested')
        self.assertEqual(verify_delta_check_plan(plan), [])
        checks.append({'check_id': 'unknown', 'endpoint_ids': [], 'asset_ids': [], 'requires': [], 'dependencies_complete': False})
        plan = plan_delta_checks(delta, checks)
        self.assertEqual(plan['selected_check_ids'], ['check', 'control', 'unknown'])
        self.assertIn('unknown', plan['unknown_dependencies'])


class DiscoveryTests(unittest.TestCase):
    def http_scope(self, origin, paths=('/', '/api'), budget=20):
        return scope([origin], [{'origin': origin, 'method': 'GET', 'path': p, 'purpose': 'discovery'} for p in paths], budget)

    def test_plan_is_offline_exact_and_out_of_scope_rejected(self):
        origin = 'http://127.0.0.1:8080'; policy = self.http_scope(origin)
        with patch.object(socket, 'socket', side_effect=AssertionError('network')), patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS')):
            plan = plan_discovery(policy, [{'origin': origin, 'paths': ['/']}])
            self.assertEqual(verify_discovery_plan(plan), [])
            with self.assertRaisesRegex(DiscoveryError, 'outside_scope'):
                plan_discovery(policy, [{'origin': origin, 'paths': ['/outside']}])
        plan['seeds'][0]['paths'] = ['/outside']
        self.assertTrue(verify_discovery_plan(plan))

    def test_real_crawl_uses_engine_and_same_budget_without_secret_capture(self):
        with webfixture() as (origin, requests):
            plan = plan_discovery(self.http_scope(origin), [{'origin': origin, 'paths': ['/'], 'follow_links': True, 'max_depth': 1}])
            result = execute_discovery(plan)
        self.assertEqual(requests, ['/', '/api'])
        self.assertEqual(result['coverage']['dispatched_requests'], 2)
        self.assertEqual(result['ledger']['by_kind']['discovery'], 2)
        self.assertEqual(len(result['catalog']['endpoints']), 2)
        self.assertEqual(verify_discovery(result), [])
        serialized = json.dumps(result)
        for secret in ['DO_NOT_RETAIN', 'BODY_PRIVATE_SECRET', 'outside.invalid', 'private-secret']:
            self.assertNotIn(secret, serialized)
        self.assertEqual(result['observations'][0]['projection']['excluded_link_count'], 2)
        altered = copy.deepcopy(result)
        altered['ledger']['dispatched_total'] = 0
        altered['coverage']['dispatched_requests'] = 0
        altered = seal('discovery-execution', altered, 'execution_digest')
        self.assertEqual(verify_discovery(altered), ['discovery_ledger_summary_mismatch'])

    def test_global_budget_partial_coverage_and_cancel_do_not_send(self):
        with webfixture() as (origin, requests):
            plan = plan_discovery(self.http_scope(origin, budget=1), [{'origin': origin, 'paths': ['/'], 'follow_links': True, 'max_depth': 1}])
            result = execute_discovery(plan)
            self.assertEqual(requests, ['/'])
            self.assertEqual(len(result['coverage']['not_visited_ids']), 1)
            self.assertEqual(verify_discovery(result), [])
            context = context_for_scope(plan['scope']); context.cancel()
            stopped = execute_discovery(plan, context=context)
            self.assertEqual(requests, ['/'])
            self.assertEqual(stopped['coverage']['dispatched_requests'], 0)
            self.assertEqual(stopped['observations'][0]['state'], 'blocked')
            self.assertEqual(verify_discovery(stopped), [])

    def test_service_probe_is_one_budgeted_connection_and_numeric_hint(self):
        server = socket.socket(); server.bind(('127.0.0.1', 0)); server.listen(1)
        port = server.getsockname()[1]; accepted = []
        def serve():
            conn, _ = server.accept(); accepted.append(True)
            with conn:
                conn.sendall(b'SSH-2.0-OpenSSH_9.7 PRIVATE_BANNER_SECRET\r\n')
        thread = threading.Thread(target=serve, daemon=True); thread.start()
        origin = 'tcp://127.0.0.1:' + str(port)
        policy = scope([origin], [{'origin': origin, 'method': 'CONNECT', 'path': '/', 'purpose': 'service'}], 1)
        try:
            result = execute_discovery(plan_discovery(policy, [{'kind': 'service', 'host': '127.0.0.1', 'ports': [port]}]))
        finally:
            server.close(); thread.join(timeout=2)
        self.assertEqual(accepted, [True])
        self.assertEqual(result['coverage']['dispatched_requests'], 1)
        self.assertEqual(result['observations'][0]['probe']['state'], 'open')
        self.assertNotIn('PRIVATE_BANNER_SECRET', json.dumps(result))
        self.assertEqual(verify_discovery(result), [])

    def test_expired_historical_plan_remains_verifiable_but_execution_refused(self):
        origin = 'http://127.0.0.1:8080'; policy = self.http_scope(origin)
        policy['expires_at'] = '2000-01-01T00:00:00Z'
        plan = plan_discovery(policy, [{'origin': origin, 'paths': ['/']}])
        self.assertEqual(verify_discovery_plan(plan), [])
        with self.assertRaisesRegex(ValueError, 'authorization-expired'):
            execute_discovery(plan)


if __name__ == '__main__':
    unittest.main()
