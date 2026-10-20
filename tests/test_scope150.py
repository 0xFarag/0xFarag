"""Scope enforcement at actual dispatch and socket boundaries, including regressions."""
import copy
import json
import socket
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from authzledger.engine import run
from authzledger.execution import ExecutionContext, ExecutionError
from authzledger.scope import (ScopeError, BoundSocketPolicy, canonical_origin, context_for_scope,
                              probe_service, validate_scope, verify_scope, _resolve_addresses)


def scope(origin='http://127.0.0.1:8080', operations=None, **changes):
    result = {'schema_version': 1, 'kind': 'assessment-scope', 'id': 'test-scope',
              'authorization_ref': 'local-fixture-owner', 'origins': [origin],
              'operations': operations or [{'origin': origin, 'method': 'GET', 'path': '/', 'purpose': 'application'}],
              'allowed_networks': ['127.0.0.0/8'], 'expires_at': (datetime.now(timezone.utc)+timedelta(minutes=5)).isoformat(),
              'limits': {'max_requests': 8, 'concurrency': 2, 'timeout_seconds': 1, 'max_response_bytes': 4096},
              'allowed_effects': ['read']}
    result.update(changes)
    return result


def contract(origin, path='/'):
    return {'version': 1, 'name': 'scope-test', 'target': origin,
            'identities': {'anon': {'headers': {}}},
            'limits': {'max_requests': 8, 'timeout_seconds': 1, 'max_response_bytes': 4096, 'concurrency': 1},
            'cases': [{'id': 'probe', 'identity': 'anon', 'method': 'GET', 'path': path, 'expect': {'status': [200]}}]}


class Scope150Tests(unittest.TestCase):
    def test_normalized_digest_and_historical_expiry(self):
        value = scope(expires_at='2020-01-01T00:00:00Z')
        normalized = validate_scope(value)
        self.assertEqual(verify_scope(normalized), [])
        self.assertEqual(validate_scope(normalized), normalized)
        with self.assertRaisesRegex(ExecutionError, 'authorization-expired'):
            context_for_scope(normalized)
        normalized['authorization_ref'] = 'different'
        self.assertTrue(verify_scope(normalized))

    def test_missing_network_boundary_rejected(self):
        for networks in ([], ['127.0.0.1'], ['127.0.0.1/8']):
            with self.assertRaises(ScopeError):
                validate_scope(scope(allowed_networks=networks))

    def test_composite_operations_cannot_cross_origins(self):
        a, b = 'http://127.0.0.1:8001', 'http://127.0.0.1:8002'
        ctx = context_for_scope(scope(a, origins=[a, b], operations=[
            {'origin': a, 'method': 'GET', 'path': '/a', 'purpose': 'application'},
            {'origin': b, 'method': 'GET', 'path': '/b', 'purpose': 'application'}]))
        for origin, path in ((a, '/b'), (b, '/a')):
            with self.assertRaisesRegex(ExecutionError, 'operation-outside-scope'):
                ctx.reserve(kind='application', operation_id='denied', target_origin=origin, method='GET', path=path)
        self.assertEqual(ctx.snapshot()['dispatched_total'], 0)
        r = ctx.reserve(kind='application', operation_id='allowed', target_origin=a, method='GET', path='/a')
        ctx.dispatch(r, lambda: None)
        self.assertEqual(ctx.snapshot()['dispatched_total'], 1)

    def test_legacy_three_field_operations_preserved(self):
        ctx = ExecutionContext(1, ['http://127.0.0.1'], 1, 1, approved_operations=[('application', 'GET', '/')])
        r = ctx.reserve(kind='application', operation_id='legacy', target_origin='http://127.0.0.1', method='GET', path='/')
        ctx.dispatch(r, lambda: None)
        self.assertEqual(ctx.snapshot()['dispatched_total'], 1)

    def test_expiry_after_reservation_blocks_before_dispatch(self):
        ctx = context_for_scope(scope())
        r = ctx.reserve(kind='application', operation_id='reserved', target_origin='http://127.0.0.1:8080', method='GET', path='/')
        with patch('authzledger.scope.time.time', return_value=time.time()+3600):
            with self.assertRaisesRegex(ExecutionError, 'authorization-expired'):
                ctx.dispatch(r, lambda: self.fail('dispatched expired authorization'))
        self.assertEqual(ctx.snapshot()['dispatched_total'], 0)
        self.assertEqual(ctx.snapshot()['reserved_pending'], 0)

    def test_scope_limits_cannot_expand(self):
        value = validate_scope(scope())
        with self.assertRaises(ScopeError): context_for_scope(value, max_requests=9)
        with self.assertRaises(ExecutionError):
            ExecutionContext(9, value['origins'], 1, 1, scope_policy=value)
        self.assertEqual(context_for_scope(value, max_requests=2).max_requests, 2)

    def test_side_effect_authorization_and_ambiguous_paths(self):
        origin = 'http://127.0.0.1:8080'
        for path in ('//other/x', '/%2fadmin', '/a/../b', '/%252fadmin'):
            with self.assertRaises(ValueError):
                validate_scope(scope(operations=[{'origin': origin, 'method': 'GET', 'path': path, 'purpose': 'application'}]))
        with self.assertRaises(ScopeError):
            validate_scope(scope(operations=[{'origin': origin, 'method': 'GET', 'path': '/', 'purpose': 'application', 'effect': 'mutate'}]))

    def test_service_origin_is_typed_and_port_preserved(self):
        self.assertEqual(canonical_origin('tcp://localhost:80'), 'tcp://localhost:80')
        self.assertEqual(canonical_origin('tcp://[::1]:443'), 'tcp://[::1]:443')
        for origin in ('tcp://localhost', 'tcp://user:secret@localhost:22', 'tcp://localhost:22/path'):
            with self.assertRaises(ValueError): canonical_origin(origin)

    def test_dns_mixed_answers_all_checked_before_connect(self):
        origin = 'http://example.test:8080'
        ctx = context_for_scope(scope(origin))
        values = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 8080)),
                  (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.4', 8080))]
        with patch('authzledger.scope._resolve_addresses', return_value=values), patch('socket.socket') as connect:
            with self.assertRaisesRegex(ExecutionError, 'resolved-address-outside-scope'):
                ctx.connection_policy(origin).resolve('example.test', 8080, time.monotonic()+1)
            connect.assert_not_called()

    def test_dns_resolves_each_connection_and_pins_only_one_candidate(self):
        origin = 'http://example.test:8080'
        ctx = context_for_scope(scope(origin))
        values = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 8080)),
                  (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.2', 8080))]
        with patch('authzledger.scope._resolve_addresses', return_value=values) as resolve:
            self.assertEqual(ctx.connection_policy(origin).resolve('example.test', 8080, time.monotonic()+1), values[:1])
            ctx.connection_policy(origin).resolve('example.test', 8080, time.monotonic()+1)
            self.assertEqual(resolve.call_count, 2)
        with self.assertRaisesRegex(ExecutionError, 'transport-target-mismatch'):
            ctx.connection_policy(origin).resolve('other.test', 8080, time.monotonic()+1)

    def test_deny_cidr_and_mapped_ipv4_cannot_escape(self):
        origin = 'http://example.test:8080'
        ctx = context_for_scope(scope(origin, denied_networks=['127.0.0.2/32']))
        for address in ('127.0.0.2', '::ffff:192.0.2.2'):
            family = socket.AF_INET6 if ':' in address else socket.AF_INET
            destination = (address, 8080, 0, 0) if family == socket.AF_INET6 else (address, 8080)
            with patch('authzledger.scope._resolve_addresses', return_value=[(family, socket.SOCK_STREAM, 6, '', destination)]):
                with self.assertRaises(ExecutionError):
                    ctx.connection_policy(origin).resolve('example.test', 8080, time.monotonic()+1)

    def test_literal_resolution_never_uses_subprocess(self):
        with patch('subprocess.Popen') as process:
            addresses = _resolve_addresses('127.0.0.1', 80, time.monotonic()+1)
            self.assertEqual(addresses[0][4], ('127.0.0.1', 80))
            process.assert_not_called()

    def test_dns_subprocess_deadline_kills_and_reaps(self):
        import subprocess
        with patch('subprocess.Popen') as popen:
            process = popen.return_value
            process.communicate.side_effect = [subprocess.TimeoutExpired('resolver', 1), (b'', None)]
            with self.assertRaises(TimeoutError): _resolve_addresses('example.test', 80, time.monotonic()+.01)
            process.kill.assert_called_once()
            self.assertEqual(process.communicate.call_count, 2)

    def test_http_actual_pinned_request_and_no_redirect(self):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                seen.append(self.path)
                self.send_response(302 if self.path == '/redirect' else 200)
                if self.path == '/redirect': self.send_header('Location', '/forbidden')
                self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'{}')
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        origin = 'http://127.0.0.1:' + str(server.server_port)
        try:
            for path in ('/', '/redirect'):
                ctx = context_for_scope(scope(origin, operations=[{'origin': origin, 'method': 'GET', 'path': path, 'purpose': 'application'}]))
                result = run(contract(origin, path), context=ctx)
                self.assertEqual(result['results'][0]['outcome'], 'pass' if path == '/' else 'error')
                self.assertEqual(ctx.snapshot()['dispatched_total'], 1)
            self.assertEqual(seen, ['/', '/redirect'])
        finally:
            server.shutdown(); server.server_close(); thread.join()

    def test_http_scope_ip_denial_performs_no_connection(self):
        origin = 'http://127.0.0.1:9999'
        ctx = context_for_scope(scope(origin, allowed_networks=['192.0.2.0/24']))
        with patch('socket.socket') as sock:
            result = run(contract(origin), context=ctx)
            sock.assert_not_called()
        self.assertEqual(result['results'][0]['outcome'], 'error')
        self.assertIn('resolved-address-outside-scope', result['results'][0]['reason'])
        self.assertEqual(ctx.snapshot()['dispatched_total'], 1)

    def test_explicit_cleanup_still_connects_after_cancel_but_never_after_expiry(self):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                seen.append(self.path)
                self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'{}')
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .01}, daemon=True); thread.start()
        origin = 'http://127.0.0.1:' + str(server.server_port)
        try:
            policy = scope(origin, operations=[{'origin': origin, 'method': 'GET', 'path': '/', 'purpose': 'cleanup'}])
            ctx = context_for_scope(policy, cleanup_reserve=2, allow_cleanup_after_cancel=True)
            ctx.cancel()
            result = run(contract(origin), context=ctx, request_kind='cleanup')
            self.assertEqual(result['results'][0]['outcome'], 'pass')
            with patch('authzledger.scope.time.time', return_value=time.time()+3600):
                expired = run(contract(origin), context=ctx, request_kind='cleanup')
            self.assertEqual(expired['results'][0]['outcome'], 'inconclusive')
            self.assertIn('authorization-expired', expired['results'][0]['reason'])
            self.assertEqual(seen, ['/'])
        finally:
            server.shutdown(); server.server_close(); thread.join(2)

    def test_one_tcp_connection_counts_banner_without_exposing_contents(self):
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen()
        accepted = []
        def serve():
            conn, addr = listener.accept(); accepted.append(addr)
            with conn: conn.sendall(b'SSH-2.0-OpenSSH_9.9 private-secret-canary\r\n')
        thread = threading.Thread(target=serve, daemon=True); thread.start()
        origin = 'tcp://127.0.0.1:' + str(listener.getsockname()[1])
        value = scope(origin, operations=[{'origin': origin, 'purpose': 'service', 'method': 'CONNECT', 'path': '/'}])
        try:
            ctx = context_for_scope(value, max_requests=1)
            result = probe_service(ctx, origin)
            self.assertEqual(result['state'], 'open'); self.assertEqual(result['protocol_hint'], 'ssh')
            self.assertEqual(result['version_hint'], '2.0'); self.assertNotIn('private-secret-canary', json.dumps(result))
            self.assertEqual(ctx.snapshot()['dispatched_total'], 1)
            self.assertEqual(probe_service(ctx, origin)['error_code'], 'request-budget')
            self.assertEqual(len(accepted), 1)
        finally:
            listener.close(); thread.join(1)

    def test_cancel_prevents_service_connection(self):
        origin = 'tcp://127.0.0.1:65000'
        ctx = context_for_scope(scope(origin, operations=[{'origin': origin, 'purpose': 'service', 'method': 'CONNECT', 'path': '/'}]))
        ctx.cancel()
        with patch('socket.socket') as sock:
            result = probe_service(ctx, origin)
            self.assertEqual(result['error_code'], 'cancelled'); sock.assert_not_called()
        self.assertEqual(ctx.snapshot()['dispatched_total'], 0)


if __name__ == '__main__': unittest.main()
