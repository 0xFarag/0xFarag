"""The public CLI and the authenticated Studio endpoint share one offline projection."""
import base64
import contextlib
import hashlib
import http.client
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path

from authzledger.cli import main
from authzledger.studio import StudioServer


class FederationEntrypointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.store = Path(cls.directory.name) / 'assessment.sqlite'
        cls.server = StudioServer(history_path=cls.store)
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={'poll_interval': 0.01}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)
        cls.directory.cleanup()

    def request(self, body, authenticated=True, operation='federation-preview'):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=10)
        headers = {'Content-Type': 'application/json', 'Origin': self.server.origin}
        if authenticated:
            headers['Authorization'] = 'Bearer ' + self.server.token
        try:
            conn.request('POST', '/api/platform/' + operation, json.dumps(body), headers)
            response = conn.getresponse()
            return response.status, json.loads(response.read())
        finally:
            conn.close()

    def test_cli_and_studio_use_exact_bytes_and_equal_projections(self):
        before = self.server.workbench.list()
        scope = 'tcp://192.0.2.10:443'
        raw = b'{\r\n"results": [{"url":"https://192.0.2.10/docs","status":200,"length":3}]}\r\n'
        body = {'allowed_services': [scope], 'sources': {'ffuf': base64.b64encode(raw).decode('ascii')}}
        status, result = self.request(body)
        self.assertEqual(status, 200, result)
        self.assertEqual(result['receipts'][0]['sha256'], hashlib.sha256(raw).hexdigest())
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(io.StringIO()):
            path = Path(directory) / 'private-case-name.json'
            path.write_bytes(raw)
            out = Path(directory) / 'graph.json'
            args = ['assessment', 'federation-preview', '--scope-service', scope, '--ffuf', str(path), '--out', str(out)]
            self.assertEqual(main(args), 0)
            self.assertEqual(result, json.loads(out.read_text()))
            self.assertNotIn(path.name, out.read_text())
            self.assertEqual(main(args), 2)
            self.assertEqual(result, json.loads(out.read_text()))
            with contextlib.redirect_stdout(io.StringIO()) as repeated_stdout:
                self.assertEqual(main(['assessment', 'federation-preview', '--scope-service', scope, '--ffuf', str(path),
                                       '--ffuf', str(path)]), 2)
            self.assertFalse(repeated_stdout.getvalue())
        self.assertEqual(self.server.workbench.list(), before)

    def test_cli_and_studio_retention_bind_reviewed_bytes_revision_and_consent(self):
        service = 'tcp://192.0.2.10:443'
        scope = {'schema_version': 1, 'kind': 'assessment-scope', 'id': 'federation-scope', 'authorization_ref': 'fixture',
                 'origins': [service], 'operations': [{'origin': service, 'purpose': 'service', 'method': 'CONNECT', 'path': '/'}],
                 'allowed_networks': ['192.0.2.10/32'], 'expires_at': '2028-01-01T00:00:00Z', 'allowed_effects': ['read'],
                 'limits': {'max_requests': 1, 'concurrency': 1, 'timeout_seconds': 1, 'max_response_bytes': 100}}
        raw = b'{"results":[{"url":"https://192.0.2.10/private-case-path","status":200,"length":12}]}'
        common = {'allowed_services': [service], 'sources': {'ffuf': base64.b64encode(raw).decode('ascii')}}
        status, reviewed = self.request({**common, 'with_review': True})
        self.assertEqual(status, 200, reviewed)
        workspace = self.server.workbench.create('Scoped receipt test', scope)
        payload = {**common, 'assessment_id': workspace['id'], 'preview_digest': reviewed['preview_digest'],
                   'expected_revision': workspace['revision'], 'release_sources': True}
        for patch in ({'expected_revision': None}, {'expected_revision': 999}, {'release_sources': False},
                      {'preview_digest': '0' * 64}, {'sources': {'ffuf': base64.b64encode(raw + b' ').decode('ascii')}}):
            status, _ = self.request({**payload, **patch}, operation='federation-retain')
            self.assertEqual(status, 400, patch)
        self.assertEqual(self.server.workbench.get(workspace['id'])['artifacts'], [])
        status, retained = self.request(payload, operation='federation-retain')
        self.assertEqual(status, 200, retained)
        self.assertEqual(retained['artifact']['kind'], 'federation-receipt')
        self.assertNotIn('private-case-path', json.dumps(retained))
        cli_workspace = self.server.workbench.create('CLI receipt test', scope)
        with tempfile.TemporaryDirectory() as folder:
            source, reviewed_file = Path(folder) / 'source.json', Path(folder) / 'reviewed.json'
            source.write_bytes(raw)
            reviewed_file.write_text(json.dumps(reviewed['projection']))
            args = ['assessment', 'federation-retain', cli_workspace['id'], '--store', str(self.store),
                    '--scope-service', service, '--ffuf', str(source), '--release-sources',
                    '--expected-revision', str(cli_workspace['revision']), '--reviewed-projection', str(reviewed_file)]
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(main(args), 0)
            self.assertEqual(json.loads(stdout.getvalue())['kind'], 'federation-receipt')
        artifacts = self.server.workbench.get(cli_workspace['id'])['artifacts']
        self.assertEqual(len(artifacts), 1)
        self.assertNotIn('private-case-path', json.dumps(artifacts))

    def test_foreign_paths_and_unexpected_browser_fields_rejected(self):
        for sources in ({'shell': 'x'}, {'ffuf': '*not-base64*'}, {}, {'ffuf': {'path': '/tmp/private'}}):
            with self.subTest(sources=sources):
                self.assertEqual(self.request({'allowed_services': ['tcp://192.0.2.10:443'], 'sources': sources})[0], 400)
        self.assertEqual(self.request({'path': '/tmp/private'})[0], 400)
        self.assertNotEqual(self.request({'sources': {}}, authenticated=False)[0], 200)

    def test_oversize_combined_uploads_rejected_before_parser(self):
        # The shared 4 MiB Studio HTTP limit admits this JSON; the source limit is 2 MiB combined.
        blob = base64.b64encode(b'x' * (1024 * 1024 + 1)).decode('ascii')
        status, response = self.request({'allowed_services': ['tcp://192.0.2.10:443'],
                                         'sources': {'nmap': blob, 'ffuf': blob}})
        self.assertEqual(status, 400)
        self.assertIn('2 MiB', response['error'])
