"""CLI and authenticated Studio project the same immutable freeze."""
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
from tests.test_federation_offline import SCOPE, ffuf, match
from tests.test_federation_retention import policy


class FederationIndexEntrypointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = StudioServer()
        cls.thread = threading.Thread(target=cls.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)

    def request(self, action, body, *, authenticated=True, origin=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=10)
        headers = {'Content-Type': 'application/json', 'Origin': origin or self.server.origin}
        if authenticated:
            headers['Authorization'] = 'Bearer ' + self.server.token
        try:
            connection.request('POST', '/api/platform/' + action, json.dumps(body), headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def freeze(self, assessment_id):
        status, data = self.request('freeze', {'assessment_id': assessment_id})
        self.assertEqual(status, 200, data)
        return json.loads(data)

    def test_same_index_from_studio_and_exported_snapshot_after_workspace_edit(self):
        service = self.server.workbench
        case = service.create('Read-only index', policy())
        identifier = case['id']
        raw = ffuf(length=10)
        service.retain_federation(identifier, SCOPE, [('ffuf', raw)], expected_revision=case['revision'])
        frozen = self.freeze(identifier)
        body = {'snapshot_id': frozen['snapshot_id']}
        status, original_bytes = self.request('export', {**body, 'format': 'json'})
        self.assertEqual(status, 200, original_bytes)
        revision = service.get(identifier)['assessment']['revision']
        service.retain_federation(identifier, SCOPE, [('nuclei', match())], expected_revision=revision)
        workspace = service.get(identifier)
        status, data = self.request('federation-index', body)
        self.assertEqual(status, 200, data)
        index = json.loads(data)
        self.assertEqual(index['snapshot_digest'], frozen['snapshot']['snapshot_digest'])
        self.assertEqual([row['source_ref']['sha256'] for row in index['observations']], [hashlib.sha256(raw).hexdigest()])
        self.assertEqual(index['observations'][0]['evidence_level'], 'hint')
        with tempfile.TemporaryDirectory() as folder:
            source, output = Path(folder) / 'freeze.json', Path(folder) / 'index.json'
            source.write_bytes(original_bytes)
            args = ['assessment', 'federation-index', str(source)]
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(main(args), 0)
                self.assertEqual(json.loads(stdout.getvalue()), index)
            self.assertEqual(main([*args, '--out', str(output)]), 0)
            self.assertEqual(json.loads(output.read_bytes()), index)
            self.assertEqual(source.read_bytes(), original_bytes)
            retained_bytes = output.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([*args, '--out', str(output)]), 2)
            self.assertEqual(output.read_bytes(), retained_bytes)
        self.assertEqual(service.get(identifier), workspace)
        self.assertEqual(self.request('export', {**body, 'format': 'json'}), (200, original_bytes))

    def test_foreign_or_unverified_freezes_are_rejected(self):
        case = self.server.workbench.create('Freeze validation', policy())
        frozen = self.freeze(case['id'])
        body = {'snapshot_id': frozen['snapshot_id']}
        for bad in ({}, {'snapshot_id': []}, {'snapshot_id': 'missing'}, {'snapshot': frozen['snapshot']},
                    {**body, 'assessment_id': case['id']}):
            with self.subTest(bad=list(bad)):
                self.assertEqual(self.request('federation-index', bad)[0], 400)
        self.assertEqual(self.request('federation-index', body, authenticated=False)[0], 403)
        self.assertEqual(self.request('federation-index', body, origin='https://example.test')[0], 403)
        changed = {**frozen['snapshot'], 'snapshot_digest': '0' * 64}
        foreign_id = self.server.retain_assessment(self.server.platform_snapshots, changed)
        self.assertEqual(self.request('federation-index', {'snapshot_id': foreign_id})[0], 400)
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stderr(io.StringIO()):
            source, output = Path(folder) / 'changed.json', Path(folder) / 'index.json'
            source.write_text(json.dumps(changed), encoding='utf-8')
            self.assertEqual(main(['assessment', 'federation-index', str(source), '--out', str(output)]), 2)
            self.assertFalse(output.exists())
