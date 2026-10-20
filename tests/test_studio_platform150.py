"""Persistent Studio main path uses the same scope, detector and proof services."""
import copy
import http.client
import io
import json
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from authzledger.studio import StudioServer
from authzledger.detectors import verify_check_execution
from authzledger.platform_reports import verify_platform
from test_detectors150 import service, header_spec, scope_for


class StudioPlatformTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.fixture = service()
        self.origin, self.state = self.fixture.__enter__()
        self.spec = header_spec(self.origin)
        self.server = StudioServer(history_path=Path(self.directory.name) / 'history.sqlite3')
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(2)
        self.fixture.__exit__(None, None, None)
        self.directory.cleanup()

    def request(self, path, body=None, *, authenticated=True, origin=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=15)
        headers = {'Origin': self.server.origin if origin is None else origin, 'Content-Type': 'application/json'}
        if authenticated:
            headers['Authorization'] = 'Bearer ' + self.server.token
        connection.request('POST' if body is not None else 'GET', path, json.dumps(body) if body is not None else None, headers)
        response = connection.getresponse(); raw = response.read(); code = response.status
        content_type = response.getheader('Content-Type'); connection.close()
        return code, json.loads(raw) if content_type.startswith('application/json') else raw

    def create(self):
        status, result = self.request('/api/platform/create', {'title': 'Persistent fixture assessment', 'scope': scope_for(self.spec)})
        self.assertEqual(status, 200, result)
        return result['assessment']['id']

    def plan(self, identifier):
        status, result = self.request('/api/platform/check-plan', {'assessment_id': identifier, 'spec': self.spec})
        self.assertEqual(status, 200, result)
        return result

    def execute(self, plan):
        body = {'review': plan['review'], 'approve': plan['artifact']['value']['plan_digest'], 'authorized': True}
        code, job = self.request('/api/platform/run', body)
        self.assertEqual(code, 200, job)
        for _ in range(300):
            code, result = self.request('/api/jobs/' + job['id'])
            if result['state'] != 'running':
                self.assertEqual(result['state'], 'complete', result)
                return result
            time.sleep(.01)
        self.fail('Loopback check did not complete')

    def test_main_path_retest_and_signed_snapshot(self):
        identifier = self.create()
        planned = self.plan(identifier)
        self.assertEqual(self.state['requests'], [])
        result = self.execute(planned)
        self.assertEqual(verify_check_execution(result['artifact']['value']), [])
        self.assertEqual(result['artifact']['value']['findings'][0]['evidence_level'], 'confirmed')
        self.assertEqual(len(self.state['requests']), 2)
        repeated = self.execute(planned)
        self.assertEqual(repeated['id'], result['id'])
        self.assertEqual(len(self.state['requests']), 2)
        self.state['headers'] = True
        status, retest = self.request('/api/platform/retest-plan', {'assessment_id': identifier,
            'execution_id': result['artifact']['artifact_id']})
        self.assertEqual(status, 200, retest)
        self.execute(retest)
        status, frozen = self.request('/api/platform/freeze', {'assessment_id': identifier})
        self.assertEqual(status, 200, frozen)
        self.assertEqual(verify_platform(frozen['snapshot']), [])
        record_id = frozen['snapshot']['findings'][0]['id']
        current = self.server.workbench.get(identifier)['assessment']
        self.assertEqual(self.request('/api/platform/annotate', {'assessment_id': identifier,
            'expected_revision': current['revision'], 'annotations': {record_id: {'evidence_level': 'confirmed'}}})[0], 400)
        self.assertEqual(self.server.workbench.get(identifier)['assessment']['revision'], current['revision'])
        status, reviewed = self.request('/api/platform/annotate', {'assessment_id': identifier,
            'expected_revision': current['revision'], 'annotations': {record_id: {'severity': 'low', 'review': 'reviewed',
            'rationale': 'Configuration observation confirmed by two controlled responses.',
            'impact': 'The explicitly required response protection was absent.',
            'remediation': 'Set the required header on this route and repeat the same controls.'}}})
        self.assertEqual(status, 200, reviewed)
        status, frozen = self.request('/api/platform/freeze', {'assessment_id': identifier})
        self.assertEqual(status, 200, frozen)
        self.assertEqual(frozen['snapshot']['findings'][0]['review'], 'reviewed')
        for format_name in ('json', 'html', 'pdf'):
            status, raw = self.request('/api/platform/export', {'snapshot_id': frozen['snapshot_id'], 'format': format_name})
            self.assertEqual(status, 200, raw)
            if format_name == 'pdf':
                self.assertTrue(raw.startswith(b'%PDF'))
        status, key = self.request('/api/assessment/signing', {'create_session_key': True})
        self.assertEqual(status, 200, key)
        status, archive = self.request('/api/platform/proof', {'snapshot_id': frozen['snapshot_id']})
        self.assertEqual(status, 200, archive)
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            self.assertIn('attachments/platform.json', zipped.namelist())
            self.assertNotIn('private.pem', zipped.namelist())

    def test_review_bound_to_revision_and_credential_generation(self):
        identifier = self.create(); planned = self.plan(identifier)
        current = self.server.workbench.get(identifier)['assessment']
        self.server.workbench_store.update(identifier, {'title': 'Changed'}, current['revision'])
        payload = {'review': planned['review'], 'approve': planned['artifact']['value']['plan_digest'], 'authorized': True}
        self.assertEqual(self.request('/api/platform/run', payload)[0], 400)
        planned = self.plan(identifier)
        self.server.credential_resolver.bind_session('FIXTURE_REF', 'fixture-secret-12345', identity='anonymous', target_origin=self.origin)
        payload.update(review=planned['review'], approve=planned['artifact']['value']['plan_digest'])
        self.assertEqual(self.request('/api/platform/run', payload)[0], 400)
        self.assertEqual(self.state['requests'], [])

    def test_same_origin_auth_approval_and_untrusted_fields(self):
        identifier = self.create(); planned = self.plan(identifier)
        for payload in ({'review': planned['review']}, {'review': planned['review'], 'approve': '0'*64, 'authorized': True},
                        {'review': planned['review'], 'approve': planned['artifact']['value']['plan_digest'], 'authorized': True, 'plan': {}}):
            self.assertEqual(self.request('/api/platform/run', payload)[0], 400)
        self.assertEqual(self.request('/api/platform', authenticated=False)[0], 403)
        self.assertEqual(self.request('/api/platform/get', {'assessment_id': identifier}, origin='https://evil.example')[0], 403)
        self.assertEqual(self.state['requests'], [])

    def test_store_reopen_retains_evidence_without_credentials_or_execution(self):
        identifier = self.create(); self.execute(self.plan(identifier))
        path = Path(self.directory.name) / 'history.sqlite3'
        from authzledger.workbench import WorkbenchStore, WorkbenchService
        store = WorkbenchStore(path)
        try:
            with patch('socket.getaddrinfo', side_effect=AssertionError('reopening must be offline')):
                retained = WorkbenchService(store).get(identifier)
            self.assertEqual(len([a for a in retained['artifacts'] if a['kind'] == 'check-execution']), 1)
            self.assertEqual(len(self.state['requests']), 2)
        finally:
            store.close()


if __name__ == '__main__':
    unittest.main()
