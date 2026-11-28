"""Revision commits and tenant boundaries for management exports. © Nasser Aldin Farag (0xFarag)."""
import base64
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from team import management_report, proof_api, server


class ManagementExport(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.path = Path(work.name)
        self.password = 'Disposable evidence test passphrase'
        server.bootstrap(self.path, 'admin@example.test', self.password)
        self.auth, self.tid = self.login('admin@example.test')
        self.base = f'/api/teams/{self.tid}/proof'

    def login(self, name):
        who, token = server.dispatch(self.path, 'POST', '/api/login', {'email': name, 'password': self.password})
        return {'token': token, 'csrf': who['csrf']}, who['teams'][0]['id']

    def call(self, method, path, body=None, auth=None):
        return server.dispatch(self.path, method, path, body, **(self.auth if auth is None else auth))[0]

    def test_revisions_signing_retests_and_reader_access(self):
        run = self.call('POST', self.base, {'mode': 'lab'})['run']
        path = self.base + '/' + run['id']
        url = path + '/management-report'
        self.call('POST', f'/api/teams/{self.tid}/members', {'email': 'reader@example.test', 'role': 'read_only', 'password': self.password})
        reader = self.login('reader@example.test')[0]
        def download(suffix=''):
            return self.call('GET', url + suffix, auth=reader)['report']
        first = download()
        self.assertEqual(first['baseline']['byStatus']['inconclusive'], 4)
        self.assertEqual(first['retests']['latestByStatus'], {})
        self.assertEqual(first['revision'], 1)
        self.assertIsNone(first['handover']['latestSignedRevision'])
        controls = dict.fromkeys(proof_api.CONTROLS, True)
        self.call('POST', path + '/controls', {'version': 1, 'controls': controls})
        self.call('POST', path + '/sign', {'version': 2, 'language': 'de'})
        self.call('POST', path + '/retest', {'version': 3, 'selected': run['selected'], 'controls': controls, 'labAfter': True})
        current = download()
        self.assertEqual(current['revision'], 4)
        self.assertEqual(current['baseline']['byStatus']['confirmed'], 4)
        self.assertEqual(current['retests'], {'runs': 1, 'latestByStatus': {'resolved_check': 3, 'not_retested': 1}})
        self.assertEqual(current['budget'], {'limit': 12, 'spent': 7, 'remaining': 5})
        self.assertEqual(current['exportStatus'], 'unsigned')
        self.assertEqual(current['handover']['latestSignedRevision'], 3)
        self.assertEqual(download('/1'), first)
        self.assertEqual(download('/4'), current)
        self.assertIsNone(download('/2')['handover']['latestSignedRevision'])
        with closing(server.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM proof_management_reports').fetchone()[0], 4)
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute('UPDATE proof_management_reports SET summary=?', ('changed',))
        other = self.call('POST', '/api/teams', {'name': 'Other'})['team']['id']
        for bad_url, auth, status in [(url, {}, 401), (url + '/5', reader, 404), (url + '/0', reader, 404),
                                      (url.replace(self.tid, other) + '/1', self.auth, 404)]:
            with self.subTest(bad_url=bad_url), self.assertRaises((server.ApiError, proof_api.Error)) as error:
                self.call('GET', bad_url, auth=auth)
            self.assertEqual(error.exception.status, status)

    def test_import_minimization_and_atomic_capture(self):
        run = self.call('POST', self.base, {'mode': 'commercial', 'hosts': ['private.example.test', 'unobserved.example.test'],
                                            'roe': 'Limited internal scope', 'budget': 1})['run']
        path = self.base + '/' + run['id']
        url = path + '/management-report'
        empty = self.call('GET', url)['report']
        self.assertEqual(empty['evidenceStatus'], 'awaiting_evidence')
        self.assertEqual(empty['baseline']['observations'], 0)
        matches = [{'template-id': 'private-rule', 'type': 'http', 'matcher-status': True, 'matched-at': 'https://' + hostname + '/private?token=private-value',
                    'info': {'severity': level}} for hostname, level in [('private.example.test', 'high'), ('outside.example.test', 'critical')]]
        data = '\n'.join(json.dumps(m) for m in matches)
        body = {'version': 1, 'format': 'nuclei', 'content_b64': base64.b64encode(data.encode()).decode()}
        # A failed snapshot insert must roll back the run update and its history together.
        with patch.object(management_report, 'capture', side_effect=sqlite3.IntegrityError('report insert failed')):
            with self.assertRaises(sqlite3.IntegrityError):
                self.call('POST', path + '/import', body)
        self.assertEqual(self.call('GET', url)['report'], empty)
        self.call('POST', path + '/import', body)
        result = self.call('GET', url)
        report = result['report']
        self.assertEqual(result['filename'], f'AuthzLedger-Management-{run["id"]}-v2.json')
        self.assertEqual(report['coverage'], {'scopedHosts': 2, 'observedScopedHosts': 1})
        self.assertEqual(report['sources'], {'total': 1, 'byFormat': {'nuclei': 1}})
        self.assertEqual(report['scannerSignals']['total'], 1)
        self.assertEqual(report['scannerSignals']['bySeverity']['high'], 1)
        self.assertEqual(report['scannerSignals']['bySeverity']['critical'], 0)
        self.assertEqual(report['baseline']['byStatus']['confirmed'], 0)
        self.assertEqual(report['baseline']['byStatus']['out_of_scope'], 1)
        for private in ['private', 'internal scope', 'example.test', 'reader@', self.auth['csrf']]:
            self.assertNotIn(private, json.dumps(report))

    def test_existing_db_only_exposes_reconstructible_revisions(self):
        run = self.call('POST', self.base, {'mode': 'lab'})['run']
        path = self.base + '/' + run['id']
        url = path + '/management-report'
        body = {'version': 1, 'controls': dict.fromkeys(proof_api.CONTROLS, True)}
        self.call('POST', path + '/controls', body)
        # Simulate an older installation which did not store report snapshots.
        with closing(server.connect(self.path)) as db:
            db.execute('DROP TABLE proof_management_reports')
        server.initialize(self.path)
        previous = self.call('GET', url + '/2')['report']
        self.assertEqual(self.call('GET', path)['run']['managementReportFrom'], 2)
        with closing(server.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM proof_management_reports').fetchone()[0], 0)
        self.call('POST', path + '/controls', body | {'version': 2})
        self.assertEqual(previous, self.call('GET', url + '/2')['report'])
        self.assertEqual(self.call('GET', path)['run']['managementReportFrom'], 2)
        with self.assertRaises(proof_api.Error) as error:
            self.call('GET', url + '/1')
        self.assertEqual(error.exception.status, 404)
