# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Passive ZAP integration through the authenticated server's workflow dispatcher."""
import base64
import copy
import json
import sqlite3
import tempfile
import unittest

from team import evidence
from team.documents import render_html
from team.evidence_formats import canonical, sha


def report(method='GET', uri='https://example.test/accounts?view=mine'):
    # Synthetic Traditional JSON structure with distinct product and private fields.
    instance = {'uri': uri, 'method': method, 'param': '', 'attack': '',
                'evidence': 'PRIVATE ZAP OBSERVATION', 'otherinfo': ''}
    alert = {'pluginid': '10038', 'alertRef': '10038-1', 'alert': 'Content Security Policy (CSP) Header Not Set',
             'riskcode': '2', 'confidence': '3', 'riskdesc': 'Medium (High)',
             'instances': [instance], 'count': '1'}
    return {'@version': '2.16.0', 'site': [{'@name': 'https://example.test', '@host': 'example.test',
            '@port': '443', '@ssl': 'true', 'alerts': [alert]}]}


class ZapScanIntegration(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = folder.name
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        evidence.init_db(self.db)
        self.route = ['cases', self.api(['cases'], {'title': 'Review', 'scope': 'Test fixtures',
                      'assets': ['example.test']})['case']['id']]
        self.capture = self.upload('har', {'log': {'version': '1.2', 'entries': [
            {'request': {'method': 'GET', 'url': 'https://example.test' + path}, 'response': {'status': code}}
            for path, code in [('/accounts?view=mine', 200), ('/control', 403)]]}})
        self.base = {'title': 'Independent review', 'asset': 'example.test', 'status': 'confirmed',
                     'expected': 'denied', 'observed': 'allowed', 'evidence_id': self.capture['id'], 'record': 1,
                     'control_evidence_id': self.capture['id'], 'control_record': 2,
                     'control_expected': 'denied', 'control_observed': 'denied'}

    def api(self, route, body, team='team'):
        with self.db:
            return evidence.handle(self.db, team, 'reviewer', 'POST', route, body, data_dir=self.folder)

    def upload(self, fmt, obj):
        return self.api(self.route + ['imports'], {'format': fmt,
                        'content_b64': base64.b64encode(canonical(obj)).decode()})['import']

    def link(self, item, **overrides):
        body = {**self.base, 'zap_lead': {'import_id': item['id'], 'record': 1}, **overrides}
        return self.api(self.route + ['finding'], body)['finding']

    def test_linked_source_round_trip_and_signed_projection(self):
        source = self.upload('zap', report())
        self.assertEqual(source['records'], 1)
        row = source['entries'][0]
        self.assertEqual((row['rule_id'], row['alert_ref'], row['riskcode'], row['confidence']),
                         ('10038', '10038-1', 2, 3))
        alert = report()['site'][0]['alerts'][0]
        self.assertEqual(row['fingerprint'], sha(canonical([alert['pluginid'], alert['instances'][0]])))
        self.assertEqual(source, self.upload('zap', report()))
        hint = self.api(self.route + ['finding'], {**self.base, 'status': 'hint', 'evidence_id': source['id']})['finding']
        self.assertIsNone(hint['control'])
        finding = self.link(source)
        package = self.api(self.route + ['handover'], {'language': 'de'})['package']
        signed = next(row for row in package['report']['appendix'] if row['id'] == finding['id'])
        self.assertEqual(signed['retest'], 'not_retested')
        self.assertEqual(signed['scanner_lead']['sha256'], source['sha256'])
        self.assertEqual([item['format'] for item in signed['evidence_index']['observations']], ['har', 'har'])
        self.assertIn('Verknüpfter ZAP-Hinweis', render_html(package['report'], package['manifest']).decode())
        self.assertTrue(self.api(['verify'], {'package': package})['valid'])
        for blob in (source, package):
            self.assertNotIn('PRIVATE ZAP', json.dumps(blob))
            self.assertNotIn('/accounts', json.dumps(blob))
        for change in ({'format': 'har'}, {'record': 5}, {'asset_id': 'f' * 64}):
            damaged = copy.deepcopy(package)
            next(r for r in damaged['report']['appendix'] if r['id'] == finding['id'])['scanner_lead'].update(change)
            with self.assertRaises(ValueError):
                evidence.check_evidence_indices(damaged['report'], damaged['manifest'])
            self.assertFalse(self.api(['verify'], {'package': damaged})['valid'])

    def test_localized_pdf_contains_signed_scanner_reference(self):
        source = self.upload('zap', report())
        self.link(source)
        for language in ('de', 'en', 'fr', 'it', 'ar'):
            with self.subTest(language=language):
                archive = self.api(self.route + ['handover'], {'language': language, 'format': 'pdf'})
                checked = self.api(['verify'], {'archive_b64': archive['archive_b64']})
                self.assertTrue(checked['valid'])
                self.assertEqual(checked['report']['appendix'][0]['scanner_lead']['sha256'], source['sha256'])

    def test_mutually_independent_http_capture_and_control_required(self):
        source = self.upload('zap', report())
        for changes in ({'evidence_id': source['id']}, {'control_evidence_id': source['id'], 'control_record': 1},
                        {'control_record': 1}, {'control_observed': 'unexpected'}, {'status': 'hint'},
                        {'zap_lead': {'import_id': self.capture['id'], 'record': 1}},
                        {'zap_lead': {'import_id': source['id'], 'record': True}}):
            with self.subTest(changes=changes), self.assertRaises(evidence.WorkflowError):
                self.link(source, **changes)
        for method, uri in [('POST', 'https://example.test/accounts?view=mine'),
                            ('GET', 'https://example.test/accounts?view=all'), ('GET', 'https://example.test/other'),
                            ('GET', 'https://example.test:444/accounts?view=mine'),
                            ('GET', 'http://example.test/accounts?view=mine'), ('GET', 'https://other.test/accounts?view=mine')]:
            with self.subTest(method=method, uri=uri), self.assertRaises(evidence.WorkflowError):
                self.link(self.upload('zap', report(method, uri)))
        other_case = self.api(['cases'], {'title': 'Other', 'scope': 'Test fixtures', 'assets': ['example.test']})['case']
        self.route = ['cases', other_case['id']]
        distinct = self.upload('zap', report(uri='https://example.test:443/accounts?view=mine'))
        self.route = ['cases', self.db.execute('SELECT id FROM evidence_cases ORDER BY rowid LIMIT 1').fetchone()[0]]
        with self.assertRaises(evidence.WorkflowError) as err:
            self.link(distinct)
        self.assertEqual(err.exception.status, 404)
        with self.assertRaises(evidence.WorkflowError):
            self.api(self.route + ['finding'], self.base, team='another-team')

    def test_empty_report_remains_empty_and_bad_input_fails(self):
        for empty in ({'site': []}, {'site': [{'alerts': []}]}):
            source = self.upload('zap', empty)
            self.assertEqual(source['records'], 0)
            with self.assertRaises(evidence.WorkflowError):
                self.link(source)
        handover = self.api(self.route + ['handover'], {'language': 'en'})['package']
        self.assertEqual(handover['report']['counts']['findings'], 0)
        self.assertTrue(self.api(['verify'], {'package': handover})['valid'])
        invalid = report()
        invalid['site'][0]['alerts'][0]['instances'] = []
        for obj in (invalid, {'site': {}}, {'alerts': []}, report(uri='file:///private')):
            with self.assertRaises(evidence.WorkflowError):
                self.upload('zap', obj)

    def test_old_records_resolve_against_retained_original_bytes(self):
        source = self.upload('zap', report())
        for doc in (self.capture, source):
            for row in doc['entries']:
                row.pop('endpoint_key')
                for key in ('rule_id', 'alert_ref', 'riskcode', 'confidence'):
                    row.pop(key, None)
            self.db.execute("UPDATE evidence_items SET document=? WHERE kind='imports' AND id=?",
                            (canonical(doc).decode(), doc['id']))
        self.assertEqual(self.link(source)['scanner_lead']['sha256'], source['sha256'])
        self.db.execute('UPDATE evidence_bytes SET attachment=? WHERE import_id=?', (b'altered', source['id']))
        with self.assertRaises(evidence.WorkflowError) as err:
            self.link(source)
        self.assertEqual(err.exception.status, 409)
