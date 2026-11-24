# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Repeated issuance from a fixed case preserves its proof across issuance times."""
import base64
from hashlib import sha256
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
import uuid

from team import evidence, review_records
from team.evidence_formats import canonical
from test_team_evidence import har


class RepeatableHandover(unittest.TestCase):
    def setUp(self):
        data = tempfile.TemporaryDirectory()
        self.addCleanup(data.cleanup)
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.data_dir = data.name
        evidence.init_db(self.db)
        self.team = 'review-team'
        case = self.request('POST', ['cases'], {
            'title': 'Access review', 'scope': 'Approved local exports', 'assets': ['example.test']
        })['case']
        self.path = ['cases', case['id']]

    def request(self, method, path, body=None):
        with self.db:
            return evidence.handle(self.db, self.team, 'member', method, path, body or {}, data_dir=self.data_dir)

    def upload(self, raw):
        return self.request('POST', self.path + ['imports'], {
            'format': 'har', 'content_b64': base64.b64encode(raw).decode()
        })['import']

    def review(self, **body):
        with self.db:
            return review_records.handle(self.db, self.team, 'member', 'POST', self.path + ['control-reviews'],
                                         dict(body, request_id=str(uuid.uuid4())))['record']

    def test_reissue_preserves_source_bound_projection(self):
        before = self.upload(har())
        plan = self.review(kind='plan', asset='example.test', hypothesis='Check the saved decision',
                           expected='Denied', control='Permitted')
        baseline = dict(asset='example.test', status='confirmed', expected='Denied', observed='Visible',
                        evidence_id=before['id'], record=1, control_evidence_id=before['id'], control_record=2,
                        control_expected='Permitted', control_observed='Permitted')
        with self.assertRaises(evidence.WorkflowError):
            self.request('POST', self.path + ['finding'], dict(baseline, title='Invalid control', control_record=1))
        fixed, pending = [self.request('POST', self.path + ['finding'], dict(baseline, title=title))['finding']
                          for title in ('Selected for retest', 'Awaiting retest')]
        review = self.review(kind='review', parent_id=plan['id'], parent_sha256=plan['sha256'],
                             finding_id=fixed['id'], outcome='supports', observed='Visible', control_observed='Permitted',
                             evidence={'import_id': before['id'], 'record': 1},
                             control_evidence={'import_id': before['id'], 'record': 2})
        after = self.upload(har('after', return_status=403))
        self.request('POST', self.path + ['retest'], {
            'finding_id': fixed['id'], 'status': 'fix_verified', 'observed': 'Denied',
            'evidence_id': after['id'], 'record': 1, 'control_evidence_id': after['id'], 'control_record': 2,
            'control_expected': 'Permitted', 'control_observed': 'Permitted',
        })
        key = self.request('GET', ['trust-key'])
        for language in ('de', 'en', 'fr'):
            with self.subTest(language=language):
                issued = []
                # Only change the handover clock. Stored observations and identifiers remain untouched.
                for instant in ('2026-11-24T12:00:00+00:00', '2026-11-24T12:00:02+00:00'):
                    with patch.object(evidence, 'now', return_value=instant):
                        package = self.request('POST', self.path + ['handover'], {'language': language})['package']
                    self.assertTrue(evidence.verify_package(package, key, self.team)['valid'])
                    self.assertEqual(package['manifest']['created_at'], instant)
                    issued.append(package)
                first, second = issued
                first_manifest = {k: v for k, v in first['manifest'].items() if k != 'created_at'}
                second_manifest = {k: v for k, v in second['manifest'].items() if k != 'created_at'}
                self.assertEqual(first_manifest, second_manifest)
                report = first['report']
                self.assertEqual(report, second['report'])
                digest = sha256(canonical(report)).hexdigest()
                self.assertEqual([p['manifest']['report_sha256'] for p in issued], [digest, digest])
                self.assertNotEqual(first['signature'], second['signature'])
                self.assertEqual(report['language'], language)
                self.assertEqual((report['counts']['fix_verified'], report['counts']['not_retested']), (1, 1))
                rows = {row['id']: row for row in report['appendix']}
                row = rows[fixed['id']]
                self.assertEqual(row['retest'], 'fix_verified')
                self.assertEqual(first['manifest']['retests'][0]['baseline_sha256'], fixed['finding_sha256'])
                self.assertEqual(row['retest_evidence']['sha256'], after['sha256'])
                self.assertEqual(row['retest_control']['sha256'], after['sha256'])
                self.assertEqual(row['retest_control']['record'], 2)
                self.assertEqual(rows[pending['id']]['retest'], 'not_retested')
                self.assertIsNone(rows[pending['id']]['retest_evidence'])
                index = row['evidence_index']
                self.assertEqual([(ref['role'], ref['sha256'], ref['record']) for ref in index['observations']],
                                 [('evidence', before['sha256'], 1), ('control', before['sha256'], 2)])
                chain = index['experiments'][0]['revisions']
                self.assertEqual([r['sha256'] for r in chain], [plan['sha256'], review['sha256']])
                self.assertEqual(chain[1]['parent_sha256'], chain[0]['sha256'])
