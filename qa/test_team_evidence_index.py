# © Nasser Aldin Farag (0xFarag). All rights reserved.
import base64
import copy
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from team import evidence, review_records
from team.documents import verify_document
from team.evidence_formats import canonical, sha


class SignedEvidenceIndex(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        evidence.init_db(self.db)
        self.team = 'team-one'
        self.case = self.api('POST', ['cases'], {'title':'Check', 'scope':'Local record review', 'assets':['example.test']})['case']
        self.route = ['cases', self.case['id']]
        self.plan = self.review({'kind':'plan', 'asset':'example.test', 'hypothesis':'PRIVATE HYPOTHESIS',
                                 'control':'approved comparison', 'expected':'expected decision'})
        raw = canonical({'log':{'version':'1.2','entries':[
            {'request':{'url':'https://example.test/' + name, 'method':'GET'}, 'response':{'status':status}}
            for name, status in [('private-item', 403), ('private-comparison', 200)]]}})
        source = self.api('POST', self.route + ['imports'], {'format':'har', 'content_b64':base64.b64encode(raw).decode()})['import']
        self.finding = self.api('POST', self.route + ['finding'], {
            'title':'PRIVATE FINDING', 'asset':'example.test', 'status':'confirmed',
            'expected':'private expectation', 'observed':'private observation', 'evidence_id':source['id'], 'record':1,
            'control_evidence_id':source['id'], 'control_record':2, 'control_expected':'allowed', 'control_observed':'allowed'
        })['finding']
        self.assessment = self.review({'kind':'review', 'parent_id':self.plan['id'], 'parent_sha256':self.plan['sha256'],
            'finding_id':self.finding['id'], 'observed':'PRIVATE REVIEW', 'control_observed':'PRIVATE CONTROL',
            'outcome':'supports','evidence':{'import_id':source['id'],'record':1},
            'control_evidence':{'import_id':source['id'],'record':2}})
        self.draft = self.review({'kind':'plan','asset':'example.test','hypothesis':'Unlinked private plan',
                                  'control':'other comparison','expected':'other outcome'})
        self.package = self.api('POST', self.route + ['handover'], {'language':'de'})['package']
        self.key = self.api('GET', ['trust-key'], {})

    def api(self, method, route, body):
        return evidence.handle(self.db, self.team, 'reviewer', method, route, body, data_dir=self.temp.name)

    def review(self, body):
        return review_records.handle(self.db, self.team, 'reviewer', 'POST', self.route + ['control-reviews'],
                                     {**body, 'request_id':str(uuid.uuid4())})['record']

    def test_minimal_projection_after_late_link_matches_signed_report(self):
        detail = self.api('GET', self.route, {})
        row = self.package['report']['appendix'][0]
        index = row['evidence_index']
        self.assertEqual(detail['evidence_index_schema'], evidence.EVIDENCE_INDEX_SCHEMA)
        self.assertEqual(self.package['report']['evidence_index_schema'], detail['evidence_index_schema'])
        self.assertEqual(detail['findings'][0]['evidence_index'], index)
        self.assertEqual([r['role'] for r in index['observations']], ['evidence','control'])
        self.assertEqual([r['record'] for r in index['observations']], [1,2])
        self.assertEqual(index['observations'][0]['sha256'], self.finding['evidence']['sha256'])
        self.assertEqual(index['experiments'], [{'plan_id':self.plan['id'], 'revisions':[
            {k: revision[k] for k in ('id','sha256','parent_sha256')} for revision in [self.plan, self.assessment]]}])
        self.assertEqual(row['retest'], 'not_retested')
        raw = canonical(self.package)
        for private in (b'PRIVATE', b'private-item', self.draft['id'].encode(), self.draft['sha256'].encode()):
            self.assertNotIn(private, raw)
        stored = evidence.one(self.db, self.team, self.case['id'], 'findings', self.finding['id'])
        self.assertNotIn('evidence_index', stored)
        self.assertEqual(self.finding['finding_sha256'], sha(canonical({k:v for k,v in stored.items() if k != 'finding_sha256'})))
        self.assertTrue(evidence.verify_package(self.package, self.key)['valid'])

    def test_tampered_and_structurally_inconsistent_indices_are_rejected(self):
        for damage in ('source','parent','repeat','private_field','missing_schema','missing_index','unknown_schema',
                       'empty_asset','finding_hash','false_fix','coverage_count','duplicate_source','record_type'):
            with self.subTest(damage=damage):
                package = copy.deepcopy(self.package)
                report = package['report']
                row = report['appendix'][0]
                index = row['evidence_index']
                chain = index['experiments'][0]['revisions']
                if damage == 'source': index['observations'][0]['record'] = 2
                if damage == 'parent': chain[1]['parent_sha256'] = '0' * 64
                if damage == 'repeat': chain[1]['id'] = chain[0]['id']
                if damage == 'private_field': chain[1]['operator'] = 'private'
                if damage == 'missing_schema': del report['evidence_index_schema']
                if damage == 'missing_index': del row['evidence_index']
                if damage == 'unknown_schema': report['evidence_index_schema'] = 'v0'
                if damage == 'empty_asset': row['evidence']['asset_id'] = row['control']['asset_id'] = ''
                if damage == 'finding_hash': row['finding_sha256'] = ''
                if damage == 'false_fix': row['retest'] = 'fix_verified'
                if damage == 'coverage_count': report['counts']['not_retested'] = 0
                if damage == 'duplicate_source': package['manifest']['sources'] *= 2
                if damage == 'record_type': package['manifest']['sources'][0]['records'] = True
                self.assertFalse(evidence.verify_package(package, self.key)['valid'])
                # A valid signature also must not certify inconsistent coordinates.
                package['manifest']['report_sha256'] = sha(canonical(report))
                key, _ = evidence.signer(self.db, self.temp.name)
                signed = key.sign(evidence.SIGNING_CONTEXT + canonical(package['manifest']))
                package['signature'] = base64.b64encode(signed).decode()
                self.assertFalse(evidence.verify_package(package, self.key)['valid'])

    def test_pre_index_signed_json_and_html_stay_valid(self):
        path = Path(__file__).parent / 'fixtures' / 'team-proof-cockpit.json'
        fixture = json.loads(path.read_text(encoding='utf-8'))
        proof, key = fixture['proof'], fixture['trustedKey']
        self.assertNotIn('evidence_index_schema', proof['handover']['report'])
        self.assertTrue(evidence.verify_package(proof['handover'], key)['valid'])
        self.assertTrue(verify_document(proof, fixture['document'].encode(), key)['valid'])
