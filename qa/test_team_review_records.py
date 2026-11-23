"""Case-bound append-only control review plans using captured files."""
import base64
import json
import sqlite3
import unittest
import uuid

from team import evidence, review_records, server


def nonce():
    return str(uuid.uuid4())


class ControlReviews(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(':memory:')
        self.addCleanup(self.db.close)
        self.db.execute('PRAGMA foreign_keys=ON')
        evidence.init_db(self.db)
        review_records.init_db(self.db)
        self.team = 'team-one'
        self.case = self.new_case(self.team)
        self.route = ['cases', self.case['id'], 'control-reviews']
        self.plan_input = {'kind':'plan','request_id':nonce(),'asset':'example.test','hypothesis':'The saved decision follows policy.',
                           'expected':'The sample records the approved decision.','control':'Compare with a distinct captured control.'}

    def new_case(self, team):
        return evidence.create_case(self.db,team,'member',{'title':'Policy review','scope':'Approved records only',
                                                           'assets':['example.test','other.test']})['case']

    def post(self, body, team=None, route=None):
        return review_records.handle(self.db,team or self.team,'member','POST',route or self.route,body)['record']

    def import_file(self, case=None, asset='example.test'):
        raw = json.dumps({'log':{'version':'1.2','entries':[
            {'startedDateTime':'2026-01-01T00:00:00Z','request':{'method':'GET','url':'https://'+asset+path,
              'headers':[{'name':'X-Private-Input','value':'NEVER_IN_REVIEW'}]},'response':{'status':status}}
            for path,status in [('/primary',200),('/comparison',204)]]}}).encode()
        return evidence.add_import(self.db,self.team,'member',case or self.case,{'format':'har',
             'content_b64':base64.b64encode(raw).decode()})['import']

    def assessment(self, parent, source=None):
        return {'kind':'review','request_id':nonce(),'parent_id':parent['id'],'parent_sha256':parent['sha256'],
                'outcome':'supports' if source else 'inconclusive','observed':'Recorded from local evidence.',
                'control_observed':'Comparison reviewed.',
                'evidence':{'import_id':source['id'],'record':1} if source else None,
                'control_evidence':{'import_id':source['id'],'record':2} if source else None}

    def test_plan_before_finding_retry_and_control_chain(self):
        plan = self.post(self.plan_input)
        self.assertIsNone(plan['finding'])
        self.assertEqual(self.post(self.plan_input),plan)
        with self.assertRaises(evidence.WorkflowError):
            self.post({**self.plan_input,'hypothesis':'Unrelated use of the same request token'})
        source = self.import_file()
        finding = evidence.add_finding(self.db,self.team,'member',self.case,{'title':'Captured decision',
            'asset':'example.test','expected':'Decision recorded','observed':'Result available','status':'hint',
            'evidence_id':source['id'],'record':1})['finding']
        body = {**self.assessment(plan,source),'finding_id':finding['id']}
        review = self.post(body)
        self.assertEqual(self.post(body),review)
        self.assertEqual(review['finding'],{'id':finding['id'],'sha256':finding['finding_sha256']})
        self.assertNotEqual(review['evidence']['fingerprint'],review['control_evidence']['fingerprint'])
        self.assertEqual(review['evidence']['sha256'],source['sha256'])
        self.assertNotIn('NEVER_IN_REVIEW',json.dumps(review))
        update = self.post(self.assessment(review))
        self.assertEqual(update['parent_sha256'],review['sha256'])
        self.assertEqual(update['finding'],review['finding'])
        with self.assertRaises(evidence.WorkflowError) as stale:
            self.post(self.assessment(plan))
        self.assertEqual(stale.exception.status,409)
        all_rows = review_records.handle(self.db,self.team,'reader','GET',self.route,{})['records']
        self.assertEqual(all_rows,[plan,review,update])
        for row in all_rows:
            self.assertEqual(row['sha256'],evidence.sha(evidence.canonical({k:v for k,v in row.items() if k!='sha256'})))

    def test_authenticated_route_roles(self):
        def route(role,method,body):
            return server._team_route(self.db,None,self.team,{'id':'actor-'+role},role,method,self.route,body)
        for role in ('read_only','reviewer'):
            with self.assertRaises(server.ApiError) as failure:
                route(role,'POST',self.plan_input)
            self.assertEqual(failure.exception.status,403)
        plan = route('pentester','POST',self.plan_input)['record']
        with self.assertRaises(server.ApiError):
            route('read_only','POST',self.assessment(plan))
        review = route('reviewer','POST',self.assessment(plan))['record']
        self.assertEqual(route('read_only','GET',{})['records'],[plan,review])

    def test_asset_case_and_team_boundaries(self):
        plan = self.post(self.plan_input)
        for bad_source in [self.import_file(asset='other.test'),self.import_file(case=self.new_case(self.team))]:
            with self.assertRaises(evidence.WorkflowError):
                self.post(self.assessment(plan,bad_source))
        good = self.import_file()
        same = self.assessment(plan,good)
        same['control_evidence'] = same['evidence']
        with self.assertRaises(evidence.WorkflowError):
            self.post(same)
        with self.assertRaises(evidence.WorkflowError):
            self.post({**self.assessment(plan),'outcome':'supports'})
        with self.assertRaises(evidence.WorkflowError) as gone:
            review_records.handle(self.db,'another-team','reader','GET',self.route,{})
        self.assertEqual(gone.exception.status,404)
        with self.assertRaises(evidence.WorkflowError):
            self.post({**self.plan_input,'request_id':nonce(),'asset':'unlisted.test'})
        with self.assertRaises(evidence.WorkflowError):
            self.post({**self.assessment(plan),'parent_sha256':'0'*64})
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute('UPDATE case_control_reviews SET request_sha256=? WHERE id=?',('tampered',plan['id']))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute('DELETE FROM case_control_reviews WHERE id=?',(plan['id'],))


if __name__ == '__main__':
    unittest.main()
