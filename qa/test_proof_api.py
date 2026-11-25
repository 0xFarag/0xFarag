# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Exercise the real persisted workflow through the authenticated dispatcher."""
import base64
import io
import json
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

from team import proof_api, server

PASSWORD = "Disposable local test credentials 384"
ADMIN = "owner@fixture.test"
CONTROL = dict.fromkeys(('token','identity','owner','denial'), True)


class Workflow(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root = Path(work.name)
        server.bootstrap(self.root, ADMIN, PASSWORD)
        self.login_body, self.auth = self.login(ADMIN)
        self.tid = self.login_body['teams'][0]['id']
        self.teams = '/api/teams/'+self.tid
        self.base = self.teams+'/proof'

    def login(self, name):
        result, token = server.dispatch(self.root, 'POST', '/api/login', {'email': name, 'password': PASSWORD})
        return result, {'token':token,'csrf':result['csrf']}

    def call(self, method, url, body=None, auth=None, **kwargs):
        return server.dispatch(self.root, method, url, body, **(self.auth if auth is None else auth), **kwargs)[0]

    def fails(self, status, method, url, body=None, auth=None, **kwargs):
        with self.assertRaises((server.ApiError,proof_api.Error)) as caught:
            self.call(method, url, body, auth=auth, **kwargs)
        self.assertEqual(caught.exception.status, status, caught.exception)

    def create(self, mode='commercial'):
        body = {'mode': mode}
        if mode=='commercial':
            body.update(hosts=['fixture.test'], roe='Authorized evidence handling', budget=12)
        return self.call('POST', self.base, body)['run']

    def member(self, name, role):
        self.call('POST', self.teams+'/members', {'email':name,'role':role,'password':PASSWORD})
        return self.login(name)[1]

    def test_lab_freeze_archive_rotation_verification_and_audit(self):
        self.assertIn('All rights reserved.', self.login_body['rights'])
        self.assertFalse(self.login_body['teams'][0]['legacyCases'])
        self.fails(410, 'GET', self.teams+'/cases')
        run = self.create('lab')
        route = self.base+'/'+run['id']
        self.assertEqual(len(run['sources'][0]['observations']), 4)
        run = self.call('POST', route+'/controls', {'version':run['version'],'controls':CONTROL})['run']
        root = run['report']['evidenceRoot']
        run = self.call('POST', route+'/retest', {'version':run['version'], 'selected':run['selected'],
                        'controls':CONTROL, 'labAfter':True})['run']
        self.assertEqual([r['status'] for r in run['retests']], ['resolved_check']*3+['not_retested'])
        self.assertEqual(root, run['report']['evidenceRoot'])
        self.fails(409,'POST', route+'/controls', {'version':run['version'],'controls':CONTROL})
        run = self.call('POST', route+'/sign', {'version':run['version'],'language':'fr'})['run']
        member = self.member('read@fixture.test','reviewer')
        for action in ('sign','export','token','controls','retest'):
            self.fails(403,'POST', route+'/'+action, {}, auth=member)
        self.fails(403, 'POST', self.base+'/rotate', {}, auth=member)
        old = self.call('POST', route+'/export', {'packageId':run['signed'][0]['id']})
        with ZipFile(io.BytesIO(base64.b64decode(old['archive_b64']))) as archive:
            self.assertIn('report.pdf', archive.namelist())
            self.assertEqual(json.loads(archive.read('report.json'))['evidenceRoot'],root)
        def verify(data):
            return self.call('POST', route+'/verify', {'archive_b64':data}, auth=member)
        self.assertTrue(verify(old['archive_b64'])['valid'])
        rotated = self.call('POST', self.base+'/rotate', {})
        self.assertNotEqual(rotated['activeKeyId'],run['signed'][0]['keyId'])
        self.assertTrue(verify(old['archive_b64'])['valid'])
        self.assertFalse(verify(base64.b64encode(base64.b64decode(old['archive_b64'])+b'!').decode())['valid'])
        self.assertEqual(self.call('GET',route)['run']['history'][-1]['action'],'sign')
        events = self.call('GET',self.teams+'/audit')['events']
        actions = {e['action'] for e in events if e['outcome']=='ok'}
        self.assertTrue({'post.sign','post.rotate','post.export','post.retest','post.controls','login'}<=actions)

    def test_workspace_isolation_untrusted_ids_and_optimistic_concurrency(self):
        run=self.create('lab')
        route=self.base+'/'+run['id']
        team=self.call('POST','/api/teams',{'name':'Other'})['team']['id']
        other='/api/teams/'+team+'/proof/'+run['id']
        self.fails(404,'GET',other)
        self.fails(404,'POST',other+'/verify',{'archive_b64':'abc'})
        self.fails(400,'POST',route+'/controls',{'version':1,'controls':CONTROL,'userId':self.auth['token']})
        self.fails(403,'POST',route+'/controls',{'version':1,'controls':CONTROL},auth=self.auth|{'csrf':'bad'})
        def write(_):
            try:
                self.call('POST',route+'/controls',{'version':run['version'],'controls':CONTROL})
                return 200
            except (server.ApiError,proof_api.Error) as exc:
                return exc.status
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(write, range(2))),[200,409])
        self.assertEqual(self.call('GET',route)['run']['version'],2)

    def test_sanitized_import_and_session_bound_limited_token(self):
        run=self.create()
        route=self.base+'/'+run['id']
        row=dict(id='request-1',host='fixture.test',method='GET',path='/invoices/123',
                 status=403,marker=False,rule='protected-marker',source='Burp')
        def mint():
            return self.call('POST',route+'/token',{})['token']
        def send(token,obs,**opts):
            return self.call('POST','/api/proof-import',{'observations':[obs]},auth={},bearer=token,**opts)
        secret=mint()
        self.fails(403,'POST', '/api/proof-import',{'observations':[row|{'host':'other.test'}]},auth={},bearer=secret)
        self.fails(400,'POST', '/api/proof-import',{'observations':[row|{'Authorization':'no'}]},auth={},bearer=secret)
        self.fails(403,'GET', self.base,auth={},bearer=secret)
        self.assertEqual(send(secret,{k:v for k,v in row.items() if k!='marker'})['accepted'],1)
        self.fails(401,'POST', '/api/proof-import',{'observations':[row]},auth={},bearer=secret)
        self.assertNotEqual(self.call('GET',route)['run']['report']['findings'][0]['status'],'confirmed')
        hdr='MUSTNOTPERSIST-BEARER'
        raw=json.dumps({'log':{'version':'1.2','entries':[{'request':{'url':'https://fixture.test/invoices/124?x='+hdr,
                    'method':'GET','headers':[{'name':'Authorization','value':hdr}]},'response':{'status':403,
                    'content':{'text':hdr}}}]}}).encode()
        run=self.call('POST',route+'/import',{'version':2,'format':'har','content_b64':base64.b64encode(raw).decode()})['run']
        self.assertNotIn(hdr,json.dumps(run))
        with closing(server.connect(self.root)) as db:
            self.assertNotIn(hdr,'\n'.join(db.iterdump()))
        expired=mint()
        import time
        self.fails(401,'POST','/api/proof-import',{'observations':[row]},auth={},bearer=expired,now=int(time.time())+301)
        self.call('POST','/api/logout',{})
        self.fails(401,'POST','/api/proof-import',{'observations':[row]},auth={},bearer=expired)

    def test_zap_ingestion_and_role_matrix(self):
        from team import proof_zap
        run = self.create()
        route = self.base+'/'+run['id']
        rows = [dict(id='zap-'+str(i),host=host,method='GET',path='/accounts',status=status,
                     marker=False,rule='10010',source='ZAP')
                for i,(host,status) in enumerate([('fixture.test',403),('outside.test',None)])]
        with patch.object(proof_zap,'read_alerts',side_effect=proof_zap.ZapImportError('zap_unreachable',502)):
            self.fails(502,'POST',route+'/zap',{'version':1,'apiKey':'disposable-fixture-key'})
        events = self.call('GET',self.teams+'/audit')['events']
        self.assertTrue(any(e['action']=='post.zap' and e['outcome']=='rejected' for e in events))
        with patch.object(proof_zap,'read_alerts',return_value=rows) as reader:
            run=self.call('POST',route+'/zap',{'version':1,'apiKey':'disposable-fixture-key'})['run']
            reader.assert_called_once()
        self.assertEqual([r['status'] for r in run['report']['findings']],['inconclusive','out_of_scope'])
        for role in ['read_only','reviewer','pentester','lead_pentester']:
            with self.subTest(role=role):
                who=self.member(role+'@fixture.test',role)
                self.assertEqual(self.call('GET',route,auth=who)['run']['id'],run['id'])
                self.fails(403,'POST',self.base+'/rotate',{},auth=who)
                self.fails(403,'POST',self.teams+'/members',{},auth=who)
                if role in ('reviewer','read_only'):
                    for op in ['export','sign','token','controls','zap']:
                        self.fails(403,'POST',route+'/'+op,{},auth=who)
                else:
                    run=self.call('POST',route+'/sign',{'version':run['version'],'language':'en'},auth=who)['run']
                    self.assertTrue(self.call('POST',route+'/export',{'packageId':run['signed'][0]['id']},auth=who)['archive_b64'])
        with closing(server.connect(self.root)) as db:
            self.assertNotIn('disposable-fixture-key','\n'.join(db.iterdump()))

    def test_existing_legacy_email_principal_remains_compatible(self):
        # Simulate a user and team created by the old schema, before capability records existed.
        with closing(server.connect(self.root)) as db:
            db.execute('DELETE FROM proof_accounts')
            db.execute('DELETE FROM proof_workspaces')
        old,auth=self.login(ADMIN)
        self.assertNotIn('legacyCases',old['teams'][0])
        self.assertEqual(self.call('GET',self.teams+'/cases',auth=auth)['cases'],[])
        self.call('POST',self.teams+'/members',{'username':'operator@old','role':'pentester',
                                                'password':PASSWORD},auth=auth)
        new=self.member('new@fixture.test','reviewer')
        self.fails(410, 'GET', self.teams+'/cases',auth=new)

    def test_live_permissions_rechecked_after_local_zap_read(self):
        from team import proof_zap
        run=self.create()
        route=self.base+'/'+run['id']
        who=self.member('analyst@fixture.test','pentester')
        account=self.call('GET',self.teams+'/members')['members']
        uid=next(m['id'] for m in account if m['username']=='analyst@fixture.test')
        def revoke(url,key):
            self.assertEqual(key, 'short-lived-test-key')
            self.call('PATCH',self.teams+'/members/'+uid,{'role':'read_only'})
            return []
        with patch.object(proof_zap,'read_alerts',side_effect=revoke):
            self.fails(403,'POST',route+'/zap',{'version':1,'apiKey':'short-lived-test-key'},auth=who)
        self.assertEqual(self.call('GET',route)['run']['sources'],[])
        with closing(server.connect(self.root)) as db:
            self.assertNotIn('short-lived-test-key','\n'.join(db.iterdump()))


class DesktopSetup(unittest.TestCase):
    def setUp(self):
        import importlib.util
        launcher = Path(__file__).resolve().parents[1] / 'packaging' / 'team' / 'launcher.py'
        spec = importlib.util.spec_from_file_location('proof_desktop_setup', launcher)
        self.desktop = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.desktop)
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.directory = Path(work.name)

    def test_first_run_retries_in_dialog_and_creates_only_email_admin(self):
        responses = ['not-an-email', 'user@-broken.test', ' Owner@Fixture.Test ', 'short', PASSWORD,
                     'wrong-confirmation', PASSWORD, PASSWORD]
        def text(key):
            return self.desktop.DESKTOP_TEXT[key][0]
        with patch('tkinter.simpledialog.askstring', side_effect=responses), patch('tkinter.messagebox.showerror') as error:
            self.assertTrue(self.desktop.setup_admin(self.directory, None, 'de', text))
        self.assertEqual([call.args[1] for call in error.call_args_list],
                         [text('invalid_email')]*2+[text('invalid_password_length'), text('mismatch')])
        account,_ = server.dispatch(self.directory,'POST','/api/login',{'email':ADMIN,'password':PASSWORD})
        self.assertFalse(account['teams'][0]['legacyCases'])
        self.assertEqual(account['user']['username'], ADMIN)
        self.assertFalse(server.needs_bootstrap(self.directory))

    def test_cancel_never_leaves_a_claimable_network_listener(self):
        self.assertTrue(server.needs_bootstrap(self.directory))
        with patch('tkinter.simpledialog.askstring', side_effect=['owner@fixture.test',None]):
            self.assertFalse(self.desktop.setup_admin(self.directory, None, 'fr', lambda key:key))
        self.assertTrue(server.needs_bootstrap(self.directory))
        with self.assertRaisesRegex(ValueError, 'Initialize'):
            server.make_server(self.directory, host='127.0.0.1', port=0)
        with self.assertRaisesRegex(ValueError, 'requires TLS'):
            server.make_server(self.directory, host='0.0.0.0', port=0)


if __name__=='__main__':
    unittest.main()
