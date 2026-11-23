# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Exercise the actual HTTP endpoint, SQLite transactions, cookie protocol and role boundaries."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import hashlib
import ipaddress
import ssl
from datetime import datetime,timedelta,timezone
import http.client
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest

from team import server
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

PASSWORD='Only for this isolated test 103!'

class Workspace(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.assertTrue(server.needs_bootstrap(self.root))
        server.bootstrap(self.root,'admin',PASSWORD,team_name='Alpha')
        self.assertFalse(server.needs_bootstrap(self.root))
        self.server=server.make_server(self.root,port=0)
        thread=threading.Thread(target=self.server.serve_forever,kwargs={'poll_interval':0.05},daemon=True)
        thread.start()
        self.addCleanup(thread.join,2)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.admin=self.login('admin')
        self.tid=self.admin['teams'][0]['id']

    def req(self,method,path,body=None,auth=None,headers=None):
        h=dict(headers or {})
        if auth:
            h.setdefault('Cookie',auth['cookie'])
            h.setdefault('X-CSRF-Token',auth['csrf'])
        encoded=None if body is None else json.dumps(body).encode()
        if encoded is not None: h.setdefault('Content-Type','application/json')
        with closing(http.client.HTTPConnection('127.0.0.1',self.server.server_address[1],timeout=10)) as conn:
            conn.request(method,path,body=encoded,headers=h)
            res=conn.getresponse()
            return res.status,json.loads(res.read()),res.getheaders()

    def login(self,username):
        status,data,headers=self.req('POST','/api/login',{'username':username,'password':PASSWORD})
        self.assertEqual(status,200,data)
        cookie=dict(headers)['Set-Cookie']
        self.assertIn('HttpOnly',cookie)
        self.assertIn('SameSite=Strict',cookie)
        data['cookie']=cookie.split(';')[0]
        return data

    def call(self,method,path,body=None,who=None,status=200):
        actual,value,_=self.req(method,path,body,who or self.admin)
        self.assertEqual(actual,status,value)
        return value

    def url(self,suffix,tid=None): return '/api/teams/'+(tid or self.tid)+'/'+suffix

    def create_member(self,name,role):
        return self.call('POST',self.url('members'),{'username':name,'password':PASSWORD,'role':role,'locale':'it'})['id']

    def test_bootstrap_credentials_cookie_csrf_expiry_and_restart(self):
        with self.assertRaisesRegex(server.ApiError,'already_initialized'):
            server.bootstrap(self.root,'intruder',PASSWORD)
        self.assertEqual(self.req('GET','/api/session')[0],401)
        self.assertEqual(self.req('POST','/api/login',{'username':'admin','password':'wrong'})[0],401)
        self.assertEqual(self.req('GET','/api/session',auth=self.admin,headers={'Host':'example.com'})[0],403)
        self.assertEqual(self.req('PATCH','/api/me',{'locale':'fr'},self.admin,{'Origin':'https://example.com'})[0],403)
        self.assertEqual(self.req('PATCH','/api/me',{'locale':'fr'},self.admin,{'X-CSRF-Token':'no'})[0],403)
        self.call('PATCH','/api/me',{'locale':'fr'})
        self.assertEqual(self.call('GET','/api/session')['user']['locale'],'fr')
        token=self.admin['cookie'].split('=',1)[1]
        with closing(server.connect(self.root)) as db:
            row=db.execute('SELECT password_hash FROM users LIMIT 1').fetchone()
            self.assertNotIn(PASSWORD,row['password_hash'])
            self.assertEqual(db.execute('SELECT token_hash FROM sessions').fetchone()[0],hashlib.sha256(token.encode()).hexdigest())
            db.execute('UPDATE sessions SET last_seen=?',(int(time.time())-server.IDLE_LIFETIME,))
        self.assertEqual(self.req('GET','/api/session',auth=self.admin)[0],401)
        self.admin=self.login('admin')
        self.call('POST','/api/logout',{})
        self.assertEqual(self.req('GET','/api/session',auth=self.admin)[0],401)

    def test_roles_audit_and_team_isolation(self):
        second=self.call('POST','/api/teams',{'name':'Beta'})['team']['id']
        for role in ('lead_pentester','pentester','reviewer','read_only'):
            with self.subTest(role=role):
                self.create_member(role,role)
                account=self.login(role)
                self.assertEqual(account['teams'],[{'id':self.tid,'name':'Alpha','role':role}])
                self.call('GET',self.url('cases'),who=account)
                self.call('GET',self.url('cases',second),who=account,status=404)
                self.call('GET',self.url('members'),who=account,status=403)
                self.call('GET',self.url('audit'),who=account,status=200 if role in server.REVIEWERS else 403)
                self.call('POST','/api/teams',{'name':'New'},who=account,status=403)
                self.call('POST',self.url('cases'),{'title':'Review','scope':'sample.test','assets':['sample.test']},
                          who=account,status=200 if role in server.WRITERS else 403)
                attachment_path=self.url('cases/unknown/imports/unknown/attachment')
                self.call('GET',attachment_path,who=account,status=404 if role in server.WRITERS else 403)
                if role not in server.WRITERS:
                    for suffix in ('imports','finding','retest'):
                        self.call('POST',self.url('cases/unknown/'+suffix),{},who=account,status=403)
                if role not in server.REVIEWERS:
                    self.call('POST',self.url('cases/unknown/handover'),{},who=account,status=403)
        events=self.call('GET',self.url('audit'))['events']
        self.assertTrue(any(e['outcome']=='denied' and e['actor']=='read_only' for e in events))
        self.assertTrue(any(e['action']=='post.cases' and e['outcome']=='ok' for e in events))
        self.assertFalse(any('Beta' in str(event) for event in events))
        with closing(server.connect(self.root)) as db:
            with self.assertRaises(sqlite3.IntegrityError): db.execute('DELETE FROM audit_events')

    def test_existing_accounts_revocation_and_last_admin(self):
        alice=self.create_member('alice','lead_pentester')
        a=self.login('alice')
        second=self.call('POST','/api/teams',{'name':'Beta'})['team']['id']
        self.call('POST',self.url('members',second),{'username':'alice','password':'Cannot overwrite other user!','role':'admin'},status=409)
        self.call('POST',self.url('members',second),{'username':'alice','role':'reviewer'})
        self.call('PATCH',self.url('members/'+alice),{'role':'read_only'})
        self.call('POST',self.url('cases'),{'title':'Example','scope':'example.test'},who=a,status=403)
        self.call('PATCH',self.url('members/'+alice),{'active':False})
        self.call('GET',self.url('cases'),who=a,status=404)
        self.assertEqual(self.call('GET','/api/session',who=a)['teams'][0]['role'],'reviewer')
        self.call('PATCH',self.url('members/'+self.admin['user']['id']),{'active':False},status=409)
        self.call('PATCH',self.url('members/'+alice,second),{'active':False})
        self.assertEqual(self.req('GET','/api/session',auth=a)[0],401)

    def test_concurrent_member_creation_and_account_throttle(self):
        task=lambda unused:self.req('POST',self.url('members'),{'username':'colleague','password':PASSWORD,'role':'reviewer'},self.admin)[0]
        with ThreadPoolExecutor(max_workers=3) as workers:
            self.assertEqual(sorted(workers.map(task,range(3))),[200,409,409])
        with closing(server.connect(self.root)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM users WHERE username='colleague'").fetchone()[0],1)
        for _ in range(10):
            self.assertEqual(self.req('POST','/api/login',{'username':'colleague','password':'incorrect'})[0],401)
        self.assertEqual(self.req('POST','/api/login',{'username':'colleague','password':PASSWORD})[0],429)
        self.assertEqual(self.req('POST','/api/login',{'username':'admin','password':PASSWORD})[0],200)
        with self.assertRaisesRegex(ValueError,'TLS'):
            server.make_server(self.root,host='0.0.0.0',port=0)

    def test_real_tls_transport_and_password_rotation(self):
        key=ec.generate_private_key(ec.SECP256R1())
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
        now=datetime.now(timezone.utc)
        cert=(x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
              .public_key(key.public_key()).serial_number(x509.random_serial_number())
              .not_valid_before(now-timedelta(minutes=1)).not_valid_after(now+timedelta(hours=1))
              .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
              .sign(key,hashes.SHA256()))
        certfile=self.root/'certificate.pem'
        keyfile=self.root/'private.pem'
        certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        with server.make_server(self.root,port=0,certfile=certfile,keyfile=keyfile) as tls:
            thread=threading.Thread(target=tls.serve_forever,kwargs={'poll_interval':0.05},daemon=True)
            thread.start()
            try:
                context=ssl.create_default_context(cafile=str(certfile))
                with closing(http.client.HTTPSConnection('127.0.0.1',tls.server_address[1],context=context,timeout=4)) as conn:
                    conn.request('POST','/api/login',json.dumps({'username':'admin','password':PASSWORD}),{'Content-Type':'application/json'})
                    response=conn.getresponse()
                    self.assertEqual(response.status,200)
                    self.assertIn('__Host-authz_session_',response.getheader('Set-Cookie'))
                    self.assertIn('; Secure',response.getheader('Set-Cookie'))
                    self.assertIn('max-age',response.getheader('Strict-Transport-Security'))
                    response.read()
            finally:
                tls.shutdown()
                thread.join(2)
        self.call('PATCH','/api/me',{'current_password':'bad','password':'Replacement phrase test 1019'},status=403)
        self.assertTrue(self.call('PATCH','/api/me',{'current_password':PASSWORD,'password':'Replacement phrase test 1019'})['reauthenticate'])
        self.assertEqual(self.req('GET','/api/session',auth=self.admin)[0],401)
        self.assertEqual(self.req('POST','/api/login',{'username':'admin','password':PASSWORD})[0],401)
