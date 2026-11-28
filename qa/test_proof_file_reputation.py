"""File-reputation isolation, consent, quota and fixed-provider contract. © Nasser Aldin Farag (0xFarag)."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from email.message import Message
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from team import file_reputation as vt, server

DIGEST = 'ac' * 32
KEY_NAME = 'AUTHZLEDGER_VT_PREMIUM_API_KEY'
KEY = 'disposable-unit-test-key-only'
SUMMARY = {'analysisDate': None, 'stats': dict.fromkeys(vt.STATS, 0)}


class Response(io.BytesIO):
    def __init__(self, body, status=200):
        super().__init__(body)
        self.status = status
        self.headers = Message()
        self.headers['Content-Type'] = 'application/json; charset=utf-8'


class Provider(unittest.TestCase):
    def request(self, raw, status=200):
        with patch.dict(os.environ, {KEY_NAME: KEY}), patch.object(vt.http.client, 'HTTPSConnection') as connect:
            conn = connect.return_value
            conn.getresponse.return_value = Response(raw, status)
            try:
                return vt.read_report(DIGEST)
            finally:
                connect.assert_called_once_with('www.virustotal.com', timeout=vt.TIMEOUT)
                conn.request.assert_called_once_with('GET', '/api/v3/files/' + DIGEST, headers={'x-apikey': KEY, 'Accept': 'application/json'})
                conn.close.assert_called_once()

    def test_provider_minimizes_checks_identity_and_preserves_uncertainty(self):
        stats = dict.fromkeys(vt.STATS, 0) | {'malicious':2,'suspicious':1}
        file = {'type':'file', 'id':DIGEST, 'attributes':{'last_analysis_stats':stats, 'last_analysis_date':1700000000,
                                                        'names':['private.exe'], 'sha256':DIGEST}}
        query = lambda payload: self.request(json.dumps({'data':payload}).encode())
        summary = query(file)
        self.assertEqual(summary['analysisDate'], '2023-11-14T22:13:20+00:00')
        self.assertEqual(summary['stats']['malicious'], 2)
        self.assertNotIn('private.exe',str(summary))
        self.assertEqual(query(file | {'attributes':{}}), SUMMARY)
        self.assertEqual(query(file | {'attributes':{'last_analysis_date':0}})['analysisDate'], '1970-01-01T00:00:00+00:00')
        for change in [{'id':'0'*64},{'type':'url'},{'attributes':{'sha256':'1'*64}},
                       {'attributes':{'last_analysis_stats':{'harmless':87}}}, {'attributes':{'last_analysis_stats':stats|{'malicious':False}}},
                       {'attributes':{'last_analysis_date':-1}}]:
            with self.subTest(change=change), self.assertRaisesRegex(vt.Error, '^vt_provider_error$'):
                query(file | change)
        for status, code in [(301,'vt_provider_error'),(401,'vt_provider_error'),(404,'vt_not_found'),(429,'vt_rate_limited')]:
            with self.subTest(status=status), self.assertRaisesRegex(vt.Error, code):
                self.request(b'private provider details', status)
        with self.assertRaisesRegex(vt.Error, 'vt_provider_error'):
            self.request(b'x'*(vt.MAX_BYTES+1))


class ReputationAccess(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name)
        self.password = 'Disposable 123 test operator password'
        server.bootstrap(self.path, 'owner', self.password)
        who, token = server.dispatch(self.path, 'POST', '/api/login', {'username':'owner','password':self.password})
        self.auth = {'token':token,'csrf':who['csrf']}
        self.team = '/api/teams/' + who['teams'][0]['id']
        self.prefix = self.team + '/file-reputation'
        self.body = {'sha256':DIGEST, 'consent':True}
        environ = patch.dict(os.environ, {KEY_NAME:KEY})
        environ.start()
        self.addCleanup(environ.stop)

    def call(self, method, path, body=None, auth=None, **kwargs):
        return server.dispatch(self.path, method, path, body, **(self.auth if auth is None else auth), **kwargs)[0]

    def test_config_roles_consent_and_cache_isolation(self):
        self.assertEqual(self.call('GET',self.prefix+'/status'), {'canLookup':True, 'configured':True})
        self.call('POST', self.team+'/members', {'username':'guest','role':'read_only','password':self.password})
        who, token = server.dispatch(self.path, 'POST', '/api/login', {'username':'guest','password':self.password})
        guest = {'token':token,'csrf':who['csrf']}
        self.assertFalse(self.call('GET',self.prefix+'/status',auth=guest)['canLookup'])
        other = '/api/teams/' + self.call('POST','/api/teams',{'name':'Other'})['team']['id'] + '/file-reputation'
        with patch.object(vt, 'read_report', return_value=SUMMARY) as reader:
            with patch.dict(os.environ,{KEY_NAME:''}):
                self.assertFalse(self.call('GET',self.prefix+'/status')['configured'])
                with self.assertRaisesRegex(vt.Error,'vt_not_configured'):
                    self.call('POST', self.prefix+'/lookup', self.body)
            for error, body, auth in [('consent_required',{'sha256':DIGEST},self.auth),('invalid_hash',{'sha256':'http://remote','consent':True},self.auth),
                    ('invalid_fields', self.body | {'file':'ignored'},self.auth),('forbidden',self.body,guest),('invalid_csrf',self.body,self.auth|{'csrf':''})]:
                with self.subTest(error=error), self.assertRaisesRegex((vt.Error,server.ApiError), error):
                    self.call('POST', self.prefix+'/lookup', body, auth)
            reader.assert_not_called()
            result = self.call('POST',self.prefix+'/lookup',self.body|{'sha256':DIGEST.upper()})
            self.assertEqual(result, {'provider':'VirusTotal','sha256':DIGEST,'cached':False,**SUMMARY})
            self.assertTrue(self.call('POST', self.prefix+'/lookup', self.body)['cached'])
            self.assertFalse(self.call('POST', other+'/lookup', self.body)['cached'])
            self.assertEqual(reader.call_count, 2)
        with closing(server.connect(self.path)) as db:
            dump = '\n'.join(db.iterdump())
            self.assertNotIn(KEY,dump)
            self.assertNotIn(DIGEST,dump)

    def test_overlapping_lookup_and_revocation_without_database_lock(self):
        member = self.call('POST',self.team+'/members',{'username':'writer','role':'pentester','password':self.password})
        who, token = server.dispatch(self.path,'POST','/api/login',{'username':'writer','password':self.password})
        auth = {'token':token,'csrf':who['csrf']}
        pending, release = threading.Event(), threading.Event()
        def lookup(digest):
            pending.set()
            self.assertTrue(release.wait(4))
            return SUMMARY
        with patch.object(vt,'read_report',side_effect=lookup) as reader, ThreadPoolExecutor(max_workers=1) as pool:
            first = pool.submit(self.call,'POST',self.prefix+'/lookup',self.body,auth)
            try:
                self.assertTrue(pending.wait(4))
                with self.assertRaisesRegex(vt.Error, 'vt_lookup_pending'):
                    self.call('POST',self.prefix+'/lookup',self.body)
                self.call('PATCH',self.team+'/members/'+member['id'],{'role':'reviewer'})
            finally:
                release.set()
            with self.assertRaisesRegex(vt.Error,'forbidden'):
                first.result(timeout=4)
            reader.assert_called_once()
        with closing(server.connect(self.path)) as db:
            self.assertIsNone(db.execute('SELECT summary FROM file_reputation_requests').fetchone()[0])

    def test_negative_cache_quota_reset_and_provider_backoff(self):
        start = 2000000000
        # Base fake time on a freshly issued session so the boundary checks apply throughout.
        who,token = server.dispatch(self.path,'POST','/api/login',{'username':'owner','password':self.password},now=start)
        self.auth = {'token':token,'csrf':who['csrf']}
        with patch.object(vt,'read_report',side_effect=vt.Error(404,'vt_not_found')) as reader:
            for n in (1,1,2,3,4):
                with self.assertRaisesRegex(vt.Error,'vt_not_found'):
                    self.call('POST',self.prefix+'/lookup',self.body|{'sha256':f'{n:064x}'},now=start)
            self.assertEqual(reader.call_count,4)
            with self.assertRaisesRegex(vt.Error,'vt_rate_limited'):
                self.call('POST',self.prefix+'/lookup',self.body,now=start+59)
        with patch.object(vt,'read_report',side_effect=vt.Error(429,'vt_rate_limited')) as reader:
            other='/api/teams/'+self.call('POST','/api/teams',{'name':'other'},now=start+60)['team']['id']+'/file-reputation'
            for prefix in (self.prefix,other):
                with self.assertRaisesRegex(vt.Error,'vt_rate_limited'):
                    self.call('POST',prefix+'/lookup',self.body,now=start+60)
            reader.assert_called_once()

    def test_installation_quota_and_team_cache_expiry(self):
        import time
        start = int(time.time())
        prefixes = [self.prefix]
        for n in range(3):
            team = self.call('POST', '/api/teams', {'name': str(n)})['team']['id']
            prefixes.append('/api/teams/' + team + '/file-reputation')
        with patch.object(vt, 'read_report', return_value=SUMMARY) as reader:
            for prefix in prefixes[:3]:
                for n in range(4):
                    self.call('POST', prefix + '/lookup', self.body | {'sha256': f'{n:064x}'}, now=start)
            with self.assertRaisesRegex(vt.Error, 'vt_rate_limited'):
                self.call('POST', prefixes[3] + '/lookup', self.body, now=start)
            self.assertEqual(reader.call_count, 12)
            url = self.prefix + '/lookup'
            body = self.body | {'sha256': '0' * 64}
            self.assertTrue(self.call('POST', url, body, now=start+299)['cached'])
            self.assertFalse(self.call('POST', url, body, now=start+300)['cached'])
            self.assertEqual(reader.call_count, 13)
