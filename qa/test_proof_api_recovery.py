# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Perform the documented closed-server restore drill in isolated directories."""
import base64
from contextlib import closing
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from team import proof_packages, server


@unittest.skipUnless(shutil.which('tar') and shutil.which('sha256sum'), 'Linux backup toolchain')
class Recovery(unittest.TestCase):
    def test_cold_restore_and_independent_pin(self):
        with tempfile.TemporaryDirectory() as work:
            source=Path(work)/'source'
            backup=Path(work)/'backup'
            restored=Path(work)/'restored'
            backup.mkdir(mode=0o700)
            restored.mkdir(mode=0o700)
            credentials={'email':'restore@example.test', 'password':'Test placeholder phrase 7061'}
            server.bootstrap(source, credentials['email'], credentials['password'])

            def login(location):
                session,token=server.dispatch(location,'POST','/api/login',credentials)
                return {'token':token,'csrf':session['csrf']}, session['teams'][0]['id']

            first,tid=login(source)
            route='/api/teams/'+tid+'/proof'
            def post(location, endpoint, body, auth):
                return server.dispatch(location, 'POST', endpoint, body, **auth)[0]
            run=post(source,route,{'mode':'lab'},first)['run']
            run_route=route+'/'+run['id']
            run=post(source,run_route+'/sign',{'version':run['version'],'language':'de'},first)['run']
            archive_id={'packageId':run['signed'][0]['id']}
            original=base64.b64decode(post(source,run_route+'/export',archive_id,first)['archive_b64'])
            keys=server.dispatch(source,'GET',route+'/keys',**first)[0]['keys']
            pinned=next(key['jwk'] for key in keys if key['keyId']==run['signed'][0]['keyId'])

            subprocess.run(['tar','-cpf',str(backup/'team-data.tar'),'-C',str(source),'.'],check=True)
            with (backup/'team-data.tar.sha256').open('wb') as sums:
                subprocess.run(['sha256sum','team-data.tar'],cwd=backup,check=True,stdout=sums)
            subprocess.run(['sha256sum','-c','team-data.tar.sha256'],cwd=backup,check=True,capture_output=True)
            subprocess.run(['tar','-xpf',str(backup/'team-data.tar'),'-C',str(restored)],check=True)
            with closing(server.connect(restored)) as db:
                self.assertEqual(db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
                self.assertIsNone(db.execute('PRAGMA foreign_key_check').fetchone())
                db.execute('DELETE FROM proof_import_tokens')
                db.execute('DELETE FROM sessions')

            with self.assertRaisesRegex(server.ApiError, 'unauthenticated'):
                server.dispatch(restored,'GET','/api/session',**first)
            second,restored_tid=login(restored)
            self.assertEqual(tid,restored_tid)
            recovered=base64.b64decode(post(restored,run_route+'/export',archive_id,second)['archive_b64'])
            self.assertEqual(recovered,original)
            proof_packages.verify_package(recovered,pinned,workspace=tid)
            rerun=post(restored,run_route+'/sign',{'version':run['version'],'language':'fr'},second)['run']
            self.assertEqual(rerun['signed'][0]['keyId'],run['signed'][0]['keyId'])
            fresh=base64.b64decode(post(restored,run_route+'/export',{'packageId':rerun['signed'][0]['id']},second)['archive_b64'])
            self.assertEqual(proof_packages.verify_package(fresh,pinned,workspace=tid)['language'],'fr')
