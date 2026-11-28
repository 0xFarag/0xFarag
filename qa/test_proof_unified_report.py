"""Management and signed reports for mixed offline sources. © Nasser Aldin Farag (0xFarag)."""
import base64
from contextlib import closing
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from zipfile import ZipFile

from team import proof_packages, server

FIXTURES = Path(__file__).parent / 'fixtures'


class UnifiedReports(unittest.TestCase):
    def test_report_counts_persist_per_source_and_preserve_observation_meaning(self):
        with tempfile.TemporaryDirectory() as root:
            server.bootstrap(root, 'admin@example.test', 'Disposable local report passphrase')
            session, token = server.dispatch(root, 'POST', '/api/login',
                                             {'email':'admin@example.test', 'password':'Disposable local report passphrase'})
            team = session['teams'][0]['id']
            def call(method, path, body=None):
                return server.dispatch(root, method, path, body, token=token, csrf=session['csrf'])[0]
            base = f'/api/teams/{team}/proof'
            run = call('POST', base, {'mode':'commercial', 'hosts':['corp.example'], 'roe':'Inventory review', 'budget':20})['run']
            path = base + '/' + run['id']
            report_url = path + '/management-report'
            self.assertNotIn('graphInventory', call('GET', report_url)['report'])

            graph = (FIXTURES/'neo4j-inventory.jsonl').read_bytes()
            csv = (b'Target URL,Place,Parameter,Technique(s),Note(s)\n'
                   b'https://corp.example/private,GET,private_id,B,\n'
                   b'https://corp.example/private,GET,private_id,B,false positive or unexploitable\n'
                   b'https://corp.example/other,,,,\n'
                   b'https://outside.example/private,GET,private_id,B,\n')
            for fmt, raw in [('bloodhound',(FIXTURES/'bloodhound-groups.json').read_bytes()), ('neo4j',graph),
                             ('neo4j',graph.replace(b'corp.example',b'outside.example')), ('sqlmap',csv)]:
                run = call('POST', path+'/import', {'format':fmt, 'content_b64':base64.b64encode(raw).decode(),
                                                    'version':run['version']})['run']
            summary = call('GET', report_url)['report']
            self.assertEqual(summary['graphInventory']['byFormat'], {
                'bloodhound':{'observedNodes':1,'referencedNodes':1,'relationships':1},
                'neo4j':{'observedNodes':2,'referencedNodes':0,'relationships':1}})
            self.assertEqual(summary['sqlmapResults'], {'reported':1, 'disputed':1, 'noTechniqueReported':1})
            self.assertEqual(summary['baseline']['byStatus']['confirmed'], 0)
            self.assertNotIn('sqlmapResults', call('GET', report_url+'/2')['report'])
            for private in ('private_id', 'S-1-5-', 'private-group', 'corp.example', 'outside.example'):
                self.assertNotIn(private, json.dumps(summary))
            signed = call('POST', path+'/sign', {'version':run['version'], 'language':'en'})['run']
            encoded = call('POST', path+'/export', {'packageId':signed['signed'][0]['id']})['archive_b64']
            self.assertTrue(call('POST', path+'/verify', {'archive_b64':encoded})['valid'])
            with ZipFile(BytesIO(base64.b64decode(encoded))) as archive:
                signed_body = json.loads(archive.read('report.json'))
                html = archive.read('report.html').split(b'<details>',1)[0]
                for text in (b'Object reference', b'Declared object', b'MemberOf', b'Tool-reported signal',
                             b'Disputed by the tool', b'No technique reported'):
                    self.assertIn(text, html)
                self.assertNotIn(b'HTTP ?', html)
                # Both human-readable documents and the archive verification use this projection.
                self.assertEqual(proof_packages.render_pdf(signed_body), archive.read('report.pdf'))
            with closing(server.connect(root)) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM proof_management_reports').fetchone()[0], 6)


if __name__ == '__main__':
    unittest.main()
