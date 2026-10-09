import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from authzledger.cli import main


class IntelligenceCliTests(unittest.TestCase):
    def test_complete_cli_graph_proof_and_retest_workflow(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            root = Path(temporary)
            self.assertEqual(main(['demo', '--out', str(root / 'demo')]), 0)
            graph = root / 'graph.json'
            self.assertEqual(main(['graph', str(root / 'demo/contract.json'), '--report', str(root / 'demo/fixed/report.json'), '--out', str(graph)]), 0)
            self.assertEqual(main(['graph', str(root / 'demo/contract.json'), '--out', str(graph)]), 2)
            self.assertEqual(main(['explain', str(graph), '--out', str(root / 'explain.json')]), 0)
            self.assertEqual(main(['keygen', '--private', str(root / 'private.pem'), '--public', str(root / 'public.pem')]), 0)
            self.assertEqual(main(['bundle', str(root / 'demo/fixed/report.json'), '--key', str(root / 'private.pem'), '--contract', str(root / 'demo/contract.json'), '--graph', str(graph), '--out', str(root / 'proof')]), 0)
            self.assertEqual(main(['verify-bundle', str(root / 'proof'), '--public-key', str(root / 'public.pem')]), 0)
            report = root / 'proof/report.json'
            value = json.loads(report.read_text())
            value['summary']['pass'] = 900
            report.write_text(json.dumps(value))
            self.assertEqual(main(['verify-bundle', str(root / 'proof'), '--public-key', str(root / 'public.pem')]), 2)
            self.assertEqual(main(['retest', str(root / 'demo/contract.json'), '--case', 'peer-cannot-read-owner', '--out', str(root / 'retest.json')]), 0)
            self.assertEqual(set(json.loads((root / 'retest.json').read_text())['dependency_ids']), {'owner-own-invoice', 'peer-own-invoice'})

    def test_invalid_graph_and_missing_history_are_configuration_errors(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stderr(io.StringIO()):
            root = Path(temporary)
            path = root / 'invalid.json'
            path.write_text('{"edges":[]}')
            self.assertEqual(main(['explain', str(path), '--out', str(root / 'explanation.json')]), 2)
            self.assertEqual(main(['history', str(root / 'absent.sqlite3')]), 2)
            self.assertFalse((root / 'absent.sqlite3').exists())
