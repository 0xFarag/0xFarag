"""Publication must fail closed on missing, stale or modified actual receipts."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import release_gate150 as gate


class Publication150Tests(unittest.TestCase):
    def receipt(self, directory):
        rows = []
        for identifier in sorted(gate.REQUIRED):
            log = directory / (identifier + '.log')
            log.write_bytes(b'fixture receipt\n')
            rows.append({'id': identifier, 'returncode': 0, 'log': log.name,
                         'log_sha256': hashlib.sha256(log.read_bytes()).hexdigest()})
        result = {'kind': 'release-verification150', 'producer_version': gate.__version__,
                  'source_digest': gate.source_digest(), 'completed': True, 'commands': rows}
        (directory / 'verification.json').write_text(json.dumps(result))
        return result

    def test_development_cannot_publish_even_with_allow_development(self):
        with patch.object(gate, '__version__', '1.5.0.dev0'):
            errors = gate.blockers(allow_development=True, publication=True)
        self.assertIn('Producer must be exactly 1.5.0 for publication.', errors)

    def test_missing_execution_and_changed_log_are_both_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            receipt = self.receipt(directory)
            receipt['commands'] = [row for row in receipt['commands'] if row['id'] != 'installed_wheel']
            (directory / 'verification.json').write_text(json.dumps(receipt))
            (directory / 'unit.log').write_text('tampered')
            errors = gate.blockers(directory, allow_development=True)
            self.assertIn('Required test, browser, demo, package or installation executions are missing.', errors)
            self.assertIn('Execution log changed: unit', errors)

    def test_sources_changed_after_success_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            receipt = self.receipt(directory)
            receipt['source_digest'] = '0' * 64
            (directory / 'verification.json').write_text(json.dumps(receipt))
            self.assertIn('Sources changed since verification; rerun the complete gate.',
                          gate.blockers(directory, allow_development=True))

    def test_nonzero_execution_or_incomplete_run_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            receipt = self.receipt(directory)
            receipt['commands'][0]['returncode'] = 1
            receipt['completed'] = False
            (directory / 'verification.json').write_text(json.dumps(receipt))
            errors = gate.blockers(directory, allow_development=True)
            self.assertIn('Verification did not complete.', errors)
            self.assertTrue(any(e.startswith('Execution failed: ') for e in errors))


if __name__ == '__main__':
    unittest.main()
