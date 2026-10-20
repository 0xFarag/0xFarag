"""End-to-end loopback proof: real requests, persistence and isolated verification."""
import json
from pathlib import Path
import tempfile
import unittest

from authzledger.demo150 import run_demos
from authzledger.signing import verify_bundle
from authzledger.platform_reports import verify_platform


class PlatformDemoTests(unittest.TestCase):
    def test_three_real_demos_and_tamper_boundary(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'demos'
            result = run_demos(output, standalone_verifier=root / 'tools' / 'verify_bundle.py', formats=('json', 'html'))
            self.assertEqual(result, json.loads((output / 'results.json').read_text()))
            self.assertEqual(result['demos']['A']['confirmed'], 'confirmed')
            self.assertEqual(result['demos']['A']['invalid_controls'], 'inconclusive')
            self.assertEqual(result['demos']['A']['error_200'], 'rejected')
            self.assertEqual(result['demos']['B']['service_connections_observed'], 1)
            self.assertEqual(result['demos']['B']['finding_status'], 'confirmed')
            self.assertEqual([t['status'] for t in result['demos']['C']['transitions']], ['fix_verified', 'not_retested'])
            self.assertTrue(result['workspace_reopened'])
            self.assertTrue(result['fixture_stopped_before_export'])
            self.assertEqual(result['standalone_verification']['returncode'], 0)
            self.assertNotEqual(result['tamper']['standalone']['returncode'], 0)
            self.assertEqual(result['tamper']['changed_bytes'], 1)
            self.assertFalse(result['private_key_retained'])
            for demo in result['demos'].values():
                self.assertEqual(demo['network_operations_observed'], demo['execution_ledger']['dispatched_total'])
                self.assertLessEqual(demo['execution_ledger']['dispatched_total'], demo['limits']['max_requests'])
            self.assertEqual(result['total_network_operations_observed'], result['total_http_requests_observed'] + result['total_service_connections_observed'])
            for name in ('A-authorization', 'B-discovery-detect', 'C-retest-proof'):
                self.assertEqual(verify_platform(json.loads((output / name / 'snapshot.json').read_text())), [])
            self.assertEqual(verify_bundle(output / 'C-retest-proof' / 'proof', output / 'trusted-public.pem'), [])
            self.assertTrue(verify_bundle(output / 'C-retest-proof' / 'tampered-proof', output / 'trusted-public.pem'))
            with self.assertRaises(FileExistsError):
                run_demos(output, standalone_verifier=root / 'tools' / 'verify_bundle.py', formats=('json',))

    def test_missing_independent_verifier_does_not_fake_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'must-not-exist'
            with self.assertRaisesRegex(ValueError, 'Independent verifier file required'):
                run_demos(output, standalone_verifier=Path(temporary) / 'missing.py')
            self.assertFalse(output.exists())
