"""The publication guard must retain independent source evidence checks."""
import unittest
from unittest.mock import patch

from tools import release_gate110 as gate


class ReleaseGateTests(unittest.TestCase):
    def test_native_evidence_failure_blocks_even_a_complete_ledger(self):
        with patch.object(gate, 'check_native_burp', side_effect=ValueError('native_bytes_changed')):
            self.assertIn('Native Burp evidence: native_bytes_changed', gate.blockers())

    def test_development_producer_cannot_pass_publication(self):
        with patch.object(gate, '__version__', '1.1.0.dev0'):
            self.assertTrue(any('production 1.1.0 is not enabled' in reason for reason in gate.blockers()))

    def test_release_version_cannot_disagree_with_package_metadata(self):
        with patch.object(gate.json, 'loads', return_value={'version': '1.0.0'}):
            self.assertIn('Producer, wheel metadata and RELEASE.json versions must agree.', gate.blockers())
