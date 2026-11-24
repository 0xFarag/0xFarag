# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Exercise key history through the authenticated dispatcher and its commit boundary."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from team import keyring, server


class TeamKeyRoutes(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.folder = Path(directory.name)
        self.password = 'Isolated install test only'
        server.bootstrap(self.folder, 'admin', self.password)
        self.admin, self.base = self.login('admin')

    def login(self, name):
        session, token = server.dispatch(self.folder, 'POST', '/api/login', {
            'username': name, 'password': self.password
        })
        return {'token': token, 'csrf': session['csrf']}, '/api/teams/' + session['teams'][0]['id']

    def call(self, method, route, body=None, account=None):
        return server.dispatch(self.folder, method, route, body, **(account or self.admin))[0]

    def test_key_reads_require_membership_and_cannot_change_trust(self):
        self.call('POST', self.base + '/members', {
            'username': 'reader', 'role': 'read_only', 'password': self.password, 'locale': 'en'
        })
        reader, _ = self.login('reader')
        history = self.call('GET', self.base + '/trust-keys', account=reader)
        current = self.call('GET', self.base + '/trust-key', account=reader)
        self.assertEqual(set(current), {'algorithm', 'public_key', 'fingerprint'})
        self.assertEqual(current['fingerprint'], history['active_fingerprint'])
        other = self.call('POST', '/api/teams', {'name': 'Other'})['team']['id']
        with self.assertRaises(server.ApiError) as denied:
            self.call('GET', '/api/teams/' + other + '/trust-keys', account=reader)
        self.assertEqual(denied.exception.status, 404)
        with self.assertRaises(server.ApiError) as rejected:
            self.call('POST', self.base + '/trust-keys', current, account=reader)
        self.assertEqual(rejected.exception.status, 404)
        audit = self.call('GET', self.base + '/audit')['events']
        self.assertTrue(any(e['actor'] == 'reader' and e['action'] == 'get.trust-keys' for e in audit))

    def test_rotation_commits_once_and_retries_private_key_cleanup(self):
        route = self.base + '/trust-keys'
        case = self.call('POST', self.base + '/cases', {
            'title': 'Signed handover', 'scope': 'Local records', 'assets': ['example.test']
        })['case']
        handover = self.base + '/cases/' + case['id'] + '/handover'
        with patch.object(keyring, 'unix_time', return_value=1_700_000_000):
            first = self.call('POST', handover, {'language': 'de', 'format': 'json'})['package']
        with patch.object(keyring, 'unix_time', return_value=1_700_000_000 + keyring.PERIOD):
            with patch.object(keyring, 'prune_committed', side_effect=PermissionError('cleanup unavailable')):
                with self.assertLogs('team.server', level='WARNING'):
                    second = self.call('POST', handover, {'language': 'en', 'format': 'json'})['package']
            old, new = [p['manifest']['fingerprint'] for p in (first, second)]
            self.assertNotEqual(old, new)
            self.assertTrue((self.folder/'evidence-signing.key').is_file())
            history = self.call('GET', route)
            self.assertEqual({key['fingerprint'] for key in history['keys']}, {old, new})
            self.assertEqual(history['active_fingerprint'], new)
            self.assertFalse((self.folder/'evidence-signing.key').exists())
            for package in (first, second):
                self.assertTrue(self.call('POST', self.base + '/verify', {'package': package})['valid'])
        audit = self.call('GET', self.base + '/audit')['events']
        self.assertEqual(sum(e['action'] == 'post.handover' and e['outcome'] == 'ok' for e in audit), 2)
