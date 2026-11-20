"""Retained offline source claims, optimistic revisions, bounded scope and revalidation."""
import copy
import json
import runpy
import socket
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from authzledger.federation_offline import project_federation
from authzledger.federation_records import KIND, federation_preview_digest
from authzledger.oracles import seal
from authzledger.platform_reports import freeze_platform, render_platform_html, verify_platform
from authzledger.workbench import WorkbenchStore, WorkbenchService
from tests.test_federation_offline import NMAP, SCOPE, ffuf, match
from tests.test_scope150 import scope


def policy(services=SCOPE, **changes):
    operations = [{'origin': s, 'path': '/', 'method': 'CONNECT', 'purpose': 'service'} for s in services]
    return scope(services[0], operations, origins=list(services), allowed_networks=['192.0.2.0/24'], **changes)


class FederationRetentionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.db = Path(self.directory.name) / 'workspace.sqlite'
        self.store = WorkbenchStore(self.db)
        self.addCleanup(self.store.close)
        self.service = WorkbenchService(self.store)
        self.assessment = self.service.create('Offline inventory', policy())
        self.aid = self.assessment['id']
        self.sources = [('nmap', NMAP), ('ffuf', ffuf(length=0)), ('nuclei', match())]

    def retain(self, *, revision=1, sources=None, **options):
        return self.service.retain_federation(self.aid, SCOPE, self.sources if sources is None else sources,
                                             expected_revision=revision, **options)

    def test_preview_binding_atomic_idempotent_restart_and_report(self):
        expected = federation_preview_digest(project_federation(SCOPE, self.sources))
        with (patch.object(socket, 'socket', side_effect=AssertionError('network')),
              patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS')),
              patch.object(subprocess, 'Popen', side_effect=AssertionError('process'))):
            one = self.retain(preview_digest=expected)
            self.assertEqual(self.retain(preview_digest=expected), one)
            self.assertEqual(self.retain(revision=2), one)
            with WorkbenchStore(self.db) as other:
                reopened = WorkbenchService(other)
                stored = reopened.get(self.aid)
                self.assertEqual(stored['assessment']['revision'], 2)
                self.assertEqual(stored['artifacts'], [one])
                snapshot = reopened.report(self.aid)
        self.assertEqual(verify_platform(snapshot), [])
        self.assertEqual(snapshot['inventory'][0]['source_digest'], one['value']['receipt_digest'])
        self.assertEqual(snapshot['findings'][0]['status'], 'hint')
        self.assertEqual(snapshot['findings'][0]['controls'], [])
        self.assertEqual(snapshot['findings'][0]['retest_status'], 'not_retested')
        self.assertEqual(snapshot['coverage'][0]['activity'], 'retained_offline')
        self.assertIn('Bound source inventory', render_platform_html(snapshot))
        self.assertEqual(len(one['value']['catalog']['endpoints']), 1)

    def test_two_connections_same_revision_retry_one_append(self):
        with WorkbenchStore(self.db) as peer, ThreadPoolExecutor(max_workers=2) as pool:
            services = [self.service, WorkbenchService(peer)]
            futures = [pool.submit(s.retain_federation, self.aid, SCOPE, self.sources,
                                   expected_revision=1) for s in services]
            self.assertEqual(futures[0].result(), futures[1].result())
        self.assertEqual(len(self.store.artifacts(self.aid)), 1)
        self.assertEqual(self.store.get(self.aid)['revision'], 2)

    def test_both_verifiers_accept_bound_content_and_reject_one_changed_payload_byte(self):
        from authzledger.signing import generate_keypair, verify_bundle
        self.retain()
        folder = Path(self.directory.name)
        private, public = folder / 'private.pem', folder / 'public.pem'
        generate_keypair(private, public)
        package = folder / 'package'
        self.service.report(self.aid, out=package, key=private, formats=('json', 'html'))
        independent = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'tools/verify_bundle.py'))['verify_bundle']
        for verify in (verify_bundle, independent):
            self.assertEqual(verify(package, public), [])
        target = package / 'attachments' / 'platform.json'
        data = bytearray(target.read_bytes())
        data[len(data) // 2] ^= 1
        target.write_bytes(data)
        for verify in (verify_bundle, independent):
            self.assertTrue(verify(package, public))

    def test_bad_source_preview_change_and_stale_edit_leave_no_partial_append(self):
        for sources, options in [(self.sources, {'preview_digest': '0' * 64}),
                                 ([*self.sources[:1], ('ffuf', b'invalid')], {}),
                                 (self.sources, {'revision': None})]:
            with self.assertRaises(ValueError):
                self.retain(sources=sources, **options)
        self.assertEqual(self.store.snapshot(self.aid)[1], [])
        self.retain()
        with self.assertRaisesRegex(ValueError, 'revision_conflict'):
            self.retain(sources=[('ffuf', ffuf(length=123))])
        self.assertEqual(len(self.store.artifacts(self.aid)), 1)

    def test_scope_requires_exact_service_network_and_no_deny(self):
        policies = [policy(['tcp://192.0.2.10:444']), policy(denied_networks=['192.0.2.10/32']),
                    scope('https://192.0.2.10', allowed_networks=['192.0.2.0/24'])]
        for scoped in policies:
            aid = self.service.create('Different policy', scoped)['id']
            with self.assertRaisesRegex(ValueError, 'outside_assessment_scope'):
                self.service.retain_federation(aid, SCOPE, self.sources, expected_revision=1)
            self.assertEqual(self.store.artifacts(aid), [])

    def test_ffuf_method_and_rejected_request_context_are_preserved(self):
        source = json.loads(ffuf())
        source['config'] = {'method': 'HEAD'}
        receipt = self.retain(sources=[('ffuf', json.dumps(source).encode())])
        self.assertEqual(receipt['value']['sources'][0]['records'][0]['asserted']['method'], 'HEAD')
        source['config']['headers'] = {'x-fixture': 'free-text'}
        receipt = self.retain(revision=2, sources=[('ffuf', json.dumps(source).encode())])
        self.assertEqual(receipt['value']['sources'][0]['records'][0],
                         {'locator': '/results/0', 'disposition': 'unsupported_request_context'})

    def test_hash_only_free_text_and_all_omissions_remain_visible(self):
        secret = 'FreeStringNoKeyword'
        sources = [('ffuf', ffuf(url='https://192.0.2.10/' + secret)),
                   ('nuclei', match(**{'matcher-name': secret}) + b'\n' + match(request=secret.encode().hex()))]
        record = self.retain(sources=sources)
        serialized = json.dumps(self.service.report(self.aid))
        self.assertNotIn(secret, serialized)
        self.assertNotIn(secret.encode().hex(), serialized)
        self.assertEqual(record['value']['catalog']['omitted_records'], 1)
        self.assertEqual(record['value']['sources'][1]['records'][1],
                         {'locator': 'line:2', 'disposition': 'unsupported_raw_record'})

    def test_rehashed_invalid_source_catalog_scope_and_foreign_assessment_rejected(self):
        original = self.retain()['value']
        for edit in [
            lambda v: v['catalog']['source_hints'][0].update(evidence_level='confirmed'),
            lambda v: v['sources'][0]['records'][0]['asserted'].update(name='secret'),
            lambda v: v['sources'][1]['records'][0]['asserted'].update(length=False),
            lambda v: v['sources'][1]['records'][0].update(service='tcp://192.0.2.10:444'),
            lambda v: v['sources'][2]['records'][0].update(locator='line:0'),
            lambda v: v['sources'][2]['records'][0]['asserted'].update(template_id_digest=None),
            lambda v: v.update(assessment_id='other'),
            lambda v: v['allowed_services'].append('tcp://192.0.2.10:444'),
        ]:
            value = copy.deepcopy(original)
            edit(value)
            forged = seal(KIND, value, 'receipt_digest')
            with self.assertRaises(ValueError):
                freeze_platform(self.assessment, [{'artifact_id': 'federation-test', 'value': forged}])

    def test_new_freeze_revalidates_current_scope_and_old_frozen_view_remains_valid(self):
        self.retain()
        snapshot = self.service.report(self.aid)
        self.service.update(self.aid, {'scope': policy(['tcp://192.0.2.10:444'])}, 2)
        self.assertEqual(verify_platform(snapshot), [])
        with self.assertRaisesRegex(ValueError, 'outside_assessment_scope'):
            self.service.report(self.aid)
        self.assertEqual(len(self.store.artifacts(self.aid)), 1)
