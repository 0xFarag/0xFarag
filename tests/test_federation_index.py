"""The mixed-source index binds exactly one intact snapshot and grants no coverage."""
import copy
import json
import socket
import subprocess
import unittest
from unittest.mock import patch

from authzledger.federation_index import build_surface_index
from authzledger.oracles import canonical, digest, pointer, seal
from authzledger.platform_reports import freeze_platform
from authzledger.workbench import WorkbenchService, WorkbenchStore
from tests.test_federation_offline import NMAP, SCOPE, TARGET, ffuf, match
from tests.test_scope150 import scope


def har(entries):
    return json.dumps({'log': {'version': '1.2', 'entries': [
        {'request': {'url': url, 'method': method}, 'response': {'status': 200}} for url, method in entries
    ]}}).encode()


class FederationIndexTests(unittest.TestCase):
    def setUp(self):
        self.store = WorkbenchStore()
        self.addCleanup(self.store.close)
        self.service = WorkbenchService(self.store)
        self.origin = 'https://192.0.2.10'
        self.declared = [self.origin, SCOPE[0], 'https://other.example', 'http://192.0.2.10:443']
        self.policy = scope(self.origin, origins=self.declared, operations=[
            {'origin': SCOPE[0], 'method': 'CONNECT', 'path': '/', 'purpose': 'service'},
            {'origin': self.origin, 'method': 'GET', 'path': '/docs', 'purpose': 'application'}
        ], allowed_networks=['192.0.2.0/24'])
        self.aid = self.service.create('Local inventory', self.policy)['id']

    def legacy(self, entries):
        return self.service.import_source(self.aid, har(entries), 'har-1.2')

    def retained(self, sources=None):
        return self.service.retain_federation(self.aid, SCOPE, sources or [('nmap', NMAP), ('ffuf', ffuf()),
            ('nuclei', match() + b'\n' + match(False))], expected_revision=self.store.get(self.aid)['revision'])

    def test_real_mixed_freeze_no_network_and_no_mutation(self):
        self.legacy([(TARGET, 'GET')])
        self.retained()
        snap = self.service.report(self.aid)
        original = canonical(snap)
        with (patch.object(socket, 'socket', side_effect=AssertionError('network')),
              patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS')),
              patch.object(subprocess, 'Popen', side_effect=AssertionError('process'))):
            index = build_surface_index(snap)
            self.assertEqual(index, build_surface_index(snap))
        self.assertEqual(canonical(snap), original)
        self.assertEqual(index['index_digest'], digest('federated-surface-index', index, 'index_digest'))
        self.assertEqual(index['snapshot_digest'], snap['snapshot_digest'])
        self.assertEqual(index['summary'], {'services': 1, 'endpoints': 1, 'observations': 5,
                         'omissions': 0, 'mixed_services': 1, 'mixed_endpoints': 1})
        self.assertNotIn('/docs', canonical(index).decode())
        self.assertNotIn('confirmed', canonical(index).decode())
        self.assertEqual(index['endpoints'][0]['source_families'], ['legacy_surface', 'offline_federation'])
        raw = {a['artifact_id']: a['value'] for a in snap['artifacts']}
        for obs in index['observations']:
            for ref in obs['artifact_refs']:
                self.assertTrue(pointer(raw[ref['artifact_id']], ref['pointer'])[0])
        legacy = next(o for o in index['observations'] if o['source_family'] == 'legacy_surface')
        self.assertEqual(len(legacy['artifact_refs']), 2)  # The HAR and its materialised catalogue.
        self.assertEqual(legacy['method'], 'GET')
        self.assertIsNone(next(o for o in index['observations'] if o['source_kind'] == 'ffuf')['method'])
        negative = next(o for o in index['observations'] if o['asserted'].get('matched') is False)
        self.assertIsNone(negative['evidence_level'])

    def test_legacy_only_freeze_scope_and_omissions(self):
        self.legacy([(TARGET, 'GET'), ('https://198.51.100.10/PRIVATE_CANARY', 'GET')])
        snap = self.service.report(self.aid)
        index = build_surface_index(snap)
        self.assertEqual(index['summary']['observations'], 1)
        self.assertEqual(index['summary']['mixed_services'], 0)
        self.assertEqual(index['omissions'][0]['reason'], 'outside_snapshot_scope')
        self.assertNotIn('PRIVATE_CANARY', canonical(index).decode())
        self.assertEqual(index['omissions'][0]['source_ref']['reference_count'], 1)

    def test_protocol_name_path_and_method_identity_stay_separate(self):
        self.legacy([(TARGET, 'GET'), (TARGET, 'POST'), ('https://other.example/docs', 'GET'),
                     ('http://192.0.2.10:443/docs', 'GET'), (TARGET + '?a=1', 'GET')])
        self.retained([('ffuf', ffuf())])
        index = build_surface_index(self.service.report(self.aid))
        self.assertEqual(index['summary']['services'], 2)
        self.assertEqual(index['summary']['endpoints'], 3)
        self.assertIn('incomplete_target_binding', {o['reason'] for o in index['omissions']})
        self.assertEqual(index['summary']['mixed_endpoints'], 1)
        shared = next(e for e in index['endpoints'] if len(e['source_families']) == 2)
        methods = [o['method'] for o in index['observations'] if o['endpoint_id'] == shared['id']]
        self.assertCountEqual(methods, ['GET', 'POST', None])
        post = next(o for o in index['observations'] if o['method'] == 'POST')
        self.assertEqual(post['scope_state'], 'operation_not_authorized')

    def test_exclusion_cannot_be_reintroduced_by_cumulative_catalog(self):
        original = self.legacy([(TARGET, 'GET')])
        self.retained()
        meta, artifacts = self.store.snapshot(self.aid)
        for a in artifacts:
            if a['artifact_id'] == original['artifact_id']:
                a.update(included=False, exclusion_reason='operator excluded raw source')
        index = build_surface_index(freeze_platform(meta, artifacts))
        self.assertEqual(index['summary']['mixed_services'], 0)
        self.assertNotIn('legacy_surface', index['endpoints'][0]['source_families'])
        self.assertEqual({o['reason'] for o in index['omissions']}, {'excluded_artifact', 'excluded_source'})

    def test_same_locator_in_two_different_originals_preserves_both_assertions(self):
        one = self.retained([('ffuf', ffuf(length=10))])
        two = self.retained([('ffuf', ffuf(length=11))])
        self.assertNotEqual(one['artifact_id'], two['artifact_id'])
        index = build_surface_index(self.service.report(self.aid))
        self.assertEqual(index['summary']['endpoints'], 1)
        self.assertCountEqual([o['asserted']['length'] for o in index['observations']], [10, 11])
        self.assertEqual(len({o['source_ref']['sha256'] for o in index['observations']}), 2)
        self.assertEqual(len({o['id'] for o in index['observations']}), 2)

    def test_forged_snapshot_rejected_and_equal_origins_in_other_assessment_have_distinct_ids(self):
        self.legacy([(TARGET, 'GET')])
        snap = self.service.report(self.aid)
        origin_id = build_surface_index(snap)['services'][0]['id']
        second = self.service.create('Another inventory', self.policy)['id']
        self.service.import_source(second, har([(TARGET, 'GET')]), 'har-1.2')
        self.assertNotEqual(build_surface_index(self.service.report(second))['services'][0]['id'], origin_id)
        fake = copy.deepcopy(snap)
        fake['inventory'][0]['source_digest'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'invalid_platform_snapshot'):
            build_surface_index(seal('platform-snapshot', fake, 'snapshot_digest'))

    def test_legacy_adapters_match_materialised_catalog_without_double_counting(self):
        self.service.import_source(self.aid, NMAP, 'nmap-xml-v1')
        self.retained([('nmap', NMAP)])
        index = build_surface_index(self.service.report(self.aid))
        self.assertEqual(index['summary']['observations'], 2)
        self.assertEqual(index['summary']['mixed_services'], 1)
        self.assertEqual(index['summary']['endpoints'], 0)
        self.assertEqual(index['observations'][0]['evidence_level'], 'hint')

    def test_conflicting_burp_targets_and_invalid_path_are_explained_without_join_or_disclosure(self):
        for wire in (b'GET /docs HTTP/1.1\r\nHost: outside.example\r\n\r\n',
                     b'GET https://outside.example/docs HTTP/1.1\r\nHost: 192.0.2.10\r\n\r\n',
                     b'GET /private%ZZ HTTP/1.1\r\nHost: 192.0.2.10\r\nAuthorization: Bearer CANARY_PRIVATE\r\n\r\n'):
            self.service.import_source(self.aid, wire, 'burp-http-pair-v1', source_origin=self.origin)
        self.retained([('ffuf', ffuf())])
        snap = self.service.report(self.aid)
        index = build_surface_index(snap)
        self.assertEqual(index['summary']['mixed_endpoints'], 0)
        self.assertEqual(index['summary']['observations'], 1)
        self.assertCountEqual([row['reason'] for row in index['omissions']],
                              ['ambiguous_target_binding', 'ambiguous_target_binding', 'unresolved_source_record'])
        raw = {a['artifact_id']: a['value'] for a in snap['artifacts']}
        for omitted in index['omissions']:
            for ref in omitted['artifact_refs']:
                self.assertTrue(pointer(raw[ref['artifact_id']], ref['pointer'])[0])
        for canary in ('outside.example', 'private%ZZ', 'CANARY_PRIVATE'):
            self.assertNotIn(canary, canonical(index).decode())

    def test_redacted_or_duplicate_query_keys_never_prove_same_route(self):
        self.legacy([(TARGET + '?value=FIRST_CANARY&value=SECOND_CANARY', 'GET')])
        self.retained([('ffuf', ffuf())])
        index = build_surface_index(self.service.report(self.aid))
        self.assertEqual(index['summary']['mixed_endpoints'], 0)
        self.assertEqual(index['omissions'][0]['reason'], 'incomplete_target_binding')
        self.assertNotIn('CANARY', canonical(index).decode())

    def test_closed_or_filtered_native_nmap_records_are_receipted_without_an_open_surface(self):
        for state in ('closed', 'filtered'):
            raw = NMAP.replace(b'state="open"', b'state="' + state.encode() + b'"')
            self.service.import_source(self.aid, raw, 'nmap-xml-v1')
        index = build_surface_index(self.service.report(self.aid))
        self.assertEqual(index['summary']['services'], 0)
        self.assertCountEqual([r['source_ref']['source_state'] for r in index['omissions']], ['closed', 'filtered'])
        self.assertTrue(all(r['artifact_refs'][0]['pointer'] == '/records/0' for r in index['omissions']))

    def test_omitted_federated_rows_keep_scope_and_integrity_without_target(self):
        self.retained([('ffuf', ffuf('https://198.51.100.8/PRIVATE_CANARY'))])
        index = build_surface_index(self.service.report(self.aid))
        self.assertEqual(index['summary']['services'], 0)
        self.assertEqual(index['omissions'][0]['reason'], 'out_of_scope')
        self.assertEqual(index['omissions'][0]['source_ref']['locator'], '/results/0')
        self.assertNotIn('PRIVATE_CANARY', canonical(index).decode())


if __name__ == '__main__':
    unittest.main()
