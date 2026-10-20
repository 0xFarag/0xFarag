import copy
import unittest
from unittest.mock import patch

from authzledger.knowledge import (builtin_knowledge_pack, validate_knowledge_pack, verify_knowledge_pack,
    match_cve_candidates, verify_knowledge_result, validate_standard_refs)
from authzledger.oracles import seal


class Knowledge150Tests(unittest.TestCase):
    def observation(self, version='2.4.49', **extra):
        return dict(product='apache:http_server', version=version, source_ref='observation-1', source_kind='banner', **extra)

    def test_builtin_is_offline_and_never_confirms_banner_candidates(self):
        with patch('socket.getaddrinfo', side_effect=AssertionError('network')):
            pack = builtin_knowledge_pack()
            self.assertEqual(verify_knowledge_pack(pack), [])
            result = match_cve_candidates([self.observation()], pack)
            self.assertEqual(verify_knowledge_result(result), [])
        self.assertEqual({c['cve'] for c in result['candidates']}, {'CVE-2021-41773', 'CVE-2021-42013'})
        self.assertTrue(all(c['evidence_level'] == 'hint' and c['exploitability'] == 'not_established' for c in result['candidates']))

    def test_numeric_ranges_not_lexical_and_boundaries(self):
        for version, count in [('2.4.9', 0), ('2.4.48', 0), ('2.4.49', 2), ('2.4.50', 1), ('2.4.51', 0), ('2.4.100', 0)]:
            with self.subTest(version=version):
                result = match_cve_candidates([self.observation(version)])
                self.assertEqual(len(result['candidates']), count)

    def test_unsupported_backports_and_prereleases_are_explicit(self):
        for version in ['2.4.49-1ubuntu2', 'v2.4.49', '2.4.50rc1', '2.04.49']:
            result = match_cve_candidates([self.observation(version)])
            self.assertEqual(result['coverage'][0]['status'], 'unsupported_version_scheme')
            self.assertEqual(result['candidates'], [])

    def test_exact_product_identity_required(self):
        observation = self.observation(); observation['product'] = 'nginx:nginx'
        result = match_cve_candidates([observation])
        self.assertEqual(result['coverage'][0]['status'], 'product_not_in_pack')
        self.assertEqual(result['candidates'], [])

    def test_credentials_or_unproven_extra_fields_rejected(self):
        with self.assertRaises(ValueError):
            match_cve_candidates([self.observation(authorization='Bearer abc')])
        bad = self.observation(); bad.pop('source_ref')
        with self.assertRaises(ValueError):
            match_cve_candidates([bad])

    def test_resealed_forged_finding_does_not_verify(self):
        result = match_cve_candidates([self.observation()])
        result['candidates'][0]['evidence_level'] = 'confirmed'
        result = seal('knowledge-result', result, 'result_digest')
        self.assertTrue(verify_knowledge_result(result))

    def test_pack_provenance_schema_and_range_fail_closed(self):
        pack = builtin_knowledge_pack()
        for field, value in [('version_scheme', 'lexical'), ('affected', [{'gt': '3.0', 'lt': '2.0'}]),
                             ('source', {'url': 'http://evil.invalid', 'publisher': 'x', 'retrieved_at': '2026-10-20'})]:
            candidate = copy.deepcopy(pack); candidate.pop('pack_digest'); candidate['entries'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_knowledge_pack(candidate)

    def test_authenticated_inventory_is_still_candidate(self):
        observation = self.observation(); observation['source_kind'] = 'authenticated_inventory'
        result = match_cve_candidates([observation])
        self.assertTrue(all(c['status'] == 'candidate' and c['evidence_level'] == 'hint' for c in result['candidates']))

    def test_standards_version_and_evidence_are_bound(self):
        mapping = {'standard': 'API', 'version': '2023', 'id': 'API1:2023', 'relation': 'partially_covers',
                   'rationale': 'Tenant resource read test only.', 'evidence_refs': ['obs-1']}
        self.assertEqual(validate_standard_refs([mapping], ['obs-1']), [mapping])
        for key, value in [('version', '2024'), ('relation', 'compliant'), ('id', 'API99:2023'), ('evidence_refs', ['foreign'])]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                validate_standard_refs([{**mapping, key: value}], ['obs-1'])


if __name__ == '__main__':
    unittest.main()
