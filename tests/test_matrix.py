import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from authzledger.benchmark import run_benchmark, sample_project
from authzledger.cli import main
from authzledger.evidence import compare_reports, seal_report, verify_report
from authzledger.matrix import compile_matrix, explain_report, policy_diff
from authzledger.model import ContractError, contract_digest


class MatrixTests(unittest.TestCase):
    def test_complete_cartesian_coverage_and_two_control_obligations(self):
        result = compile_matrix(sample_project())
        self.assertEqual(result['manifest']['coverage'], {'allow': 8, 'deny': 16, 'unknown': 0, 'blocked': 0, 'total': 24})
        cases = {c['id']: c for c in result['contract']['cases']}
        for c in cases.values():
            if c['expect']['status'] == [200]:
                self.assertFalse(c['requires'])
                self.assertTrue(c['expect']['json'])
            else:
                controls = [cases[k] for k in c['requires']]
                self.assertTrue(any(x['identity'] == c['identity'] for x in controls))
                self.assertTrue(any(x['path'] == c['path'] for x in controls))
                self.assertTrue(all(x['expect']['status'] == [200] for x in controls))

    def test_unknown_is_a_gap_and_never_defaults_to_deny(self):
        p = sample_project()
        del p['decisions']['north_member']['invoice-b']
        r = compile_matrix(p, require_complete=False)
        self.assertIsNone(r['contract'])
        self.assertEqual(r['manifest']['coverage']['unknown'], 1)
        self.assertEqual(r['manifest']['coverage']['total'], 24)
        with self.assertRaises(ContractError):
            compile_matrix(p)

    def test_missing_actor_control_blocks_its_denials(self):
        p = sample_project()
        p['decisions']['north_member']['invoice-a'] = 'deny'
        r = compile_matrix(p, require_complete=False)
        self.assertEqual(len([g for g in r['gaps'] if g['actor'] == 'north_member']), 6)
        self.assertIsNone(r['contract'])

    def test_missing_resource_control_blocks_all_denials_to_it(self):
        p = sample_project()
        for row in p['decisions'].values():
            row['audit-north'] = 'deny'
        r = compile_matrix(p, require_complete=False)
        self.assertEqual(len([g for g in r['gaps'] if g['resource'] == 'audit-north']), 4)

    def test_order_invariant_compilation_and_hashes(self):
        p = sample_project()
        q = copy.deepcopy(p)
        q['actors'].reverse()
        q['resources'].reverse()
        self.assertEqual(compile_matrix(p), compile_matrix(q))

    def test_duplicate_actors_resources_paths_and_environment_refs_rejected(self):
        for kind in ('actor', 'resource', 'path', 'env'):
            with self.subTest(kind=kind):
                p = sample_project()
                if kind == 'actor': p['actors'][1]['id'] = p['actors'][0]['id']
                if kind == 'resource': p['resources'][1]['id'] = p['resources'][0]['id']
                if kind == 'path': p['resources'][1]['path'] = p['resources'][0]['path']
                if kind == 'env': p['actors'][1]['env'] = p['actors'][0]['env']
                with self.assertRaises(ContractError): compile_matrix(p)

    def test_unknown_schema_keys_and_decision_references_rejected(self):
        for field in ('root', 'actor', 'resource', 'decision-actor', 'decision-resource'):
            p = sample_project()
            if field == 'root': p['autodiscover'] = True
            if field == 'actor': p['actors'][0]['token'] = 'must-not-be-accepted'
            if field == 'resource': p['resources'][0]['method'] = 'DELETE'
            if field == 'decision-actor': p['decisions']['undeclared'] = {}
            if field == 'decision-resource': p['decisions']['north_member']['undeclared'] = 'deny'
            with self.subTest(field=field), self.assertRaises(ContractError): compile_matrix(p)

    def test_limits_and_mutating_or_redirect_paths_rejected(self):
        for path in ('https://outside.invalid/x', '//outside.invalid/x', '/%2felsewhere', '/../secret'):
            p = sample_project()
            p['resources'][0]['path'] = path
            with self.assertRaises(ContractError): compile_matrix(p)
        p = sample_project()
        p['limits']['max_requests'] = 23
        with self.assertRaises(ContractError): compile_matrix(p)

    def test_no_authentication_failure_can_count_as_matrix_denial(self):
        p = sample_project()
        p['resources'][0]['deny_status'] = [401, 403]
        with self.assertRaises(ContractError): compile_matrix(p)

    def test_positive_controls_require_body_identity_assertions(self):
        for value in ({}, {'': {}}):
            p = sample_project()
            p['resources'][0]['assertions'] = value
            with self.assertRaises(ContractError): compile_matrix(p)

    def test_offline_compile_does_not_resolve_credentials_or_send_requests(self):
        with patch.dict(os.environ, {'AUTHZ_NORTH_MEMBER_TOKEN': 'secret-not-in-artifact'}), patch('socket.create_connection', side_effect=AssertionError('network')):
            r = compile_matrix(sample_project())
            self.assertNotIn('secret-not-in-artifact', json.dumps(r))
            self.assertEqual(r['manifest']['contract_sha256'], contract_digest(r['contract']))

    def test_policy_change_is_not_a_resolved_vulnerability(self):
        p = sample_project()
        q = copy.deepcopy(p)
        q['decisions']['north_member']['invoice-b'] = 'allow'
        r = policy_diff(p, q)
        changed = next(x for x in r['changes'] if x['actor'] == 'north_member' and x['resource'] == 'invoice-b')
        self.assertEqual(changed['before'], 'deny')
        self.assertEqual(changed['after'], 'allow')
        self.assertIn('policy-change', changed['reasons'])
        self.assertNotIn('resolved', r)
        self.assertTrue(r['approval_required'])

    def test_removed_coverage_remains_in_migration(self):
        p = sample_project()
        q = copy.deepcopy(p)
        q['resources'] = [x for x in q['resources'] if x['id'] != 'audit-north']
        for row in q['decisions'].values(): del row['audit-north']
        r = policy_diff(p, q)
        self.assertEqual(sum('removed' in x['reasons'] for x in r['changes']), 4)
        self.assertEqual(r['before_coverage']['total'], 24)
        self.assertEqual(r['after_coverage']['total'], 20)

    def test_fixture_and_scope_changes_are_explicit(self):
        p = sample_project()
        q = copy.deepcopy(p)
        q['target'] = 'https://staging.example.com'
        q['resources'][0]['assertions']['/id'] = 'replacement'
        r = policy_diff(p, q)
        self.assertTrue(r['scope_changed'])
        self.assertEqual(sum('resource-binding-change' in x['reasons'] for x in r['changes']), 4)

    def test_cli_generates_reviewable_artifacts_without_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'project.json'
            source.write_text(json.dumps(sample_project()))
            self.assertEqual(main(['matrix', str(source), '--out', str(root / 'built')]), 0)
            self.assertTrue((root / 'built/manifest.json').exists())
            self.assertEqual(main(['matrix', str(source), '--out', str(root / 'built')]), 2)
            self.assertEqual(main(['policy-diff', str(source), str(source), '--out', str(root / 'migration.json')]), 0)


class FaultCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.result = run_benchmark()

    def test_all_authored_fault_outcomes_and_clean_retest_match(self):
        r = self.result
        self.assertTrue(r['accepted'])
        self.assertEqual(len(r['scenarios']), 8)
        self.assertEqual(r['report']['summary']['pass'], 24)
        self.assertLess(r['baseline']['finished_at'], r['report']['started_at'])
        self.assertEqual(len(compare_reports(r['baseline'], r['report'])['resolved']), 2)

    def test_status_only_misses_data_leak_and_masks_invalid_controls(self):
        rows = {x['scenario']: x for x in self.result['scenarios']}
        self.assertEqual(rows['denial-leak']['status_only_missed_denial_violations'], 1)
        for name in ('expired-credential', 'missing-resource', 'wrong-object'):
            self.assertEqual(rows[name]['naive_status_only_false_passes_on_unresolved'], 7)
            self.assertEqual(rows[name]['observed_requests'], 17)

    def test_all_evidence_verifies_and_temporary_credentials_are_removed(self):
        for pair in self.result['evidence'].values():
            for report in pair.values(): self.assertEqual(verify_report(report), [])
        for a in self.result['project']['actors']: self.assertNotIn(a['env'], os.environ)
        self.assertNotIn('Bearer ', json.dumps(self.result))

    def test_browser_integer_number_roundtrip_preserves_report_seals(self):
        # JSON.parse/stringify in JavaScript serializes whole-valued floats as ints.
        def browser_numbers(v):
            if isinstance(v, float) and v.is_integer(): return int(v)
            if isinstance(v, list): return [browser_numbers(x) for x in v]
            if isinstance(v, dict): return {k: browser_numbers(x) for k, x in v.items()}
            return v
        for pair in self.result['evidence'].values():
            for report in pair.values():
                self.assertEqual(verify_report(browser_numbers(report)), [])

    def test_explanations_bind_contract_identity_and_integrity(self):
        r = self.result
        result = explain_report(r['project'], r['evidence']['expired-credential']['report'])
        skipped = [x for x in result['trace'] if x['outcome'] == 'inconclusive']
        self.assertEqual(len(skipped), 7)
        self.assertTrue(all(x['failed_controls'] for x in skipped))
        changed = copy.deepcopy(r['project'])
        changed['resources'][0]['assertions']['/id'] = 'different'
        with self.assertRaises(ContractError): explain_report(changed, r['report'])
        bad = copy.deepcopy(r['report'])
        bad['summary']['pass'] = 500
        with self.assertRaises(ContractError): explain_report(r['project'], bad)

    def test_same_hash_does_not_override_case_scope_mismatch(self):
        report = copy.deepcopy(self.result['report'])
        report['results'][0]['path'] = '/different'
        report = seal_report(report)
        with self.assertRaises(ContractError): explain_report(self.result['project'], report)
