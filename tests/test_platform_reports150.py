import copy
import importlib.util
import io
import json
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

from authzledger.platform_reports import (freeze_platform, verify_platform, render_platform_json,
    render_platform_html, render_platform_pdf, export_platform, create_platform_bundle, platform_anchor)
from authzledger.signing import generate_keypair, verify_bundle, create_bundle
from authzledger.knowledge import match_cve_candidates
from authzledger.oracles import seal
from authzledger.experiments import compile_experiment, execute_experiment, plan_experiment_retest, compare_executions
from test_experiments import fixture_spec, fixture_service


def assessment(origin='http://127.0.0.1:19999'):
    return {'id': 'platform-test', 'title': 'Assessment Zürich', 'revision': 1, 'scope': {
        'schema_version': 1, 'kind': 'assessment-scope', 'id': 'local', 'authorization_ref': 'owned local fixture',
        'origins': [origin], 'operations': [{'origin': origin, 'method': 'GET', 'path': '/', 'purpose': 'application'}],
        'allowed_networks': ['127.0.0.0/8'], 'expires_at': '2099-01-01T00:00:00Z', 'allowed_effects': ['read'],
        'limits': {'max_requests': 20, 'concurrency': 1, 'timeout_seconds': 2, 'max_response_bytes': 65536}}}


def artifact(value, aid='source', **kwargs):
    return {'artifact_id': aid, 'kind': value['kind'], 'value': value, **kwargs}


class PlatformReports150Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with fixture_service() as (origin, state):
            cls.before = execute_experiment(compile_experiment(fixture_spec(origin)))
            state['mode'] = 'fixed'
            cls.after = execute_experiment(plan_experiment_retest(cls.before, ['cross-tenant']))
            cls.comparison = compare_executions(cls.before, cls.after)
        cls.assessment = assessment(origin)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)

    def snapshot(self):
        return freeze_platform(self.assessment, [artifact(self.before, 'before'), artifact(self.after, 'after')], comparisons=[self.comparison])

    def test_legacy_sources_retained_and_retest_derived_offline(self):
        original = copy.deepcopy(self.before)
        with patch('socket.getaddrinfo', side_effect=AssertionError('offline only')):
            snapshot = self.snapshot()
            self.assertEqual(verify_platform(snapshot), [])
            html = render_platform_html(snapshot)
        self.assertEqual(original, self.before)
        self.assertIn('fix_verified', html)
        self.assertEqual(snapshot['artifacts'][1]['value'], self.before)
        self.assertEqual(json.loads(render_platform_json(snapshot)), snapshot)
        self.assertTrue(snapshot['findings'][0]['controls'])

    def test_omitted_retest_visible_and_no_safety_percentage(self):
        snapshot = freeze_platform(self.assessment, [artifact(self.before)])
        self.assertEqual(snapshot['findings'][0]['retest_status'], 'not_retested')
        self.assertEqual(snapshot['summary']['not_retested_records'], 1)
        self.assertNotIn('safe_percentage', snapshot['summary'])

    def test_forged_resealed_summary_and_comparison_fail(self):
        snapshot = self.snapshot(); snapshot['summary']['finding_records'] = 0
        self.assertTrue(verify_platform(seal('platform-snapshot', snapshot, 'snapshot_digest')))
        comparison = copy.deepcopy(self.comparison); comparison['transitions'][0]['status'] = 'violation_persists'
        with self.assertRaises(ValueError):
            freeze_platform(self.assessment, [artifact(self.before), artifact(self.after, 'current')], comparisons=[seal('experiment-comparison', comparison, 'comparison_digest')])

    def test_excluded_findings_stay_in_inventory_and_sources(self):
        snapshot = freeze_platform(self.assessment, [artifact(self.before, included=False, exclusion_reason='Reviewed duplicate')])
        self.assertEqual(snapshot['summary']['excluded_finding_records'], 1)
        self.assertFalse(snapshot['findings'][0]['included'])
        self.assertEqual(snapshot['artifacts'][0]['value'], self.before)
        self.assertIn('Reviewed duplicate', render_platform_html(snapshot))
        with self.assertRaises(ValueError):
            freeze_platform(self.assessment, [artifact(self.before, included=False)])

    def test_visual_injection_escaped(self):
        meta = copy.deepcopy(self.assessment); meta['title'] = '<script>alert(1)</script>'
        html = render_platform_html(freeze_platform(meta, []))
        self.assertNotIn('<script>', html); self.assertIn('&lt;script&gt;', html)
        self.assertIn("default-src 'none'", html)

    def test_duplicate_and_unknown_artifacts_fail_closed(self):
        for sources in [[artifact(self.before), artifact(self.before)], [artifact({'kind': 'untrusted', 'findings': []})]]:
            with self.assertRaises(ValueError):
                freeze_platform(self.assessment, sources)

    def test_duplicate_source_evidence_counted_once_with_all_artifact_decisions(self):
        snapshot = freeze_platform(self.assessment, [artifact(self.before, 'direct'),
            artifact(self.before, 'copy', included=False, exclusion_reason='Duplicate retained association')])
        self.assertEqual(len(snapshot['findings']), 1)
        self.assertEqual(len(snapshot['findings'][0]['artifact_refs']), 2)
        self.assertTrue(snapshot['findings'][0]['included'])
        self.assertTrue(all(item['finding_records'] == 1 for item in snapshot['inventory']))
        self.assertEqual(verify_platform(snapshot), [])

    def test_cve_candidates_never_become_confirmed_report_rows(self):
        knowledge = match_cve_candidates([{'product': 'apache:http_server', 'version': '2.4.49', 'source_ref': 'obs', 'source_kind': 'banner'}])
        snapshot = freeze_platform(self.assessment, [artifact(knowledge)])
        self.assertEqual(len(snapshot['findings']), 2)
        self.assertTrue(all(f['evidence_level'] == 'hint' for f in snapshot['findings']))

    def test_empty_discovery_workspace_signed_without_fake_execution(self):
        snapshot = freeze_platform(self.assessment, [])
        self.assertEqual(platform_anchor(snapshot)['kind'], 'platform-anchor')
        self.assertNotIn('results', platform_anchor(snapshot))
        private, public = self.root / 'private.pem', self.root / 'trusted.pem'; generate_keypair(private, public)
        proof = self.root / 'proof'; create_platform_bundle(snapshot, proof, private, ('json', 'html'))
        self.assertEqual(verify_bundle(proof, public), [])
        standalone = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'tools/verify_bundle.py'))
        self.assertEqual(standalone['verify_bundle'](proof, public), [])
        (proof / 'attachments/platform.html').write_text('tampered')
        self.assertTrue(verify_bundle(proof, public)); self.assertTrue(standalone['verify_bundle'](proof, public))

    def test_signed_visual_requires_exact_snapshot_and_anchor(self):
        private, public = self.root / 'private.pem', self.root / 'trusted.pem'; generate_keypair(private, public)
        with self.assertRaisesRegex(ValueError, 'require platform.json'):
            create_bundle(platform_anchor(self.snapshot()), self.root / 'bad', private, {'platform.html': b'false claim'})
        with self.assertRaisesRegex(ValueError, 'does not match'):
            create_bundle(platform_anchor(self.snapshot()), self.root / 'bad2', private,
                          {'platform.json': render_platform_json(self.snapshot()).encode(), 'platform.html': b'false claim'})

    def test_export_no_overwrite_and_mandatory_json(self):
        files = export_platform(self.snapshot(), self.root / 'export', ('html',))
        self.assertEqual(set(files), {'platform.json', 'platform.html'})
        with self.assertRaises(ValueError):
            export_platform(self.snapshot(), self.root / 'export', ('html',))

    @unittest.skipUnless(importlib.util.find_spec('reportlab'), 'reportlab not installed')
    def test_pdf_deterministic_and_same_inventory(self):
        snapshot = self.snapshot()
        pdf = render_platform_pdf(snapshot)
        self.assertEqual(pdf, render_platform_pdf(snapshot))
        self.assertTrue(pdf.startswith(b'%PDF'))
        if importlib.util.find_spec('pypdf'):
            from pypdf import PdfReader
            text = '\n'.join(page.extract_text() for page in PdfReader(io.BytesIO(pdf)).pages)
            self.assertIn('Zürich', text)
            self.assertIn('fix_verified', text)
            for row in snapshot['findings']:
                self.assertIn(row['id'], text)

    def test_finding_review_does_not_override_evidence(self):
        snapshot = freeze_platform(self.assessment, [artifact(self.before)])
        fid = snapshot['findings'][0]['id']
        meta = {**self.assessment, 'finding_annotations': {fid: {'review': 'accepted_risk', 'rationale': 'Time-limited operational decision'}}}
        reviewed = freeze_platform(meta, [artifact(self.before)])
        self.assertEqual(reviewed['findings'][0]['status'], 'confirmed')
        self.assertEqual(reviewed['findings'][0]['review'], 'accepted_risk')
        meta['finding_annotations'][fid]['status'] = 'fixed'
        with self.assertRaises(ValueError):
            freeze_platform(meta, [artifact(self.before)])

    def test_engagement_and_remediation_handover_preserves_evidence_verdict(self):
        source = freeze_platform(self.assessment, [artifact(self.before)])
        fid = source['findings'][0]['id']
        meta = {**self.assessment, 'engagement': {'reference': 'ENG-123', 'roe_ref': 'ROE-456', 'notes': 'Owned fixture only'},
                'finding_annotations': {fid: {'remediation': 'Enforce tenant ownership before loading the object.',
                    'impact': 'A tenant can read the other tenant fixture marker.'}}}
        snapshot = freeze_platform(meta, [artifact(self.before)])
        row = snapshot['findings'][0]
        self.assertEqual(snapshot['assessment']['engagement'], meta['engagement'])
        self.assertEqual(row['status'], 'confirmed'); self.assertEqual(row['retest_status'], 'not_retested')
        self.assertEqual(row['remediation_basis'], 'assessment_annotation_not_verified_fix')
        rendered = render_platform_html(snapshot)
        for value in ('ENG-123', 'ROE-456', 'Enforce tenant ownership', 'other tenant fixture marker', 'required_controls'):
            self.assertIn(value, rendered)
        self.assertEqual(verify_platform(snapshot), [])
        meta['finding_annotations'][fid]['impact'] = 'Bearer DO_NOT_RETAIN_SECRET'
        with self.assertRaisesRegex(ValueError, 'credential material'):
            freeze_platform(meta, [artifact(self.before)])

    def test_workflow_cleanup_failure_keeps_missing_variant_without_invented_evidence(self):
        from authzledger.detectors import compile_check, execute_check
        from test_detectors150 import scope_for
        from test_workflows import fixture, spec as workflow_spec
        with fixture() as (origin, state):
            workflow = workflow_spec(origin); workflow['variants'].append({'id': 'unexecuted', 'omit': ['approve']})
            state['cleanup'] = False
            spec = {'schema_version': 1, 'kind': 'check-spec', 'id': 'workflow-stop',
                'check_id': 'business_logic.skipped_approval', 'version': '1.0.0', 'source_refs': ['fixture'], 'workflow_spec': workflow}
            scope = scope_for(spec)
            for operation in list(scope['operations']):
                if 'placeholder' in operation['path']:
                    for number in ('1', '2'):
                        scope['operations'].append({**operation, 'path': operation['path'].replace('placeholder', number)})
            result = execute_check(compile_check(spec, scope))
        snapshot = freeze_platform({**assessment(origin), 'scope': scope}, [artifact(result)])
        self.assertEqual(verify_platform(snapshot), [])
        self.assertEqual(len(snapshot['findings']), 2)
        missing = next(f for f in snapshot['findings'] if f['reason'] == 'adapter_variant_not_run')
        self.assertEqual(missing['evidence_level'], 'inconclusive')
        self.assertEqual((missing['controls'], missing['observations'], missing['observation_refs']), ([], [], []))
        self.assertEqual(missing['retest_status'], 'not_retested')
        self.assertIn('adapter_variant_not_run', render_platform_html(snapshot))

    def test_detector_controls_retest_wrapper_and_comparison_preserved(self):
        from authzledger.detectors import compile_check, execute_check, plan_check_retest, compare_check_executions
        from test_detectors150 import header_spec, scope_for, service
        with service() as (origin, state):
            spec = header_spec(origin); scope = scope_for(spec)
            before = execute_check(compile_check(spec, scope)); state['headers'] = True
            after = execute_check(plan_check_retest(before))
        current = artifact(after, 'retest'); current['kind'] = 'retest-execution'
        snapshot = freeze_platform({**assessment(origin), 'scope': scope},
            [artifact(before, 'base'), current, artifact(compare_check_executions(before, after), 'comparison')])
        self.assertEqual(verify_platform(snapshot), [])
        self.assertTrue(all(f['controls'] and f['observations'] for f in snapshot['findings']))
        self.assertTrue(all(f['retest_status'] == 'not_reproduced_under_tested_conditions' for f in snapshot['findings']))
        self.assertEqual(snapshot['artifacts'][-1]['kind'], 'check-execution')

    def test_legacy_snapshot_with_two_historical_versions_keeps_unique_rows_and_retests(self):
        from authzledger.assessment_reports import freeze_assessment
        legacy = freeze_assessment([self.before, self.after], {'title': 'Retained legacy assessment'}, [self.comparison])
        snapshot = freeze_platform(self.assessment, [artifact(legacy)])
        self.assertEqual(verify_platform(snapshot), [])
        self.assertEqual(len(snapshot['findings']), 2)
        self.assertEqual(len({f['id'] for f in snapshot['findings']}), 2)
        self.assertTrue(all(f['retest_status'] == 'fix_verified' for f in snapshot['findings']))

    def test_discovery_plan_execution_delta_selection_and_hints_sign_offline(self):
        from authzledger.discovery import plan_discovery, execute_discovery
        from authzledger.surface import build_catalog, candidate_experiments, diff_catalogs, plan_delta_checks
        from test_discovery150 import webfixture, scope
        with webfixture() as (origin, requests):
            policy = scope([origin], [{'origin': origin, 'method': 'GET', 'path': '/', 'purpose': 'discovery'}])
            plan = plan_discovery(policy, [{'origin': origin, 'paths': ['/']}])
            run = execute_discovery(plan)
        catalog = run['catalog']; delta = diff_catalogs(build_catalog([]), catalog)
        selection = plan_delta_checks(delta, [])
        sources = [plan, run, catalog, candidate_experiments(catalog), delta, selection]
        with patch('socket.getaddrinfo', side_effect=AssertionError('offline report')):
            snapshot = freeze_platform({**assessment(origin), 'scope': policy}, [artifact(v, str(i)) for i, v in enumerate(sources)])
            self.assertEqual(verify_platform(snapshot), [])
            self.assertEqual(snapshot['findings'], [])
            private, public = self.root / 'private.pem', self.root / 'trusted.pem'; generate_keypair(private, public)
            create_platform_bundle(snapshot, self.root / 'discovery-proof', private, ('json', 'html'))
            self.assertEqual(verify_bundle(self.root / 'discovery-proof', public), [])

    def test_workflow_and_reduction_nested_execution_inventory_complete(self):
        from authzledger.workflows import compile_workflow, execute_workflow
        from authzledger.minimize import plan_reduction, execute_reduction, removable_units
        from test_workflows import fixture as workflow_fixture, spec as workflow_spec
        from test_minimize import fixture as reduction_fixture, source
        with workflow_fixture() as (origin, state):
            workflow = execute_workflow(compile_workflow(workflow_spec(origin)))
        with reduction_fixture() as (origin, state):
            before = execute_experiment(compile_experiment(source(origin)))
            units = [u for u in removable_units(before) if u.get('name') == 'noise']
            reduction = execute_reduction(plan_reduction(before, units, max_requests=12))
        snapshot = freeze_platform(assessment(origin), [artifact(workflow, 'workflow'), artifact(reduction, 'reduction')])
        self.assertEqual(verify_platform(snapshot), [])
        reductions = [f for f in snapshot['findings'] if f['artifact_id'] == 'reduction']
        expected = {before['execution_digest'], reduction['accepted_execution']['execution_digest'],
                    *[a['execution']['execution_digest'] for a in reduction['attempts'] if a.get('execution')]}
        self.assertEqual({f['source_digest'] for f in reductions}, expected)
        self.assertTrue(all(f['controls'] and f['observations'] for f in snapshot['findings']))

    def test_playbook_retains_original_sources_and_does_not_double_count_child(self):
        from authzledger.playbooks import plan_playbook, execute_playbook
        from test_playbooks150 import prepared, service
        with service() as (origin, state):
            scope, steps = prepared(origin); plan = plan_playbook(scope, steps); result = execute_playbook(plan)
        child = result['steps'][1]['execution']
        snapshot = freeze_platform({**assessment(origin), 'scope': scope},
            [artifact(plan, 'plan'), artifact(result, 'playbook'), artifact(child, 'child')])
        self.assertEqual(verify_platform(snapshot), [])
        self.assertEqual(len(snapshot['findings']), 1)
        self.assertEqual(len(snapshot['findings'][0]['artifact_refs']), 2)
        self.assertTrue(snapshot['findings'][0]['controls'])
        rendered = render_platform_html(snapshot)
        self.assertIn('Observed endpoints', rendered)
        self.assertIn('Static playbook step outcomes', rendered)
        self.assertIn('completed_steps', rendered)
        changed = copy.deepcopy(snapshot)
        changed['artifacts'][2]['value']['steps'][1]['status'] = 'not_run'
        self.assertTrue(verify_platform(seal('platform-snapshot', changed, 'snapshot_digest')))

    def test_external_scanner_receipts_remain_hints_without_imported_severity_or_secrets(self):
        from authzledger.adapters import import_adapter
        nuclei = {'type': 'http', 'matched-at': 'http://127.0.0.1:19999/', 'template-id': 'test-template',
            'info': {'severity': 'critical', 'name': 'PRIVATE_NAME', 'classification': {'cve-id': ['CVE-2021-41773']}},
            'request': 'GET / HTTP/1.1\r\nAuthorization: Bearer DO_NOT_EXPORT\r\n\r\n',
            'response': 'HTTP/1.1 200 OK\r\n\r\nPRIVATE_BODY', 'extracted-results': ['PRIVATE_EXTRACTION']}
        nmap = b'<nmaprun scanner="nmap"><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="19999"><state state="open"/><service name="http" method="probed" product="Apache httpd" version="2.4.49"/><script id="x" output="PRIVATE_SCRIPT"/></port></ports></host></nmaprun>'
        receipts = [import_adapter(json.dumps(nuclei).encode(), 'nuclei-jsonl-v1'), import_adapter(nmap, 'nmap-xml-v1')]
        with patch('socket.getaddrinfo', side_effect=AssertionError('offline imports and report')):
            snapshot = freeze_platform(assessment(), [artifact(r, str(i)) for i, r in enumerate(receipts)])
            self.assertEqual(verify_platform(snapshot), [])
            self.assertEqual(len(snapshot['findings']), 1)
            row = snapshot['findings'][0]
            self.assertEqual((row['status'], row['evidence_level'], row['severity']), ('hint', 'hint', 'not_assessed'))
            self.assertEqual(row['record']['reported_severity'], 'critical')
            self.assertEqual(row['retest_status'], 'not_retested')
            rendered = render_platform_html(snapshot)
            for secret in ('DO_NOT_EXPORT', 'PRIVATE_NAME', 'PRIVATE_BODY', 'PRIVATE_EXTRACTION', 'PRIVATE_SCRIPT'):
                self.assertNotIn(secret, rendered)
            self.assertIn('Source inventory and omissions', rendered)
            private, public = self.root / 'private.pem', self.root / 'trusted.pem'; generate_keypair(private, public)
            create_platform_bundle(snapshot, self.root / 'adapter-proof', private, ('json', 'html'))
            self.assertEqual(verify_bundle(self.root / 'adapter-proof', public), [])


if __name__ == '__main__':
    unittest.main()
