"""Assessment endpoints preserve offline planning, credentials and review identity."""
import copy
import http.client
import io
import json
import threading
import tempfile
import subprocess
import sys
from pathlib import Path
import time
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from authzledger.studio import StudioServer
from authzledger.experiments import verify_execution
import test_experiments as fixtures


class StudioAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.fixture_service()
        self.target, self.fixture_state = self.fixture.__enter__()
        self.server = StudioServer()
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.thread.start()
        self.spec = fixtures.fixture_spec(self.target)

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(2)
        self.fixture.__exit__(None, None, None)

    def request(self, path, body=None, *, authenticated=True):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=15)
        headers = {'Origin': self.server.origin, 'Content-Type': 'application/json'}
        if authenticated: headers['Authorization'] = 'Bearer ' + self.server.token
        connection.request('POST' if body is not None else 'GET', path,
                           json.dumps(body) if body is not None else None, headers)
        response = connection.getresponse(); raw = response.read(); code = response.status
        content_type = response.getheader('Content-Type'); connection.close()
        return code, json.loads(raw) if content_type.startswith('application/json') else raw

    def preview(self):
        code, result = self.request('/api/assessment/plan', {'spec': self.spec})
        self.assertEqual(code, 200, result)
        return result

    def run_job(self, review):
        code, job = self.request('/api/assessment/run', {'review': review, 'authorized': True})
        self.assertEqual(code, 200, job)
        for _ in range(300):
            code, result = self.request('/api/jobs/' + job['id'])
            if result['state'] != 'running':
                self.assertEqual(result['state'], 'complete', result)
                return result
            time.sleep(.01)
        self.fail('Assessment job exceeded fixture deadline')

    def test_planning_offline_and_shared_service_execution(self):
        preview = self.preview()
        self.assertEqual(self.fixture_state['requests'], [])
        result = self.run_job(preview['review'])
        self.assertEqual(verify_execution(result['execution']), [])
        self.assertEqual(result['execution']['findings'][0]['status'], 'confirmed')
        self.assertEqual(result['execution']['budget_ledger']['dispatched_total'], 4)
        self.assertNotIn('Bearer owner', json.dumps(result))
        self.assertNotIn('Bearer peer', json.dumps(self.server.list_runs()))

    def test_explicit_authorization_required(self):
        review = self.preview()['review']
        for payload in [{'review': review}, {'review': review, 'authorized': False}, {'review': review, 'authorized': True, 'spec': self.spec}]:
            self.assertEqual(self.request('/api/assessment/run', payload)[0], 400)
        self.assertEqual(self.fixture_state['requests'], [])

    def test_idempotent_review_returns_same_job_without_second_execution(self):
        review = self.preview()['review']; body = {'review': review, 'authorized': True}
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda _: self.request('/api/assessment/run', body), range(2)))
        self.assertEqual([code for code, _ in responses], [200, 200])
        self.assertEqual(responses[0][1]['id'], responses[1][1]['id'])
        self.run_job(review)
        self.assertEqual(len(self.fixture_state['requests']), 4)

    def test_credential_values_not_echoed_and_generation_invalidates_review(self):
        review = self.preview()['review']
        code, result = self.request('/api/assessment/credentials', {'env': 'CONTRAST_PEER', 'value': 'Bearer peer',
            'identity': 'peer', 'target_origin': self.target})
        self.assertEqual(code, 200); self.assertNotIn('Bearer', json.dumps(result))
        self.assertEqual(self.request('/api/assessment/run', {'review': review, 'authorized': True})[0], 400)
        result = self.run_job(self.preview()['review'])
        self.assertEqual(result['execution']['findings'][0]['status'], 'confirmed')

    def test_invalid_control_never_confirmed(self):
        self.fixture_state['mode'] = 'invalid_controls'
        result = self.run_job(self.preview()['review'])
        self.assertEqual(result['execution']['findings'][0]['interpretation'], 'inconclusive')
        self.assertNotEqual(result['execution']['findings'][0]['status'], 'confirmed')
        self.assertEqual(len(self.fixture_state['requests']), 2)

    def test_source_bound_retest_and_finding_fix_status(self):
        baseline = self.run_job(self.preview()['review'])
        self.fixture_state['mode'] = 'fixed'
        code, preview = self.request('/api/assessment/retest', {'execution_id': baseline['execution_id'], 'selected_ids': ['target']})
        self.assertEqual(code, 200, preview)
        result = self.run_job(preview['review'])
        self.assertEqual(result['finding_comparison']['transitions'][0]['status'], 'fix_verified')
        self.assertEqual(baseline['execution']['report'], result['comparison_envelope']['baseline_report'])

    def test_import_sanitized_before_retention(self):
        har = {'log': {'version': '1.2', 'creator': {'name': 'fixture', 'version': '1'}, 'entries': [
            {'request': {'method': 'GET', 'url': self.target + '/invoice/A', 'headers': [{'name': 'Authorization', 'value': 'Bearer hidden-secret'}]},
             'response': {'status': 403, 'content': {'text': 'sensitive-body'}}}]}}
        code, result = self.request('/api/assessment/import', {'text': json.dumps(har), 'profile': 'har-1.2'})
        self.assertEqual(code, 200, result)
        self.assertEqual(len(result['import']['entries']), 1)
        self.assertNotIn('hidden-secret', json.dumps(result)); self.assertNotIn('sensitive-body', json.dumps(result))
        self.assertNotIn('hidden-secret', json.dumps(self.server.assessment_imports))
        self.assertEqual(self.fixture_state['requests'], [])

    def test_public_query_mapping_keeps_original_import_immutable(self):
        har = {'log': {'version': '1.2', 'entries': [{'request': {'method': 'GET',
            'url': self.target + '/invoice/A?note=private-original', 'headers': []}, 'response': {'status': 403}}]}}
        code, imported = self.request('/api/assessment/import', {'text': json.dumps(har), 'profile': 'har-1.2'})
        self.assertEqual(code, 200, imported)
        retained = copy.deepcopy(self.server.assessment_imports[imported['import_id']])
        slot = next(slot for slot in imported['import']['entries'][0]['secret_slots'] if slot['kind'] == 'query_value')
        bindings = {'id': 'mapped', 'title': 'Mapped public query', 'target': self.target,
            'identities': self.spec['contract']['identities'], 'actor_identity': 'peer', 'owner_identity': 'owner',
            'identity_probe': {'path': '/me', 'expect': {'status': [200], 'json': {'/principal': 'peer'}}},
            'negative_probe': {'path': '/known-denial', 'expect': {'status': [403], 'json_absent': ['/marker']}},
            'rule': self.spec['rule']}
        code, preview = self.request('/api/assessment/plan', {'import_id': imported['import_id'],
            'bindings': bindings, 'mappings': {slot['id']: {'literal': 'approved-public'}}})
        self.assertEqual(code, 200, preview)
        self.assertIn('note=approved-public', preview['plan']['contract']['cases'][-1]['path'])
        self.assertEqual(self.server.assessment_imports[imported['import_id']], retained)
        self.assertEqual(self.fixture_state['requests'], [])

    def test_recovery_is_read_only_and_review_expires(self):
        preview = self.preview()
        self.server.assessment_reviews[preview['review']]['expires'] = 0
        self.assertEqual(self.request('/api/assessment/run', {'review': preview['review'], 'authorized': True})[0], 400)
        result = self.run_job(self.preview()['review'])
        count = len(self.fixture_state['requests'])
        code, recovered = self.request('/api/assessment/recover', {'job_id': result['id']})
        self.assertEqual(code, 200, recovered)
        self.assertEqual(recovered['job']['id'], result['id'])
        self.assertEqual(len(self.fixture_state['requests']), count)

    def test_reports_freeze_and_local_key_proof(self):
        result = self.run_job(self.preview()['review'])
        code, frozen = self.request('/api/assessment/freeze', {'execution_ids': [result['execution_id']],
            'metadata': {'title': 'Studio proof', 'assessment_id': 'studio-proof'}})
        self.assertEqual(code, 200, frozen)
        for fmt in ['json', 'html', 'pdf']:
            code, content = self.request('/api/assessment/export', {'assessment_id': frozen['assessment_id'], 'format': fmt})
            self.assertEqual(code, 200, content)
            if fmt == 'pdf': self.assertTrue(content.startswith(b'%PDF'))
        code, key = self.request('/api/assessment/signing', {'create_session_key': True})
        self.assertEqual(code, 200, key); self.assertNotIn('PRIVATE KEY', json.dumps(key))
        code, archive = self.request('/api/assessment/proof', {'assessment_id': frozen['assessment_id']})
        self.assertEqual(code, 200, archive)
        with zipfile.ZipFile(io.BytesIO(archive)) as package:
            names = package.namelist(); self.assertIn('public.pem', names)
            self.assertTrue(any(name.endswith('assessment.pdf') for name in names))
            self.assertFalse(any('private' in name for name in names))

    def test_cancel_during_control_prevents_following_dispatches(self):
        from authzledger import engine
        self.spec['contract']['limits'] = {'concurrency': 1}
        preview = self.preview()
        entered, release = threading.Event(), threading.Event()
        execute = engine._execute
        def held(*args, **kwargs):
            entered.set()
            release.wait(5)
            return execute(*args, **kwargs)
        with patch('authzledger.engine._execute', held):
            code, job = self.request('/api/assessment/run', {'review': preview['review'], 'authorized': True})
            self.assertEqual(code, 200, job)
            try:
                self.assertTrue(entered.wait(2))
                self.assertEqual(self.request('/api/cancel', {'id': job['id']})[0], 200)
            finally:
                release.set()
            result = self.run_job(preview['review'])
        self.assertTrue(result['cancelled'])
        self.assertEqual(len(self.fixture_state['requests']), 1)
        self.assertEqual(result['execution']['budget_ledger']['dispatched_total'], 1)
        self.assertEqual(result['execution']['findings'][0]['interpretation'], 'inconclusive')

    def test_historical_inspector_never_requeries_configured_opa(self):
        result = self.run_job(self.preview()['review'])
        from authzledger.policy import load_policy
        self.server.policy_config = load_policy({'schema_version': 1, 'engine': 'opa',
            'endpoint': self.target + '/v1/data/authz/allow', 'allowed_origins': [self.target]})
        count = len(self.fixture_state['requests'])
        with patch('authzledger.policy.evaluate_policy', side_effect=AssertionError('historical inspection must be offline')):
            code, inspector = self.request('/api/assessment/inspect', {'execution_id': result['execution_id'],
                'finding_id': result['execution']['findings'][0]['id']})
        self.assertEqual(code, 200, inspector)
        self.assertEqual(len(self.fixture_state['requests']), count)

    def test_shared_inspector_and_unknown_dependency_full_scope(self):
        execution = self.run_job(self.preview()['review'])
        finding = execution['execution']['findings'][0]
        code, inspector = self.request('/api/assessment/inspect', {'execution_id': execution['execution_id'], 'finding_id': finding['id']})
        self.assertEqual(code, 200, inspector)
        self.assertEqual(inspector['finding'], finding)
        self.assertEqual(inspector['report_root'], execution['execution']['report']['evidence']['root_sha256'])
        dispatched = len(self.fixture_state['requests'])
        code, result = self.request('/api/assessment/impact', {'execution_id': execution['execution_id'], 'changes': [
            {'kind': 'policy', 'id': 'unknown-policy', 'before_digest': '0' * 64, 'after_digest': '1' * 64}]})
        self.assertEqual(code, 200, result)
        self.assertEqual(result['impact']['request_upper_bound'], 4)
        self.assertEqual(result['impact']['unknown_dependencies'], ['policy:unknown-policy'])
        self.assertEqual(len(self.fixture_state['requests']), dispatched)
        self.assertTrue(result['review'])

    def test_cli_and_studio_exact_plan_and_normalized_decision_parity(self):
        preview = self.preview()
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            source, plan_path, execution_path = folder / 'spec.json', folder / 'plan.json', folder / 'execution.json'
            source.write_text(json.dumps(self.spec), encoding='utf-8')
            command = [sys.executable, '-m', 'authzledger', 'assessment']
            compiled = subprocess.run(command + ['plan', str(source), '--out', str(plan_path)], capture_output=True, text=True, timeout=10)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            cli_plan = json.loads(plan_path.read_text())
            self.assertEqual(cli_plan, preview['plan'])
            completed = subprocess.run(command + ['run', str(plan_path), '--approve', cli_plan['plan_digest'], '--out', str(execution_path)], capture_output=True, text=True, timeout=10)
            self.assertIn(completed.returncode, (0, 1), completed.stderr)
            cli_execution = json.loads((execution_path / 'execution.json').read_text())
        studio_execution = self.run_job(preview['review'])['execution']
        def decisions(execution):
            return {'plan': execution['plan'],
                    'findings': [{key: value for key, value in finding.items() if key not in {'evidence_refs', 'finding_digest'}} for finding in execution['findings']],
                    'results': [{key: value for key, value in result.items() if key not in {'duration_ms', 'record_sha256'}} for result in execution['report']['results']],
                    'oracles': [observation['oracle'] for observation in execution['observations']]}
        self.assertEqual(decisions(cli_execution), decisions(studio_execution))

    def test_bounded_workflow_assurance_shared_service_and_signed_snapshot_inputs(self):
        import test_workflows as workflows
        from authzledger.workflow_assurance import verify_workflow_assurance
        with workflows.fixture() as (origin, state):
            state['vulnerable'] = False
            specification = {'schema_version': 1, 'kind': 'workflow-assurance-spec',
                'workflow': workflows.spec(origin), 'max_cycles': 2, 'interval_seconds': 0,
                'max_requests_total': 20, 'max_history_age_seconds': 86400}
            code, preview = self.request('/api/assessment/workflow-assurance/plan', {'spec': specification})
            self.assertEqual(code, 200, preview)
            self.assertEqual(state['requests'], [])
            self.assertEqual(preview['history_storage'], 'session-only')
            result = self.run_job(preview['review'])
            self.assertEqual(verify_workflow_assurance(result['trace']), [])
            self.assertEqual(result['trace']['completed_cycles'], 2)
            self.assertEqual(result['trace']['budget_ledger']['dispatched_total'], 12)
            self.assertEqual(len(state['requests']), 12)
            self.assertEqual(state['objects'], {})
            self.assertEqual(self.run_job(preview['review'])['id'], result['id'])
            self.assertEqual(len(state['requests']), 12)
            self.assertTrue(all(cycle['history'] for cycle in result['trace']['cycles']))
            code, frozen = self.request('/api/assessment/freeze', {'execution_ids': [],
                'trace_ids': [result['trace_id']], 'metadata': {'title': 'Bounded workflow assessment'}})
            self.assertEqual(code, 200, frozen)
            self.assertEqual(frozen['assessment']['assurances'][0], result['trace'])
            self.assertEqual(len(frozen['assessment']['workflows']), 2)
            # A fresh reviewed job stops after its first confirmed violation.
            state['vulnerable'] = True
            code, preview = self.request('/api/assessment/workflow-assurance/plan', {'spec': specification})
            self.assertEqual(code, 200, preview)
            stopped = self.run_job(preview['review'])
            self.assertEqual(len(stopped['trace']['cycles']), 1)
            self.assertEqual(stopped['trace']['cycles'][0]['trace']['variants'][0]['interpretation'], 'violation')
            self.assertEqual(len(state['requests']), 18)
            self.assertEqual(state['objects'], {})

    def test_catalog_matches_shared_reporting_service(self):
        from authzledger.assessment_reports import reporting_catalog
        code, catalog = self.request('/api/assessment/catalog', {})
        self.assertEqual(code, 200)
        self.assertEqual(catalog, reporting_catalog())

    def test_untrusted_browser_cannot_choose_filesystem_or_private_keys(self):
        for path, body in [('signing', {'create_session_key': True, 'path': '/tmp/a'}), ('proof', {'assessment_id': 'x', 'signing_key': 'private'}),
                           ('credentials', {'env': 'A', 'value': 'secret', 'identity': 'peer', 'target_origin': self.target})]:
            code, _ = self.request('/api/assessment/' + path, body, authenticated=False)
            self.assertEqual(code, 403)
        self.assertEqual(self.request('/api/assessment/signing', {'create_session_key': True, 'path': '/tmp/a'})[0], 400)

    def test_session_capability_not_persisted_in_browser_storage(self):
        code, script = self.request('/app.js')
        self.assertEqual(code, 200)
        self.assertNotIn(b'sessionStorage', script); self.assertNotIn(b'localStorage', script)

if __name__ == '__main__': unittest.main()
