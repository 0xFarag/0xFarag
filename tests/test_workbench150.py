"""Durable assessment lifecycle, crash safety, scope binding and real evidence."""
import copy
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from authzledger.history import HistoryStore
from authzledger.scope import validate_scope
from authzledger.workbench import WorkbenchError, WorkbenchService, WorkbenchStore
from tests.test_scope150 import scope
from tests.test_detectors150 import header_spec, scope_for, service
from tests.test_discovery150 import webfixture


class Workbench150Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.tmp.name) / 'workspace.sqlite3')
        self.store = WorkbenchStore(self.path)
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.store.close)
        self.service = WorkbenchService(self.store)
        self.assessment = self.service.create('Local assessment', scope())
        self.aid = self.assessment['id']

    def plan(self, source=None):
        return self.store.add_artifact(self.aid, 'check-plan', source or {'plan_digest': 'approved'})

    def execute(self, plan, callback, **kwargs):
        return self.service._execute(self.aid, plan['artifact_id'], plan['value']['plan_digest'],
            expected_kind='check-plan', execute=callback, result_kind='check-execution', **kwargs)

    def test_legacy_history_coexists_in_both_creation_orders_and_reopens(self):
        record = self.store.add_artifact(self.aid, 'note', {'kind': 'observation', 'value': 'retained'})
        with HistoryStore(self.path) as history:
            self.assertEqual(history.verify_chain(), [])
            self.assertEqual(history.list_runs(), [])
        with WorkbenchStore(self.path) as reopened:
            self.assertEqual(reopened.artifact(self.aid, record['artifact_id']), record)
            self.assertEqual(reopened.get(self.aid)['artifact_head'], record['artifact_digest'])
        second = str(Path(self.tmp.name) / 'history-first.sqlite3')
        with HistoryStore(second):
            pass
        with WorkbenchStore(second) as workspace:
            item = workspace.create('Second', scope())
            self.assertEqual(workspace.get(item['id']), item)

    def test_unknown_database_is_not_implicitly_migrated(self):
        path = str(Path(self.tmp.name) / 'foreign.sqlite3')
        with sqlite3.connect(path) as connection:
            connection.execute('CREATE TABLE foreign_data(value)')
        os.chmod(path, 0o600)
        with self.assertRaises(ValueError):
            WorkbenchStore(path)
        with sqlite3.connect(path) as connection:
            self.assertEqual(connection.execute("SELECT name FROM sqlite_master WHERE name LIKE 'wb_%'").fetchall(), [])

    def test_revision_compare_and_swap_across_connections(self):
        with WorkbenchStore(self.path) as other:
            before = other.get(self.aid)
            updated = self.store.update(self.aid, {'title': 'Revised'}, before['revision'])
            with self.assertRaisesRegex(WorkbenchError, 'revision_conflict'):
                other.update(self.aid, {'title': 'Lost update'}, before['revision'])
            self.assertEqual(other.get(self.aid), updated)
            with self.assertRaisesRegex(WorkbenchError, 'revision_conflict'):
                other.add_artifact(self.aid, 'note', {'kind': 'note'}, expected_revision=before['revision'])

    def test_engagement_references_are_revisioned_without_implicit_authorization(self):
        before = self.store.get(self.aid)
        metadata = {'reference': 'engagement-150', 'roe_ref': 'signed-rules-7', 'notes': 'Owned loopback lab only.'}
        after = self.service.update(self.aid, {'engagement': metadata}, before['revision'])
        self.assertEqual(after['engagement'], metadata)
        self.assertEqual(after['scope'], before['scope'])
        with self.assertRaisesRegex(WorkbenchError, 'invalid_engagement'):
            self.service.update(self.aid, {'engagement': {'arbitrary': 'data'}}, after['revision'])

    def test_immutable_evidence_and_removed_tail_are_detected_before_append(self):
        record = self.store.add_artifact(self.aid, 'note', {'kind': 'note'})
        with self.assertRaises(sqlite3.IntegrityError):
            self.store._db.execute('DELETE FROM wb_artifacts')
        self.store._db.execute('DROP TRIGGER wb_artifacts_no_delete')
        self.store._db.execute('DELETE FROM wb_artifacts WHERE artifact_id=?', (record['artifact_id'],))
        for action in (lambda: self.store.get(self.aid), lambda: self.store.add_artifact(self.aid, 'note', {'x': 1})):
            with self.assertRaisesRegex(WorkbenchError, 'evidence_chain_corrupt'):
                action()

    def test_rewinding_assessment_head_cannot_hide_latest_revision(self):
        self.store.update(self.aid, {'title': 'New'}, 1)
        old = self.store._db.execute('SELECT value FROM wb_revisions WHERE id=? AND revision=1', (self.aid,)).fetchone()[0]
        self.store._db.execute('UPDATE wb_assessments SET value=?,revision=1 WHERE id=?', (old, self.aid))
        with self.assertRaisesRegex(WorkbenchError, 'revision_corrupt'):
            self.store.get(self.aid)

    def test_credential_slots_persist_but_values_and_reflections_do_not(self):
        secret = 'Bearer PRIVATE_WORKBENCH_SECRET_150'
        reference = {'Authorization': {'env': 'WB_TEST_TOKEN'}}
        with patch.dict(os.environ, {'WB_TEST_TOKEN': secret}):
            record = self.store.add_artifact(self.aid, 'credential-reference', {'headers': reference})
            self.assertEqual(record['value']['headers'], reference)
            for value in ({'Authorization': secret}, {'password': 'literal'}, {'Authorization': {'literal': secret}},
                          {'client_secret': 'literal'}, {'headers': reference, 'body': secret},
                          {'headers': reference, 'body': 'PRIVATE_WORKBENCH_SECRET_150'}):
                with self.assertRaisesRegex(WorkbenchError, 'credential'):
                    self.store.add_artifact(self.aid, 'rejected', value)
        self.assertNotIn(secret.encode(), Path(self.path).read_bytes())
        cycle = {}; cycle['cycle'] = cycle
        with self.assertRaisesRegex(WorkbenchError, 'finite_json'):
            self.store.add_artifact(self.aid, 'cycle', cycle)

    def test_completed_job_is_idempotent_and_requires_exact_approval(self):
        plan = self.plan(); calls = []
        callback = lambda *args, **kwargs: calls.append(1) or {'kind': 'instrumented-execution'}
        first = self.execute(plan, callback)
        self.assertEqual(self.execute(plan, callback), first)
        self.assertEqual(calls, [1])
        with self.assertRaisesRegex(WorkbenchError, 'exact_plan_approval'):
            self.service._execute(self.aid, plan['artifact_id'], 'other', expected_kind='check-plan',
                execute=callback, result_kind='check-execution')

    def test_uncertain_job_is_never_replayed_on_reopen(self):
        plan = self.plan()
        with self.assertRaisesRegex(RuntimeError, 'simulated crash'):
            self.execute(plan, lambda *a, **kw: (_ for _ in ()).throw(RuntimeError('simulated crash')))
        with WorkbenchStore(self.path) as reopened:
            with self.assertRaisesRegex(WorkbenchError, 'prior_execution_interrupted'):
                WorkbenchService(reopened)._execute(self.aid, plan['artifact_id'], 'approved', expected_kind='check-plan',
                    execute=lambda *a, **kw: self.fail('replayed uncertain run'), result_kind='check-execution')

    def test_explicit_crash_recovery_marks_uncertainty_without_repeating_work(self):
        plan = self.plan(); schedule = self.service.schedule(self.aid, plan['artifact_id'], 'approved', 1, 2, 16)
        schedule.update(state='running', reserved_requests=8)
        self.store._db.execute('UPDATE wb_schedules SET value=? WHERE id=?', (json.dumps(schedule), schedule['id']))
        self.store._db.execute('INSERT INTO wb_jobs VALUES(?,?,?,?,?,?)', ('abandoned', self.aid, plan['artifact_id'], 'running', None, datetime.now(timezone.utc).isoformat()))
        recovered = self.service.recover_interrupted(self.aid)
        self.assertEqual(recovered['jobs'][0]['state'], 'interrupted')
        self.assertEqual(recovered['schedules'][0]['state'], 'blocked')
        self.assertEqual(recovered['schedules'][0]['reserved_requests'], 8)
        self.assertEqual(self.service.run_due(self.aid), [])
        self.assertEqual(self.store.artifacts(self.aid, 'check-execution'), [])
        current = self.store.get(self.aid)
        self.service.update(self.aid, {'scope': scope()}, current['revision'])

    def test_live_job_is_exclusive_and_reopening_does_not_interrupt_it(self):
        plan = self.plan(); entered = threading.Event(); release = threading.Event(); errors = []
        def callback(*args, **kwargs):
            entered.set()
            if not release.wait(5): raise RuntimeError('test release timeout')
            return {'kind': 'instrumented-execution'}
        def run():
            try: self.execute(plan, callback)
            except BaseException as error: errors.append(error)
        thread = threading.Thread(target=run); thread.start()
        try:
            self.assertTrue(entered.wait(5))
            with WorkbenchStore(self.path) as other:
                self.assertEqual(other._db.execute('SELECT state FROM wb_jobs').fetchone()[0], 'running')
                with self.assertRaisesRegex(WorkbenchError, 'already_running'):
                    WorkbenchService(other).recover_interrupted(self.aid)
                with self.assertRaisesRegex(WorkbenchError, 'already_running'):
                    WorkbenchService(other)._execute(self.aid, plan['artifact_id'], 'approved', expected_kind='check-plan',
                        execute=lambda *a, **kw: self.fail('concurrent run'), result_kind='check-execution')
                current = other.get(self.aid)
                with self.assertRaisesRegex(WorkbenchError, 'scope_change_requires_stopped'):
                    other.update(self.aid, {'scope': scope()}, current['revision'])
        finally:
            release.set(); thread.join(5)
        self.assertFalse(thread.is_alive()); self.assertEqual(errors, [])

    def test_execution_guard_excludes_a_separate_process(self):
        code = "from authzledger.workbench import WorkbenchStore,WorkbenchError\nimport sys\nwith WorkbenchStore(sys.argv[1]) as store:\n try:\n  with store.execution_guard(): print('unexpected')\n except WorkbenchError as error: print(str(error))\n"
        with self.store.execution_guard():
            process = subprocess.run([sys.executable, '-c', code, self.path], capture_output=True, text=True, timeout=5)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(process.stdout.strip(), 'assessment_execution_already_running')

    def test_scope_change_blocks_old_plan_and_schedule(self):
        plan = self.plan(); current = self.store.get(self.aid)
        changed = copy.deepcopy(current['scope']); changed.pop('scope_digest'); changed['authorization_ref'] = 'renewed'
        self.store.update(self.aid, {'scope': changed}, current['revision'])
        with self.assertRaisesRegex(WorkbenchError, 'scope_changed'):
            self.execute(plan, lambda *a, **kw: self.fail('old scope dispatched'))
        with self.assertRaisesRegex(WorkbenchError, 'scope_changed'):
            self.service.schedule(self.aid, plan['artifact_id'], 'approved', 1, 1, 8)

    def test_schedule_finite_budget_and_no_automatic_retry(self):
        plan = self.plan()
        schedule = self.service.schedule(self.aid, plan['artifact_id'], 'approved', 1, 2, 8)
        calls = []
        def invoke(aid, pid, approval, **kwargs):
            calls.append(kwargs['request_id'])
            return self.execute(plan, lambda *a, **kw: {'kind': 'instrumented-execution'}, request_id=kwargs['request_id'])
        with patch.object(self.service, 'check_execute', side_effect=invoke):
            first = self.service.run_due(self.aid)[0]
            self.assertEqual(first['completed_iterations'], 1)
            self.assertEqual(first['reserved_requests'], 8)
            self.assertEqual(self.service.run_due(self.aid), [])
            with patch('time.time', return_value=datetime.now(timezone.utc).timestamp()+2):
                second = self.service.run_due(self.aid)[0]
            self.assertEqual(second['state'], 'budget_exhausted')
            self.assertEqual(len(calls), 1)
        failing = self.service.schedule(self.aid, plan['artifact_id'], 'approved', 1, 3, 24)
        with patch.object(self.service, 'check_execute', side_effect=ValueError('uncertain failure')) as execute:
            self.assertEqual(self.service.run_due(self.aid)[0]['state'], 'blocked')
            self.assertEqual(self.service.run_due(self.aid), [])
            execute.assert_called_once()

    def test_expired_authorization_blocks_scheduled_dispatch(self):
        plan = self.plan(); self.service.schedule(self.aid, plan['artifact_id'], 'approved', 1, 1, 8)
        with patch('authzledger.scope.time.time', return_value=datetime.now(timezone.utc).timestamp()+3600):
            with patch('authzledger.detectors.execute_check', side_effect=AssertionError('expired execution')):
                result = self.service.run_due(self.aid)
        self.assertEqual(result[0]['state'], 'blocked')
        self.assertEqual(self.store.artifacts(self.aid, 'check-execution'), [])

    def test_recovery_between_schedule_claim_and_dispatch_prevents_execution(self):
        plan = self.plan(); self.service.schedule(self.aid, plan['artifact_id'], 'approved', 1, 1, 8)
        def recover_then_execute(aid, pid, approval, **kwargs):
            self.service.recover_interrupted(aid)
            return self.execute(plan, lambda *a, **kw: self.fail('recovered schedule dispatched'), **kwargs)
        with patch.object(self.service, 'check_execute', side_effect=recover_then_execute):
            result = self.service.run_due(self.aid)
        self.assertEqual(result[0]['state'], 'blocked')
        self.assertEqual(self.service.jobs(self.aid), [])

    def test_real_discovery_retained_through_catalog_refresh_and_delta(self):
        with webfixture() as (origin, requests):
            scoped = scope(origin, operations=[{'origin': origin, 'method': 'GET', 'path': '/', 'purpose': 'discovery'}])
            assessment = self.service.create('Discovered', scoped); aid = assessment['id']
            baseline = self.service.refresh_catalog(aid)
            plan = self.service.discover_plan(aid, [{'origin': origin, 'paths': ['/']}])
            execution = self.service.discover_execute(aid, plan['artifact_id'], plan['value']['plan_digest'])
            refreshed = self.service.refresh_catalog(aid)
            again = self.service.refresh_catalog(aid)
            self.assertEqual(requests, ['/'])
            self.assertEqual(refreshed['value'], again['value'])
            self.assertEqual(refreshed['value']['observations'], execution['value']['catalog']['observations'])
            delta = self.service.delta(aid, baseline['artifact_id'], refreshed['artifact_id'], [])
            self.assertIsNotNone(delta['check_plan'])
            self.assertTrue(any(t['transition'] == 'new' for t in delta['delta']['value']['transitions']))
        knowledge = self.service.knowledge(aid, [{'product': 'apache:http_server', 'version': '2.4.49',
            'source_ref': 'explicit-inventory-record', 'source_kind': 'manual'}])
        self.assertTrue(all(item['evidence_level'] == 'hint' for item in knowledge['value']['candidates']))

    def test_offline_adapter_imports_merge_and_report_as_hints_without_scope_expansion(self):
        from tests.test_adapters150 import nmap_xml, nuclei
        from authzledger.surface import verify_catalog
        original_scope = self.store.get(self.aid)['scope']
        with patch('socket.socket', side_effect=AssertionError('offline import network')):
            first = self.service.import_source(self.aid, nmap_xml(), 'nmap-xml-v1')
            second = self.service.import_source(self.aid, nuclei(), 'nuclei-jsonl-v1')
        self.assertEqual(first['kind'], 'adapter-receipt')
        self.assertEqual(second['kind'], 'adapter-receipt')
        catalog = self.store.artifacts(self.aid, 'surface-catalog')[-1]['value']
        self.assertEqual(verify_catalog(catalog), [])
        self.assertEqual(len(catalog['assets']), 2)
        self.assertTrue(all(asset['scope_state'] == 'outside_scope' for asset in catalog['assets']))
        self.assertEqual(self.store.get(self.aid)['scope'], original_scope)
        self.assertNotIn(b'PRIVATE_', Path(self.path).read_bytes())
        report = self.service.report(self.aid)
        self.assertTrue(report['findings'])
        self.assertTrue(all(row['evidence_level'] == 'hint' for row in report['findings']))

    def test_actual_check_retest_persists_source_bound_comparison_once(self):
        with service() as (origin, state):
            spec = header_spec(origin)
            assessment = self.service.create('Headers', scope_for(spec)); aid = assessment['id']
            plan = self.service.check_plan(aid, spec)
            baseline = self.service.check_execute(aid, plan['artifact_id'], plan['value']['plan_digest'])
            self.assertEqual(baseline['value']['findings'][0]['evidence_level'], 'confirmed')
            state['headers'] = True
            retest = self.service.retest_plan(aid, baseline['artifact_id'])
            result = self.service.retest_execute(aid, retest['artifact_id'], retest['value']['plan_digest'])
            self.assertEqual(self.service.retest_execute(aid, retest['artifact_id'], retest['value']['plan_digest']), result)
            comparisons = self.store.artifacts(aid, 'check-comparison')
            self.assertEqual(len(comparisons), 1)
            self.assertEqual(comparisons[0]['value']['baseline_execution_digest'], baseline['value']['execution_digest'])
            self.assertEqual(comparisons[0]['value']['current_execution_digest'], result['value']['execution_digest'])
            self.assertEqual(len(state['requests']), 4)

    def test_playbook_composes_retained_plans_with_one_finite_budget(self):
        from authzledger.playbooks import verify_playbook
        with service() as (origin, state):
            spec = header_spec(origin); scoped = scope_for(spec)
            scoped['operations'].append({'origin': origin, 'method': 'GET', 'path': '/', 'purpose': 'discovery'})
            aid = self.service.create('Playbook', scoped)['id']
            discovery = self.service.discover_plan(aid, [{'origin': origin, 'paths': ['/']}])
            check = self.service.check_plan(aid, spec)
            plan = self.service.playbook_plan(aid, [
                {'id': 'discovery', 'plan_id': discovery['artifact_id'], 'requires': []},
                {'id': 'headers', 'plan_id': check['artifact_id'], 'requires': ['discovery']}])
            result = self.service.playbook_execute(aid, plan['artifact_id'], plan['value']['plan_digest'])
            self.assertEqual(verify_playbook(result['value']), [])
            self.assertEqual(result['value']['coverage']['completed_steps'], 2)
            self.assertEqual(result['value']['budget_ledger']['approved_total'], 3)
            self.assertEqual(len(state['requests']), 3)
            catalog = self.service.refresh_catalog(aid)
            self.assertEqual(len(catalog['value']['endpoints']), 1)
            self.assertEqual(self.service.get(aid)['coverage']['confirmed'], 1)

    def test_explicit_scope_renewal_produces_new_retest_approval_and_keeps_source(self):
        from authzledger.detectors import verify_check_execution
        with service() as (origin, state):
            spec = header_spec(origin)
            aid = self.service.create('Renewal', scope_for(spec))['id']
            plan = self.service.check_plan(aid, spec)
            baseline = self.service.check_execute(aid, plan['artifact_id'], plan['value']['plan_digest'])
            original = copy.deepcopy(baseline)
            current = self.store.get(aid)
            renewed = copy.deepcopy(current['scope']); renewed.pop('scope_digest')
            renewed['authorization_ref'] = 'owner-approved-renewal'
            renewed['expires_at'] = (datetime.now(timezone.utc)+timedelta(days=1)).isoformat()
            updated = self.service.update(aid, {'scope': renewed}, current['revision'])
            retest = self.service.retest_plan(aid, baseline['artifact_id'])
            self.assertEqual(retest['value']['scope'], updated['scope'])
            self.assertEqual(retest['value']['spec']['retest_of']['source_scope_digest'], original['value']['plan']['scope']['scope_digest'])
            state['headers'] = True
            result = self.service.retest_execute(aid, retest['artifact_id'], retest['value']['plan_digest'])
            self.assertEqual(verify_check_execution(result['value']), [])
            self.assertEqual(self.store.artifact(aid, baseline['artifact_id']), original)
            self.assertEqual(len(self.store.artifacts(aid, 'check-comparison')), 1)

    def test_review_and_standards_annotations_are_cas_bound_and_cannot_change_verdict(self):
        with service() as (origin, state):
            spec = header_spec(origin)
            aid = self.service.create('Review', scope_for(spec))['id']
            plan = self.service.check_plan(aid, spec)
            execution = self.service.check_execute(aid, plan['artifact_id'], plan['value']['plan_digest'])
            frozen = self.service.report(aid); row = frozen['findings'][0]
            revision = self.store.get(aid)['revision']
            mapping = {'standard': 'API', 'version': '2023', 'id': 'API8:2023', 'relation': 'partially_covers',
                       'rationale': 'Header configuration observation only.', 'evidence_refs': row['observation_refs']}
            annotations = {row['id']: {'review': 'accepted_risk', 'rationale': 'Owner accepted until scheduled header fix.',
                'severity': 'low', 'business_risk': 'Browser response hardening gap.', 'standard_refs': [mapping]}}
            updated = self.service.annotate(aid, annotations, revision)
            self.assertEqual(updated['revision'], revision+1)
            reviewed = self.service.report(aid)['findings'][0]
            self.assertEqual(reviewed['review'], 'accepted_risk')
            self.assertEqual(reviewed['status'], 'confirmed')
            self.assertEqual(reviewed['standard_refs'], [mapping])
            self.assertEqual(self.store.artifact(aid, execution['artifact_id']), execution)
            with self.assertRaisesRegex(WorkbenchError, 'revision_conflict'):
                self.service.annotate(aid, {}, revision)
            bad = copy.deepcopy(annotations); bad[row['id']]['status'] = 'fixed'
            with self.assertRaisesRegex(ValueError, 'cannot be overridden'):
                self.service.annotate(aid, bad, updated['revision'])
            bad = copy.deepcopy(annotations); bad[row['id']]['standard_refs'][0]['evidence_refs'] = ['foreign-evidence']
            with self.assertRaises(ValueError):
                self.service.annotate(aid, bad, updated['revision'])
            with self.assertRaisesRegex(ValueError, 'absent inventory'):
                self.service.annotate(aid, {'other-finding': {'review': 'reviewed', 'rationale': 'x'}}, updated['revision'])
            self.assertEqual(self.store.get(aid), updated)


if __name__ == '__main__':
    unittest.main()
