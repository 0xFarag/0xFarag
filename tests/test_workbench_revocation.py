"""Administrative authorization lifecycle on disposable SQLite evidence; no transport."""
import copy
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from authzledger.cli import main
from authzledger.oracles import seal
from authzledger.platform_reports import verify_platform
from authzledger.studio_platform import platform_route
from authzledger.workbench import WorkbenchError, WorkbenchService, WorkbenchStore
from tests.test_scope150 import scope


class AuthorizationRevisionTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / 'work.db'
        self.store = WorkbenchStore(self.path)
        self.addCleanup(self.store.close)
        self.service = WorkbenchService(self.store)
        origin = 'http://127.0.0.1:9'
        self.seeds = [{'origin': origin, 'paths': ['/']}]
        self.aid = self.service.create('Local review', scope(origin, operations=[
            {'origin': origin, 'method': 'GET', 'path': '/', 'purpose': 'discovery'}]), {'roe_ref': 'R1'})['id']
        self.plan = self.service.discover_plan(self.aid, self.seeds)
        tripwire = patch('authzledger.discovery.execute_discovery', side_effect=AssertionError('no backend permitted'))
        self.backend = tripwire.start()
        self.addCleanup(tripwire.stop)
        self.addCleanup(self.backend.assert_not_called)
        network = patch('socket.socket', side_effect=AssertionError('no sockets permitted'))
        network.start()
        self.addCleanup(network.stop)

    def revision(self):
        return self.store.get(self.aid)['revision']

    def schedule(self, plan, approval=None):
        return self.service.schedule(self.aid, plan['artifact_id'], approval or plan['approval_digest'], 1, 1, 8)

    def assert_shared_rejection(self, service, plan, approval, code):
        with self.assertRaisesRegex(WorkbenchError, code):
            service.discover_execute(self.aid, plan['artifact_id'], approval)
        self.assertEqual(service.jobs(self.aid), [])

    def test_cli_revoke_persists_stops_schedule_and_preserves_evidence(self):
        self.schedule(self.plan)
        initial = self.store.artifact(self.aid, self.plan['artifact_id'])
        output = io.StringIO()
        with redirect_stdout(output):
            rc = main(['assessment', 'revoke-authorization', self.aid, '--store', str(self.path),
                       '--expected-revision', str(self.revision())])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(output.getvalue())['authorization_policy']['state'], 'revoked')
        with WorkbenchStore(self.path) as reopened:
            service = WorkbenchService(reopened)
            self.assert_shared_rejection(service, self.plan, self.plan['approval_digest'], 'authorization_revoked')
            self.assertEqual(service.run_due(self.aid), [])
            registered, = service.schedules(self.aid)
            self.assertEqual((registered['state'], registered['reason'], registered['reserved_requests']), ('blocked', 'authorization_revoked', 0))
            self.assertEqual(reopened.artifact(self.aid, self.plan['artifact_id']), initial)
            frozen = service.report(self.aid)
            self.assertEqual(frozen['assessment']['authorization_policy']['state'], 'revoked')
            self.assertEqual(verify_platform(frozen), [])
        with self.assertRaisesRegex(WorkbenchError, 'authorization_revoked'):
            self.schedule(self.plan)
        with self.assertRaisesRegex(WorkbenchError, 'authorization_revoked'):
            self.service.discover_plan(self.aid, self.seeds)

    def test_roe_update_invalidates_approval_even_if_original_reference_returns(self):
        self.schedule(self.plan)
        for reference in ('R2', 'R1'):
            self.service.update(self.aid, {'engagement': {'roe_ref': reference}}, self.revision())
        self.assert_shared_rejection(self.service, self.plan, self.plan['approval_digest'], 'authorization_changed')
        self.assertEqual(self.service.schedules(self.aid)[0]['state'], 'blocked')
        with self.assertRaisesRegex(WorkbenchError, 'authorization_changed'):
            self.schedule(self.plan)
        with self.assertRaisesRegex(WorkbenchError, 'authorization_changed'):
            self.service.playbook_plan(self.aid, [{'id': 'offline-plan', 'plan_id': self.plan['artifact_id'], 'requires': []}])
        fresh = self.service.discover_plan(self.aid, self.seeds)
        self.assertEqual(fresh['value']['plan_digest'], self.plan['value']['plan_digest'])
        self.assertNotEqual(fresh['approval_digest'], self.plan['approval_digest'])
        with self.assertRaisesRegex(WorkbenchError, 'exact_plan_approval_required'):
            self.schedule(fresh, self.plan['approval_digest'])
        self.assertEqual(self.schedule(fresh)['state'], 'scheduled')

    def test_ordinary_edit_preserves_approval_and_revocation_is_terminal(self):
        self.service.update(self.aid, {'engagement': {'roe_ref': 'R1', 'notes': 'Office review'}, 'title': 'Renamed'}, self.revision())
        self.assertEqual(self.schedule(self.plan)['state'], 'scheduled')
        revoked = self.service.revoke_authorization(self.aid, self.revision())
        self.assertEqual(self.service.revoke_authorization(self.aid, self.revision()), revoked)
        with self.assertRaisesRegex(WorkbenchError, 'authorization_revoked'):
            self.service.update(self.aid, {'engagement': {'roe_ref': 'R2'}}, self.revision())
        self.assertEqual(self.store.get(self.aid), revoked)

    def test_expired_authority_refuses_approval_and_existing_due_slot_before_budget(self):
        self.schedule(self.plan)
        with patch('authzledger.scope.seconds_remaining', return_value=0):
            with self.assertRaisesRegex(WorkbenchError, 'authorization-expired'):
                self.schedule(self.plan)
            self.assert_shared_rejection(self.service, self.plan, self.plan['approval_digest'], 'authorization-expired')
            blocked, = self.service.run_due(self.aid)
            self.assertEqual((blocked['state'], blocked['reserved_requests']), ('blocked', 0))

    def test_studio_route_revision_conflict_then_revokes(self):
        responses = []
        handler = SimpleNamespace(path='/api/platform/revoke-authorization', server=SimpleNamespace(workbench=self.service),
                                  respond=lambda status, data: responses.append((status, data)))
        with self.assertRaisesRegex(WorkbenchError, 'assessment_revision_conflict'):
            platform_route(handler, {'assessment_id': self.aid, 'expected_revision': self.revision()-1})
        self.assertEqual(responses, [])
        platform_route(handler, {'assessment_id': self.aid, 'expected_revision': self.revision()})
        self.assertEqual(responses[0][1]['assessment']['authorization_policy']['state'], 'revoked')
        self.assert_shared_rejection(self.service, self.plan, self.plan['approval_digest'], 'authorization_revoked')

    def test_running_schedule_refuses_change_and_keeps_policy_atomic(self):
        item = self.schedule(self.plan)
        item['state'] = 'running'
        self.store._db.execute('UPDATE wb_schedules SET value=? WHERE id=?', (json.dumps(item), item['id']))
        before = self.store.get(self.aid)
        with self.assertRaisesRegex(WorkbenchError, 'requires_stopped_execution'):
            self.service.revoke_authorization(self.aid, self.revision())
        self.assertEqual(self.store.get(self.aid), before)
        self.service.recover_interrupted(self.aid)
        self.assertEqual(self.service.revoke_authorization(self.aid, self.revision())['authorization_policy']['state'], 'revoked')

    def test_legacy_approval_requires_fresh_plan_without_rewriting_old_artifact(self):
        # Insert a separate synthetic old-format chain. Its assessment and plan
        # use the original fields and seals, before the authority fields existed.
        previous = copy.deepcopy(self.store.get(self.aid))
        previous.pop('authorization_policy')
        previous.update(id='assessment-legacy', revision=1, artifact_head='0'*64)
        self.aid = previous['id']
        self.store._revision(previous)
        legacy_plan = {k: v for k, v in self.plan.items()
                       if k not in {'artifact_digest', 'authorization_revision', 'approval_digest'}}
        legacy_plan.update(artifact_id='historical-plan', assessment_id=self.aid, assessment_revision=1)
        legacy_plan = seal('workbench-artifact', legacy_plan, 'artifact_digest')
        self.store._db.execute('INSERT INTO wb_artifacts(artifact_id,assessment_id,kind,value) VALUES(?,?,?,?)',
                               (legacy_plan['artifact_id'], self.aid, legacy_plan['kind'], json.dumps(legacy_plan)))
        previous.update(revision=2, artifact_head=legacy_plan['artifact_digest'])
        self.store._revision(previous)
        old = legacy_plan['value']['plan_digest']
        old_slot = {'id': 'legacy-slot', 'assessment_id': self.aid, 'plan_id': legacy_plan['artifact_id'],
                    'approval': old, 'state': 'scheduled', 'next_due': '2000-01-01T00:00:00+00:00',
                    'request_budget': 8, 'reserved_requests': 0, 'completed_iterations': 0, 'iterations': 1}
        self.store._db.execute('INSERT INTO wb_schedules VALUES(?,?,?)', (old_slot['id'], self.aid, json.dumps(old_slot)))
        blocked, = self.service.run_due(self.aid)
        self.assertEqual((blocked['state'], blocked['reserved_requests'], blocked['reason']),
                         ('blocked', 0, 'historical_approval_replan_required'))
        self.assert_shared_rejection(self.service, legacy_plan, old, 'historical_approval_replan_required')
        with self.assertRaisesRegex(WorkbenchError, 'historical_approval_replan_required'):
            self.schedule(legacy_plan, old)
        fresh = self.service.discover_plan(self.aid, self.seeds)
        with self.assertRaisesRegex(WorkbenchError, 'authorization_changed'):
            self.schedule(legacy_plan, old)
        self.assertNotEqual(fresh['approval_digest'], old)
        self.assertEqual(self.schedule(fresh)['state'], 'scheduled')
        self.assertEqual(self.store.artifact(self.aid, legacy_plan['artifact_id']), legacy_plan)


if __name__ == '__main__':
    unittest.main()
