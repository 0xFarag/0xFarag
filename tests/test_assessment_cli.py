"""CLI and Studio domain-service parity at real transport boundaries."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from authzledger.assessment_demo import assessment_lab, imported_plan, write_json
from authzledger.cli import main
from authzledger.minimize import removable_units


class AssessmentCliTests(unittest.TestCase):
    def call(self, *args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(['assessment', *map(str, args)])

    def test_plan_is_offline_and_bad_approval_sends_nothing(self):
        with assessment_lab() as (target, state, _, _), tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = imported_plan(target)[2]
            write_json(root / 'spec.json', plan['spec'])
            self.assertEqual(self.call('plan', root / 'spec.json', '--out', root / 'plan.json'), 0)
            self.assertEqual(json.loads((root / 'plan.json').read_text()), plan)
            self.assertEqual(self.call('run', root / 'plan.json', '--approve', '0' * 64, '--out', root / 'run'), 2)
            self.assertEqual(state['requests'], [])
            self.assertFalse((root / 'run').exists())

    def test_real_run_reduce_inspect_retest_and_report_preserve_baseline(self):
        with assessment_lab() as (target, state, _, values), tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = imported_plan(target)[2]
            write_json(root / 'plan.json', plan)
            with patch.dict('os.environ', {'DEMO_OWNER': values['owner'], 'DEMO_PEER': values['peer']}):
                self.assertEqual(self.call('run', root / 'plan.json', '--approve', plan['plan_digest'], '--out', root / 'run'), 1)
                original = (root / 'run/execution.json').read_bytes()
                execution = json.loads(original)
                self.assertEqual(self.call('verify', root / 'run/execution.json'), 0)
                self.assertEqual(self.call('inspect', root / 'run/execution.json', '--finding', execution['findings'][0]['id']), 0)
                write_json(root / 'units.json', removable_units(execution))
                self.assertEqual(self.call('reduction-plan', root / 'run/execution.json', root / 'units.json', '--out', root / 'reduce.json'), 0)
                reduction = json.loads((root / 'reduce.json').read_text())
                self.assertEqual(self.call('minimize', root / 'reduce.json', '--approve', reduction['plan_digest'], '--out', root / 'reduced'), 0)
                self.assertEqual(self.call('retest-plan', root / 'run/execution.json', '--variant', 'peer-1', '--out', root / 'retest.json'), 0)
                retest = json.loads((root / 'retest.json').read_text())
                state['mode'] = 'fixed'
                self.assertEqual(self.call('run', root / 'retest.json', '--approve', retest['plan_digest'], '--out', root / 'current'), 0)
                self.assertEqual(self.call('compare', root / 'run/execution.json', root / 'current/execution.json', '--out', root / 'comparison.json'), 0)
            self.assertEqual((root / 'run/execution.json').read_bytes(), original)
            self.assertEqual(self.call('snapshot', root / 'run/execution.json', root / 'current/execution.json', '--comparison', root / 'comparison.json',
                                       '--reduction', root / 'reduced/execution.json', '--out', root / 'snapshot.json'), 0)
            self.assertEqual(self.call('report', root / 'snapshot.json', '--formats', 'json', 'html', '--out', root / 'reports'), 0)
            self.assertEqual(self.call('verify', root / 'snapshot.json'), 0)
            for path in root.rglob('*.json'):
                text = path.read_text()
                self.assertNotIn(values['owner'], text)
                self.assertNotIn(values['peer'], text)

    def test_unknown_impact_keeps_full_scope_and_reasons(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = imported_plan('http://127.0.0.1:9')[2]
            write_json(root / 'contract.json', plan['contract'])
            write_json(root / 'changes.json', [{'kind': 'policy', 'id': 'unknown', 'before_digest': '1' * 64, 'after_digest': '2' * 64}])
            with patch('socket.getaddrinfo', side_effect=AssertionError('offline planning')):
                self.assertEqual(self.call('impact-plan', root / 'contract.json', root / 'changes.json', '--out', root / 'impact.json'), 0)
            result = json.loads((root / 'impact.json').read_text())
            self.assertEqual(result['unknown_dependencies'], ['policy:unknown'])
            self.assertEqual(set(result['selected_ids']), {case['id'] for case in plan['contract']['cases']})

    def test_existing_destination_refuses_run_before_dispatch(self):
        with assessment_lab() as (target, state, _, _), tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = imported_plan(target)[2]
            write_json(root / 'plan.json', plan)
            self.assertEqual(self.call('run', root / 'plan.json', '--approve', plan['plan_digest'], '--out', root), 2)
            self.assertEqual(state['requests'], [])

    def test_duplicate_and_overflow_json_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'input.json'
            for raw in ('{"kind":"a","kind":"b"}', '{"value":1e999}'):
                path.write_text(raw)
                self.assertEqual(self.call('verify', path), 2)

    def test_two_cycle_assurance_cli_history_snapshot_and_render_are_source_bound(self):
        from authzledger.history import HistoryStore
        from authzledger.lab110 import workflow_lab, workflow_spec
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with workflow_lab() as (origin, state):
                state['vulnerable'] = False
                specification = {'schema_version': 1, 'kind': 'workflow-assurance-spec',
                                 'workflow': workflow_spec(origin), 'max_cycles': 2, 'interval_seconds': 0,
                                 'max_requests_total': 12, 'max_history_age_seconds': 300}
                write_json(root / 'assurance-spec.json', specification)
                with patch('socket.getaddrinfo', side_effect=AssertionError('offline planning')):
                    self.assertEqual(self.call('assurance-plan', root / 'assurance-spec.json', '--out', root / 'assurance-plan.json'), 0)
                plan = json.loads((root / 'assurance-plan.json').read_text())
                self.assertEqual(self.call('assurance-run', root / 'assurance-plan.json', '--approve', '0' * 64,
                                           '--history', root / 'history.sqlite3', '--out', root / 'wrong-approval'), 2)
                self.assertEqual(state['requests'], [])
                self.assertFalse((root / 'wrong-approval').exists())
                self.assertFalse((root / 'history.sqlite3').exists())
                self.assertEqual(self.call('assurance-run', root / 'assurance-plan.json', '--approve', plan['plan_digest'],
                                           '--history', root / 'history.sqlite3', '--out', root / 'assurance'), 0)
                original = (root / 'assurance/execution.json').read_bytes()
                result = json.loads(original)
                self.assertEqual(result['exit_code'], 0)
                self.assertEqual(result['status'], 'satisfied')
                self.assertEqual(result['completed_cycles'], 2)
                self.assertEqual(result['budget_ledger']['dispatched_total'], 12)
                self.assertEqual(len(state['requests']), 12)
                self.assertEqual(state['objects'], {})
            # The target is now stopped. Reopening SQLite verifies persistence,
            # and every following CLI step must remain entirely offline.
            with HistoryStore(root / 'history.sqlite3') as history:
                self.assertEqual(history.verify_chain(), [])
                durable = history.workflow_snapshot(plan['scope_key'])
                self.assertEqual(len(durable['records']), 2)
                self.assertEqual(history.list_runs(), [])
                self.assertEqual([record['trace'] for record in durable['records']], [cycle['trace'] for cycle in result['cycles']])
                self.assertEqual(durable['workflow_root_sha256'], result['cycles'][-1]['history']['record_sha256'])
            with patch('socket.getaddrinfo', side_effect=AssertionError('offline retained-evidence workflow')):
                self.assertEqual(self.call('verify', root / 'assurance/execution.json'), 0)
                self.assertEqual(self.call('snapshot', '--assurance', root / 'assurance/execution.json',
                                           '--id', 'workflow-watch', '--title', 'Finite workflow assurance', '--out', root / 'snapshot.json'), 0)
                self.assertEqual(self.call('verify', root / 'snapshot.json'), 0)
                self.assertEqual(self.call('report', root / 'snapshot.json', '--formats', 'json', 'html', '--out', root / 'reports'), 0)
            snapshot = json.loads((root / 'snapshot.json').read_text())
            exported = json.loads((root / 'reports/assessment.json').read_text())
            self.assertEqual(exported, snapshot)
            self.assertEqual(snapshot['assurances'], [result])
            self.assertEqual(len(snapshot['workflows']), 2)
            self.assertIn(result['assurance_digest'], (root / 'reports/assessment.html').read_text())
            self.assertEqual((root / 'assurance/execution.json').read_bytes(), original)

    def test_assurance_cli_violation_exit_one_retains_first_cycle_and_stops(self):
        from authzledger.history import HistoryStore
        from authzledger.lab110 import workflow_lab, workflow_spec
        with workflow_lab() as (origin, state), tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            write_json(root / 'spec.json', {'schema_version': 1, 'kind': 'workflow-assurance-spec',
                       'workflow': workflow_spec(origin), 'max_cycles': 2, 'interval_seconds': 0,
                       'max_requests_total': 12, 'max_history_age_seconds': 300})
            self.assertEqual(self.call('assurance-plan', root / 'spec.json', '--out', root / 'plan.json'), 0)
            plan = json.loads((root / 'plan.json').read_text())
            self.assertEqual(self.call('assurance-run', root / 'plan.json', '--approve', plan['plan_digest'],
                                       '--history', root / 'history.sqlite3', '--out', root / 'run'), 1)
            result = json.loads((root / 'run/execution.json').read_text())
            self.assertEqual((result['status'], result['exit_code'], result['stop_reason']), ('violation', 1, 'workflow_violation'))
            self.assertEqual(result['completed_cycles'], 1)
            self.assertEqual(len(state['requests']), 6)
            with HistoryStore(root / 'history.sqlite3') as history:
                self.assertEqual(history.verify_chain(), [])
                self.assertEqual(len(history.workflow_snapshot()['records']), 1)
            self.assertEqual(self.call('verify', root / 'run/execution.json'), 0)

    def test_assurance_cli_global_budget_exit_two_retains_both_finished_cycles(self):
        from authzledger.lab110 import workflow_lab, workflow_spec
        with workflow_lab() as (origin, state), tempfile.TemporaryDirectory() as directory:
            state['vulnerable'] = False
            root = Path(directory)
            write_json(root / 'spec.json', {'schema_version': 1, 'kind': 'workflow-assurance-spec',
                       'workflow': workflow_spec(origin), 'max_cycles': 3, 'interval_seconds': 0,
                       'max_requests_total': 12, 'max_history_age_seconds': 300})
            self.assertEqual(self.call('assurance-plan', root / 'spec.json', '--out', root / 'plan.json'), 0)
            plan = json.loads((root / 'plan.json').read_text())
            self.assertEqual(self.call('assurance-run', root / 'plan.json', '--approve', plan['plan_digest'],
                                       '--history', root / 'history.sqlite3', '--out', root / 'run'), 2)
            result = json.loads((root / 'run/execution.json').read_text())
            self.assertEqual(result['stop_reason'], 'request_budget')
            self.assertEqual(result['completed_cycles'], 2)
            self.assertEqual(result['budget_ledger']['dispatched_total'], 12)
            self.assertEqual(self.call('verify', root / 'run/execution.json'), 0)
