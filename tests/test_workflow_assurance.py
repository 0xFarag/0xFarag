"""Combined finite workflow assurance, history integrity and global budget gates."""
import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from authzledger.history import HistoryStore, HistoryError, _workflow_digest
from authzledger.workflow_assurance import (compile_workflow_assurance,run_workflow_assurance,
    verify_workflow_assurance,WorkflowAssuranceError)
from authzledger.oracles import seal
from test_workflows import fixture,spec


def assurance_spec(origin,cycles=2,budget=12):
    return {'schema_version':1,'kind':'workflow-assurance-spec','workflow':spec(origin),'max_cycles':cycles,
            'interval_seconds':0,'max_requests_total':budget,'max_history_age_seconds':300}


class WorkflowAssuranceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/'history.sqlite3'
        self.history=HistoryStore(self.path);self.addCleanup(self.history.close)

    def test_two_safe_cycles_share_budget_fresh_fixture_and_durable_traces(self):
        with fixture() as (origin,state):
            state['vulnerable']=False
            plan=compile_workflow_assurance(assurance_spec(origin))
            result=run_workflow_assurance(plan,history=self.history)
        self.assertEqual(result['completed_cycles'],2)
        self.assertEqual(result['status'],'satisfied')
        self.assertEqual(result['budget_ledger']['dispatched_total'],12)
        self.assertEqual(result['budget_ledger']['by_kind']['setup'],2)
        self.assertEqual(result['budget_ledger']['by_kind']['cleanup'],2)
        self.assertEqual(verify_workflow_assurance(result),[])
        self.assertEqual(self.history.verify_chain(),[])
        self.assertEqual(len(self.history.workflow_snapshot()['records']),2)
        self.assertEqual(self.history.list_runs(),[])
        self.history.close();self.history=HistoryStore(self.path)
        self.assertEqual(len(self.history.workflow_snapshot()['records']),2)

    def test_corrupt_legacy_history_schema_blocks_all_workflow_requests(self):
        with sqlite3.connect(self.path) as connection:connection.execute('DROP TRIGGER runs_no_update')
        with fixture() as (origin,state):
            with self.assertRaises(HistoryError):
                run_workflow_assurance(compile_workflow_assurance(assurance_spec(origin)),history=self.history)
            self.assertEqual(state['requests'],[])

    def test_corrupt_workflow_history_blocks_next_requests(self):
        with fixture() as (origin,state):
            state['vulnerable']=False
            plan=compile_workflow_assurance(assurance_spec(origin,1,6))
            run_workflow_assurance(plan,history=self.history)
            with sqlite3.connect(self.path) as connection:
                connection.execute('DROP TRIGGER workflow_runs_no_update')
                connection.execute("UPDATE workflow_runs SET record_sha256=?",('f'*64,))
            state['requests'].clear()
            with self.assertRaises(HistoryError):run_workflow_assurance(plan,history=self.history)
            self.assertEqual(state['requests'],[])

    def test_stale_history_is_rejected_before_traffic_even_when_chain_is_valid(self):
        with fixture() as (origin,state):
            state['vulnerable']=False
            plan=compile_workflow_assurance(assurance_spec(origin,1,6))
            result=run_workflow_assurance(plan,history=self.history)
            row=self.history.workflow_snapshot()['records'][0]
            old=(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat().replace('+00:00','Z')
            with sqlite3.connect(self.path) as connection:
                context=json.loads(connection.execute('SELECT context_json FROM workflow_runs WHERE id=1').fetchone()[0])
                anchor=_workflow_digest({'schema_version':1,'id':1,'created_at':old,'previous_sha256':row['previous_sha256'],'context':context})
                connection.execute('DROP TRIGGER workflow_runs_no_update')
                connection.execute('UPDATE workflow_runs SET created_at=?,record_sha256=? WHERE id=1',(old,anchor))
                from authzledger.history import _WORKFLOW_TRIGGERS
                connection.execute(_WORKFLOW_TRIGGERS['workflow_runs_no_update'])
            self.assertEqual(self.history.verify_chain(),[])
            state['requests'].clear()
            with self.assertRaisesRegex(WorkflowAssuranceError,'stale_workflow_history'):
                run_workflow_assurance(plan,history=self.history)
            self.assertEqual(state['requests'],[])

    def test_violation_stops_before_next_cycle(self):
        with fixture() as (origin,state):
            result=run_workflow_assurance(compile_workflow_assurance(assurance_spec(origin,3,18)),history=self.history)
        self.assertEqual(result['completed_cycles'],1)
        self.assertEqual(result['stop_reason'],'workflow_violation')
        self.assertEqual(len(state['requests']),6)
        self.assertEqual(verify_workflow_assurance(result),[])

    def test_failed_cleanup_stops_and_retains_inconclusive_original_trace(self):
        with fixture() as (origin,state):
            state.update(vulnerable=False,cleanup=False)
            result=run_workflow_assurance(compile_workflow_assurance(assurance_spec(origin)),history=self.history)
        self.assertEqual(result['completed_cycles'],1)
        self.assertEqual(result['stop_reason'],'cleanup_pending')
        self.assertEqual(result['cycles'][0]['trace'],self.history.workflow_snapshot()['records'][0]['trace'])
        self.assertEqual(verify_workflow_assurance(result),[])

    def test_reused_fixture_is_stopped_before_second_cycle_action(self):
        with fixture() as (origin,state):
            state.update(vulnerable=False,reuse=True)
            result=run_workflow_assurance(compile_workflow_assurance(assurance_spec(origin)),history=self.history)
        self.assertEqual(result['completed_cycles'],2)
        self.assertEqual(result['status'],'inconclusive')
        self.assertEqual(len(state['requests']),9)
        self.assertEqual(sum('complete' in path for _,path in state['requests']),1)
        self.assertEqual(verify_workflow_assurance(result),[])

    def test_retained_fixture_registry_survives_new_job_and_rule_rename(self):
        with fixture() as (origin,state):
            state.update(vulnerable=False,reuse=True)
            source=assurance_spec(origin,1,6)
            first=run_workflow_assurance(compile_workflow_assurance(source),history=self.history)
            source['workflow']['rule']['id']='renamed-rule'
            source['workflow']['id']='renamed-workflow'
            state['requests'].clear()
            second=run_workflow_assurance(compile_workflow_assurance(source),history=self.history)
        self.assertEqual(first['plan']['scope_key'],second['plan']['scope_key'])
        self.assertEqual(second['status'],'inconclusive')
        self.assertEqual(len(state['requests']),3)
        self.assertFalse(any('complete' in path for _,path in state['requests']))
        self.assertTrue(second['fixture_history']['known_fixture_sha256'])
        self.assertEqual(verify_workflow_assurance(second),[])

    def test_total_budget_stops_further_cycles_including_cleanup(self):
        with fixture() as (origin,state):
            state['vulnerable']=False
            result=run_workflow_assurance(compile_workflow_assurance(assurance_spec(origin,5,12)),history=self.history)
        self.assertEqual(result['completed_cycles'],2)
        self.assertEqual(result['stop_reason'],'request_budget')
        self.assertEqual(len(state['requests']),12)
        self.assertEqual(verify_workflow_assurance(result),[])

    def test_plan_is_offline_and_mutation_of_trace_status_does_not_verify(self):
        with patch('socket.getaddrinfo',side_effect=AssertionError('network')):
            plan=compile_workflow_assurance(assurance_spec('http://127.0.0.1:9'))
            self.assertEqual(plan,compile_workflow_assurance(copy.deepcopy(plan['spec'])))
        with fixture() as (origin,state):
            result=run_workflow_assurance(compile_workflow_assurance(assurance_spec(origin)),history=self.history)
        result.update(status='satisfied',exit_code=0,stop_reason='cycle_limit')
        result=seal('workflow-assurance-result',result,'assurance_digest')
        self.assertTrue(verify_workflow_assurance(result))

    def test_rehashed_cycle_cannot_replace_prior_shared_budget_records(self):
        with fixture() as (origin,state):
            state['vulnerable']=False
            result=run_workflow_assurance(compile_workflow_assurance(assurance_spec(origin)),history=self.history)
        second=result['cycles'][1]
        second['trace']['budget_ledger']['requests'][0]['elapsed_ms']+=1
        second['trace']=seal('workflow-trace',second['trace'],'workflow_digest')
        row=second['history']; row['workflow_digest']=second['trace']['workflow_digest']
        context={'schema_version':1,'kind':'workflow-assurance-cycle','assurance_plan_digest':result['plan']['plan_digest'],
                 'scope_key':result['plan']['scope_key'],'cycle':2,'trace':second['trace']}
        row['record_sha256']=_workflow_digest({'schema_version':1,'id':row['id'],'created_at':row['created_at'],
                                             'previous_sha256':row['previous_sha256'],'context':context})
        result['budget_ledger']=copy.deepcopy(second['trace']['budget_ledger'])
        result=seal('workflow-assurance-result',result,'assurance_digest')
        self.assertEqual(verify_workflow_assurance(result),['cycle_budget_reset_or_scope_change'])

    def test_cancel_after_completed_cycle_preserves_verifiable_receipt(self):
        event=threading.Event()
        with fixture() as (origin,state):
            state['vulnerable']=False
            result=run_workflow_assurance(compile_workflow_assurance(assurance_spec(origin)),history=self.history,
                                         stop_event=event,on_cycle=lambda cycle,item:event.set())
        self.assertEqual(result['completed_cycles'],1)
        self.assertEqual(result['stop_reason'],'cancelled')
        self.assertEqual(verify_workflow_assurance(result),[])

    def test_removed_workflow_table_is_not_mistaken_for_new_history(self):
        with fixture() as (origin,state):
            state['vulnerable']=False
            plan=compile_workflow_assurance(assurance_spec(origin,1,6))
            run_workflow_assurance(plan,history=self.history)
            with sqlite3.connect(self.path) as connection:connection.execute('DROP TABLE workflow_runs')
            state['requests'].clear()
            with self.assertRaises(HistoryError):run_workflow_assurance(plan,history=self.history)
            self.assertEqual(state['requests'],[])

    def test_corruption_between_cycles_stops_before_next_network_request(self):
        def corrupt(cycle,item):
            with sqlite3.connect(self.path) as connection:connection.execute('DROP TRIGGER workflow_runs_no_update')
        with fixture() as (origin,state):
            state['vulnerable']=False
            result=run_workflow_assurance(compile_workflow_assurance(assurance_spec(origin)),history=self.history,on_cycle=corrupt)
        self.assertEqual(result['completed_cycles'],1)
        self.assertEqual(result['stop_reason'],'history_integrity_failed')
        self.assertEqual(len(state['requests']),6)
        self.assertEqual(verify_workflow_assurance(result),[])

    def test_explicit_cancel_before_cycle_sends_no_requests(self):
        event=threading.Event();event.set()
        with fixture() as (origin,state):
            result=run_workflow_assurance(compile_workflow_assurance(assurance_spec(origin)),history=self.history,stop_event=event)
        self.assertEqual(result['stop_reason'],'cancelled')
        self.assertEqual(state['requests'],[])
        self.assertEqual(verify_workflow_assurance(result),[])


if __name__=='__main__':unittest.main()
