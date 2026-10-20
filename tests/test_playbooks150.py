import copy
import threading
import unittest
from unittest.mock import patch

from authzledger.detectors import compile_check
from authzledger.discovery import plan_discovery
from authzledger.oracles import seal
from authzledger.playbooks import plan_playbook,execute_playbook,verify_playbook,verify_playbook_plan,PlaybookError
from authzledger.scope import context_for_scope
from tests.test_detectors150 import service,header_spec,scope_for


def prepared(origin):
    spec=header_spec(origin);scope=scope_for(spec)
    scope['operations'].append({'origin':origin,'method':'GET','path':'/','purpose':'discovery'})
    discover=plan_discovery(scope,[{'kind':'http','origin':origin,'paths':['/']}])
    check=compile_check(spec,scope)
    steps=[{'id':'discover','plan':discover},{'id':'headers','plan':check,'requires':['discover']}]
    return scope,steps


class PlaybookTests(unittest.TestCase):
    def test_compile_offline_exact_scope_and_digests(self):
        scope,steps=prepared('http://127.0.0.1:9')
        with patch('socket.getaddrinfo',side_effect=AssertionError('network')):
            plan=plan_playbook(scope,steps);self.assertEqual([],verify_playbook_plan(plan));self.assertEqual(3,plan['request_upper_bound'])
        self.assertFalse(plan['dynamic_chaining']);self.assertEqual('exact_plan_digest',plan['approval_required'])

    def test_discovery_then_check_share_one_budget(self):
        with service() as (origin,state):
            scope,steps=prepared(origin);result=execute_playbook(plan_playbook(scope,steps));self.assertEqual([],verify_playbook(result));self.assertEqual(3,len(state['requests']))
        self.assertEqual(3,result['budget_ledger']['approved_total']);self.assertEqual(3,result['budget_ledger']['dispatched_total'])
        self.assertEqual(1,result['steps'][0]['execution']['ledger']['dispatched_total'])
        self.assertEqual(3,result['steps'][1]['execution']['budget_ledger']['dispatched_total'])
        self.assertEqual(2,result['coverage']['completed_steps']);self.assertEqual(0,result['coverage']['not_run_steps'])

    def test_invalid_later_plan_stops_before_any_dispatch(self):
        with service() as (origin,state):
            scope,steps=prepared(origin);plan=plan_playbook(scope,steps)
            plan['steps'][1]['plan']['spec']['params']['required_headers']=[]
            plan=seal('playbook-plan',plan,'plan_digest')
            with self.assertRaisesRegex(PlaybookError,'invalid_playbook_plan'):execute_playbook(plan)
            self.assertEqual([],state['requests'])

    def test_control_failure_marks_all_later_steps_not_run(self):
        with service() as (origin,state):
            scope,steps=prepared(origin);steps=[{'id':'first','plan':steps[1]['plan']},{'id':'second','plan':steps[1]['plan'],'requires':['first']}]
            state['available']=False;result=execute_playbook(plan_playbook(scope,steps));self.assertEqual([],verify_playbook(result));self.assertEqual(1,len(state['requests']))
        self.assertEqual('controls_or_observations_inconclusive',result['steps'][0]['reason'])
        self.assertEqual('not_run',result['steps'][1]['status']);self.assertEqual('prior_step_inconclusive',result['steps'][1]['reason'])

    def test_total_budget_not_reset_between_steps(self):
        scope,steps=prepared('http://127.0.0.1:9');scope['limits']['max_requests']=2
        steps=[{'id':'one','plan':compile_check(header_spec('http://127.0.0.1:9'),scope)}, {'id':'two','plan':compile_check(header_spec('http://127.0.0.1:9'),scope)}]
        with self.assertRaisesRegex(PlaybookError,'total_exceeds'):plan_playbook(scope,steps)

    def test_arbitrary_step_or_dynamic_dataflow_refused(self):
        scope,steps=prepared('http://127.0.0.1:9')
        steps[1]['bindings']={'target_from':'discover'}
        with self.assertRaisesRegex(PlaybookError,'invalid_playbook_step_fields'):plan_playbook(scope,steps)
        steps[1].pop('bindings');steps[1]['plan']={'kind':'shell','command':'echo no'}
        with self.assertRaisesRegex(PlaybookError,'unsupported_step'):plan_playbook(scope,steps)

    def test_forward_dependencies_and_duplicates_refused(self):
        scope,steps=prepared('http://127.0.0.1:9');steps[0]['requires']=['headers']
        with self.assertRaisesRegex(PlaybookError,'earlier_steps'):plan_playbook(scope,steps)
        steps[0]['requires']=[];steps[1]['id']=steps[0]['id'];steps[1]['requires']=[]
        with self.assertRaisesRegex(PlaybookError,'duplicate'):plan_playbook(scope,steps)

    def test_mixed_authorization_policies_refused(self):
        scope,steps=prepared('http://127.0.0.1:9');different=copy.deepcopy(scope);different['authorization_ref']='other'
        steps[1]['plan']=compile_check(header_spec('http://127.0.0.1:9'),different)
        with self.assertRaisesRegex(PlaybookError,'scope_mismatch'):plan_playbook(scope,steps)

    def test_pre_cancelled_shared_context_sends_nothing(self):
        with service() as (origin,state):
            scope,steps=prepared(origin);stop=threading.Event();stop.set();result=execute_playbook(plan_playbook(scope,steps),stop_event=stop)
            self.assertEqual([],state['requests']);self.assertEqual([],verify_playbook(result))
        self.assertEqual(2,result['coverage']['not_run_steps']);self.assertTrue(all(s['reason']=='cancelled' for s in result['steps']))

    def test_missing_later_credentials_fail_preflight_without_discovery(self):
        from authzledger.credentials import CredentialResolver
        with service() as (origin,state):
            scope,steps=prepared(origin);spec=header_spec(origin)
            spec['contract']['identities']['anonymous']['headers']={'Authorization':{'env':'MISSING_PLAYBOOK_TOKEN'}}
            spec['contract']['cases'].insert(0,{'id':'identity','identity':'anonymous','method':'GET','path':'/me','expect':{'status':[200],'json':{'/principal':'actor'}}})
            spec['contract']['cases'][1]['requires']=['identity'];spec['contract']['cases'][2]['requires']=['baseline','identity'];spec['controls']=['identity','baseline'];spec['identity_controls']={'anonymous':'identity'}
            scope['operations'].append({'origin':origin,'method':'GET','path':'/me','purpose':'identity_control'})
            steps[0]['plan']=plan_discovery(scope,[{'kind':'http','origin':origin,'paths':['/']}]);steps[1]['plan']=compile_check(spec,scope)
            with patch.dict('os.environ',{},clear=True):
                with self.assertRaisesRegex(PlaybookError,'credential_preflight'):execute_playbook(plan_playbook(scope,steps),credential_resolver=CredentialResolver())
            self.assertEqual([],state['requests'])

    def test_larger_supplied_budget_refused(self):
        scope,steps=prepared('http://127.0.0.1:9');plan=plan_playbook(scope,steps)
        with self.assertRaisesRegex(PlaybookError,'exact_remaining_shared_budget'):execute_playbook(plan,context=context_for_scope(scope))

    def test_rehash_cannot_invent_skips_or_reset_child_budget(self):
        with service() as (origin,state):
            scope,steps=prepared(origin);result=execute_playbook(plan_playbook(scope,steps))
        changed=copy.deepcopy(result);changed['steps'][1]['status']='not_run';changed['steps'][1]['execution']=None;changed=seal('playbook-execution',changed,'execution_digest');self.assertTrue(verify_playbook(changed))
        changed=copy.deepcopy(result);changed['steps'][1]['execution']['budget_ledger']['dispatched_total']=2;changed['steps'][1]['execution']=seal('check-execution',changed['steps'][1]['execution'],'execution_digest');changed=seal('playbook-execution',changed,'execution_digest');self.assertTrue(verify_playbook(changed))

    def test_scope_declared_get_mutation_is_visible_in_effects(self):
        origin='http://127.0.0.1:9';spec=header_spec(origin);scope=scope_for(spec)
        for op in scope['operations']:op['effect']='mutate'
        plan=plan_playbook(scope,[{'id':'declared-effect','plan':compile_check(spec,scope)}]);self.assertIn('mutate',plan['effects'])

    def test_effects_and_cleanup_reserve_are_declared(self):
        from tests.test_workflows import fixture,spec as workflow_spec
        with fixture() as (origin,state):
            spec={'schema_version':1,'kind':'check-spec','id':'workflow','check_id':'business_logic.skipped_approval','version':'1.0.0','source_refs':['fixture'],'workflow_spec':workflow_spec(origin)}
            scope=scope_for(spec)
            for op in list(scope['operations']):
                if 'placeholder' in op['path']:
                    item=dict(op);item['path']=item['path'].replace('placeholder','1');scope['operations'].append(item)
            plan=plan_playbook(scope,[{'id':'workflow','plan':compile_check(spec,scope)}]);self.assertEqual(1,plan['cleanup_reserve']);self.assertIn('mutate',plan['effects'])
            result=execute_playbook(plan);self.assertEqual([],verify_playbook(result));self.assertEqual('complete',result['steps'][0]['execution']['adapter_execution']['variants'][0]['cleanup'])

if __name__=='__main__':unittest.main()
