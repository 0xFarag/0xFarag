"""Real-loopback Contrast Lab acceptance and adversarial offline verification."""
import contextlib
import copy
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from unittest.mock import patch
from authzledger.experiments import (compile_experiment,compile_imported_experiment,execute_experiment,
    verify_execution,verify_plan,ExperimentError,plan_experiment_retest,compare_executions)
from authzledger.oracles import evaluate_input,capture_input,seal,equal


def fixture_spec(target='http://127.0.0.1:9',capture='safe_values'):
    return {'schema_version':1,'kind':'experiment-spec','id':'invoice','title':'Tenant isolation',
      'contract':{'version':1,'name':'Contrast fixture','target':target,'identities':{
        'owner':{'headers':{'Authorization':{'env':'CONTRAST_OWNER'}}},
        'peer':{'headers':{'Authorization':{'env':'CONTRAST_PEER'}}}},'cases':[
        {'id':'actor','identity':'peer','method':'GET','path':'/me','expect':{'status':[200],'json':{'/principal':'peer','/tenant':'B'}}},
        {'id':'owner','identity':'owner','method':'GET','path':'/invoice/A','expect':{'status':[200],'json':{'/marker':'synthetic-A'}}},
        {'id':'negative','identity':'peer','method':'GET','path':'/known-denial','requires':['actor','owner'],'expect':{'status':[403],'json_absent':['/marker']}},
        {'id':'target','identity':'peer','method':'GET','path':'/invoice/A','requires':['actor','owner','negative'],'expect':{'status':[403],'json_absent':['/marker']}}]},
      'rule':{'id':'tenant-isolation','resource_id':'invoice-A','kind':'forbid_field_equal','pointer':'/marker','value':'synthetic-A'},
      'variants':[{'id':'cross-tenant','case_id':'target','identity_control':'actor','object_control':'owner','negative_control':'negative'}], 'capture_mode':capture}

@contextlib.contextmanager
def fixture_service():
    state={'mode':'vulnerable','requests':[]}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*_):pass
        def do_GET(self):
            state['requests'].append(self.path)
            actor=self.headers.get('Authorization')
            if self.path=='/me': status,body=200,{'principal':'owner' if state['mode']=='invalid_controls' or actor!='Bearer peer' else 'peer','tenant':'B'}
            elif self.path.startswith('/invoice/A') and actor=='Bearer owner': status,body=200,{'marker':'synthetic-A'}
            elif self.path=='/known-denial':status,body=403,{'error':'denied'}
            elif state['mode']=='vulnerable':status,body=403,{'marker':'synthetic-A'}
            elif state['mode']=='200error':status,body=200,{'error':'denied'}
            elif state['mode']=='duplicate':status,body=403,None
            else:status,body=403,{'error':'denied'}
            raw=b'{"marker":"wrong","marker":"synthetic-A"}' if body is None else json.dumps(body).encode()
            self.send_response(status);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);worker=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);worker.start()
    with patch.dict('os.environ',{'CONTRAST_OWNER':'Bearer owner','CONTRAST_PEER':'Bearer peer'}):
        try:yield 'http://127.0.0.1:'+str(server.server_port),state
        finally:server.shutdown();server.server_close();worker.join(2)

class ExperimentTests(unittest.TestCase):
    def test_same_input_same_plan_and_no_network(self):
        spec=fixture_spec();other=json.loads(json.dumps(spec,sort_keys=True))
        with patch('socket.getaddrinfo',side_effect=AssertionError('network')):
            self.assertEqual(compile_experiment(spec),compile_experiment(other))
    def test_exact_three_controls_required(self):
        spec=fixture_spec();spec['contract']['cases'][-1]['requires']=['owner']
        with self.assertRaises(ExperimentError):compile_experiment(spec)
    def test_marker_owner_binding_required(self):
        spec=fixture_spec();spec['contract']['cases'][1]['expect']['json']['/marker']='other'
        with self.assertRaises(ExperimentError):compile_experiment(spec)
    def test_status_only_identity_not_binding(self):
        spec=fixture_spec();spec['contract']['cases'][0]['expect'].pop('json')
        with self.assertRaises(ExperimentError):compile_experiment(spec)
    def test_normalizer_cannot_remove_marker(self):
        spec=fixture_spec();spec['volatile_pointers']=['/marker']
        with self.assertRaises(ExperimentError):compile_experiment(spec)
    def test_no_25_variant_expansion(self):
        spec=fixture_spec();spec['variants']*=25
        with self.assertRaises(ExperimentError):compile_experiment(spec)
    def test_explicit_mutation_approval(self):
        spec=fixture_spec();spec['contract']['cases'][-1]['method']='POST'
        with self.assertRaises(ExperimentError):compile_experiment(spec)
        spec['mutation_approval']=['target'];self.assertFalse(verify_plan(compile_experiment(spec)))
    def test_credentials_not_allowed_in_query_or_body(self):
        spec=fixture_spec();spec['contract']['cases'][-1]['path']+='?access_token=private'
        with self.assertRaises(ExperimentError):compile_experiment(spec)
    def test_leak_403_confirmed_and_replayed_offline(self):
        with fixture_service() as (url,state):
            result=execute_experiment(compile_experiment(fixture_spec(url)))
            self.assertEqual(result['findings'][0]['status'],'confirmed')
            self.assertEqual(result['findings'][0]['category'],'denial_data_disclosure')
            self.assertEqual(result['budget_ledger']['dispatched_total'],4)
            self.assertEqual(verify_execution(result),[])
            self.assertNotIn('Bearer',json.dumps(result))
    def test_200_error_not_bola(self):
        with fixture_service() as (url,state):
            state['mode']='200error';result=execute_experiment(compile_experiment(fixture_spec(url)))
            self.assertEqual(result['findings'][0]['status'],'rejected');self.assertEqual(verify_execution(result),[])
    def test_invalid_controls_inconclusive_no_target_request(self):
        with fixture_service() as (url,state):
            state['mode']='invalid_controls';result=execute_experiment(compile_experiment(fixture_spec(url)))
            self.assertEqual(result['findings'][0]['interpretation'],'inconclusive');self.assertEqual(len(state['requests']),2)
            self.assertEqual(verify_execution(result),[])
    def test_duplicate_json_inconclusive(self):
        with fixture_service() as (url,state):
            state['mode']='duplicate';result=execute_experiment(compile_experiment(fixture_spec(url)))
            self.assertEqual(result['findings'][0]['interpretation'],'inconclusive');self.assertEqual(verify_execution(result),[])
    def test_rehashed_false_finding_rejected(self):
        with fixture_service() as (url,state):
            result=execute_experiment(compile_experiment(fixture_spec(url)))
        result['findings'][0]['status']='rejected';result=seal('experiment-execution',result,'execution_digest')
        self.assertTrue(verify_execution(result))
    def test_rehashed_false_predicate_rejected(self):
        with fixture_service() as (url,state):result=execute_experiment(compile_experiment(fixture_spec(url)))
        obs=result['observations'][0];obs['oracle']['decision']={'interpretation':'satisfied','reason':'predicate_satisfied'};obs['interpretation']='satisfied'
        result['observations'][0]=seal('observation',obs,'observation_digest');result=seal('experiment-execution',result,'execution_digest')
        self.assertTrue(verify_execution(result))
    def test_default_attestation_does_not_export_observed_values(self):
        with fixture_service() as (url,state):result=execute_experiment(compile_experiment(fixture_spec(url,'attested')))
        self.assertIsNone(result['observations'][0]['oracle']['input']);self.assertEqual(verify_execution(result),[])
        self.assertEqual(result['observations'][0]['verification_level'],'evaluation_attested')
    def test_retest_preserves_roots_and_confirms_scoped_fix(self):
        with fixture_service() as (url,state):
            before=execute_experiment(compile_experiment(fixture_spec(url)));original=copy.deepcopy(before)
            plan=plan_experiment_retest(before,['cross-tenant']);state['mode']='fixed';after=execute_experiment(plan)
            comparison=compare_executions(before,after)
        self.assertEqual(comparison['transitions'][0]['status'],'fix_verified');self.assertEqual(before,original)
    def test_changed_rule_not_a_fix(self):
        with fixture_service() as (url,state):
            before=execute_experiment(compile_experiment(fixture_spec(url)));spec=fixture_spec(url);spec['rule']['id']='another';after=execute_experiment(compile_experiment(spec))
        with self.assertRaises(ExperimentError):compare_executions(before,after)
    def test_import_mapping_requires_explicit_scope(self):
        entry={'id':'entry','origin':'http://127.0.0.1:9','path':'/invoice/A','method':'GET','headers':{},'execution_blockers':[]}
        s=fixture_spec();b={'id':'import','title':'Import','target':s['contract']['target'],'identities':s['contract']['identities'],'actor_identity':'peer','owner_identity':'owner','identity_probe':{'path':'/me','expect':s['contract']['cases'][0]['expect']},'negative_probe':{'path':'/known-denial','expect':s['contract']['cases'][2]['expect']},'rule':s['rule']}
        self.assertEqual(compile_imported_experiment(entry,b)['request_upper_bound'],4)
        b['target']='http://127.0.0.1:10'
        with self.assertRaises(ExperimentError):compile_imported_experiment(entry,b)
    def test_full_100_case_baseline_to_ten_case_retest(self):
        with fixture_service() as (url,state):
            spec=fixture_spec(url);spec['contract']['limits']={'max_requests':100}
            original=spec['contract']['cases'].pop();template=spec['variants'].pop()
            for i in range(7):
                case=copy.deepcopy(original);case['id']='target-'+str(i);spec['contract']['cases'].append(case)
                variant=copy.deepcopy(template);variant.update(id='variant-'+str(i),case_id=case['id']);spec['variants'].append(variant)
            for i in range(90):
                case=copy.deepcopy(spec['contract']['cases'][1]);case['id']='outside-'+str(i);spec['contract']['cases'].append(case)
            before=execute_experiment(compile_experiment(spec));state['mode']='fixed'
            after=execute_experiment(plan_experiment_retest(before,[v['id'] for v in spec['variants']]))
            compared=compare_executions(before,after)
            self.assertEqual(before['budget_ledger']['dispatched_total'],100)
            self.assertEqual(after['budget_ledger']['dispatched_total'],10)
            self.assertEqual(compared['comparison_envelope']['coverage']['not_retested_cases'],90)
            self.assertTrue(all(t['status']=='fix_verified' for t in compared['transitions']))
    def test_binding_must_assert_principal_not_alive_flag(self):
        spec=fixture_spec();spec['contract']['cases'][0]['expect']['json']={'/alive':True}
        with self.assertRaises(ExperimentError):compile_experiment(spec)
    def test_unrelated_resource_route_requires_resource_pointer(self):
        spec=fixture_spec();spec['contract']['cases'][-1]['path']='/other-object'
        with self.assertRaises(ExperimentError):compile_experiment(spec)
    def test_rehashed_budget_forgery_rejected(self):
        with fixture_service() as (url,state):result=execute_experiment(compile_experiment(fixture_spec(url)))
        result['budget_ledger']['dispatched_total']=0;result=seal('experiment-execution',result,'execution_digest')
        self.assertTrue(verify_execution(result))
    def test_token_b_actually_belongs_to_a_fails_principal_control(self):
        with fixture_service() as (url,state):
            with patch.dict('os.environ',{'CONTRAST_PEER':'Bearer owner'}):
                result=execute_experiment(compile_experiment(fixture_spec(url)))
            self.assertEqual(result['findings'][0]['interpretation'],'inconclusive')
            actor=next(r for r in result['report']['results'] if r['id']=='actor')
            self.assertEqual(actor['outcome'],'fail')
            self.assertEqual(len(state['requests']),2)
            self.assertEqual(verify_execution(result),[])
    def test_rotated_credentials_without_fresh_binding_cannot_verify_fix(self):
        with fixture_service() as (url,state):
            before=execute_experiment(compile_experiment(fixture_spec(url)))
            state['mode']='fixed'
            with patch.dict('os.environ',{'CONTRAST_PEER':'Bearer rotated-unbound-identity'}):
                after=execute_experiment(plan_experiment_retest(before,['cross-tenant']))
            compared=compare_executions(before,after)
            self.assertEqual(compared['transitions'][0]['status'],'inconclusive')
            self.assertEqual(after['findings'][0]['interpretation'],'inconclusive')
            missing=fixture_spec(url);missing['contract']['cases'][0]['expect']['json']={'/tenant':'B'}
            with self.assertRaises(ExperimentError):compile_experiment(missing)
    def test_typed_missing_null_bool_and_duplicate_headers(self):
        rule={'id':'r','resource_id':'a','kind':'forbid_field_equal','pointer':'/x','value':True}
        self.assertFalse(equal(True,1));self.assertEqual(evaluate_input(rule,{'present':True,'value':1})['interpretation'],'satisfied')
        rule.update(kind='require_header_equal');rule.pop('pointer');rule['header']='X-Test';rule['value']='ok'
        self.assertEqual(capture_input(rule,{'complete':True,'headers':[('X-Test','ok'),('x-test','ok')],'body':b'{}','status':200})['error'],'missing_or_duplicate_header')
