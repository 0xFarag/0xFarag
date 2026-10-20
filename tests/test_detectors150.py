import contextlib
import copy
import json
import threading
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode, urlsplit, parse_qs
from unittest.mock import patch

from authzledger.detectors import (CheckSpec, DetectionError, catalog, select_checks,
    compile_check, execute_check, verify_check_execution, plan_check_retest,
    compare_check_executions, validate_pack)
from authzledger.oracles import seal, digest


def scope_for(spec):
    contract=spec.get('contract') or spec.get('experiment_spec',spec.get('workflow_spec'))['contract']
    origin=contract['target'];ops=[]
    for c in contract['cases']:
        for purpose in ('application','object_control','identity_control','negative_control','setup','state_probe','replay','cleanup'):
            ops.append({'origin':origin,'method':c['method'],'path':c['path'],'purpose':purpose})
    return {'schema_version':1,'kind':'assessment-scope','id':'test-scope','authorization_ref':'loopback fixture owner',
        'origins':[origin],'operations':ops,'allowed_networks':['127.0.0.0/8'],
        'expires_at':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat(),
        'limits':{'max_requests':100,'concurrency':1,'timeout_seconds':10,'max_response_bytes':1048576},'allowed_effects':['read','mutate']}


def header_spec(origin):
    return {'schema_version':1,'kind':'check-spec','id':'headers','check_id':'misconfig.security_headers','version':'1.0.0','source_refs':['fixture-import'],
        'contract':{'version':1,'name':'Headers','target':origin,'identities':{'anonymous':{'headers':{}}},'cases':[
            {'id':'baseline','identity':'anonymous','method':'GET','path':'/','expect':{'status':[200]}},
            {'id':'probe','identity':'anonymous','method':'GET','path':'/','requires':['baseline'],'expect':{'status':[200]}}]},
        'controls':['baseline'],'target_case':'probe','params':{'required_headers':['x-content-type-options']}}


def injection_spec(origin):
    s=header_spec(origin);s['id']='expression';s['check_id']='injection.expression_evaluation';s['controls']=['baseline','negative']
    s['params']={'pointer':'/result','parameter':'q','baseline_case':'baseline','negative_case':'negative','secondary_case':'probe2'}
    cases=[]
    for cid,value in [('baseline','ALCTL_LITERAL'),('negative','13*17'),('probe','{{13*17}}'),('probe2','{{19*23}}')]:
        case={'id':cid,'identity':'anonymous','method':'GET','path':'/expression?'+urlencode({'q':value}),'expect':{'status':[200]}}
        if cid in s['controls']:case['expect']['json']={'/result':value}
        else:case['requires']=list(s['controls'])
        cases.append(case)
    s['contract']['cases']=cases
    return s


@contextlib.contextmanager
def service():
    state={'headers':False,'available':True,'eval':True,'control':True,'cors':True,'requests':[],'principal':'actor','reflect':None}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            state['requests'].append(self.path)
            body={'ok':True};status=200 if state['available'] else 503
            if self.path.startswith('/expression?'):
                value=parse_qs(urlsplit(self.path).query)['q'][0]
                result={'{{13*17}}':'221','{{19*23}}':'437'}.get(value,value) if state['eval'] else value
                if not state['control'] and value=='ALCTL_LITERAL':result='broken'
                if state['reflect'] and value.startswith('{{'):result=state['reflect']
                body={'result':result}
            if self.path=='/me':body={'principal':state['principal']}
            if self.path=='/verbose':body={'error':'Traceback (most recent call last):'}
            if self.path=='/field':body={'debug':True}
            raw=json.dumps(body).encode();self.send_response(status)
            if state['headers']:self.send_header('X-Content-Type-Options','nosniff')
            if state['cors'] and self.headers.get('Origin'):
                self.send_header('Access-Control-Allow-Origin',self.headers.get('Origin'));self.send_header('Access-Control-Allow-Credentials','true')
            self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);t=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);t.start()
    try:yield 'http://127.0.0.1:'+str(server.server_port),state
    finally:server.shutdown();server.server_close();t.join(2)


class Detection150Tests(unittest.TestCase):
    def run_spec(self,s):
        result=execute_check(compile_check(s,scope_for(s)))
        self.assertEqual([],verify_check_execution(result))
        return result

    def test_registry_frozen_and_deterministic(self):
        self.assertEqual(catalog(),catalog());self.assertEqual(len(catalog()['checks']),13)
        s=CheckSpec('x','1','info','x',('baseline',),'x','info')
        with self.assertRaises(Exception):s.title='y'
        self.assertTrue(select_checks('authz-deep'));self.assertNotIn('business_logic.idempotency',[x['check_id'] for x in select_checks('full-safe')])

    def test_profile_aliases_preserve_canonical_profiles(self):
        self.assertEqual(select_checks('quick'),select_checks('web-quick'))
        self.assertEqual(select_checks('deep-authz'),select_checks('authz-deep'))
        self.assertEqual(catalog()['profiles']['quick'],catalog()['profiles']['web-quick'])
        with self.assertRaisesRegex(DetectionError,'unknown_check_profile'):select_checks('unapproved')

    def test_declarative_pack_lock_and_revocation(self):
        m=catalog()['checks'][0];pack={'schema_version':1,'kind':'check-pack','checks':[m]}
        lock={'pack_digest':digest('check-pack',pack),'checks':{m['check_id']+'@'+m['version']:m['rule_digest']}}
        self.assertEqual(pack,validate_pack(pack,lock))
        pack['checks'][0]['lifecycle']='revoked';pack['checks'][0]=seal('check-manifest',pack['checks'][0],'rule_digest')
        lock={'pack_digest':digest('check-pack',pack),'checks':{m['check_id']+'@'+m['version']:pack['checks'][0]['rule_digest']}}
        with self.assertRaisesRegex(DetectionError,'revoked'):validate_pack(pack,lock)

    def test_compile_offline_and_scope_required(self):
        s=header_spec('http://127.0.0.1:9')
        with patch('socket.getaddrinfo',side_effect=AssertionError('network')):
            p=compile_check(s,scope_for(s));self.assertEqual(p,compile_check(s,p['scope']))
        with self.assertRaises(ValueError):compile_check(s,{})

    def test_missing_headers_confirm_config_not_exploit(self):
        with service() as (origin,state):r=self.run_spec(header_spec(origin))
        self.assertEqual('confirmed',r['findings'][0]['evidence_level']);self.assertEqual(2,r['budget_ledger']['dispatched_total'])
        self.assertIn('configuration observation',r['findings'][0]['limitations'][0])

    def test_header_present_not_observed(self):
        with service() as (origin,state):
            state['headers']=True;r=self.run_spec(header_spec(origin))
        self.assertEqual('not_observed',r['findings'][0]['status'])

    def test_failed_baseline_blocks_probe(self):
        with service() as (origin,state):
            state['available']=False;r=self.run_spec(header_spec(origin));self.assertEqual(1,len(state['requests']))
        self.assertEqual('inconclusive',r['findings'][0]['evidence_level'])

    def test_control_dag_cannot_be_bypassed(self):
        s=header_spec('http://127.0.0.1:9');s['contract']['cases'][1]['requires']=[]
        with self.assertRaisesRegex(DetectionError,'controls_must_gate'):compile_check(s,scope_for(s))

    def test_arithmetic_two_probes_confirm_narrow_evaluation(self):
        with service() as (origin,state):r=self.run_spec(injection_spec(origin))
        self.assertEqual('confirmed',r['findings'][0]['evidence_level']);self.assertEqual(4,r['budget_ledger']['dispatched_total'])
        self.assertIn('not code execution',r['findings'][0]['limitations'][0])

    def test_literal_echo_not_injection(self):
        with service() as (origin,state):
            state['eval']=False;r=self.run_spec(injection_spec(origin))
        self.assertEqual('not_observed',r['findings'][0]['status'])

    def test_injection_invalid_control_blocks_both_probes(self):
        with service() as (origin,state):
            state['control']=False;r=self.run_spec(injection_spec(origin));self.assertEqual(2,len(state['requests']))
        self.assertEqual('inconclusive',r['findings'][0]['evidence_level'])

    def test_arbitrary_payload_refused(self):
        s=injection_spec('http://127.0.0.1:9');s['contract']['cases'][2]['path']='/expression?q=arbitrary'
        with self.assertRaisesRegex(DetectionError,'curated_arithmetic'):compile_check(s,scope_for(s))

    def test_cors_headers_only_hint(self):
        with service() as (origin,state):
            s=header_spec(origin);s['check_id']='misconfig.cors.reflection';s['params']={'untrusted_origin':'https://untrusted.invalid'}
            s['contract']['identities']['cors']={'headers':{'Origin':'https://untrusted.invalid'}};s['contract']['cases'][1]['identity']='cors'
            r=self.run_spec(s)
        self.assertEqual('hint',r['findings'][0]['evidence_level']);self.assertEqual('violation',r['findings'][0]['interpretation'])

    def test_verbose_error_and_json_fields_are_hints(self):
        with service() as (origin,state):
            for check,path,params in [('info.verbose_errors','/verbose',{}),('info.json_field_exposure','/field',{'pointer':'/debug'})]:
                s=header_spec(origin);s['check_id']=check;s['params']=params;s['contract']['cases'][1]['path']=path
                r=self.run_spec(s);self.assertEqual('hint',r['findings'][0]['evidence_level']);self.assertEqual('violation',r['findings'][0]['interpretation'])

    def test_credentialed_check_requires_fresh_identity_control(self):
        s=header_spec('http://127.0.0.1:9');s['contract']['identities']['anonymous']['headers']={'Authorization':{'env':'DETECT_TEST'}}
        with self.assertRaisesRegex(DetectionError,'identity_control_required'):compile_check(s,scope_for(s))

    def test_credential_rotation_wrong_identity_inconclusive(self):
        from authzledger.credentials import CredentialResolver
        with service() as (origin,state):
            s=header_spec(origin);s['contract']['identities']['anonymous']['headers']={'Authorization':{'env':'DETECT_TEST'}}
            s['contract']['cases'].insert(0,{'id':'identity','identity':'anonymous','method':'GET','path':'/me','expect':{'status':[200],'json':{'/principal':'actor'}}})
            s['contract']['cases'][1]['requires']=['identity'];s['contract']['cases'][2]['requires']=['identity','baseline'];s['controls']=['identity','baseline'];s['identity_controls']={'anonymous':'identity'}
            resolver=CredentialResolver();resolver.bind_session('DETECT_TEST','Bearer private-fixture-credential',identity='anonymous',target_origin=origin)
            p=compile_check(s,scope_for(s));r=execute_check(p,credential_resolver=resolver);self.assertEqual([],verify_check_execution(r));self.assertNotIn('private-fixture-credential',json.dumps(r))
            state['principal']='other';r=execute_check(p,credential_resolver=resolver)
            self.assertEqual('inconclusive',r['findings'][0]['evidence_level']);self.assertEqual([],verify_check_execution(r))

    def test_retest_bound_and_missing_retest_visible(self):
        with service() as (origin,state):
            before=self.run_spec(header_spec(origin));state['headers']=True
            after=execute_check(plan_check_retest(before));self.assertEqual([],verify_check_execution(after))
            compared=compare_check_executions(before,after)
        self.assertEqual('not_reproduced_under_tested_conditions',compared['transitions'][0]['status'])
        self.assertEqual('not_retested',compare_check_executions(before,None)['transitions'][0]['status'])

    def test_retest_scope_renewal_is_explicit_and_source_bound(self):
        with service() as (origin,state):
            before=self.run_spec(header_spec(origin));original=copy.deepcopy(before)
            renewed=copy.deepcopy(before['plan']['scope']);renewed.pop('scope_digest');renewed['authorization_ref']='explicit renewed authorization';renewed['expires_at']=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()
            plan=plan_check_retest(before,scope=renewed)
            self.assertEqual(before['plan']['scope']['scope_digest'],plan['spec']['retest_of']['source_scope_digest'])
            self.assertNotEqual(before['plan']['scope']['scope_digest'],plan['scope']['scope_digest'])
            state['headers']=True;after=execute_check(plan);self.assertEqual([],verify_check_execution(after))
            self.assertEqual('not_reproduced_under_tested_conditions',compare_check_executions(before,after)['transitions'][0]['status'])
            self.assertEqual(original,before)
            plan['spec']['retest_of']['source_scope_digest']='0'*64
            forged=execute_check(compile_check(plan['spec'],plan['scope']))
            with self.assertRaisesRegex(DetectionError,'retest_plan_changed'):compare_check_executions(before,forged)

    def test_expired_original_authorization_requires_explicit_renewal(self):
        import time
        with service() as (origin,state):
            before=self.run_spec(header_spec(origin));renewed=copy.deepcopy(before['plan']['scope']);renewed.pop('scope_digest');renewed['expires_at']=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat();renewed['authorization_ref']='renewed lab window'
            future=time.time()+7200
            with patch('authzledger.scope.time.time',return_value=future):
                with self.assertRaisesRegex(ValueError,'authorization-expired'):execute_check(plan_check_retest(before))
                state['headers']=True;after=execute_check(plan_check_retest(before,scope=renewed))
                self.assertEqual([],verify_check_execution(after));self.assertEqual('not_reproduced_under_tested_conditions',compare_check_executions(before,after)['transitions'][0]['status'])

    def test_endpoint_disappears_never_fix(self):
        with service() as (origin,state):
            before=self.run_spec(header_spec(origin));state['available']=False;after=execute_check(plan_check_retest(before));comparison=compare_check_executions(before,after)
        self.assertEqual('inconclusive',comparison['transitions'][0]['status'])

    def test_unbound_comparison_refused(self):
        with service() as (origin,state):
            before=self.run_spec(header_spec(origin));after=self.run_spec(header_spec(origin))
        with self.assertRaisesRegex(DetectionError,'source_bound'):compare_check_executions(before,after)

    def test_rehashed_claim_cannot_override_oracle(self):
        with service() as (origin,state):r=self.run_spec(header_spec(origin))
        r['findings'][0]['evidence_level']='hint';r=seal('check-execution',r,'execution_digest')
        self.assertTrue(verify_check_execution(r))

    def test_reproducer_recipe_and_scope_are_bound(self):
        with service() as (origin,state):r=self.run_spec(header_spec(origin))
        r['reproducer']['request_upper_bound']=1;r=seal('check-execution',r,'execution_digest');self.assertTrue(verify_check_execution(r))

    def test_legacy_unrestricted_context_refused(self):
        from authzledger.execution import ExecutionContext
        s=header_spec('http://127.0.0.1:9');p=compile_check(s,scope_for(s))
        with self.assertRaisesRegex(DetectionError,'scope_bound'):execute_check(p,context=ExecutionContext(10,[s['contract']['target']],10,1))

    def test_contrast_adapter_preserves_original_verifier(self):
        from tests.test_experiments import fixture_service,fixture_spec
        with fixture_service() as (origin,state):
            s={'schema_version':1,'kind':'check-spec','id':'disclosure','check_id':'authz.object.disclosure','version':'1.0.0','source_refs':['fixture-import'],'experiment_spec':fixture_spec(origin)}
            r=self.run_spec(s)
        self.assertEqual('confirmed',r['findings'][0]['evidence_level']);self.assertIn('adapter_execution',r)

@contextlib.contextmanager
def boundary_service():
    state={'fixed':False,'objects':{},'next':0}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def send(self,status,body):
            raw=json.dumps(body).encode();self.send_response(status);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def do_GET(self):
            actor=self.headers.get('Authorization')
            if self.path=='/me':return self.send(200,{'principal':'peer','tenant':'B','role':'reader'})
            if self.path=='/owner-me':return self.send(200,{'principal':'owner','tenant':'A','role':'admin'})
            if self.path=='/known-denial':return self.send(403,{'error':'denied'})
            if self.path=='/invoice/A':
                if actor=='Bearer owner':return self.send(200,{'marker':'synthetic-A','tenant':'A'})
                return self.send(403,{'error':'denied'} if state['fixed'] else {'marker':'synthetic-A'})
            if self.path=='/control':return self.send(200,{'principal':self.headers.get('X-Actor','operator')})
            key=self.path.split('/')[-1]
            if key in state['objects']:return self.send(200,dict(state['objects'][key],id=key))
            self.send(404,{})
        def do_POST(self):
            self.rfile.read(int(self.headers.get('Content-Length','0')))
            if self.path=='/objects':
                state['next']+=1;key=str(state['next']);state['objects'][key]={'state':'draft','effects':0};return self.send(201,{'id':key})
            _,_,key,action=self.path.split('/');obj=state['objects'][key]
            if action=='approve':obj['state']='approved'
            if action=='complete':
                if state['fixed'] and self.headers.get('X-Actor')=='guest':return self.send(403,{})
                obj['state']='completed';obj['effects']+=1
            self.send(200,{})
        def do_DELETE(self):
            state['objects'].pop(self.path.split('/')[-1],None);self.send(200,{})
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.01},daemon=True);thread.start()
    with patch.dict('os.environ',{'CONTRAST_OWNER':'Bearer owner','CONTRAST_PEER':'Bearer peer'}):
        try:yield 'http://127.0.0.1:'+str(server.server_port),state
        finally:server.shutdown();server.server_close();thread.join(2)


class Adapter150Tests(unittest.TestCase):
    def test_all_five_contrast_recipes_have_distinct_validators(self):
        from tests.test_experiments import fixture_spec
        with service() as (origin,state):
            # Compilation verifies the additional tenant/role bindings. Existing
            # executor tests cover response and denial marker evidence itself.
            base=fixture_spec(origin)
            for check in ('authz.object.disclosure','authz.denial.disclosure','authz.response.contract','authz.tenant.disclosure','authz.role.disclosure'):
                experiment=copy.deepcopy(base)
                if check=='authz.response.contract':experiment['rule']={'id':'field-policy','resource_id':'invoice-A','kind':'require_absent','pointer':'/marker'}
                if check=='authz.tenant.disclosure':experiment['contract']['cases'][1]['expect']['json']['/tenant']='A'
                if check=='authz.role.disclosure':
                    experiment['contract']['cases'][0]['expect']['json']['/role']='reader'
                    experiment['contract']['cases'].insert(0,{'id':'owner-principal','identity':'owner','method':'GET','path':'/owner-me','expect':{'status':[200],'json':{'/principal':'owner','/role':'admin'}}})
                    experiment['contract']['cases'][-1]['requires'].append('owner-principal')
                spec={'schema_version':1,'kind':'check-spec','id':'recipe','check_id':check,'version':'1.0.0','source_refs':['fixture-import'],'experiment_spec':experiment}
                self.assertEqual(check,compile_check(spec,scope_for(spec))['check']['check_id'])
            bad={'schema_version':1,'kind':'check-spec','id':'bad','check_id':'authz.tenant.disclosure','version':'1.0.0','source_refs':['fixture-import'],'experiment_spec':base}
            with self.assertRaisesRegex(DetectionError,'tenants'):compile_check(bad,scope_for(bad))

    def test_five_authz_recipes_execute_real_controls_and_evidence(self):
        from tests.test_experiments import fixture_spec
        with boundary_service() as (origin,state):
            for check in ('authz.object.disclosure','authz.denial.disclosure','authz.response.contract','authz.tenant.disclosure','authz.role.disclosure'):
                exp=fixture_spec(origin)
                if check=='authz.response.contract':exp['rule']={'id':'field','resource_id':'invoice-A','kind':'require_absent','pointer':'/marker'}
                if check=='authz.tenant.disclosure':exp['contract']['cases'][1]['expect']['json']['/tenant']='A'
                if check=='authz.role.disclosure':
                    exp['contract']['cases'][0]['expect']['json']['/role']='reader'
                    exp['contract']['cases'].insert(0,{'id':'owner-principal','identity':'owner','method':'GET','path':'/owner-me','expect':{'status':[200],'json':{'/principal':'owner','/role':'admin'}}})
                    exp['contract']['cases'][-1]['requires'].append('owner-principal')
                spec={'schema_version':1,'kind':'check-spec','id':'authz-recipe','check_id':check,'version':'1.0.0','source_refs':['fixture-import'],'experiment_spec':exp}
                result=execute_check(compile_check(spec,scope_for(spec)))
                self.assertEqual([],verify_check_execution(result));self.assertEqual('confirmed',result['findings'][0]['evidence_level'],check)

    def test_workflow_actor_override_requires_distinct_controls_and_runs(self):
        from tests.test_workflows import spec as workflow_spec
        with boundary_service() as (origin,state):
            workflow=workflow_spec(origin);workflow['contract']['identities']={'operator':{'headers':{'X-Actor':'operator'}},'guest':{'headers':{'X-Actor':'guest'}}}
            workflow['contract']['cases'].insert(1,{'id':'guest-control','identity':'guest','method':'GET','path':'/control','expect':{'status':[200],'json':{'/principal':'guest'}}})
            workflow['controls'].append('guest-control');workflow['variants']=[{'id':'guest-complete','identity_overrides':{'complete':'guest'}}]
            spec={'schema_version':1,'kind':'check-spec','id':'role-transition','check_id':'business_logic.role_transition','version':'1.0.0','source_refs':['workflow-fixture'],'workflow_spec':workflow}
            scope=scope_for(spec)
            for op in list(scope['operations']):
                if 'placeholder' in op['path']:
                    for number in ('1','2'):
                        item=dict(op);item['path']=item['path'].replace('placeholder',number);scope['operations'].append(item)
            plan=compile_check(spec,scope);before=execute_check(plan);self.assertEqual([],verify_check_execution(before));self.assertEqual('confirmed',before['findings'][0]['evidence_level'])
            state['fixed']=True;after=execute_check(plan_check_retest(before));self.assertEqual([],verify_check_execution(after));self.assertEqual('not_reproduced_under_tested_conditions',compare_check_executions(before,after)['transitions'][0]['status'])
            bad=copy.deepcopy(spec);bad['workflow_spec']['variants'][0]['identity_overrides']['complete']='operator'
            with self.assertRaisesRegex(DetectionError,'must_change_identity'):compile_check(bad,scope)

    def test_contrast_subset_keeps_fix_verified_and_not_retested(self):
        from tests.test_experiments import fixture_service,fixture_spec
        with fixture_service() as (origin,state):
            exp=fixture_spec(origin);case=copy.deepcopy(exp['contract']['cases'][-1]);case['id']='target2';exp['contract']['cases'].append(case)
            variant=copy.deepcopy(exp['variants'][0]);variant.update(id='second',case_id='target2');exp['variants'].append(variant)
            spec={'schema_version':1,'kind':'check-spec','id':'two','check_id':'authz.object.disclosure','version':'1.0.0','source_refs':['fixture-import'],'experiment_spec':exp}
            before=execute_check(compile_check(spec,scope_for(spec)));selected=[before['findings'][0]['id']]
            state['mode']='fixed';after=execute_check(plan_check_retest(before,selected));self.assertEqual([],verify_check_execution(after))
            comparison=compare_check_executions(before,after)
        self.assertEqual({'fix_verified','not_retested'},{t['status'] for t in comparison['transitions']})
        self.assertIsNotNone(comparison['adapter_comparison']['comparison_envelope'])

    def test_workflow_omission_and_idempotency_use_shared_engine(self):
        from tests.test_workflows import fixture,spec as workflow_spec
        for check in ('business_logic.skipped_approval','business_logic.idempotency'):
            with fixture() as (origin,state):
                workflow=workflow_spec(origin)
                if check=='business_logic.idempotency':
                    state['replay']=True
                    workflow['rule']={'id':'effect','kind':'effect_increase','pointer':'/effects','max_delta':1}
                    workflow['variants']=[{'id':'repeat','repeat':{'complete':2}}]
                spec={'schema_version':1,'kind':'check-spec','id':'workflow','check_id':check,'version':'1.0.0','source_refs':['workflow-fixture'],'workflow_spec':workflow}
                scope=scope_for(spec)
                for op in list(scope['operations']):
                    if 'placeholder' in op['path']:
                        added=dict(op);added['path']=added['path'].replace('placeholder','1');scope['operations'].append(added)
                result=execute_check(compile_check(spec,scope))
                self.assertEqual([],verify_check_execution(result));self.assertEqual('confirmed',result['findings'][0]['evidence_level'])
                self.assertEqual('complete',result['adapter_execution']['variants'][0]['cleanup'])

    def test_cleanup_failure_keeps_unexecuted_planned_variants_visible(self):
        from tests.test_workflows import fixture,spec as workflow_spec
        with fixture() as (origin,state):
            workflow=workflow_spec(origin);workflow['variants'].append({'id':'another-omission','omit':['approve']});state['cleanup']=False
            spec={'schema_version':1,'kind':'check-spec','id':'workflow-stop','check_id':'business_logic.skipped_approval','version':'1.0.0','source_refs':['fixture'],'workflow_spec':workflow};scope=scope_for(spec)
            for op in list(scope['operations']):
                if 'placeholder' in op['path']:
                    for number in ('1','2'):
                        item=dict(op);item['path']=item['path'].replace('placeholder',number);scope['operations'].append(item)
            result=execute_check(compile_check(spec,scope));self.assertEqual([],verify_check_execution(result));self.assertEqual(1,len(result['adapter_execution']['variants']))
            self.assertEqual(2,result['coverage']['planned_findings']);self.assertEqual(2,len(result['findings']))
            missing=result['findings'][1];self.assertEqual('adapter_variant_not_run',missing['reason']);self.assertEqual('inconclusive',missing['evidence_level']);self.assertEqual([],missing['observation_refs'])

    def test_projection_schema_and_budget_cannot_be_rehashed_around(self):
        with service() as (origin,state):original=execute_check(compile_check(header_spec(origin),scope_for(header_spec(origin))))
        changed=copy.deepcopy(original);changed['observations'][0]['projection']['extra']='untrusted'
        changed['observations'][0]=seal('check-observation',changed['observations'][0],'observation_digest');changed=seal('check-execution',changed,'execution_digest')
        self.assertTrue(verify_check_execution(changed))
        changed=copy.deepcopy(original);changed['budget_ledger']['requests']=[];changed=seal('check-execution',changed,'execution_digest')
        self.assertTrue(verify_check_execution(changed))


if __name__=='__main__':unittest.main()
