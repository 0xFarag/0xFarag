"""Deterministic Contrast Lab plans and evidence-bound execution over the v1 engine."""
from __future__ import annotations
import copy
import hashlib
import uuid
from . import engine
from .assurance import retest_plan
from .evidence import verify_report
from .intelligence import build_graph
from .model import load_contract, contract_digest, _identifier, _string
from .oracles import canonical, digest, seal, equal, validate_rule, evaluate_input, parse_json, pointer
from .observations import make_observation

class ExperimentError(ValueError):
    pass

def _fields(value, allowed, required, label):
    if not isinstance(value,dict) or set(value)-set(allowed) or set(required)-set(value):
        raise ExperimentError('invalid_' + label + '_fields')

def _closure(cases, case_id):
    found=set(); pending=list(cases[case_id]['requires'])
    while pending:
        item=pending.pop()
        if item not in found:
            found.add(item); pending.extend(cases[item]['requires'])
    return found

def _reject_literal_credentials(contract):
    import re
    from urllib.parse import parse_qsl, urlsplit
    sensitive=re.compile(r'(?:password|passwd|authorization|cookie|credential|secret|token|api.?key|session)',re.I)
    def scan(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if sensitive.search(key): raise ExperimentError('literal_credential_body_field_unsupported')
                scan(item)
        elif isinstance(value,list):
            for item in value: scan(item)
    for case in contract['cases']:
        for key,value in parse_qsl(urlsplit(case['path']).query,keep_blank_values=True):
            if sensitive.search(key): raise ExperimentError('credential_query_field_unsupported')
        scan(case.get('body'))


def compile_experiment(spec):
    """Validate without resolving credentials, probing endpoints or expanding a product."""
    required={'schema_version','kind','id','title','contract','rule','variants'}
    _fields(spec, required|{'capture_mode','sources','mutation_approval','volatile_pointers','identity_bindings'},required,'experiment')
    if type(spec['schema_version']) is not int or spec['schema_version'] != 1 or spec['kind']!='experiment-spec':
        raise ExperimentError('unsupported_experiment_schema')
    _identifier(spec['id'],'experiment id'); _string(spec['title'],'experiment title')
    contract=load_contract(spec['contract'],allow_mutations=True)
    _reject_literal_credentials(contract)
    approvals=spec.get('mutation_approval',[])
    if not isinstance(approvals,list) or any(not isinstance(v,str) for v in approvals) or len(set(approvals))!=len(approvals):
        raise ExperimentError('invalid_mutation_approval')
    mutations={c['id'] for c in contract['cases'] if c['method'] not in {'GET','HEAD','OPTIONS'}}
    if set(approvals)!=mutations:
        raise ExperimentError('explicit_mutation_approval_required')
    capture=spec.get('capture_mode','attested')
    if capture not in {'attested','safe_values'}: raise ExperimentError('unsupported_capture_mode')
    rule=validate_rule(spec['rule']); cases={c['id']:c for c in contract['cases']}
    variants=spec['variants']
    if not isinstance(variants,list) or not 1<=len(variants)<=24:
        raise ExperimentError('select_one_to_24_explicit_variants')
    normalized=[]; ids=set(); targets=set(); bindings=copy.deepcopy(spec.get('identity_bindings',{}))
    if not isinstance(bindings,dict) or set(bindings)-set(contract['identities']): raise ExperimentError('invalid_identity_bindings')
    for variant in variants:
        fields={'id','case_id','identity_control','object_control','negative_control'}
        _fields(variant,fields,fields,'variant')
        _identifier(variant['id'],'variant id')
        if variant['id'] in ids or variant['case_id'] in targets:
            raise ExperimentError('duplicate_variant')
        if any(variant[k] not in cases for k in fields-{'id'}):
            raise ExperimentError('unknown_variant_case')
        ids.add(variant['id']); targets.add(variant['case_id'])
        case=cases[variant['case_id']]; identity=cases[variant['identity_control']]
        obj=cases[variant['object_control']]; negative=cases[variant['negative_control']]
        controls={variant[k] for k in fields-{'id','case_id'}}
        if len(controls)!=3 or not controls <= _closure(cases,case['id']):
            raise ExperimentError('three_distinct_transitive_controls_required')
        if identity['identity']!=case['identity'] or not identity['expect'].get('json'):
            raise ExperimentError('explicit_principal_binding_required')
        binding=bindings.get(case['identity'])
        if binding is None:
            values=identity['expect']['json']
            if '/principal' not in values: raise ExperimentError('explicit_principal_binding_required')
            binding={'principal_pointer':'/principal','principal':values['/principal']}
            if '/tenant' in values: binding.update(tenant_pointer='/tenant',tenant=values['/tenant'])
            bindings[case['identity']]=binding
        _fields(binding,{'principal_pointer','principal','tenant_pointer','tenant'},{'principal_pointer','principal'},'identity_binding')
        if ('tenant_pointer' in binding)!=('tenant' in binding): raise ExperimentError('incomplete_tenant_binding')
        for prefix in ('principal','tenant'):
            if prefix in binding:
                from .model import _pointer
                _pointer(binding[prefix+'_pointer'])
                if not isinstance(binding[prefix],str) or not binding[prefix]: raise ExperimentError('identity_binding_requires_nonempty_string')
                if binding[prefix+'_pointer'] not in identity['expect']['json'] or not equal(identity['expect']['json'][binding[prefix+'_pointer']],binding[prefix]):
                    raise ExperimentError('identity_binding_check_mismatch')
        if any(s>=300 for s in identity['expect']['status']) or any(s>=300 for s in obj['expect']['status']):
            raise ExperimentError('positive_control_success_required')
        if obj['identity']==case['identity'] or not obj['expect'].get('json'):
            raise ExperimentError('independent_owner_control_required')
        if negative['identity']!=case['identity'] or not all(s in {401,403,404} for s in negative['expect']['status']):
            raise ExperimentError('explicit_denial_control_required')
        if not negative['expect'].get('json_absent') and not negative['expect'].get('json'):
            raise ExperimentError('denial_content_control_required')
        if rule['kind']=='forbid_field_equal':
            from urllib.parse import urlsplit
            if 'resource_pointer' in rule:
                if rule['resource_pointer'] not in obj['expect']['json'] or not equal(obj['expect']['json'][rule['resource_pointer']],rule['resource_value']):
                    raise ExperimentError('resource_binding_check_required')
            elif urlsplit(obj['path']).path!=urlsplit(case['path']).path:
                raise ExperimentError('different_route_requires_explicit_resource_binding')
            if rule['pointer'] not in obj['expect'].get('json',{}) or not equal(obj['expect']['json'][rule['pointer']],rule['value']):
                raise ExperimentError('owner_must_bind_exact_protected_marker')
        normalized.append(copy.deepcopy(variant))
    volatile=spec.get('volatile_pointers',[])
    if not isinstance(volatile,list) or len(volatile)>100:
        raise ExperimentError('invalid_volatile_pointers')
    from .model import _pointer
    protected={rule.get('pointer','')}
    for c in contract['cases']: protected.update(c['expect'].get('json',{})); protected.update(c['expect'].get('json_absent',[]))
    for p in volatile:
        _pointer(p)
        if any(p==q or p=='' or q.startswith(p+'/') or p.startswith(q+'/') for q in protected):
            raise ExperimentError('normalizer_may_not_remove_evidence')
    sources=spec.get('sources',[])
    if not isinstance(sources,list) or len(sources)>500 or any(not isinstance(s,str) or len(s)>128 for s in sources):
        raise ExperimentError('source_ids_required')
    normalized_spec=copy.deepcopy(spec)
    normalized_spec.update(contract=contract,rule=rule,variants=sorted(normalized,key=lambda v:v['id']),capture_mode=capture,sources=sorted(set(sources)),mutation_approval=sorted(approvals),volatile_pointers=sorted(set(volatile)),identity_bindings=bindings)
    plan={'schema_id':'authzledger.experiment-plan','schema_version':1,'kind':'experiment-plan',
          'spec':normalized_spec,'contract':contract,'contract_digest':contract_digest(contract),
          'rule':rule,'rule_digest':digest('rule',rule),'variants':normalized_spec['variants'],
          'normalization_digest':digest('normalization',{'version':1,'volatile_pointers':normalized_spec['volatile_pointers']}),
          'request_upper_bound':len(contract['cases']), 'scope':{'target':contract['target']},
          'limitations':['Explicit variants only; no automatic discovery or deployment-policy attestation.',
                         'Identity and resource claims depend on configured response assertions; marker uniqueness and tenant semantics are operator-declared.']}
    return seal('experiment-plan',plan,'plan_digest')

def verify_plan(plan):
    try:
        expected=compile_experiment(plan['spec'])
        return [] if canonical(expected)==canonical(plan) else ['experiment_plan_mismatch']
    except (ValueError,KeyError,TypeError,RecursionError): return ['invalid_experiment_plan']

def _controls(plan,variant,results):
    cases={c['id']:c for c in plan['contract']['cases']}
    refs=sorted(_closure(cases,variant['case_id']))
    valid=all(results.get(cid,{}).get('outcome')=='pass' for cid in refs)
    return valid,refs

def _finding(plan, variant, observation):
    case=next(c for c in plan['contract']['cases'] if c['id']==variant['case_id'])
    interpretation=observation['interpretation']
    category='denial_data_disclosure' if interpretation=='violation' and observation['status'] in {401,403,404} and plan['rule']['kind']=='forbid_field_equal' else 'authorization_rule_violation'
    # A status-only predicate never establishes protected-data or business impact.
    confirmed=interpretation=='violation' and plan['rule']['kind']!='require_status'
    item={'schema_id':'authzledger.finding','schema_version':1,'kind':'finding',
          'id':'finding-'+digest('finding-id',{'rule':plan['rule']['id'],'resource':plan['rule']['resource_id'],'identity':case['identity'],'variant':variant['id']})[:24],
          'case_id':case['id'],'title':plan['spec']['title'],'category':category,
          'status':'confirmed' if confirmed else ('rejected' if interpretation=='satisfied' else 'candidate'),
          'interpretation':interpretation,'rule_digest':plan['rule_digest'],'resource_id':plan['rule']['resource_id'],
          'identity':case['identity'],'evidence_refs':[observation['observation_digest']],
          'control_refs':observation['control_refs'],
          'impact':'The configured protected marker was disclosed to the tested identity.' if confirmed and plan['rule']['kind']=='forbid_field_equal' else 'Limited to the explicitly evaluated predicate; business impact requires review.',
          'remediation':'Enforce the configured rule at the resource and response boundary; rerun this experiment with fresh controls.',
          'verification_level':observation['verification_level'],'limitations':list(observation['limitations'])}
    return seal('finding',item,'finding_digest')

def execute_experiment(plan,*,context=None,credential_resolver=None):
    if verify_plan(plan): raise ExperimentError('invalid_experiment_plan')
    contract=copy.deepcopy(plan['contract'])
    from .credentials import CredentialResolver
    resolver=credential_resolver if credential_resolver is not None else CredentialResolver()
    resolved=resolver.resolve_contract(contract)
    secret_values=set()
    for identity,config in contract['identities'].items():
        for key,reference in config['headers'].items():
            if not isinstance(reference,dict): continue
            value=resolved[identity][key];secret_values.add(value)
            if key.lower()=='authorization' and ' ' in value: secret_values.add(value.split(' ',1)[1])
            if key.lower()=='cookie':
                for cookie in value.split(';'):
                    if '=' in cookie: secret_values.add(cookie.split('=',1)[1].strip())
    # A plan containing a credential cannot become an exportable evidence object.
    def credential_in_plan(value):
        if isinstance(value,str): return any(secret and (len(secret)>=8 or ' ' in secret) and secret in value for secret in secret_values)
        if isinstance(value,dict): return any(credential_in_plan(k) or credential_in_plan(v) for k,v in value.items())
        if isinstance(value,list): return any(credential_in_plan(v) for v in value)
        return False
    if credential_in_plan(plan): raise ExperimentError('credential_value_in_plan')
    class PinnedResolver:
        def resolve_contract(self,request_contract):
            if contract_digest(request_contract)!=contract_digest(contract): raise ExperimentError('credential_scope_changed')
            return copy.deepcopy(resolved)
    if context is None:
        from .execution import ExecutionContext
        context=ExecutionContext(max_requests=contract['limits']['max_requests'],allowed_origins=[contract['target']],timeout_seconds=min(86400,contract['limits']['timeout_seconds']*len(contract['cases'])+1),concurrency=contract['limits']['concurrency'])
    captures={}; observed_case_ids={variant['case_id'] for variant in plan['variants']}
    def receive(item):
        if item['case_id'] in observed_case_ids: captures[item['case_id']]=item
    kinds={c['id']:'application' for c in contract['cases']}
    for variant in plan['variants']:
        kinds[variant['identity_control']]='identity_control'; kinds[variant['object_control']]='object_control'; kinds[variant['negative_control']]='negative_control'
    report=engine.run(contract,context=context,credential_resolver=PinnedResolver(),observation_sink=receive,request_kind=kinds)
    execution_id=str(uuid.uuid4()); results={r['id']:r for r in report['results']}
    observations=[]; findings=[]
    for variant in plan['variants']:
        cid=variant['case_id']; controls_valid,refs=_controls(plan,variant,results)
        observation=make_observation(plan=plan,execution_id=execution_id,case=next(c for c in contract['cases'] if c['id']==cid),result=results[cid],capture=captures.get(cid),report_root=report['evidence']['root_sha256'],controls_valid=controls_valid,control_refs=refs,secret_values=secret_values)
        observations.append(observation); findings.append(_finding(plan,variant,observation))
    captures.clear();resolved.clear();secret_values.clear()
    execution={'schema_id':'authzledger.execution','schema_version':1,'kind':'experiment-execution',
               'execution_id':execution_id,'plan':copy.deepcopy(plan),'contract':contract,'report':report,
               'graph':build_graph(contract,report),'observations':observations,'findings':findings,
               'budget_ledger':context.snapshot()}
    return seal('experiment-execution',execution,'execution_digest')

def _source_oracle_consistent(rule, case, result, oracle):
    """Use only assertion facts whose pointer binding is unambiguous in v1.

    v1 JSON equality checks omit pointers and canonical object key order is not
    semantic. Thus mixed multi-pointer equality results cannot be attributed to
    individual keys. All-pass and one-pointer equality facts remain definitive.
    JSON-absence selectors are ordered arrays, so their binding is exact.
    """
    if 'pointer' not in rule: return True
    checks=result['checks']; decision=oracle['decision']['interpretation']; projected=oracle.get('input')
    json_checks=[c['passed'] for c in checks if c['type']=='json']
    parse_checks=[c['passed'] for c in checks if c['type']=='json_parse']
    if parse_checks and not all(parse_checks): return decision=='inconclusive'
    if not parse_checks: return True
    known=None; selector=rule['pointer']; expected=case['expect'].get('json',{})
    absent=case['expect'].get('json_absent',[])
    absence_checks=[c['passed'] for c in checks if c['type']=='json_absent']
    if selector in absent:
        is_absent=absence_checks[absent.index(selector)]
        if projected is not None and not projected.get('error') and projected['present'] is is_absent: return False
        if is_absent: known={'present':False}
    if selector in expected and json_checks:
        if all(json_checks) or (len(expected)==1 and json_checks[0]):
            known={'present':True,'value':expected[selector]}
        elif len(expected)==1 and not json_checks[0]:
            if projected is not None and not projected.get('error') and projected['present'] and equal(projected.get('value'),expected[selector]): return False
            if equal(rule.get('value'),expected[selector]):
                if rule['kind']=='forbid_field_equal' and decision=='violation': return False
                if rule['kind']=='require_field_equal' and decision=='satisfied': return False
    if known is not None:
        if projected is not None and not projected.get('error'):
            if projected['present']!=known['present']: return False
            if known['present'] and not equal(projected.get('value'),known['value']): return False
        if decision!='inconclusive' and evaluate_input(rule,known)['interpretation']!=decision: return False
    return True


def verify_execution(execution):
    """Recompute derived claims; distinguish selected-input replay from attestation."""
    try:
        fields={'schema_id','schema_version','kind','execution_id','plan','contract','report','graph','observations','findings','budget_ledger','execution_digest'}
        if not isinstance(execution,dict) or set(execution)!=fields or execution['schema_id']!='authzledger.execution' or type(execution['schema_version']) is not int or execution['schema_version']!=1 or execution['kind']!='experiment-execution': return ['invalid_execution_schema']
        if digest('experiment-execution',execution,'execution_digest')!=execution['execution_digest']: return ['execution_digest_mismatch']
        plan=execution['plan']; errors=verify_plan(plan)
        if errors: return errors
        if canonical(execution['contract'])!=canonical(plan['contract']): return ['execution_contract_mismatch']
        report=execution['report']
        from .comparison import _profile
        _profile(report,'execution')
        errors=verify_report(report)
        if errors: return ['invalid_execution_report']
        graph=build_graph(execution['contract'],report)
        if canonical(graph)!=canonical(execution['graph']): return ['execution_graph_mismatch']
        ledger=execution['budget_ledger']
        if not isinstance(ledger,dict) or ledger.get('kind')!='request-budget-ledger' or type(ledger.get('dispatched_total')) is not int or type(ledger.get('approved_total')) is not int or not 0<=ledger['dispatched_total']<=ledger['approved_total']: return ['invalid_budget_ledger']
        records=ledger.get('requests',[])
        if not isinstance(records,list) or len({r['sequence'] for r in records})!=len(records): return ['invalid_budget_sequence']
        dispatched=[r for r in records if r['state'] in {'dispatched','finished'}]
        if len(dispatched)!=ledger['dispatched_total'] or sum(ledger['by_kind'].values())!=ledger['dispatched_total']: return ['budget_ledger_count_mismatch']
        if any(count!=sum(r['kind']==kind for r in dispatched) for kind,count in ledger['by_kind'].items()): return ['budget_ledger_kind_mismatch']
        results={r['id']:r for r in report['results']}; cases={c['id']:c for c in execution['contract']['cases']}
        sent={cid for cid,r in results.items() if r['outcome'] in {'pass','fail','error'}}
        witnessed={r['operation_id'] for r in dispatched}
        if not sent<=witnessed or len(dispatched)<len(sent): return ['execution_dispatch_witness_missing']
        observations=execution['observations']
        if len(observations)!=len(plan['variants']) or len(execution['findings'])!=len(observations): return ['execution_variant_count_mismatch']
        for index,(variant,obs) in enumerate(zip(plan['variants'],observations)):
            cid=variant['case_id']; valid,refs=_controls(plan,variant,results)
            observation_fields={'schema_id','schema_version','kind','plan_digest','execution_id','case_id','attempt_id','contract_digest','report_root','request_projection_digest','capture_profile','body_sha256','status','body_complete','headers_retained','rule_digest','normalization_digest','oracle','control_refs','controls_valid','interpretation','verification_level','limitations','observation_digest'}
            if set(obs)!=observation_fields or obs['schema_id']!='authzledger.observation' or type(obs['schema_version']) is not int or obs['schema_version']!=1 or obs['kind']!='observation': return ['invalid_observation_schema']
            if type(obs['body_complete']) is not bool or obs['headers_retained'] is not False or not isinstance(obs['limitations'],list): return ['invalid_observation_capture']
            if set(obs['oracle'])!={'oracle_id','oracle_version','decision','input','input_retained'}: return ['invalid_oracle_fields']
            if obs['controls_valid'] is not valid or obs['control_refs']!=refs: return ['observation_control_mismatch']
            safe=plan['spec']['capture_mode']=='safe_values'
            level='captured_inputs_replayed' if safe else 'evaluation_attested'
            if obs['verification_level']!=level or obs['oracle']['input_retained'] is not safe: return ['observation_verification_level_mismatch']
            if obs['capture_profile']!=('selected-values-v1' if safe else 'predicate-attestation-v1'): return ['observation_capture_profile_mismatch']
            expected_limits=['Remote response authenticity is not established by local signing.', 'Only selected oracle inputs are replayed; their projection from the omitted raw body remains signer-attested.' if safe else 'Predicate values are not retained; evaluation is signer-attested.']
            if obs['limitations']!=expected_limits: return ['observation_limitations_mismatch']
            if obs['oracle']['oracle_id']!=plan['rule']['kind'] or type(obs['oracle']['oracle_version']) is not int or obs['oracle']['oracle_version']!=1: return ['observation_oracle_mismatch']
            if safe:
                oracle_input=obs['oracle']['input']
                if not isinstance(oracle_input,dict) or set(oracle_input)-{'present','value','error'} or type(oracle_input.get('present')) is not bool: return ['invalid_oracle_input']
                if oracle_input.get('error') not in {None,'incomplete_capture','invalid_json_capture','missing_or_duplicate_header','credential_reflection_redacted'}: return ['invalid_oracle_error']
                if oracle_input.get('error') and (oracle_input['present'] or 'value' in oracle_input): return ['invalid_oracle_error_input']
                if not oracle_input['present'] and 'value' in oracle_input: return ['unexpected_absent_value']
                if oracle_input['present'] and 'value' not in oracle_input: return ['missing_oracle_value']
                if plan['rule']['kind']=='require_status' and not oracle_input.get('error') and (oracle_input['present'] is not True or oracle_input['value']!=results[cid]['status']): return ['status_oracle_source_mismatch']
                decision=evaluate_input(plan['rule'],oracle_input)
                if not valid: decision={'interpretation':'inconclusive','reason':'invalid_controls'}
                if decision!=obs['oracle']['decision']: return ['observation_oracle_result_mismatch']
            elif obs['oracle']['input'] is not None: return ['unexpected_retained_oracle_input']
            elif obs['oracle']['decision'] not in [{'interpretation':x,'reason':r} for x,r in [('violation','predicate_violated'),('satisfied','predicate_satisfied'),('inconclusive','invalid_controls'),('inconclusive','incomplete_capture'),('inconclusive','invalid_json_capture'),('inconclusive','missing_or_duplicate_header'),('inconclusive','credential_reflection_redacted')]]: return ['invalid_attested_decision']
            if not _source_oracle_consistent(plan['rule'],cases[cid],results[cid],obs['oracle']): return ['oracle_projection_contradicts_source_report']
            if not valid and obs['interpretation']!='inconclusive': return ['invalid_control_claim']
            if obs['interpretation']!=obs['oracle']['decision']['interpretation']: return ['observation_interpretation_mismatch']
            if (not obs['body_complete'] or results[cid]['outcome'] in {'error','inconclusive'}) and obs['interpretation']!='inconclusive': return ['incomplete_observation_claim']
            expected_refs={'plan_digest':plan['plan_digest'],'execution_id':execution['execution_id'],'case_id':cid,'attempt_id':cid+':1','contract_digest':plan['contract_digest'],'report_root':report['evidence']['root_sha256'],'rule_digest':plan['rule_digest'],'normalization_digest':plan['normalization_digest'],'body_sha256':results[cid].get('response_sha256'),'status':results[cid].get('status'),'request_projection_digest':hashlib.sha256(canonical({k:v for k,v in cases[cid].items() if k!='expect'})).hexdigest()}
            if any(obs.get(k)!=v for k,v in expected_refs.items()): return ['observation_source_binding_mismatch']
            if digest('observation',obs,'observation_digest')!=obs['observation_digest']: return ['observation_digest_mismatch']
            if canonical(_finding(plan,variant,obs))!=canonical(execution['findings'][index]): return ['finding_semantics_mismatch']
        return []
    except (ValueError,TypeError,KeyError,IndexError,RecursionError,AttributeError): return ['invalid_execution']


def compile_imported_experiment(entry, bindings):
    """Map one reviewed import to an explicit control DAG; never infer credentials."""
    required={'id','title','target','identities','actor_identity','owner_identity','identity_probe','negative_probe','rule'}
    _fields(bindings,required|{'limits','capture_mode','mutation_approval','selected_variants','identity_probes','identity_bindings','omitted_secret_slots','owner_probe'},required,'import_bindings')
    if not isinstance(entry,dict) or entry.get('execution_blockers'):
        raise ExperimentError('import_execution_blocked')
    from .model import _target
    if _target(bindings['target'])!=_target(entry['origin']): raise ExperimentError('import_origin_outside_scope')
    rule=validate_rule(bindings['rule'])
    if rule['kind']!='forbid_field_equal': raise ExperimentError('import_recipe_requires_marker_rule')
    actor=bindings['actor_identity']; owner=bindings['owner_identity']
    omitted=bindings.get('omitted_secret_slots',[])
    if not isinstance(omitted,list) or any(not isinstance(v,str) for v in omitted): raise ExperimentError('invalid_secret_slot_omissions')
    slots=entry.get('secret_slots',[])
    if set(omitted)-{slot['id'] for slot in slots}: raise ExperimentError('unknown_secret_slot_omission')
    for slot in slots:
        if slot['id'] in omitted: continue
        header=slot['location'].split('/')[-1]
        if header not in {'authorization','cookie'}: raise ExperimentError('explicit_secret_slot_mapping_required')
        for name in (actor,owner):
            configured=bindings['identities'].get(name,{}).get('headers',{})
            if not any(k.lower()==header and isinstance(v,dict) and set(v)=={'env'} for k,v in configured.items()):
                raise ExperimentError('credential_header_mapping_required')
    if actor==owner: raise ExperimentError('distinct_actor_and_owner_required')
    selections=bindings.get('selected_variants',[{'id':'cross-identity','identity':actor,'path':entry['path']}])
    if not isinstance(selections,list) or not 1<=len(selections)<=24: raise ExperimentError('invalid_variant_selection')
    cases=[]; variants=[]; actor_controls={}
    owner_case={'id':'owner-object','identity':owner,'method':'GET','path':entry['path'],'expect':{'status':[200],'json':{rule['pointer']:rule['value']}}}
    if 'owner_probe' in bindings:
        _fields(bindings['owner_probe'],{'path','expect'},{'path','expect'},'owner_probe')
        owner_case.update(copy.deepcopy(bindings['owner_probe']))
    if 'resource_pointer' in rule: owner_case['expect']['json'][rule['resource_pointer']]=rule['resource_value']
    cases.append(owner_case)
    for selection in selections:
        _fields(selection,{'id','identity','path','method','headers','body'}, {'id','identity','path'},'selected_variant')
        _identifier(selection['id'],'variant id')
        identity=selection['identity']
        if identity not in actor_controls:
            probe=bindings['identity_probe'] if identity==actor else bindings.get('identity_probes',{}).get(identity)
            if probe is None: raise ExperimentError('variant_identity_probe_required')
            _fields(probe,{'path','expect'},{'path','expect'},'identity_probe')
            index=len(actor_controls); ic='actor-identity-'+str(index); nc='known-denial-'+str(index)
            negative=bindings['negative_probe']; _fields(negative,{'path','expect'},{'path','expect'},'negative_probe')
            cases.append({'id':ic,'identity':identity,'method':'GET','path':probe['path'],'expect':copy.deepcopy(probe['expect'])})
            cases.append({'id':nc,'identity':identity,'method':'GET','path':negative['path'],'expect':copy.deepcopy(negative['expect']),'requires':[ic,'owner-object']})
            actor_controls[identity]=(ic,nc)
        ic,nc=actor_controls[identity]; case_id='variant-'+selection['id']
        case={'id':case_id,'identity':identity,'method':entry['method'],'path':selection['path'],'headers':copy.deepcopy(entry.get('headers',{})), 'expect':{'status':[401,403,404],'json_absent':[rule['pointer']]},'requires':[ic,'owner-object',nc]}
        if 'json' in entry: case['body']=copy.deepcopy(entry['json'])
        for field in ('method','headers','body'):
            if field in selection: case[field]=copy.deepcopy(selection[field])
        cases.append(case); variants.append({'id':selection['id'],'case_id':case_id,'identity_control':ic,'object_control':'owner-object','negative_control':nc})
    contract={'version':1,'name':bindings['title'],'target':bindings['target'],'identities':copy.deepcopy(bindings['identities']),'cases':cases}
    if 'limits' in bindings: contract['limits']=copy.deepcopy(bindings['limits'])
    spec={'schema_version':1,'kind':'experiment-spec','id':bindings['id'],'title':bindings['title'],'contract':contract,'rule':rule,'variants':variants,'capture_mode':bindings.get('capture_mode','attested'),'sources':[entry['id']],'mutation_approval':bindings.get('mutation_approval',[])}
    if 'identity_bindings' in bindings: spec['identity_bindings']=copy.deepcopy(bindings['identity_bindings'])
    return compile_experiment(spec)

def plan_experiment_retest(baseline_execution, selected_variant_ids):
    if verify_execution(baseline_execution): raise ExperimentError('invalid_baseline_execution')
    variants={v['id']:v for v in baseline_execution['plan']['variants']}
    if not isinstance(selected_variant_ids,list) or not selected_variant_ids or len(set(selected_variant_ids))!=len(selected_variant_ids) or any(v not in variants for v in selected_variant_ids):
        raise ExperimentError('invalid_retest_selection')
    selected=[variants[v] for v in sorted(selected_variant_ids)]
    subset=retest_plan(baseline_execution['contract'],[v['case_id'] for v in selected],allow_mutations=True)
    spec=copy.deepcopy(baseline_execution['plan']['spec']); spec['contract']=subset['contract']; spec['variants']=selected
    spec['mutation_approval']=[c['id'] for c in spec['contract']['cases'] if c['method'] not in {'GET','HEAD','OPTIONS'}]
    return compile_experiment(spec)

def compare_executions(baseline, current):
    """Finding-level retest derived from fresh controls, unchanged rule and source."""
    if verify_execution(baseline) or verify_execution(current): raise ExperimentError('invalid_retest_execution')
    selected=[v['id'] for v in current['plan']['variants']]
    expected=plan_experiment_retest(baseline,selected)
    if canonical(expected)!=canonical(current['plan']): raise ExperimentError('retest_rule_source_or_binding_drift')
    from .comparison import create_comparison
    envelope=create_comparison(baseline['contract'],baseline['report'],current['report'],[v['case_id'] for v in current['plan']['variants']])
    current_obs={o['case_id']:o for o in current['observations']}; current_findings={f['case_id']:f for f in current['findings']}
    transitions=[]
    for before in baseline['findings']:
        cid=before['case_id']; after=current_findings.get(cid); obs=current_obs.get(cid)
        status='not_retested'
        if after is not None:
            if after['interpretation']=='inconclusive': status='inconclusive'
            elif before['status']=='confirmed' and after['interpretation']=='satisfied' and obs['controls_valid']: status='fix_verified'
            elif before['status']=='confirmed' and after['status']=='confirmed': status='violation_persists'
            elif before['interpretation']=='inconclusive' and after['interpretation']=='satisfied': status='testability_restored'
            elif after['status']=='confirmed': status='regression' if before['interpretation']=='satisfied' else 'inconclusive'
            else: status='unchanged'
        transitions.append({'finding_id':before['id'],'case_id':cid,'status':status,'baseline_finding_digest':before['finding_digest'],'current_finding_digest':after['finding_digest'] if after else None,
                            'verification_level':after['verification_level'] if after else before['verification_level']})
    value={'schema_id':'authzledger.experiment-comparison','schema_version':1,'kind':'experiment-comparison',
           'baseline_execution_digest':baseline['execution_digest'],'current_execution_digest':current['execution_digest'],
           'comparison_envelope':envelope,'transitions':transitions,
           'limitations':['Fix statements apply only to selected rule/resource/identity bindings and fresh configured controls.',
                          'Unselected findings remain historical; deployment and remote response authenticity are not independently attested.']}
    return seal('experiment-comparison',value,'comparison_digest')
