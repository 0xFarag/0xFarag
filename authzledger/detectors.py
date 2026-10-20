"""Versioned, control-bound assessment checks over the existing execution engine.

No plugin code is imported and no transport is implemented here. All runtime
captures are discarded after bounded, credential-free oracle projection.
"""
from __future__ import annotations

import copy
import dataclasses
import re
import uuid
from dataclasses import dataclass
from enum import Enum
from urllib.parse import parse_qsl, urlsplit

from . import engine
from .credentials import CredentialResolver
from .evidence import verify_report
from .experiments import (compile_experiment, execute_experiment, verify_execution,
                          _reject_literal_credentials, _closure)
from .model import load_contract, contract_digest, _identifier, _pointer
from .oracles import canonical, digest, seal, parse_json, pointer, equal
from .workflows import compile_workflow, execute_workflow, verify_workflow


class DetectionError(ValueError):
    pass


class EvidenceLevel(str, Enum):
    HINT = 'hint'
    CANDIDATE = 'candidate'
    CONFIRMED = 'confirmed'
    INCONCLUSIVE = 'inconclusive'


@dataclass(frozen=True)
class CheckSpec:
    check_id: str
    version: str
    family: str
    title: str
    required_controls: tuple[str, ...]
    oracle_id: str
    severity_default: str
    adapter: str = 'generic'
    lifecycle: str = 'validated'
    evidence_ceiling: str = 'confirmed'
    effects: tuple[str, ...] = ('read',)
    limitations: tuple[str, ...] = ()

    def manifest(self):
        value = dataclasses.asdict(self)
        for key in ('required_controls', 'effects', 'limitations'):
            value[key] = list(value[key])
        value.update(kind='check-manifest', schema_version=1, oracle_version=1,
                     capture_profile='selected-predicates-v1', executable_code=False)
        return seal('check-manifest', value, 'rule_digest')

    def digest(self):
        return self.manifest()['rule_digest']


_SPECS = (
    CheckSpec('authz.object.disclosure','1.0.0','authz','Object marker disclosed across identities',('identity','owner','denial'),'contrast.forbid_field_equal','high','contrast',limitations=('Operator declares resource ownership and protected marker uniqueness.',)),
    CheckSpec('authz.tenant.disclosure','1.0.0','authz','Protected marker crosses an asserted tenant boundary',('identity','owner','denial','tenant'),'contrast.tenant_disclosure','high','contrast',limitations=('Tenant claims require explicit response assertions.',)),
    CheckSpec('authz.role.disclosure','1.0.0','authz','Protected marker crosses asserted role boundary',('identity','owner','denial','role'),'contrast.role_disclosure','high','contrast',limitations=('Role ordering and protected operation are operator-declared.',)),
    CheckSpec('authz.denial.disclosure','1.0.0','authz','Denied response contains protected marker',('identity','owner','denial'),'contrast.denial_disclosure','high','contrast'),
    CheckSpec('authz.response.contract','1.0.0','authz','Identity-bound response field policy violation',('identity','owner','denial'),'contrast.response_contract','medium','contrast',limitations=('Confirms only the configured field invariant; no automatic BOLA attribution.',)),
    CheckSpec('business_logic.skipped_approval','1.0.0','business_logic','Omitted required step permits forbidden state',('identity','fresh_fixture','pre_state','post_state','cleanup'),'workflow.forbidden_state','high','workflow',effects=('read','mutate')),
    CheckSpec('business_logic.role_transition','1.0.0','business_logic','Changed actor permits forbidden state transition',('identity','fresh_fixture','pre_state','post_state','cleanup'),'workflow.role_transition','high','workflow',effects=('read','mutate')),
    CheckSpec('business_logic.idempotency','1.0.0','business_logic','Repeated operation exceeds permitted effect count',('identity','fresh_fixture','pre_state','post_state','cleanup'),'workflow.effect_increase','high','workflow',effects=('read','mutate')),
    CheckSpec('injection.expression_evaluation','1.0.0','injection','Controlled arithmetic template evaluation',('literal_baseline','unevaluated_negative','two_probes'),'arithmetic-template-v1','medium',limitations=('Proves only two arithmetic expressions were evaluated at the declared sink, not code execution or general injection coverage.',)),
    CheckSpec('misconfig.security_headers','1.0.0','misconfig','Missing explicitly required security response headers',('same_route_baseline',),'required-headers-v1','low',limitations=('A missing configured header is a configuration observation, not proof of exploitability.',)),
    CheckSpec('misconfig.cors.reflection','1.0.0','misconfig','Untrusted Origin reflected with credentials enabled',('same_route_baseline',),'cors-reflection-v1','info',evidence_ceiling='hint',limitations=('Header reflection alone does not prove browser-readable sensitive data or exploitable CORS.',)),
    CheckSpec('info.verbose_errors','1.0.0','info','Recognized diagnostic traceback exposed',('available_baseline',),'verbose-signatures-v1','info',evidence_ceiling='hint',limitations=('Recognized text signatures can occur in documentation; review context.',)),
    CheckSpec('info.json_field_exposure','1.0.0','info','Operator-declared sensitive JSON field present',('available_baseline',),'json-presence-v1','info',evidence_ceiling='hint',limitations=('Field presence does not prove sensitive content or unauthorized access.',)),
)
_REGISTRY = {s.check_id: s for s in _SPECS}
_PROFILES = {
    'authz-deep': tuple(s.check_id for s in _SPECS if s.family in {'authz','business_logic'}),
    'web-quick': tuple(s.check_id for s in _SPECS if s.family in {'misconfig','info'}),
    'full-safe': tuple(s.check_id for s in _SPECS if 'mutate' not in s.effects),
}
_PROFILE_ALIASES = {'quick':'web-quick','deep-authz':'authz-deep'}
_HEADERS = {'content-security-policy','x-content-type-options','strict-transport-security','referrer-policy','permissions-policy','x-frame-options'}
_TRACE_SIGNATURES = {'python_traceback': b'Traceback (most recent call last):',
                     'java_stack': b'java.lang.', 'php_fatal': b'Fatal error:',
                     'dotnet_stack': b'System.NullReferenceException'}


def catalog():
    result = {'schema_version':1,'kind':'check-catalog','checks':[s.manifest() for s in _SPECS],
              'profiles':{**{k:list(v) for k,v in _PROFILES.items()}, **{k:list(_PROFILES[v]) for k,v in _PROFILE_ALIASES.items()}},
              'profile_aliases':dict(_PROFILE_ALIASES),
              'profile_limitations':{'full-safe':'Read-effect check selection only; explicit scope and operation safety attestation remain required. GET is not proof of no side effects.'}}
    return seal('check-catalog', result, 'registry_digest')


def select_checks(profile):
    profile=_PROFILE_ALIASES.get(profile,profile)
    if profile not in _PROFILES:
        raise DetectionError('unknown_check_profile')
    return [copy.deepcopy(_REGISTRY[key].manifest()) for key in _PROFILES[profile]]


def validate_pack(pack, lock):
    """Validate declarative curated manifests against an explicit integrity lock.

    Lifecycle changes are metadata bound by the lock; the executable semantics
    must still exactly match an installed curated check. No arbitrary loading.
    """
    if not isinstance(pack,dict) or set(pack) != {'schema_version','kind','checks'} or pack['schema_version'] != 1 or pack['kind'] != 'check-pack':
        raise DetectionError('invalid_check_pack')
    if not isinstance(lock,dict) or set(lock) != {'pack_digest','checks'} or lock['pack_digest'] != digest('check-pack',pack):
        raise DetectionError('check_pack_lock_mismatch')
    if not isinstance(pack['checks'],list) or not 1 <= len(pack['checks']) <= 100:
        raise DetectionError('invalid_check_pack_size')
    seen=set()
    for item in pack['checks']:
        if not isinstance(item,dict) or item.get('check_id') not in _REGISTRY:
            raise DetectionError('unsupported_check_code')
        key=item['check_id']+'@'+item.get('version','')
        if key in seen or lock['checks'].get(key) != item.get('rule_digest'):
            raise DetectionError('check_manifest_lock_mismatch')
        seen.add(key)
        if item.get('lifecycle') not in {'validated','experimental','deprecated','revoked'}:
            raise DetectionError('invalid_check_lifecycle')
        expected=_REGISTRY[item['check_id']].manifest()
        expected['lifecycle']=item['lifecycle'];expected=seal('check-manifest',expected,'rule_digest')
        if expected != item:
            raise DetectionError('check_manifest_semantics_mismatch')
        if item['lifecycle']=='revoked':
            raise DetectionError('revoked_check')
    if set(lock['checks']) != seen:
        raise DetectionError('check_lock_inventory_mismatch')
    return copy.deepcopy(pack)


def _fields(value,allowed,required,label):
    if not isinstance(value,dict) or set(value)-set(allowed) or set(required)-set(value):
        raise DetectionError('invalid_'+label+'_fields')


def _refs(value):
    if not isinstance(value,list) or not value or len(value)>500 or any(not isinstance(v,str) or not 1<=len(v)<=512 for v in value) or len(set(value))!=len(value):
        raise DetectionError('explicit_source_refs_required')
    return sorted(value)


def _check_adapter(spec, check):
    if check.adapter=='contrast':
        plan=compile_experiment(spec['experiment_spec']);rule=plan['rule']
        cases={c['id']:c for c in plan['contract']['cases']}
        if check.check_id=='authz.response.contract':
            if rule['kind'] not in {'require_field_equal','require_absent','require_type','require_member','forbid_member'}:
                raise DetectionError('response_field_invariant_required')
        elif rule['kind']!='forbid_field_equal':
            raise DetectionError('protected_marker_oracle_required')
        for variant in plan['variants']:
            actor=cases[variant['identity_control']];owner=cases[variant['object_control']]
            if check.check_id=='authz.tenant.disclosure':
                binding=plan['spec']['identity_bindings'][actor['identity']]
                tenant=binding.get('tenant_pointer')
                if not tenant or tenant not in owner['expect'].get('json',{}) or equal(owner['expect']['json'][tenant],binding['tenant']):
                    raise DetectionError('distinct_asserted_tenants_required')
            if check.check_id=='authz.role.disclosure':
                if '/role' not in actor['expect'].get('json',{}):
                    raise DetectionError('actor_role_assertion_required')
                dependencies=_closure(cases,variant['case_id'])
                peers=[cases[cid] for cid in dependencies if cases[cid]['identity']==owner['identity'] and '/principal' in cases[cid]['expect'].get('json',{}) and '/role' in cases[cid]['expect'].get('json',{})]
                if not peers or any(equal(c['expect']['json']['/role'],actor['expect']['json']['/role']) or any(status>=300 for status in c['expect']['status']) for c in peers):
                    raise DetectionError('independent_distinct_owner_role_control_required')
        return plan, plan['contract']
    plan=compile_workflow(spec['workflow_spec']);w=plan['spec']
    if check.check_id=='business_logic.skipped_approval' and (w['rule']['kind']!='forbidden_state' or any(not v.get('omit') for v in w['variants'])):
        raise DetectionError('explicit_omission_and_forbidden_state_required')
    if check.check_id=='business_logic.role_transition' and (w['rule']['kind']!='forbidden_state' or any(not v.get('identity_overrides') for v in w['variants'])):
        raise DetectionError('explicit_actor_override_and_forbidden_state_required')
    if check.check_id=='business_logic.idempotency' and w['rule']['kind']!='effect_increase':
        raise DetectionError('explicit_replay_effect_oracle_required')
    # Every credentialed identity used by workflow requires a fresh principal
    # assertion among the existing workflow controls.
    cases={c['id']:c for c in w['contract']['cases']}
    if check.check_id=='business_logic.role_transition':
        steps={step['id']:step for step in w['steps']}
        for variant in w['variants']:
            for step_id,identity in variant['identity_overrides'].items():
                original=cases[steps[step_id]['case_id']]['identity']
                if original==identity:raise DetectionError('actor_override_must_change_identity')
                principals=[]
                for actor in (original,identity):
                    found=[cases[c]['expect']['json']['/principal'] for c in w['controls'] if cases[c]['identity']==actor and isinstance(cases[c]['expect'].get('json',{}).get('/principal'),str) and all(200<=status<300 for status in cases[c]['expect']['status'])]
                    if len(found)!=1:raise DetectionError('each_transition_actor_requires_principal_control')
                    principals.append(found[0])
                if principals[0]==principals[1]:raise DetectionError('distinct_transition_principals_required')
    for identity,config in w['contract']['identities'].items():
        if any(isinstance(v,dict) for v in config['headers'].values()):
            if not any(cases[c]['identity']==identity and '/principal' in cases[c]['expect'].get('json',{}) for c in w['controls']):
                raise DetectionError('credentialed_workflow_identity_control_required')
    return plan,w['contract']


def _validate_generic(spec,check):
    contract=load_contract(spec['contract'],allow_mutations=False)
    _reject_literal_credentials(contract)
    cases={c['id']:c for c in contract['cases']};target=spec['target_case'];controls=spec['controls']
    if target not in cases or not isinstance(controls,list) or not controls or len(set(controls))!=len(controls) or any(c not in cases for c in controls) or target in controls:
        raise DetectionError('explicit_distinct_controls_required')
    if not set(controls) <= _closure(cases,target):
        raise DetectionError('controls_must_gate_target_in_dag')
    if set(cases)-set(controls)-{target}-({spec.get('params',{}).get('secondary_case')} if check.family=='injection' else set()):
        raise DetectionError('unused_case_not_allowed')
    identity_controls=spec.get('identity_controls',{})
    if not isinstance(identity_controls,dict):raise DetectionError('invalid_identity_controls')
    for identity,config in contract['identities'].items():
        if any(isinstance(v,dict) for v in config['headers'].values()):
            cid=identity_controls.get(identity)
            if cid not in controls or cases[cid]['identity']!=identity or not isinstance(cases[cid]['expect'].get('json',{}).get('/principal'),str) or any(s>=300 for s in cases[cid]['expect']['status']):
                raise DetectionError('credentialed_identity_control_required')
    if set(identity_controls)-set(contract['identities']):raise DetectionError('unknown_identity_binding')
    params=copy.deepcopy(spec.get('params',{}))
    baseline=next((cases[c] for c in controls if c not in identity_controls.values()),None)
    if baseline is None:raise DetectionError('independent_baseline_control_required')
    if any(s>=300 for s in baseline['expect']['status']):raise DetectionError('successful_baseline_required')
    if baseline['identity']!=cases[target]['identity'] and check.check_id!='misconfig.cors.reflection':
        raise DetectionError('baseline_identity_mismatch')
    if check.check_id=='misconfig.security_headers':
        _fields(params,{'required_headers'},{'required_headers'},'header_params')
        if not isinstance(params['required_headers'],list) or not params['required_headers'] or len(set(params['required_headers']))!=len(params['required_headers']) or any(h not in _HEADERS for h in params['required_headers']):
            raise DetectionError('unsupported_security_header')
        if 'strict-transport-security' in params['required_headers'] and not contract['target'].startswith('https://'):
            raise DetectionError('hsts_requires_https')
        if (baseline['path'],baseline['method'])!=(cases[target]['path'],cases[target]['method']):raise DetectionError('same_route_baseline_required')
        params['required_headers']=sorted(params['required_headers'])
    elif check.check_id=='misconfig.cors.reflection':
        _fields(params,{'untrusted_origin'},{'untrusted_origin'},'cors_params')
        from .model import _target
        _target(params['untrusted_origin'])
        if params['untrusted_origin']==contract['target']:raise DetectionError('distinct_untrusted_origin_required')
        origin_headers={k.lower():v for k,v in contract['identities'][cases[target]['identity']]['headers'].items()}
        if origin_headers.get('origin')!=params['untrusted_origin']:raise DetectionError('probe_origin_header_required')
        base_headers={k.lower():v for k,v in contract['identities'][baseline['identity']]['headers'].items()}
        if 'origin' in base_headers or (baseline['path'],baseline['method'])!=(cases[target]['path'],cases[target]['method']):
            raise DetectionError('same_route_no_origin_baseline_required')
        if any(v!=origin_headers.get(k) for k,v in base_headers.items()) or set(origin_headers)-set(base_headers)!={'origin'}:
            raise DetectionError('cors_baseline_identity_context_mismatch')
    elif check.check_id=='info.verbose_errors':
        _fields(params,set(),set(),'verbose_params')
    elif check.check_id=='info.json_field_exposure':
        _fields(params,{'pointer'},{'pointer'},'field_params');_pointer(params['pointer'])
        if not params['pointer']:raise DetectionError('field_pointer_required')
    elif check.check_id=='injection.expression_evaluation':
        _fields(params,{'pointer','parameter','baseline_case','negative_case','secondary_case'},{'pointer','parameter','baseline_case','negative_case','secondary_case'},'expression_params')
        _pointer(params['pointer'])
        ids=[params['baseline_case'],params['negative_case'],target,params['secondary_case']]
        if len(set(ids))!=4 or any(cid not in cases for cid in ids) or not set(ids[:2])<=set(controls):raise DetectionError('four_distinct_expression_cases_required')
        if not set(controls)<=_closure(cases,ids[3]):raise DetectionError('controls_must_gate_secondary_probe')
        if not isinstance(params['parameter'],str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,63}',params['parameter']):raise DetectionError('invalid_expression_parameter')
        expected=['ALCTL_LITERAL','13*17','{{13*17}}','{{19*23}}']
        normalized=[]
        for cid,value in zip(ids,expected):
            c=cases[cid];u=urlsplit(c['path']);pairs=parse_qsl(u.query,keep_blank_values=True)
            if c['method']!='GET' or [v for k,v in pairs if k==params['parameter']]!=[value]:raise DetectionError('curated_arithmetic_payload_required')
            normalized.append((u.path,[(k,v) for k,v in pairs if k!=params['parameter']],c['identity'],c['headers']))
        if any(n!=normalized[0] for n in normalized):raise DetectionError('expression_cases_must_differ_only_in_parameter')
        for cid,value in zip(ids[:2],expected[:2]):
            if cases[cid]['expect'].get('json',{}).get(params['pointer'])!=value:raise DetectionError('literal_control_content_assertion_required')
    return contract,params


def compile_check(spec,scope):
    """Compile an immutable bounded plan. This function never resolves secrets."""
    common={'schema_version','kind','id','check_id','version','source_refs'}
    optional={'contract','controls','target_case','params','identity_controls','experiment_spec','workflow_spec','retest_of'}
    _fields(spec,common|optional,common,'check_spec')
    if type(spec['schema_version']) is not int or spec['schema_version']!=1 or spec['kind']!='check-spec':raise DetectionError('unsupported_check_spec')
    _identifier(spec['id'],'check id')
    check=_REGISTRY.get(spec['check_id'])
    if check is None or spec['version']!=check.version:raise DetectionError('unsupported_check_version')
    from .scope import validate_scope
    scoped=validate_scope(scope)
    normalized=copy.deepcopy(spec);normalized['source_refs']=_refs(spec['source_refs'])
    if 'retest_of' in normalized:
        _fields(normalized['retest_of'],{'execution_digest','plan_digest','selected_ids','source_scope_digest'},{'execution_digest','plan_digest','selected_ids'},'retest_binding')
        if any(not isinstance(normalized['retest_of'][k],str) or not re.fullmatch('[a-f0-9]{64}',normalized['retest_of'][k]) for k in ('execution_digest','plan_digest')):raise DetectionError('invalid_retest_digest')
        if not isinstance(normalized['retest_of']['selected_ids'],list):raise DetectionError('invalid_selected_retest_ids')
        if 'source_scope_digest' in normalized['retest_of'] and (not isinstance(normalized['retest_of']['source_scope_digest'],str) or not re.fullmatch('[a-f0-9]{64}',normalized['retest_of']['source_scope_digest'])):raise DetectionError('invalid_source_scope_digest')
    if check.adapter=='generic':
        if not {'contract','controls','target_case'}<=set(spec) or {'experiment_spec','workflow_spec'}&set(spec):raise DetectionError('invalid_generic_check_fields')
        contract,params=_validate_generic(spec,check);normalized.update(contract=contract,params=params,identity_controls=copy.deepcopy(spec.get('identity_controls',{})))
        upper=len(contract['cases']);adapter_plan=None
    else:
        key='experiment_spec' if check.adapter=='contrast' else 'workflow_spec'
        if key not in spec or set(spec)&({'contract','controls','target_case','params','identity_controls','experiment_spec','workflow_spec'}-{key}):raise DetectionError('invalid_adapter_check_fields')
        adapter_plan,contract=_check_adapter(spec,check);normalized[key]=copy.deepcopy(adapter_plan['spec']);upper=adapter_plan['request_upper_bound']
    if contract['target'] not in scoped['origins']:raise DetectionError('check_target_outside_scope')
    if upper>scoped['limits']['max_requests']:raise DetectionError('check_exceeds_scope_budget')
    if not set(check.effects)<=set(scoped['allowed_effects']):raise DetectionError('check_effect_not_authorized')
    plan={'schema_version':1,'kind':'check-plan','spec':normalized,'check':check.manifest(),'scope':scoped,
          'contract':contract,'contract_digest':contract_digest(contract),'adapter_plan':adapter_plan,
          'request_upper_bound':upper,'source_refs':normalized['source_refs']}
    return seal('check-plan',plan,'plan_digest')


def verify_check_plan(plan):
    try:return [] if compile_check(plan['spec'],plan['scope'])==plan else ['check_plan_mismatch']
    except (ValueError,KeyError,TypeError,RecursionError):return ['invalid_check_plan']


def _projection(check_id,params,capture,secrets):
    if not capture or not capture.get('complete') or capture.get('error_code'):return {'error':'incomplete_capture'}
    body=capture.get('body',b'');headers=capture.get('headers',[])
    result={'status':capture['status']}
    if check_id=='misconfig.security_headers':
        # Only counts/absence persist, never arbitrary header strings.
        result['headers']={name:sum(k.lower()==name and bool(v.strip()) for k,v in headers) for name in params['required_headers']}
    elif check_id=='misconfig.cors.reflection':
        allowed=[v.strip() for k,v in headers if k.lower()=='access-control-allow-origin']
        credentials=[v.strip() for k,v in headers if k.lower()=='access-control-allow-credentials']
        result.update(origin_matches=(allowed==[params['untrusted_origin']]),credentials_true=(credentials==['true']),duplicate_headers=len(allowed)>1 or len(credentials)>1)
    elif check_id=='info.verbose_errors':
        result['signatures']=sorted(name for name,marker in _TRACE_SIGNATURES.items() if marker in body)
    else:
        try:present,value=pointer(parse_json(body),params['pointer'])
        except ValueError:return {'error':'invalid_json_capture'}
        if check_id=='info.json_field_exposure':result['present']=present
        else:
            # The only retained data are predetermined safe arithmetic outcomes.
            if any(secret and secret in body.decode('utf-8',errors='replace') for secret in secrets):return {'error':'credential_reflection_redacted'}
            result['value']=value if present and type(value) in {str,int} and value in {221,437,'221','437','ALCTL_LITERAL','13*17','{{13*17}}','{{19*23}}'} else None
            result['present']=present
    return result


def _decision(plan,projections,results):
    spec=plan['spec'];check=plan['check'];cid=spec['target_case'];params=spec['params']
    controls=spec['controls'];valid=all(results.get(c,{}).get('outcome')=='pass' for c in controls)
    if not valid:return ('inconclusive','inconclusive','invalid_controls')
    ids=[cid]+([params['secondary_case']] if check['family']=='injection' else [])
    if any(results.get(c,{}).get('outcome') in {'error','inconclusive',None} or projections.get(c,{}).get('error') for c in ids):
        return ('inconclusive','inconclusive','unusable_observation')
    p=projections[cid]
    # A changed endpoint status cannot establish a fixed response policy.
    if check['family']!='info' and any(results[c]['outcome']!='pass' for c in ids):
        return ('inconclusive','inconclusive','endpoint_expectation_changed')
    if check['check_id']=='misconfig.security_headers':violation=any(count==0 for count in p['headers'].values())
    elif check['check_id']=='misconfig.cors.reflection':
        if p['duplicate_headers']:return ('inconclusive','inconclusive','ambiguous_cors_headers')
        violation=p['origin_matches'] and p['credentials_true']
    elif check['check_id']=='info.verbose_errors':violation=bool(p['signatures'])
    elif check['check_id']=='info.json_field_exposure':violation=p['present']
    else:violation=p.get('value') in {221,'221'} and projections[params['secondary_case']].get('value') in {437,'437'}
    return ('violation' if violation else 'satisfied',check['evidence_ceiling'] if violation else 'hint','predicate_violated' if violation else 'predicate_not_observed')


def _finding(plan,local_id,decision,control_refs,observation_refs,*,source_finding=None):
    interpretation,level,reason=decision
    status='confirmed' if level=='confirmed' else ('not_observed' if interpretation=='satisfied' else level)
    value={'schema_version':1,'kind':'detection-finding','id':'finding-'+digest('detection-identity',{'check':plan['check']['check_id'],'version':plan['check']['version'],'assessment_check':plan['spec']['id'],'local_id':local_id,'sources':plan['source_refs']})[:24],
           'local_id':local_id,'check_id':plan['check']['check_id'],'check_version':plan['check']['version'],'title':plan['check']['title'],
           'family':plan['check']['family'],'status':status,'evidence_level':level,'interpretation':interpretation,'reason':reason,
           'severity':plan['check']['severity_default'],'severity_basis':'curated_default_requires_context_review','cvss':{'status':'not_scored','vector':None},
           'rule_digest':plan['check']['rule_digest'],'control_refs':control_refs,'observation_refs':observation_refs,'source_refs':plan['source_refs'],
           'review_status':'unreviewed','source_finding':source_finding,'reproducer_ref':_reproducer(plan)['reproducer_digest'],'limitations':plan['check']['limitations']}
    return seal('detection-finding',value,'finding_digest')


def _adapter_findings(plan,execution):
    findings=[]
    if plan['check']['adapter']=='contrast':
        observations={o['case_id']:o for o in execution['observations']}
        variants={v['case_id']:v['id'] for v in plan['adapter_plan']['variants']}
        for f in execution['findings']:
            obs=observations[f['case_id']];inter=f['interpretation'];level='confirmed' if f['status']=='confirmed' else ('inconclusive' if inter=='inconclusive' else 'hint')
            if plan['check']['check_id']=='authz.denial.disclosure' and inter=='violation' and obs['status'] not in {401,403,404}:level='candidate';inter='inconclusive'
            findings.append(_finding(plan,variants[f['case_id']],(inter,level,'adapter_'+inter),f['control_refs'],f['evidence_refs'],source_finding=f['finding_digest']))
    else:
        traces={v['id']:v for v in execution['variants']}
        for planned in plan['adapter_plan']['variants']:
            v=traces.get(planned['id'])
            if v is None:
                findings.append(_finding(plan,planned['id'],('inconclusive','inconclusive','adapter_variant_not_run'),[],[]))
                continue
            inter=v['interpretation'];level='confirmed' if inter=='violation' and v['controls_valid'] else ('hint' if inter=='satisfied' else 'inconclusive')
            refs=[step['report']['evidence']['root_sha256'] for step in v['steps']]
            controls=[v['controls']['report']['evidence']['root_sha256']] if 'controls' in v else []
            findings.append(_finding(plan,v['id'],(inter,level,'adapter_'+inter),controls,refs))
    return findings


def _reproducer(plan):
    return seal('check-reproducer',{'schema_version':1,'kind':'check-reproducer','check_id':plan['check']['check_id'],
                'plan_digest':plan['plan_digest'],'recipe':copy.deepcopy(plan['spec']),'scope_digest':plan['scope'].get('scope_digest'),
                'source_refs':plan['source_refs'],'request_upper_bound':plan['request_upper_bound'],
                'prerequisites':['Use fresh origin-bound credentials and the original declared fixtures.','Review exact scope and expiry before execution.','Rerun all prerequisite controls.'],
                'limitations':['This is a bounded complete check recipe, not an assertion of globally minimal exploit input.']},'reproducer_digest')


def _credential_metadata(contract,resolver):
    metadata=resolver.metadata() if hasattr(resolver,'metadata') else []
    sessions={item['ref'].split('://',1)[-1]:item for item in metadata}
    bindings=[]
    for identity,config in sorted(contract['identities'].items()):
        for header,reference in sorted(config['headers'].items()):
            if not isinstance(reference,dict):continue
            name=reference['env'];session=sessions.get(name)
            bindings.append({'ref':('session://' if session else 'env://')+name,'identity':identity,
                             'target_origin':contract['target'],'generation':session['generation'] if session else None,
                             'generation_binding':'resolver_metadata_at_start' if session else 'external_environment_unversioned'})
    return bindings


def _valid_credential_metadata(bindings,contract):
    if not isinstance(bindings,list):return False
    required=[(identity,reference['env']) for identity,config in sorted(contract['identities'].items()) for header,reference in sorted(config['headers'].items()) if isinstance(reference,dict)]
    if len(bindings)!=len(required):return False
    for value,(identity,name) in zip(bindings,required):
        if not isinstance(value,dict) or set(value)!={'ref','identity','target_origin','generation','generation_binding'}:return False
        if value['identity']!=identity or value['target_origin']!=contract['target']:return False
        if value['ref']=='env://'+name:
            if value['generation'] is not None or value['generation_binding']!='external_environment_unversioned':return False
        elif value['ref']=='session://'+name:
            if not isinstance(value['generation'],str) or not re.fullmatch('[a-f0-9]{32}',value['generation']) or value['generation_binding']!='resolver_metadata_at_start':return False
        else:return False
    return True


def execute_check(plan,*,context=None,credential_resolver=None):
    if verify_check_plan(plan):raise DetectionError('invalid_check_plan')
    from .scope import context_for_scope
    if context is None:
        cleanup=plan['adapter_plan']['cleanup_reserve'] if plan['check']['adapter']=='workflow' else 0
        context=context_for_scope(plan['scope'],cleanup_reserve=cleanup,allow_cleanup_after_cancel=bool(cleanup))
    # A supplied context must be bound to exactly this authorization policy.
    context_scope=getattr(context,'scope_policy',None)
    if context_scope is not None and context_scope!=plan['scope']:raise DetectionError('execution_scope_mismatch')
    if context_scope is None:
        # The shared transport owns enforcement; never downgrade to a legacy
        # unrestricted context simply because a caller supplied one.
        if getattr(context,'scope',None)!=plan['scope']:raise DetectionError('scope_bound_context_required')
    resolver=credential_resolver or CredentialResolver()
    result={'schema_version':1,'kind':'check-execution','execution_id':str(uuid.uuid4()),'plan':copy.deepcopy(plan),'credential_bindings':_credential_metadata(plan['contract'],resolver)}
    if plan['check']['adapter']!='generic':
        run=execute_experiment if plan['check']['adapter']=='contrast' else execute_workflow
        child=run(plan['adapter_plan'],context=context,credential_resolver=resolver)
        result.update(adapter_execution=child,findings=_adapter_findings(plan,child),observations=copy.deepcopy(child.get('observations',[])))
    else:
        contract=plan['contract'];resolved=resolver.resolve_contract(contract);secrets=set()
        for identity,config in contract['identities'].items():
            for name,reference in config['headers'].items():
                if isinstance(reference,dict):
                    value=resolved[identity][name];secrets.add(value)
                    if name.lower()=='authorization' and ' ' in value:secrets.add(value.split(' ',1)[1])
                    if name.lower()=='cookie':secrets.update(c.split('=',1)[1].strip() for c in value.split(';') if '=' in c)
        if any(s and len(s)>=8 and s in canonical(plan).decode() for s in secrets):raise DetectionError('credential_in_check_plan')
        class PinnedResolver:
            def resolve_contract(self,request_contract):
                if contract_digest(request_contract)!=plan['contract_digest']:raise DetectionError('credential_scope_changed')
                return copy.deepcopy(resolved)
        spec=plan['spec'];params=spec['params'];ids={spec['target_case']}
        if plan['check']['family']=='injection':ids.add(params['secondary_case'])
        projections={}
        def receive(capture):
            cid=capture['case_id']
            if cid in ids:
                projections[cid]=_projection(plan['check']['check_id'],params,capture,secrets)
        kinds={c['id']:('identity_control' if c['id'] in spec['identity_controls'].values() else 'object_control' if c['id'] in spec['controls'] else 'application') for c in contract['cases']}
        try:report=engine.run(contract,context=context,credential_resolver=PinnedResolver(),observation_sink=receive,request_kind=kinds)
        finally:resolved.clear();secrets.clear()
        results={r['id']:r for r in report['results']}
        for cid in ids:projections.setdefault(cid,{'error':'capture_not_dispatched'})
        observations=[]
        for cid in sorted(ids):
            observations.append(seal('check-observation',{'schema_version':1,'kind':'check-observation','case_id':cid,'plan_digest':plan['plan_digest'],
                'report_root':report['evidence']['root_sha256'],'body_sha256':results[cid].get('response_sha256'),'projection':projections[cid],
                'oracle_id':plan['check']['oracle_id'],'oracle_version':1,'verification_level':'selected_predicates_replayed',
                'limitations':['Projection from omitted raw response is signer-attested; local signatures do not authenticate the remote response.']},'observation_digest'))
        decision=_decision(plan,projections,results)
        result.update(report=report,observations=observations,findings=[_finding(plan,spec['target_case'],decision,list(spec['controls']),[o['observation_digest'] for o in observations])])
    result.update(budget_ledger=context.snapshot(),reproducer=_reproducer(plan),coverage={'known_check':plan['check']['check_id'],'planned_findings':len(result['findings']),'evaluated_findings':sum(f['interpretation']!='inconclusive' for f in result['findings']),'unknown_surface':'unknown'})
    return seal('check-execution',result,'execution_digest')


def _valid_projection(plan,cid,value,result):
    if not isinstance(value,dict):return False
    if 'error' in value:
        return set(value)=={'error'} and value['error'] in {'incomplete_capture','invalid_json_capture','credential_reflection_redacted','capture_not_dispatched'}
    if value.get('status')!=result['status'] or result['outcome'] not in {'pass','fail'}:return False
    check=plan['check']['check_id'];params=plan['spec']['params']
    if check=='misconfig.security_headers':
        return set(value)=={'status','headers'} and isinstance(value['headers'],dict) and set(value['headers'])==set(params['required_headers']) and all(type(n) is int and 0<=n<=100 for n in value['headers'].values())
    if check=='misconfig.cors.reflection':
        return set(value)=={'status','origin_matches','credentials_true','duplicate_headers'} and all(type(value[k]) is bool for k in ('origin_matches','credentials_true','duplicate_headers'))
    if check=='info.verbose_errors':
        return set(value)=={'status','signatures'} and isinstance(value['signatures'],list) and value['signatures']==sorted(set(value['signatures'])) and set(value['signatures'])<=set(_TRACE_SIGNATURES)
    if check=='info.json_field_exposure':
        return set(value)=={'status','present'} and type(value['present']) is bool
    if set(value)!={'status','value','present'} or type(value['present']) is not bool:return False
    observed=value['value']
    return observed is None or type(observed) in {str,int} and observed in {221,437,'221','437','ALCTL_LITERAL','13*17','{{13*17}}','{{19*23}}'}


def verify_check_execution(execution):
    try:
        if execution.get('kind')!='check-execution' or execution.get('schema_version')!=1:return ['invalid_check_execution_schema']
        if execution.get('execution_digest')!=digest('check-execution',execution,'execution_digest'):return ['check_execution_digest_mismatch']
        plan=execution['plan']
        if verify_check_plan(plan):return ['invalid_check_plan']
        if execution['reproducer']!=_reproducer(plan):return ['check_reproducer_mismatch']
        if not _valid_credential_metadata(execution['credential_bindings'],plan['contract']):return ['invalid_credential_binding_metadata']
        if plan['check']['adapter']=='generic':
            if set(execution)!={'schema_version','kind','execution_id','plan','report','observations','findings','budget_ledger','reproducer','coverage','credential_bindings','execution_digest'}:return ['unexpected_check_execution_fields']
            report=execution['report']
            errors=verify_report(report)
            from .intelligence import build_graph
            build_graph(plan['contract'],report)
            if errors:return ['invalid_check_report']
            results={r['id']:r for r in report['results']};projections={};spec=plan['spec']
            expected_ids={spec['target_case']}
            if plan['check']['family']=='injection':expected_ids.add(spec['params']['secondary_case'])
            for obs in execution['observations']:
                cid=obs['case_id']
                if cid in projections or cid not in expected_ids or obs['observation_digest']!=digest('check-observation',obs,'observation_digest') or obs['plan_digest']!=plan['plan_digest'] or obs['report_root']!=report['evidence']['root_sha256'] or obs['body_sha256']!=results[cid].get('response_sha256') or obs['verification_level']!='selected_predicates_replayed':return ['invalid_check_observation']
                if set(obs)!={'schema_version','kind','case_id','plan_digest','report_root','body_sha256','projection','oracle_id','oracle_version','verification_level','limitations','observation_digest'} or obs['schema_version']!=1 or obs['kind']!='check-observation' or obs['oracle_id']!=plan['check']['oracle_id'] or obs['oracle_version']!=1 or not _valid_projection(plan,cid,obs['projection'],results[cid]):return ['invalid_check_projection']
                if obs['limitations']!=['Projection from omitted raw response is signer-attested; local signatures do not authenticate the remote response.']:return ['check_projection_limitations_mismatch']
                projections[cid]=obs['projection']
            if set(projections)!=expected_ids:return ['missing_check_observation']
            expected=[_finding(plan,spec['target_case'],_decision(plan,projections,results),list(spec['controls']),[o['observation_digest'] for o in execution['observations']])]
        else:
            if set(execution)!={'schema_version','kind','execution_id','plan','adapter_execution','observations','findings','budget_ledger','reproducer','coverage','credential_bindings','execution_digest'}:return ['unexpected_check_execution_fields']
            child=execution['adapter_execution'];verifier=verify_execution if plan['check']['adapter']=='contrast' else verify_workflow
            if verifier(child) or child['plan']!=plan['adapter_plan']:return ['invalid_adapter_execution']
            if execution['observations']!=child.get('observations',[]):return ['adapter_observations_mismatch']
            expected=_adapter_findings(plan,child)
        if execution['findings']!=expected:return ['check_finding_mismatch']
        coverage={'known_check':plan['check']['check_id'],'planned_findings':len(expected),'evaluated_findings':sum(f['interpretation']!='inconclusive' for f in expected),'unknown_surface':'unknown'}
        if execution['coverage']!=coverage:return ['check_coverage_mismatch']
        # This snapshot may include preceding runs sharing the same context. It
        # must still honestly cover every request represented by this artifact.
        ledger=execution['budget_ledger']
        if not isinstance(ledger,dict) or ledger.get('kind')!='request-budget-ledger' or type(ledger.get('dispatched_total')) is not int or type(ledger.get('approved_total')) is not int or not 0<=ledger['dispatched_total']<=ledger['approved_total']:return ['invalid_check_budget_ledger']
        records=ledger.get('requests',[])
        dispatched=[r for r in records if r['state'] in {'dispatched','finished'}]
        if len({r['sequence'] for r in records})!=len(records) or len(dispatched)!=ledger['dispatched_total'] or sum(ledger['by_kind'].values())!=len(dispatched):return ['check_budget_count_mismatch']
        if any(count!=sum(r['kind']==kind for r in dispatched) for kind,count in ledger['by_kind'].items()):return ['check_budget_kind_mismatch']
        if plan['check']['adapter']!='generic' and ledger!=execution['adapter_execution']['budget_ledger']:return ['adapter_budget_mismatch']
        if plan['check']['adapter']=='generic':
            sent=sum(r.get('duration_ms') is not None and r['outcome']!='inconclusive' for r in execution['report']['results'])
            if ledger['dispatched_total']<sent:return ['check_budget_undercount']
            sent_ids={r['id'] for r in execution['report']['results'] if r['outcome'] in {'pass','fail','error'}}
            if not sent_ids<={r['operation_id'] for r in dispatched}:return ['check_dispatch_witness_missing']
        return []
    except (ValueError,KeyError,TypeError,RecursionError,AttributeError):return ['invalid_check_execution']


def plan_check_retest(baseline,selected_finding_ids=None,*,scope=None):
    if verify_check_execution(baseline):raise DetectionError('invalid_retest_source')
    ids=[f['id'] for f in baseline['findings']]
    selected=ids if selected_finding_ids is None else selected_finding_ids
    if not isinstance(selected,list) or not selected or len(set(selected))!=len(selected) or set(selected)-set(ids):raise DetectionError('invalid_selected_retest_findings')
    spec=copy.deepcopy(baseline['plan']['spec']);check=baseline['plan']['check']
    local=[f['local_id'] for f in baseline['findings'] if f['id'] in selected]
    if check['adapter']=='contrast':
        from .experiments import plan_experiment_retest
        spec['experiment_spec']=plan_experiment_retest(baseline['adapter_execution'],local)['spec']
    elif check['adapter']=='workflow':
        spec['workflow_spec']['variants']=[v for v in spec['workflow_spec']['variants'] if v['id'] in local]
    spec['retest_of']={'execution_digest':baseline['execution_digest'],'plan_digest':baseline['plan']['plan_digest'],'selected_ids':sorted(selected)}
    target_scope=baseline['plan']['scope']
    if scope is not None:
        from .scope import validate_scope
        target_scope=validate_scope(scope)
        if target_scope!=baseline['plan']['scope']:
            spec['retest_of']['source_scope_digest']=baseline['plan']['scope']['scope_digest']
    return compile_check(spec,target_scope)


def compare_check_executions(baseline,current):
    if verify_check_execution(baseline):raise DetectionError('invalid_comparison_baseline')
    if current is not None and verify_check_execution(current):raise DetectionError('invalid_comparison_current')
    if current is not None:
        binding=current['plan']['spec'].get('retest_of',{})
        if binding.get('execution_digest')!=baseline['execution_digest'] or binding.get('plan_digest')!=baseline['plan']['plan_digest']:raise DetectionError('source_bound_retest_required')
        expected=plan_check_retest(baseline,binding.get('selected_ids'),scope=current['plan']['scope'])
        if expected!=current['plan']:raise DetectionError('retest_plan_changed')
    adapter_comparison=None
    if current is not None and baseline['plan']['check']['adapter']=='contrast':
        from .experiments import compare_executions
        adapter_comparison=compare_executions(baseline['adapter_execution'],current['adapter_execution'])
    now={f['id']:f for f in current['findings']} if current else {}
    transitions=[]
    for old in baseline['findings']:
        new=now.get(old['id'])
        status='not_retested'
        if new:
            if new['interpretation']=='inconclusive':status='inconclusive'
            elif new['interpretation']=='violation':status='still_present' if old['interpretation']=='violation' else 'newly_observed'
            elif old['evidence_level']=='confirmed':status='not_reproduced_under_tested_conditions'
            else:status='not_observed'
        if adapter_comparison is not None:
            source=next(f for f in baseline['adapter_execution']['findings'] if f['finding_digest']==old['source_finding'])
            status=next(t['status'] for t in adapter_comparison['transitions'] if t['finding_id']==source['id'])
        transitions.append({'finding_id':old['id'],'status':status,'baseline_finding_digest':old['finding_digest'],'current_finding_digest':new['finding_digest'] if new else None})
    return seal('check-comparison',{'schema_version':1,'kind':'check-comparison','baseline_execution_digest':baseline['execution_digest'],
                'current_execution_digest':current['execution_digest'] if current else None,'transitions':transitions,'adapter_comparison':adapter_comparison,
                'coverage':{'selected':sum(t['status']!='not_retested' for t in transitions),'not_retested':sum(t['status']=='not_retested' for t in transitions)},
                'limitations':['A negative result applies only to the retested fixture, operation, identities and rule version.']},'comparison_digest')
