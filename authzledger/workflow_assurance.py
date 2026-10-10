"""Finite workflow assurance: one executor, one budget, immutable durable traces."""
from __future__ import annotations

import copy
import hashlib
import math
import threading
from datetime import datetime, timezone
from urllib.parse import parse_qsl, unquote

from . import engine
from .credentials import CredentialResolver
from .execution import ExecutionContext
from .history import HistoryError, HistoryStore
from .oracles import canonical, digest, seal
from .workflows import compile_workflow, execute_workflow, verify_workflow


class WorkflowAssuranceError(ValueError):
    pass


def _number(value, label, lower, upper, integer=False):
    if type(value) not in ((int,) if integer else (int, float)) or not lower <= value <= upper or not math.isfinite(value):
        raise WorkflowAssuranceError('invalid_' + label)


def compile_workflow_assurance(spec):
    fields = {'schema_version','kind','workflow','max_cycles','interval_seconds','max_requests_total','max_history_age_seconds'}
    if not isinstance(spec,dict) or set(spec)!=fields or type(spec['schema_version']) is not int or spec['schema_version']!=1 or spec['kind']!='workflow-assurance-spec':
        raise WorkflowAssuranceError('invalid_workflow_assurance_spec')
    _number(spec['max_cycles'],'max_cycles',1,100,True)
    _number(spec['interval_seconds'],'interval_seconds',0,3600)
    _number(spec['max_requests_total'],'max_requests_total',1,100000,True)
    _number(spec['max_history_age_seconds'],'max_history_age_seconds',0,31536000)
    workflow = compile_workflow(spec['workflow'])
    per_cycle = workflow['request_upper_bound']
    budget_cycles = min(spec['max_cycles'],spec['max_requests_total']//per_cycle)
    if budget_cycles < 1:
        raise WorkflowAssuranceError('first_cycle_exceeds_global_budget')
    normalized = copy.deepcopy(spec); normalized['workflow']=copy.deepcopy(workflow['spec'])
    source=workflow['spec']; setup=next(c for c in source['contract']['cases'] if c['id']==source['setup']['case_id'])
    scope={'target':source['contract']['target'],'setup_method':setup['method'],'setup_path':setup['path'],
           'fixture_pointer':source['fixture']['pointer'],'fixture_type':source['fixture']['type']}
    plan={'schema_version':1,'kind':'workflow-assurance-plan','spec':normalized,'workflow_plan':workflow,
          'scope_key':digest('workflow-fixture-scope',scope),'cycle_request_upper_bound':per_cycle,
          'budget_cycles':budget_cycles,'request_upper_bound':budget_cycles*per_cycle,
          'cleanup_reserve':budget_cycles*workflow['cleanup_reserve']}
    return seal('workflow-assurance-plan',plan,'plan_digest')


def _verify_plan(plan):
    try:
        return canonical(compile_workflow_assurance(plan['spec']))==canonical(plan)
    except (ValueError,TypeError,KeyError,RecursionError):
        return False


def _fixture_tokens(trace):
    """Recover non-secret fixture IDs already retained in materialized requests.

    This is cross-cycle isolation bookkeeping, not a claim that body digests
    independently reveal the remote setup response.
    """
    spec=trace['plan']['spec']; fixture=spec['fixture']; before=spec['precondition']
    bindings=[b for b in before['bindings'] if b['source_step']==fixture['source_step'] and b.get('pointer')==fixture['pointer']]
    tokens=set()
    for variant in trace['variants']:
        record=next((r for r in variant['steps'] if r['step_id']==before['id']),None)
        if record is None: continue
        case=record['contract']['cases'][0]
        values=[]
        for binding in bindings:
            target=binding['target']
            if target['kind']=='path_segment': value=unquote(case['path'].partition('?')[0].split('/')[target['index']])
            elif target['kind']=='query':
                selected=[v for k,v in parse_qsl(case['path'].partition('?')[2],keep_blank_values=True) if k==target['name']]
                value=selected[target['occurrence']]
            elif target['kind']=='header': value=case['headers'][target['name']]
            else: value=engine._pointer(case.get('body'),target['pointer'])
            if fixture['type']=='integer' and isinstance(value,str): value=int(value)
            if type(value) is not (str if fixture['type']=='string' else int):
                raise WorkflowAssuranceError('retained_fixture_binding_invalid')
            values.append(value)
        if not values or any(not engine._json_equal(value,values[0]) for value in values[1:]):
            raise WorkflowAssuranceError('retained_fixture_binding_ambiguous')
        tokens.add(canonical(values[0]))
    return tokens


def _fresh(records,max_age):
    if not records: return
    try:
        timestamp=datetime.fromisoformat(records[-1]['created_at'].replace('Z','+00:00'))
        if timestamp.tzinfo is None: raise ValueError
        age=(datetime.now(timezone.utc)-timestamp.astimezone(timezone.utc)).total_seconds()
        if age < -5 or age > max_age: raise ValueError
    except (ValueError,TypeError,KeyError):
        raise WorkflowAssuranceError('stale_workflow_history') from None


def _cycle_status(trace):
    variants=trace['variants']
    if any(v['cleanup']=='cleanup_pending' for v in variants): return 'inconclusive',2,'cleanup_pending'
    if len(variants)!=len(trace['plan']['variants']) or any(v['interpretation']=='inconclusive' for v in variants):
        return 'inconclusive',2,'inconclusive_workflow'
    if any(v['interpretation']=='violation' for v in variants): return 'violation',1,'workflow_violation'
    return 'satisfied',0,None


def run_workflow_assurance(plan,*,history,context=None,credential_resolver=None,stop_event=None,on_cycle=None):
    if not _verify_plan(plan): raise WorkflowAssuranceError('invalid_workflow_assurance_plan')
    if not isinstance(history,HistoryStore): raise WorkflowAssuranceError('durable_history_required')
    if stop_event is not None and not isinstance(stop_event,threading.Event): raise WorkflowAssuranceError('invalid_stop_event')
    if on_cycle is not None and not callable(on_cycle): raise WorkflowAssuranceError('invalid_cycle_callback')
    spec=plan['spec']; workflow=plan['workflow_plan']; contract=workflow['spec']['contract']
    event=stop_event or threading.Event()
    resolver=credential_resolver or CredentialResolver()
    # History validation, scope/fixture checks and credential presence are offline.
    before=history.workflow_snapshot(plan['scope_key']); _fresh(before['records'],spec['max_history_age_seconds'])
    seen=set()
    for record in before['records']: seen.update(_fixture_tokens(record['trace']))
    resolver.resolve_contract(contract)
    fixture_history={'scope_key':plan['scope_key'],'known_fixture_sha256':sorted(hashlib.sha256(value).hexdigest() for value in seen),
                     'source_record_sha256':[record['record_sha256'] for record in before['records']]}
    if context is not None and context.max_requests!=spec['max_requests_total']:
        raise WorkflowAssuranceError('shared_context_budget_mismatch')
    if context is None:
        context=ExecutionContext(spec['max_requests_total'],[contract['target']],contract['limits']['timeout_seconds'],
                                 1,cleanup_reserve=plan['cleanup_reserve'],allow_cleanup_after_cancel=True,stop_event=event)
    else: context.add_stop_event(event)
    started=engine._utc(); cycles=[]; status,exit_code,reason='satisfied',0,'cycle_limit'
    anchors={key:before[key] for key in ('runs_root_sha256','workflow_root_sha256')}
    current_workflow_root=anchors['workflow_root_sha256']
    normal=plan['cycle_request_upper_bound']-workflow['cleanup_reserve']
    for cycle in range(1,spec['max_cycles']+1):
        if event.is_set() or context.snapshot()['cancelled']:
            status,exit_code,reason='cancelled',2,'cancelled'; break
        # Revalidate persisted history and age before each new cycle, not just
        # before a whole watch. Concurrent writers invalidate this reviewed tail.
        try: snapshot=history.workflow_snapshot(plan['scope_key'])
        except HistoryError:
            status,exit_code,reason='error',2,'history_integrity_failed'; break
        if snapshot['workflow_root_sha256']!=current_workflow_root or snapshot['runs_root_sha256']!=anchors['runs_root_sha256']:
            status,exit_code,reason='error',2,'history_changed'; break
        try: _fresh(snapshot['records'],spec['max_history_age_seconds'])
        except WorkflowAssuranceError:
            status,exit_code,reason='error',2,'stale_workflow_history'; break
        if cycle>plan['budget_cycles'] or context.remaining()<normal or context.remaining('cleanup')<workflow['cleanup_reserve']:
            status,exit_code,reason='inconclusive',2,'request_budget'; break
        trace=execute_workflow(workflow,context=context,credential_resolver=resolver,fixture_registry=seen)
        if verify_workflow(trace): raise WorkflowAssuranceError('invalid_workflow_execution')
        cycle_status,cycle_exit,cycle_reason=_cycle_status(trace)
        item={'cycle':cycle,'trace':trace,'history':None,'status':cycle_status,'stop_reason':cycle_reason}
        cycles.append(item)
        try:
            item['history']=history.append_workflow(trace,assurance_plan_digest=plan['plan_digest'],scope_key=plan['scope_key'],cycle=cycle,
                expected_previous_sha256=current_workflow_root,expected_runs_root_sha256=anchors['runs_root_sha256'])
            current_workflow_root=item['history']['record_sha256']
        except HistoryError:
            status,exit_code,reason='error',2,'history_persistence_failed'; break
        if on_cycle is not None: on_cycle(cycle,copy.deepcopy(item))
        if event.is_set() or context.snapshot()['cancelled']:
            status,exit_code,reason='cancelled',2,'cancelled'; break
        if cycle_exit:
            status,exit_code,reason=cycle_status,cycle_exit,cycle_reason; break
        if cycle<spec['max_cycles'] and event.wait(spec['interval_seconds']):
            status,exit_code,reason='cancelled',2,'cancelled'; break
    value={'schema_version':1,'kind':'workflow-assurance-result','plan':copy.deepcopy(plan),'cycles':cycles,
           'completed_cycles':len(cycles),'status':status,'exit_code':exit_code,'stop_reason':reason,
           'budget_ledger':context.snapshot(),'started_at':started,'finished_at':engine._utc(),'history_before':anchors,'fixture_history':fixture_history,
           'limitations':['Finite explicitly approved cycles only; intervals are unobserved.',
                          'Workflow state conclusions are signer-attested; raw response bodies are not retained.',
                          'Workflow history uses a separate additive hash chain; original v1 run rows are unchanged.',
                          'Initial fixture registry is bound to retained local history anchors; previous full history is not embedded.',
                          'Local clocks and complete replacement of all history anchors are not independently trusted.']}
    return seal('workflow-assurance-result',value,'assurance_digest')


def verify_workflow_assurance(result):
    try:
        fields={'schema_version','kind','plan','cycles','completed_cycles','status','exit_code','stop_reason','budget_ledger','started_at','finished_at','history_before','fixture_history','limitations','assurance_digest'}
        if not isinstance(result,dict) or set(result)!=fields or type(result['schema_version']) is not int or result['schema_version']!=1 or result['kind']!='workflow-assurance-result': return ['invalid_workflow_assurance_result']
        if digest('workflow-assurance-result',result,'assurance_digest')!=result['assurance_digest'] or not _verify_plan(result['plan']): return ['invalid_assurance_digest_or_plan']
        cycles=result['cycles']; plan=result['plan']
        if type(result['completed_cycles']) is not int or result['completed_cycles']!=len(cycles) or len(cycles)>plan['spec']['max_cycles']: return ['invalid_cycle_count']
        previous=result['history_before']['workflow_root_sha256']
        registry=result['fixture_history']
        if set(registry)!={'scope_key','known_fixture_sha256','source_record_sha256'} or registry['scope_key']!=plan['scope_key']: return ['invalid_fixture_history_scope']
        for field in ('known_fixture_sha256','source_record_sha256'):
            if not isinstance(registry[field],list) or len(set(registry[field]))!=len(registry[field]) or any(not isinstance(v,str) or len(v)!=64 or any(c not in '0123456789abcdef' for c in v) for v in registry[field]): return ['invalid_fixture_history_anchors']
        seen=set(registry['known_fixture_sha256']); prior_requests=[]
        for index,item in enumerate(cycles):
            if set(item)!={'cycle','trace','history','status','stop_reason'} or item['cycle']!=index+1 or verify_workflow(item['trace']): return ['invalid_cycle_trace']
            if item['trace']['plan']!=plan['workflow_plan']: return ['cycle_plan_mismatch']
            cycle_ledger=item['trace']['budget_ledger']
            if cycle_ledger['approved_total']!=plan['spec']['max_requests_total'] or cycle_ledger['requests'][:len(prior_requests)]!=prior_requests: return ['cycle_budget_reset_or_scope_change']
            prior_requests=cycle_ledger['requests']
            tokens=_fixture_tokens(item['trace'])
            token_hashes={hashlib.sha256(token).hexdigest() for token in tokens}
            if token_hashes & seen: return ['reused_fixture_across_cycles_or_retained_history']
            seen.update(token_hashes)
            status,code,reason=_cycle_status(item['trace'])
            if (item['status'],item['stop_reason'])!=(status,reason): return ['cycle_status_mismatch']
            if code and index<len(cycles)-1: return ['unsafe_next_cycle']
            row=item['history']
            if row is None:
                if index!=len(cycles)-1 or result['stop_reason']!='history_persistence_failed': return ['missing_cycle_history']
            else:
                if set(row)!={'id','created_at','previous_sha256','record_sha256','workflow_digest','scope_key','cycle'} or type(row['id']) is not int or row['id']<1 or row['scope_key']!=plan['scope_key'] or row['cycle']!=index+1: return ['invalid_history_receipt']
                from .history import _workflow_digest
                context={'schema_version':1,'kind':'workflow-assurance-cycle','assurance_plan_digest':plan['plan_digest'],
                         'scope_key':plan['scope_key'],'cycle':index+1,'trace':item['trace']}
                envelope={'schema_version':1,'id':row['id'],'created_at':row['created_at'],'previous_sha256':previous,'context':context}
                if row['previous_sha256']!=previous or row['record_sha256']!=_workflow_digest(envelope) or row['workflow_digest']!=item['trace']['workflow_digest']: return ['history_anchor_mismatch']
                previous=row['record_sha256']
        ledger=result['budget_ledger']
        if cycles:
            before_ledger=cycles[-1]['trace']['budget_ledger']
            keys={'approved_total','dispatched_total','reserved_pending','leased_pending','remaining','cleanup_remaining','by_kind','requests'}
            if any(before_ledger.get(key)!=ledger.get(key) for key in keys): return ['final_budget_mismatch']
        if ledger['approved_total']!=plan['spec']['max_requests_total'] or type(ledger['dispatched_total']) is not int or not 0<=ledger['dispatched_total']<=plan['spec']['max_requests_total']: return ['global_budget_exceeded']
        allowed={'cycle_limit':('satisfied',0),'request_budget':('inconclusive',2),'cancelled':('cancelled',2),
                 'history_changed':('error',2),'history_integrity_failed':('error',2),'stale_workflow_history':('error',2),'history_persistence_failed':('error',2),
                 'cleanup_pending':('inconclusive',2),'inconclusive_workflow':('inconclusive',2),'workflow_violation':('violation',1)}
        if result['stop_reason'] not in allowed or (result['status'],result['exit_code'])!=allowed[result['stop_reason']]: return ['invalid_assurance_status']
        if result['stop_reason']=='cycle_limit' and (len(cycles)!=plan['spec']['max_cycles'] or any(item['status']!='satisfied' for item in cycles)): return ['unearned_assurance_success']
        if result['stop_reason'] in {'workflow_violation','inconclusive_workflow','cleanup_pending'} and (not cycles or cycles[-1]['stop_reason']!=result['stop_reason']): return ['unbound_assurance_failure']
        return []
    except (ValueError,TypeError,KeyError,IndexError,RecursionError,AttributeError): return ['invalid_workflow_assurance_result']
