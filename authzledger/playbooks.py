"""Static, explicitly scoped playbooks over existing discovery/check services.

A playbook composes already reviewed immutable plans. It never substitutes
captured values into another step, expands scope, imports executable plugins,
or invokes a shell. One shared ExecutionContext accounts for every request.
"""
from __future__ import annotations

import copy
import threading
import uuid

from .credentials import CredentialResolver
from .detectors import execute_check, verify_check_execution, verify_check_plan
from .discovery import execute_discovery, verify_discovery, verify_discovery_plan
from .execution import ExecutionContext
from .model import _identifier
from .oracles import digest, seal
from .scope import validate_scope, context_for_scope


class PlaybookError(ValueError):
    pass


_PLAN_VERIFIERS={'check-plan':verify_check_plan,'discovery-plan':verify_discovery_plan}
_EXECUTION_VERIFIERS={'check-execution':verify_check_execution,'discovery-execution':verify_discovery}
_LIMITATIONS=[
    'Only predefined approved steps run; discovery results never create new active steps.',
    'Scope and authorization are operator declarations, not proof of target ownership.',
    'Unavailable controls or inconclusive observations stop all later active steps.',
    'This recipe reuses existing controlled checks and reproducers; it is not an autonomous exploitation engine.',
]


def plan_playbook(scope, steps):
    """Freeze ordered {id, plan, requires:[earlier ids]} steps without I/O."""
    scoped=validate_scope(scope)
    if not isinstance(steps,list) or not 1<=len(steps)<=32:
        raise PlaybookError('playbook_requires_one_to_32_explicit_steps')
    seen=set();normalized=[];upper=0;cleanup=0;effects=set()
    for raw in steps:
        if not isinstance(raw,dict) or set(raw)-{'id','plan','requires'} or {'id','plan'}-set(raw):
            raise PlaybookError('invalid_playbook_step_fields')
        _identifier(raw['id'],'playbook step id')
        if raw['id'] in seen:raise PlaybookError('duplicate_playbook_step')
        requires=raw.get('requires',[])
        if not isinstance(requires,list) or any(not isinstance(v,str) for v in requires) or len(set(requires))!=len(requires) or not set(requires)<=seen:
            raise PlaybookError('dependencies_must_reference_distinct_earlier_steps')
        plan=raw['plan'];kind=plan.get('kind') if isinstance(plan,dict) else None
        verifier=_PLAN_VERIFIERS.get(kind)
        if verifier is None or verifier(plan):raise PlaybookError('invalid_or_unsupported_step_plan')
        if plan['scope']!=scoped:raise PlaybookError('playbook_step_scope_mismatch')
        cap=plan['request_upper_bound']
        if type(cap) is not int or cap<=0:raise PlaybookError('invalid_step_budget')
        upper+=cap
        if kind=='check-plan':
            effects.update(plan['check']['effects'])
            # Manifest families do not prove an operation is read-only. Include
            # the explicitly authorized effect of every matching source request.
            requests={(plan['contract']['target'],case['method'],case['path']) for case in plan['contract']['cases']}
            effects.update(op['effect'] for op in scoped['operations'] if (op['origin'],op['method'],op['path']) in requests)
            if plan['check']['adapter']=='workflow':cleanup+=plan['adapter_plan']['cleanup_reserve']
        else:effects.update(plan['effects'])
        normalized.append({'id':raw['id'],'requires':sorted(requires),'plan':copy.deepcopy(plan),
                           'plan_digest':plan['plan_digest'],'request_upper_bound':cap})
        seen.add(raw['id'])
    if upper>scoped['limits']['max_requests']:raise PlaybookError('playbook_total_exceeds_scope_budget')
    if not effects<=set(scoped['allowed_effects']):raise PlaybookError('playbook_effect_not_authorized')
    value={'schema_version':1,'kind':'playbook-plan','scope':scoped,'scope_digest':scoped['scope_digest'],
           'steps':normalized,'request_upper_bound':upper,'cleanup_reserve':cleanup,'effects':sorted(effects),
           'execution_policy':'ordered-stop-on-inconclusive','dynamic_chaining':False,
           'approval_required':'exact_plan_digest','limitations':list(_LIMITATIONS)}
    return seal('playbook-plan',value,'plan_digest')


def verify_playbook_plan(plan):
    try:
        steps=[{k:step[k] for k in ('id','plan','requires')} for step in plan['steps']]
        return [] if plan_playbook(plan['scope'],steps)==plan else ['playbook_plan_mismatch']
    except (ValueError,KeyError,TypeError,RecursionError,AttributeError):return ['invalid_playbook_plan']


def _execution_reason(child):
    if child['kind']=='check-execution':
        if any(f['interpretation']=='inconclusive' for f in child['findings']):return 'controls_or_observations_inconclusive'
        return 'step_completed'
    if child['coverage']['inconclusive_ids']:return 'discovery_inconclusive'
    return 'step_completed'


def _child_ledger(child):
    return child['ledger'] if child['kind']=='discovery-execution' else child['budget_ledger']


def _validate_ledger(value):
    if not isinstance(value,dict) or value.get('kind')!='request-budget-ledger':return False
    if type(value.get('approved_total')) is not int or type(value.get('dispatched_total')) is not int or not 0<=value['dispatched_total']<=value['approved_total']:return False
    records=value.get('requests')
    if not isinstance(records,list) or any(not isinstance(r,dict) or type(r.get('sequence')) is not int for r in records):return False
    if len({r['sequence'] for r in records})!=len(records):return False
    sent=[r for r in records if r['state'] in {'dispatched','finished'}]
    kinds=value.get('by_kind')
    return isinstance(kinds,dict) and value['dispatched_total']==len(sent) and sum(kinds.values())==len(sent) and all(n==sum(r['kind']==k for r in sent) for k,n in kinds.items())


def _is_extension(before,after):
    if not _validate_ledger(before) or not _validate_ledger(after):return False
    if before['approved_total']!=after['approved_total'] or after['dispatched_total']<before['dispatched_total']:return False
    old=before['requests'];new=after['requests']
    # Steps are sequential and return after their dispatches finish. Previously
    # completed records must therefore remain byte-for-byte present in order.
    return len(new)>=len(old) and new[:len(old)]==old


def _coverage(steps,ledger_before,ledger):
    return {'planned_steps':len(steps),'completed_steps':sum(s['status']=='completed' for s in steps),
            'not_run_steps':sum(s['status']=='not_run' for s in steps),'error_steps':sum(s['status']=='error' for s in steps),
            'not_run_ids':[s['id'] for s in steps if s['status']=='not_run'],
            'dispatched_requests':ledger['dispatched_total']-ledger_before['dispatched_total'],
            'unknown_total_surface':True}


def execute_playbook(plan, *, context=None, credential_resolver=None, stop_event=None):
    """Execute a preapproved plan; the service layer checks exact digest approval.

    All plans and credential references are validated before the first request.
    Child plans share this one context, including workflow cleanup reservations.
    """
    if verify_playbook_plan(plan):raise PlaybookError('invalid_playbook_plan')
    if stop_event is not None and not isinstance(stop_event,threading.Event):raise PlaybookError('invalid_stop_event')
    resolver=credential_resolver or CredentialResolver()
    # This transient preflight is deliberately non-persistent. Each check still
    # resolves again at execution and runs its fresh identity controls.
    try:
        for step in plan['steps']:
            if step['plan']['kind']=='check-plan':
                resolved=resolver.resolve_contract(step['plan']['contract'])
                resolved.clear()
    except (ValueError,KeyError,TypeError):raise PlaybookError('credential_preflight_failed') from None
    if context is None:
        context=context_for_scope(plan['scope'],max_requests=plan['request_upper_bound'],
                                  cleanup_reserve=plan['cleanup_reserve'],allow_cleanup_after_cancel=bool(plan['cleanup_reserve']))
    if not isinstance(context,ExecutionContext) or getattr(context,'scope_policy',None)!=plan['scope']:
        raise PlaybookError('playbook_context_scope_mismatch')
    before=context.snapshot()
    if not _validate_ledger(before):raise PlaybookError('invalid_shared_context_ledger')
    available=before['approved_total']-before['dispatched_total']
    if available!=plan['request_upper_bound'] or before['reserved_pending'] or before['leased_pending']:
        raise PlaybookError('playbook_requires_exact_remaining_shared_budget')
    if context.cleanup_reserve<plan['cleanup_reserve']:raise PlaybookError('playbook_cleanup_reserve_required')
    if stop_event is not None:context.add_stop_event(stop_event)
    halted=None;steps=[]
    for step in plan['steps']:
        if halted is None and context.snapshot()['cancelled']:halted='cancelled'
        record={'id':step['id'],'requires':step['requires'],'plan_digest':step['plan_digest'],
                'status':'not_run','reason':halted or 'not_started','execution':None,
                'ledger_before':context.snapshot(),'ledger_after':None}
        if halted is None:
            runner=execute_discovery if step['plan']['kind']=='discovery-plan' else execute_check
            try:
                child=runner(step['plan'],context=context,credential_resolver=resolver)
                if _EXECUTION_VERIFIERS[child['kind']](child):
                    # Never upgrade unverifiable child evidence to findings.
                    record.update(status='error',reason='child_evidence_invalid')
                    halted='prior_step_error'
                else:
                    reason=_execution_reason(child)
                    record.update(status='completed',reason=reason,execution=child)
                    if reason!='step_completed':halted='prior_step_inconclusive'
            except (ValueError,KeyError,TypeError,RuntimeError):
                record.update(status='error',reason='step_execution_error');halted='prior_step_error'
        record['ledger_after']=context.snapshot();steps.append(record)
    ledger=context.snapshot()
    value={'schema_version':1,'kind':'playbook-execution','execution_id':str(uuid.uuid4()),'plan':copy.deepcopy(plan),
           'steps':steps,'ledger_before':before,'budget_ledger':ledger,'coverage':_coverage(steps,before,ledger),
           'limitations':list(_LIMITATIONS)}
    return seal('playbook-execution',value,'execution_digest')


def verify_playbook(value):
    """Replay static sequencing, subexecution verification, and shared accounting."""
    try:
        if isinstance(value,dict) and value.get('kind')=='playbook-plan':return verify_playbook_plan(value)
        fields={'schema_version','kind','execution_id','plan','steps','ledger_before','budget_ledger','coverage','limitations','execution_digest'}
        if not isinstance(value,dict) or set(value)!=fields or type(value['schema_version']) is not int or value['schema_version']!=1 or value['kind']!='playbook-execution':return ['invalid_playbook_execution_schema']
        if digest('playbook-execution',value,'execution_digest')!=value['execution_digest']:return ['playbook_execution_digest_mismatch']
        plan=value['plan']
        if verify_playbook_plan(plan):return ['invalid_playbook_plan']
        if value['limitations']!=_LIMITATIONS:return ['playbook_limitations_mismatch']
        if not isinstance(value['steps'],list) or len(value['steps'])!=len(plan['steps']):return ['playbook_step_count_mismatch']
        previous=value['ledger_before']
        if not _validate_ledger(previous) or previous['approved_total']-previous['dispatched_total']!=plan['request_upper_bound']:return ['invalid_playbook_start_budget']
        halted=None
        for recorded,step in zip(value['steps'],plan['steps']):
            if set(recorded)!={'id','requires','plan_digest','status','reason','execution','ledger_before','ledger_after'} or recorded['id']!=step['id'] or recorded['requires']!=step['requires'] or recorded['plan_digest']!=step['plan_digest']:return ['playbook_step_binding_mismatch']
            before,after=recorded['ledger_before'],recorded['ledger_after']
            # Cancellation may change between completed steps; request records
            # and accounting are still the same previous snapshot.
            if not _is_extension(previous,before) or before['requests']!=previous['requests'] or before['dispatched_total']!=previous['dispatched_total'] or not _is_extension(before,after):return ['playbook_shared_ledger_mismatch']
            delta=after['dispatched_total']-before['dispatched_total']
            if not 0<=delta<=step['request_upper_bound']:return ['playbook_step_budget_exceeded']
            if halted is None and before['cancelled']:halted='cancelled'
            if recorded['status']=='not_run':
                if recorded['execution'] is not None or delta or halted is None or recorded['reason']!=halted:return ['invalid_playbook_skip_claim']
            elif recorded['status']=='completed':
                if halted is not None:return ['playbook_continued_after_halt']
                child=recorded['execution'];verifier=_EXECUTION_VERIFIERS.get(child.get('kind'))
                if verifier is None or verifier(child) or child['plan']!=step['plan']:return ['invalid_playbook_child']
                if _child_ledger(child)!=after:return ['playbook_child_budget_reset_or_mismatch']
                if child['kind']=='discovery-execution' and child['ledger_before']!=before:return ['playbook_discovery_start_budget_mismatch']
                reason=_execution_reason(child)
                if recorded['reason']!=reason:return ['playbook_continuation_reason_mismatch']
                if reason!='step_completed':halted='prior_step_inconclusive'
            elif recorded['status']=='error':
                if halted is not None or recorded['execution'] is not None or recorded['reason'] not in {'step_execution_error','child_evidence_invalid'}:return ['invalid_playbook_error_claim']
                halted='prior_step_error'
            else:return ['invalid_playbook_step_status']
            previous=after
        if previous!=value['budget_ledger']:return ['playbook_final_ledger_mismatch']
        expected=_coverage(value['steps'],value['ledger_before'],value['budget_ledger'])
        if value['coverage']!=expected or expected['dispatched_requests']>plan['request_upper_bound']:return ['playbook_coverage_mismatch']
        return []
    except (ValueError,KeyError,TypeError,RecursionError,AttributeError):return ['invalid_playbook_execution']
