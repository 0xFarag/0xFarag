"""Local revision control and explanatory, dependency-closed impact selection."""
from __future__ import annotations
import copy
import threading
import uuid
from .assurance import retest_plan
from .model import load_contract, contract_digest
from .oracles import canonical, seal

class AssessmentError(ValueError):
    pass

class RevisionConflict(AssessmentError):
    pass

class AssessmentStore:
    """Memory-only editing state; callers explicitly export immutable snapshots."""
    def __init__(self):
        self._lock=threading.RLock(); self._items={}
    def create(self, specification):
        from .experiments import compile_experiment
        plan=compile_experiment(specification)
        with self._lock:
            aid=str(uuid.uuid4())
            value=seal('assessment-revision',{'schema_id':'authzledger.assessment','schema_version':1,'kind':'assessment-revision','id':aid,'revision':1,'spec':copy.deepcopy(plan['spec']),'plan_digest':plan['plan_digest']},'revision_digest')
            self._items[aid]=value
            return copy.deepcopy(value)
    def get(self, assessment_id):
        with self._lock:
            if assessment_id not in self._items: raise AssessmentError('unknown_assessment')
            return copy.deepcopy(self._items[assessment_id])
    def revise(self, assessment_id, specification, *, expected_revision):
        from .experiments import compile_experiment
        plan=compile_experiment(specification)
        with self._lock:
            current=self.get(assessment_id)
            if type(expected_revision) is not int or expected_revision!=current['revision']: raise RevisionConflict('assessment_revision_conflict')
            value=seal('assessment-revision',{'schema_id':'authzledger.assessment','schema_version':1,'kind':'assessment-revision','id':assessment_id,'revision':current['revision']+1,'spec':copy.deepcopy(plan['spec']),'plan_digest':plan['plan_digest']},'revision_digest')
            self._items[assessment_id]=value
            return copy.deepcopy(value)

def plan_impacted_retest(source_contract, changes, impact_map=None):
    """Unknown dependencies select the full scope, never an optimistic subset."""
    source=load_contract(source_contract,allow_mutations=True); cases={c['id']:c for c in source['cases']}
    if not isinstance(changes,list) or not changes or len(changes)>1000: raise AssessmentError('nonempty_changes_required')
    impact_map={} if impact_map is None else impact_map
    if not isinstance(impact_map,dict) or any(not isinstance(k,str) or not isinstance(v,list) or any(cid not in cases for cid in v) for k,v in impact_map.items()): raise AssessmentError('invalid_impact_map')
    reasons={}; unknown=[]
    allowed={'rule','case','identity_binding','fixture','policy','oracle','normalizer','source'}
    for change in changes:
        if not isinstance(change,dict) or set(change)!={'kind','id','before_digest','after_digest'} or change['kind'] not in allowed or not isinstance(change['id'],str): raise AssessmentError('invalid_change')
        for key in ('before_digest','after_digest'):
            value=change[key]
            if value is not None and (not isinstance(value,str) or len(value)!=64 or any(c not in '0123456789abcdef' for c in value)): raise AssessmentError('invalid_change_digest')
        if change['before_digest']==change['after_digest']: continue
        ref=change['kind']+':'+change['id']; affected=impact_map.get(ref)
        if change['kind']=='case' and change['id'] in cases: affected=[change['id']]
        if not affected: unknown.append(ref); continue
        for cid in affected: reasons.setdefault(cid,[]).append({'reason_code':'changed_'+change['kind'],'source_refs':[ref]})
    if unknown:
        for cid in cases: reasons.setdefault(cid,[]).append({'reason_code':'unknown_dependency_full_scope','source_refs':sorted(set(unknown))})
    changed=set(reasons)
    while True:
        added={cid for cid,c in cases.items() if cid not in reasons and set(c['requires']) & set(reasons)}
        if not added: break
        for cid in sorted(added): reasons[cid]=[{'reason_code':'dependent_on_changed_case','source_refs':sorted(set(cases[cid]['requires']) & set(reasons))}]
    if not reasons:
        return seal('impact-retest-plan',{'schema_version':1,'kind':'impact-retest-plan','source_contract_digest':contract_digest(source),'changes':copy.deepcopy(changes),'selected_ids':[],'dependency_ids':[],'not_retested_ids':list(cases),'reasons':{},'request_upper_bound':0,'unknown_dependencies':[],'limitations':['Only declared dependencies are modeled.']},'plan_digest')
    plan=retest_plan(source,list(reasons),allow_mutations=True)
    for cid in plan['dependency_ids']:
        reasons[cid]=[{'reason_code':'required_control','source_refs':sorted(k for k in plan['selected_ids'] if cid in _dependencies(cases,k))}]
    for refs in reasons.values(): refs.sort(key=lambda r:(r['reason_code'],r['source_refs']))
    result={'schema_version':1,'kind':'impact-retest-plan','source_contract_digest':contract_digest(source),'changes':sorted(copy.deepcopy(changes),key=lambda c:(c['kind'],c['id'])),'selected_ids':plan['selected_ids'],'dependency_ids':plan['dependency_ids'],'not_retested_ids':[cid for cid in cases if cid not in reasons], 'reasons':reasons,'request_upper_bound':plan['request_count'],'unknown_dependencies':sorted(set(unknown)), 'contract':plan['contract'],'limitations':['Only declared dependencies are modeled.','Unknown dependencies require the full approved scope; insufficient global budget blocks execution.']}
    return seal('impact-retest-plan',result,'plan_digest')

def _dependencies(cases,cid):
    found=set(); pending=list(cases[cid]['requires'])
    while pending:
        key=pending.pop()
        if key not in found: found.add(key); pending.extend(cases[key]['requires'])
    return found

def freeze_assessment(*args,**kwargs):
    from .assessment_reports import freeze_assessment as freeze
    return freeze(*args,**kwargs)

def verify_snapshot(snapshot):
    from .assessment_reports import verify_assessment
    return verify_assessment(snapshot)

def build_evidence_graph(execution):
    """A separate provenance graph; v1 intent/policy/observation graph is untouched."""
    from .experiments import verify_execution
    if verify_execution(execution): raise AssessmentError('invalid_execution')
    plan=execution['plan']; root=execution['report']['evidence']['root_sha256']; nodes=[]; edges=[]
    def node(identifier,kind,reference):
        if not any(n['id']==identifier for n in nodes): nodes.append({'id':identifier,'kind':kind,'reference':reference})
    def edge(source,target,relation):
        value={'source':source,'target':target,'relation':relation}
        if value not in edges: edges.append(value)
    rule='rule:'+plan['rule_digest']; experiment='experiment:'+plan['plan_digest']
    node(rule,'rule',plan['rule_digest']);node(experiment,'experiment',plan['plan_digest']);edge(experiment,rule,'evaluates')
    cases={c['id']:c for c in execution['contract']['cases']}
    for obs in execution['observations']:
        oid='observation:'+obs['observation_digest'];node(oid,'observation',obs['observation_digest']);edge(oid,experiment,'produced_by')
        for cid in obs['control_refs']:
            control='control:'+root+':'+cid;node(control,'control',{'report_root':root,'case_id':cid});edge(oid,control,'requires')
            for ancestor in cases[cid]['requires']:
                aid='control:'+root+':'+ancestor;node(aid,'control',{'report_root':root,'case_id':ancestor});edge(control,aid,'requires')
    for finding in execution['findings']:
        fid='finding:'+finding['finding_digest'];node(fid,'finding',finding['finding_digest'])
        for ref in finding['evidence_refs']:edge(fid,'observation:'+ref,'supported_by')
    result={'schema_id':'authzledger.evidence-graph','schema_version':1,'kind':'evidence-graph','execution_digest':execution['execution_digest'],'nodes':sorted(nodes,key=lambda n:n['id']),'edges':sorted(edges,key=lambda e:(e['source'],e['target'],e['relation'])),'limitations':['Provenance graph is separate from intended access, evaluated policy and observed access.','Unmodeled data and code dependencies remain unknown.']}
    return seal('evidence-graph',result,'graph_digest')

def verify_evidence_graph(graph,execution):
    try:return [] if canonical(graph)==canonical(build_evidence_graph(execution)) else ['evidence_graph_mismatch']
    except (ValueError,TypeError,KeyError,RecursionError):return ['invalid_evidence_graph']

def inspect_finding(execution,finding_id):
    from .experiments import verify_execution
    if verify_execution(execution):raise AssessmentError('invalid_execution')
    finding=next((f for f in execution['findings'] if f['id']==finding_id),None)
    if finding is None:raise AssessmentError('unknown_finding')
    observations=[o for o in execution['observations'] if o['observation_digest'] in finding['evidence_refs']]
    return {'finding':copy.deepcopy(finding),'rule':copy.deepcopy(execution['plan']['rule']),
            'identity_binding':copy.deepcopy(execution['plan']['spec']['identity_bindings'].get(finding['identity'])),
            'controls':[copy.deepcopy(r) for r in execution['report']['results'] if r['id'] in finding['control_refs']],
            'observations':copy.deepcopy(observations),'plan_digest':execution['plan']['plan_digest'],
            'report_root':execution['report']['evidence']['root_sha256'],'budget_ledger':copy.deepcopy(execution['budget_ledger']),
            'evidence_graph':build_evidence_graph(execution)}
