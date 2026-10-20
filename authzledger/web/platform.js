"use strict";
// The existing authenticated Studio session owns all state. No browser storage.
const platform = {id:null, record:null, registry:null, review:null, plan:null, operation:null,
 artifact:null, selected:null, snapshot:null, job:null, busy:false, revision:0, loaded:false,loadSequence:0};

function pInvalidate(){
 platform.revision++;platform.review=null;platform.plan=null;platform.snapshot=null;
 $('p-approved').checked=false;$('p-run').disabled=true;$('p-schedule').disabled=true;$('p-review').hidden=true;
 document.querySelectorAll('[data-platform-export]').forEach(b=>b.disabled=true);$('p-proof').disabled=true;
 for(const id of ['p-annotation-finding','p-annotation-save','p-annotations-apply'])$(id).disabled=true;
 $('p-report-status').textContent='The assessment changed. Freeze its current retained evidence before export.';
}
function pPage(name){
 assessmentStep('platform');document.querySelectorAll('.platform-page').forEach(n=>n.classList.toggle('active',n.id==='p-'+name));
 document.querySelectorAll('[data-platform-page]').forEach(n=>{if(n.dataset.platformPage===name)n.setAttribute('aria-current','step');else n.removeAttribute('aria-current');});
 pContext();
}
function pContext(){
 const a=platform.record?.assessment, node=$('p-context');node.replaceChildren();
 node.append(element('strong',a?a.title:'No assessment selected'),element('small',a?
   'Revision '+a.revision+' · '+a.scope.origins.join(', ')+' · '+a.scope.limits.max_requests+' requests per execution · Expires '+a.scope.expires_at:
   'Set explicit scope before making any target requests.'));
 if(a&&$('a-platform').classList.contains('active')){
  $('a-context-title').textContent=a.title;$('a-context-origin').textContent=a.scope.origins.join(', ');
  $('a-context-count').textContent=(platform.record.artifacts?.length||0)+' retained artifacts';
  $('a-context-meta').textContent='Assessment '+a.id+' · Revision '+a.revision+' · '+(platform.job?'Job '+platform.job:'Idle')+' · Scope '+a.scope.scope_digest.slice(0,12);
 }
}
function pRequire(){if(!platform.id)throw Error('Create or select an authorized assessment first.');return platform.id;}
function pRow(title,detail,status,action){
 const button=element('button',undefined,'platform-row'),copy=element('div');button.type='button';
 copy.append(element('strong',title),element('small',detail));button.append(copy,element('span',status,'badge'));
 button.onclick=()=>{button.parentNode.querySelectorAll('[aria-selected]').forEach(n=>n.removeAttribute('aria-selected'));button.setAttribute('aria-selected','true');action();};return button;
}
function pInspect(title,subtitle,value){aInspect(title,subtitle,value);}
function pRenderRegistry(){
 const select=$('p-profile'),old=select.value;select.replaceChildren();
 for(const name of Object.keys(platform.registry?.profiles||{})){const option=element('option',name);option.value=name;select.append(option);}
 select.value=[...select.options].some(n=>n.value===old)?old:'web-quick';pRenderChecks();
}
function pRenderChecks(){
 const keys=platform.registry?.profiles?.[$('p-profile').value]||[],previous=$('p-check').value,select=$('p-check');select.replaceChildren();
 for(const check of platform.registry?.checks||[])if(keys.includes(check.check_id)){
  const option=element('option',check.title+' · '+check.version);option.value=check.check_id;select.append(option);
 }
 select.value=[...select.options].some(n=>n.value===previous)?previous:(keys.includes('misconfig.security_headers')?'misconfig.security_headers':keys[0]||'');pCheckDescription();
}
function pCheckDescription(){
 const check=platform.registry?.checks?.find(c=>c.check_id===$('p-check').value);if(!check)return;
 $('p-check-description').textContent=check.title+' · Evidence ceiling: '+check.evidence_ceiling+'. '+(check.limitations||[]).join(' ');
 $('p-header-options').hidden=check.check_id!=='misconfig.security_headers';$('p-check-build').disabled=check.check_id!=='misconfig.security_headers';$('p-use-contrast').disabled=check.adapter!=='contrast';$('p-use-workflow').disabled=check.adapter!=='workflow';
 pInspect(check.title,'Versioned check manifest',{Version:check.version,'Evidence ceiling':check.evidence_ceiling,Controls:check.required_controls,Limitations:check.limitations,'Rule digest':check.rule_digest});
}
async function pRefresh(selectId=platform.id){
 const revision=platform.revision,response=await api('/api/platform');if(revision!==platform.revision)return;platform.loaded=true;platform.registry=response.capabilities.checks;
 $('p-storage').textContent=response.storage==='persistent'?'Persistent local assessment history is enabled. Credentials remain session-only.':'Session-only assessment history: export evidence before closing this Studio server. No background persistence is implied.';
 const select=$('p-assessment');select.replaceChildren(element('option','Choose an assessment'));select.firstChild.value='';
 for(const a of response.assessments){const option=element('option',a.title+' · revision '+a.revision);option.value=a.id;select.append(option);}
 select.value=selectId||'';pRenderRegistry();
 const jobs=$('p-job-list');jobs.replaceChildren();for(const job of response.jobs||[])if(job.assessment_id===selectId&&job.state==='running'){
  const button=element('button','Reconnect to '+job.operation+' · '+job.id);button.onclick=guarded(()=>pWatch(job));jobs.append(button);
 }
 if(selectId)await pLoad(selectId);else pContext();
}
function pLocalDate(value){const date=new Date(value);return new Date(date.getTime()-date.getTimezoneOffset()*60000).toISOString().slice(0,16);}
async function pLoad(id){
 const sequence=++platform.loadSequence,record=await api('/api/platform/get',{assessment_id:id});if(sequence!==platform.loadSequence)return;platform.id=id;platform.record=record;$('p-assessment').value=id;
 const a=record.assessment,s=a.scope;$('p-title').value=a.title;$('p-authorization-ref').value=s.authorization_ref;
 $('p-engagement-ref').value=a.engagement?.reference||'';$('p-roe-ref').value=a.engagement?.roe_ref||'';$('p-engagement-notes').value=a.engagement?.notes||'';
 $('p-origin').value=s.origins.find(o=>/^https?:/.test(o))||'';$('p-networks').value=s.allowed_networks.join(', ');
 $('p-expires').value=pLocalDate(s.expires_at);$('p-budget').value=s.limits.max_requests;$('p-timeout').value=s.limits.timeout_seconds;
 $('p-paths').value=[...new Set(s.operations.filter(o=>o.origin===$('p-origin').value&&o.method==='GET').map(o=>o.path))].join('\n');
 $('p-scope-json').value=pretty(s);$('p-source-origin').value=$('p-origin').value;$('p-credential-origin').value=$('p-origin').value;
 $('p-seed-paths').value=$('p-paths').value;$('p-update').disabled=false;
 if(!$('p-check-path').value)$('p-check-path').value=$('p-paths').value.split('\n')[0]||'';
 pContext();pRenderSurface();pRenderEvidence();pRenderPlaybook();
}
function pEngagement(){return Object.fromEntries(Object.entries({reference:$('p-engagement-ref').value.trim(),roe_ref:$('p-roe-ref').value.trim(),notes:$('p-engagement-notes').value.trim()}).filter(([,value])=>value));}
function pAnnotationFields(){
 const row=platform.snapshot?.snapshot.findings.find(f=>f.id===$('p-annotation-finding').value);if(!row)return;
 $('p-annotation-severity').value=row.severity;$('p-annotation-review').value=row.review;
 $('p-annotation-risk').value=row.business_risk==='not_assessed'?'':row.business_risk;$('p-annotation-cvss').value=row.cvss?.vector||'';
 $('p-annotation-rationale').value=row.review_rationale||row.severity_rationale||'';$('p-annotation-included').checked=row.included;$('p-annotation-exclusion').value=row.exclusion_reason||'';
 $('p-annotation-remediation').value=row.remediation||'';$('p-annotation-impact').value=row.impact||'';
 pInspect(row.title,'Source-bound report review',{Record:row.id,'Computed finding':row.status,'Evidence level':row.evidence_level,'Observation references':row.observation_refs,'Retest status':row.retest_status,Review:row.review});
}
function pRenderAnnotations(){
 const select=$('p-annotation-finding');select.replaceChildren();
 for(const row of platform.snapshot?.snapshot.findings||[]){const option=element('option',row.title+' · '+row.status+' · '+row.id);option.value=row.id;select.append(option);}
 const enabled=!!select.options.length;select.disabled=!enabled;$('p-annotation-save').disabled=!enabled;$('p-annotations-apply').disabled=false;
 $('p-annotations-json').value=pretty(platform.record.assessment.finding_annotations||{});pAnnotationFields();
}
async function pSaveAnnotations(annotations){
 await api('/api/platform/annotate',{assessment_id:pRequire(),annotations,expected_revision:platform.record.assessment.revision});pInvalidate();await pRefresh();notify('Reviewer decisions retained. Freeze a new snapshot before export.');
}
function pRenderPlaybook(){
 const list=$('p-playbook-plans');list.replaceChildren();
 for(const artifact of platform.record?.artifacts||[])if(['check-plan','discovery-plan'].includes(artifact.kind)){
  const label=element('label',undefined,'check'),input=element('input');input.type='checkbox';input.dataset.planId=artifact.artifact_id;
  label.append(input,document.createTextNode(artifact.kind+' · '+artifact.artifact_id+' · '+artifact.value.plan_digest.slice(0,12)));list.append(label);
 }
}
function pRenderSurface(){
 const artifacts=platform.record?.artifacts||[],catalogs=artifacts.filter(a=>a.kind==='surface-catalog'),latest=catalogs.at(-1)?.value;
 for(const id of ['p-delta-before','p-delta-after']){const select=$(id);select.replaceChildren();for(const artifact of catalogs){const option=element('option',artifact.artifact_id+' · '+artifact.value.endpoints.length+' endpoints');option.value=artifact.artifact_id;select.append(option);}if(id==='p-delta-after'&&catalogs.length)select.value=catalogs.at(-1).artifact_id;}
 const discoveries=artifacts.filter(a=>a.kind==='discovery-execution').flatMap(a=>a.value.catalog?.endpoints||[]);
 const endpoints=[...(latest?.endpoints||[]),...discoveries],seen=new Set(),container=$('p-surfaces');container.replaceChildren();
 for(const endpoint of endpoints){const key=endpoint.endpoint_id;if(seen.has(key))continue;seen.add(key);
  container.append(pRow(endpoint.method+' '+endpoint.path,endpoint.origin+' · '+endpoint.source_refs.length+' sources',endpoint.scope_state||'observed',()=>{
   platform.endpoint=endpoint;$('p-check-path').value=endpoint.path;pInvalidate();
   pInspect(endpoint.method+' '+endpoint.path,'Observed surface; ownership is not inferred',{Origin:endpoint.origin,Sources:endpoint.source_refs,'Scope state':endpoint.scope_state,Identity:endpoint.identity,Owner:endpoint.owner,Tenant:endpoint.tenant,Blockers:endpoint.execution_blockers,Coverage:endpoint.coverage});pPage('assess');
  }));
 }
 $('p-surface-summary').textContent=seen.size+' observed endpoints · '+artifacts.filter(a=>a.kind==='import-batch').length+' imports · Unobserved surface: unknown';
}
function pRenderEvidence(){
 const c=platform.record?.coverage||{},summary=$('p-summary');summary.replaceChildren();
 for(const [label,count] of [['Plans',c.plans||0],['Executions',c.executions||0],['Confirmed',c.confirmed||0]]){const item=element('div');item.append(element('strong',String(count)),element('span',label));summary.append(item);}
 $('p-coverage').textContent='Inconclusive: '+(c.inconclusive||0)+' · Unknown surface: '+(c.unknown_surface||'unknown')+' · Coverage denominator: '+(c.denominator||'retained explicit plans')+'.';
 $('p-schedules').textContent=(platform.record?.schedules||[]).map(s=>s.id+' · '+s.state+' · '+s.completed_iterations+'/'+s.iterations+' iterations · next due '+s.next_due).join('\n')||'No schedules retained. Register a finite schedule from an explicitly reviewed plan.';
 for(const job of platform.record?.jobs||[])if(job.state==='interrupted')$('p-job-list').append(element('p','Interrupted execution '+job.request_id+' · The outcome is unknown. Review retained evidence and prepare a new plan; no automatic retry occurs.','callout'));
 const container=$('p-evidence');container.replaceChildren();const artifacts=(platform.record?.artifacts||[]).filter(a=>['check-execution','retest-execution','discovery-execution','playbook-execution'].includes(a.kind));
 for(const artifact of artifacts){const value=artifact.value,findings=value.findings?.length?value.findings:[null];
  for(const finding of findings){const status=finding?.status||finding?.evidence_level||value.state||'retained';
   const comparison=(platform.record.artifacts||[]).filter(a=>a.kind==='check-comparison'&&(a.value.baseline_execution_digest===value.execution_digest||a.value.current_execution_digest===value.execution_digest)).at(-1)?.value;
   const transition=comparison?.transitions?.find(t=>t.finding_id===finding?.id);
   container.append(pRow(finding?.title||value.plan?.check?.title||artifact.kind,
    artifact.artifact_id+' · '+(finding?.finding_id||finding?.id||value.execution_digest||'')+' · '+(transition?.status||'not_retested'),status+(finding?' · '+finding.evidence_level:''),()=>{
    platform.selected={artifact,finding};$('p-retest').disabled=!['check-execution','retest-execution'].includes(artifact.kind);
    pInspect(finding?.title||artifact.kind,'Retained evidence · '+artifact.artifact_id,{
     'Evidence level':finding?.evidence_level||'observation','Finding status':status,'Execution state':value.run_state||value.state||'completed',
     'Rule / oracle':value.plan?.check||value.plan?.spec?.check_id||'Discovery observation',
     Controls:finding?.control_refs||value.controls||value.report?.results?.filter(r=>r.id!==value.plan?.spec?.target_case)||[],
     Observations:value.observations||value.report?.results||value.steps||[],Finding:finding||'No finding derived',
     Reproducer:value.reproducer||'Not available for this artifact',
     'Retest state':transition?.status||'not_retested','Source-bound comparison':comparison||'No comparable retest retained',
     'Request ledger':value.budget_ledger||'No active requests for this artifact',
     'Source bindings':value.plan?.spec?.source_refs||value.source_refs||[],Digest:value.execution_digest||value.discovery_digest||artifact.digest||'See retained artifact'});
   }));
  }
 }
}
async function pScope(){
 if(!$('p-read-attestation').checked)throw Error('Confirm authorization and reviewed operation effects before saving scope.');
 if($('p-scope-json').value.trim())return await strictJSON($('p-scope-json').value);
 const origin=$('p-origin').value.trim(),paths=$('p-paths').value.split('\n').map(s=>s.trim()).filter(Boolean);
 if(!origin||!paths.length||!$('p-networks').value.trim()||!$('p-authorization-ref').value.trim())throw Error('Supply authorization reference, exact origin, network CIDRs and paths.');
 const expires=new Date($('p-expires').value);if(!Number.isFinite(expires.getTime()))throw Error('Choose an explicit authorization expiry.');
 return {schema_version:1,kind:'assessment-scope',id:'scope-'+Date.now(),authorization_ref:$('p-authorization-ref').value.trim(),origins:[origin],
  operations:paths.flatMap(path=>['application','object_control','discovery'].map(purpose=>({origin,method:'GET',path,purpose,effect:'read'}))),
  allowed_networks:$('p-networks').value.split(',').map(s=>s.trim()).filter(Boolean),expires_at:expires.toISOString(),allowed_effects:['read'],
  limits:{max_requests:Number($('p-budget').value),concurrency:1,timeout_seconds:Number($('p-timeout').value),max_response_bytes:1048576}};
}
async function pPresent(result,draftRevision){
 if(platform.revision!==draftRevision)throw Error('The draft changed while planning. Review the current inputs again.');
 platform.artifact=result.artifact;platform.plan=result.artifact.value;platform.review=result.review;platform.operation=result.operation;
 $('p-plan-title').textContent='Review '+result.operation+' plan';$('p-plan-json').textContent=pretty(platform.plan);
 const scope=platform.plan.scope||platform.record.assessment.scope;
 $('p-plan-meta').textContent=scope.origins.join(', ')+' · Maximum '+scope.limits.max_requests+' requests including controls · Effects: '+scope.allowed_effects.join(', ')+' · Authorization expires '+scope.expires_at;
 $('p-plan-digest').textContent='SHA-256 · '+platform.plan.plan_digest;$('p-approved').checked=false;$('p-run').disabled=true;$('p-schedule').disabled=true;
 $('p-review').hidden=false;await pLoad(platform.id);$('p-review').scrollIntoView({block:'nearest'});
 pInspect('Reviewed '+result.operation,'Offline planning has sent no target requests',{'Plan digest':platform.plan.plan_digest,Scope:scope,Plan:platform.plan,Approval:'Waiting for explicit authorization'});
}
async function pWatch(job){
 platform.job=job.id;platform.busy=true;pPage('investigate');$('p-cancel').hidden=false;$('p-reconnect').hidden=true;$('p-run').disabled=true;
 $('p-run-status').textContent='Running only the approved plan. Controls, response limits and scope apply to every request.';pContext();
 try{for(;;){const result=await api('/api/jobs/'+job.id);if(result.state!=='running'){
   platform.job=null;platform.busy=false;$('p-cancel').hidden=true;pInvalidate();await pRefresh(platform.id);
   $('p-run-status').textContent=result.state==='complete'?(result.cancelled?'Execution ended after cancellation. Inspect incomplete evidence.':'Execution retained. Select a result to inspect its controls and observations.'):(result.error||'Execution did not complete. Inspect retained evidence before replanning.');
   if(result.state==='complete')$('p-evidence').lastElementChild?.click();return result;
  }await new Promise(resolve=>setTimeout(resolve,350));}
 }catch(error){$('p-reconnect').hidden=false;$('p-run-status').textContent='Connection interrupted. Reconnect to this job without dispatching it again.';throw error;}
}

document.querySelectorAll('[data-platform-page]').forEach(button=>button.onclick=()=>pPage(button.dataset.platformPage));
$('p-open').addEventListener('click',guarded(async()=>{if(!platform.loaded)await pRefresh();pContext();}));
$('p-refresh').onclick=guarded(()=>pRefresh());
$('p-assessment').onchange=guarded(async()=>{pInvalidate();platform.selected=null;$('p-retest').disabled=true;platform.id=$('p-assessment').value||null;if(platform.id)await pLoad(platform.id);else{platform.record=null;pContext();}});
$('p-new').onclick=()=>{pInvalidate();platform.loadSequence++;platform.id=null;platform.record=null;platform.selected=null;platform.endpoint=null;$('p-assessment').value='';$('p-scope-json').value='';$('p-title').value='Security assessment';$('p-update').disabled=true;$('p-read-attestation').checked=false;pPage('scope');};
$('p-expires').value=pLocalDate(new Date(Date.now()+3600000));
$('p-create').onclick=guarded(async()=>{const result=await api('/api/platform/create',{title:$('p-title').value.trim(),scope:await pScope(),engagement:pEngagement()});pInvalidate();await pRefresh(result.assessment.id);pPage('surface');});
$('p-update').onclick=guarded(async()=>{const id=pRequire(),scope=await pScope();await api('/api/platform/update',{assessment_id:id,title:$('p-title').value.trim(),scope,engagement:pEngagement(),expected_revision:platform.record.assessment.revision});pInvalidate();await pRefresh(id);notify('Assessment scope updated; all previous plan reviews were invalidated.');});
for(const id of ['p-origin','p-paths','p-networks','p-authorization-ref','p-expires','p-budget','p-timeout'])$(id).addEventListener('input',()=>{$('p-scope-json').value='';pInvalidate();});
for(const id of ['p-title','p-engagement-ref','p-roe-ref','p-engagement-notes','p-scope-json','p-spec','p-check-path','p-baseline-status','p-required-headers','p-seeds-json','p-seed-paths'])$(id).addEventListener('input',pInvalidate);
$('p-profile').onchange=()=>{pInvalidate();pRenderChecks();};$('p-check').onchange=()=>{pInvalidate();pCheckDescription();};
$('p-import-profile').onchange=()=>{const raw=$('p-import-profile').value==='burp-http-pair-v1';$('p-response-label').hidden=!raw;$('p-source-label').hidden=!raw;};
$('p-import').onclick=guarded(async()=>{
 pRequire();const file=$('p-import-file').files[0],response=$('p-import-response').files[0];if(!file)throw Error('Choose a saved source file.');if(file.size+(response?.size||0)>2*1024*1024)throw Error('Choose messages totalling at most 2 MiB.');
 const payload={assessment_id:platform.id,profile:$('p-import-profile').value,expected_revision:platform.record.assessment.revision};
 try{if(payload.profile==='burp-http-pair-v1'){payload.source_origin=$('p-source-origin').value.trim();payload.request_base64=await aImportFileBase64(file);if(response)payload.response_base64=await aImportFileBase64(response);}else payload.text=await file.text();
  await api('/api/platform/import',payload);pInvalidate();await pRefresh();notify('Source imported offline; no target requests were sent.');
 }finally{payload.text='';payload.request_base64='';payload.response_base64='';$('p-import-file').value='';$('p-import-response').value='';}
});
$('p-discover-plan').onclick=guarded(async()=>{pRequire();const revision=platform.revision,seeds=$('p-seeds-json').value.trim()?await strictJSON($('p-seeds-json').value):[{kind:'http',origin:platform.record.assessment.scope.origins.find(o=>/^https?:/.test(o)),paths:$('p-seed-paths').value.split('\n').map(s=>s.trim()).filter(Boolean),follow_links:$('p-follow-links').checked,max_depth:$('p-follow-links').checked?2:0}];await pPresent(await api('/api/platform/discover-plan',{assessment_id:platform.id,seeds}),revision);});
$('p-check-build').onclick=guarded(async()=>{
 pRequire();const origin=platform.endpoint?.origin||platform.record.assessment.scope.origins.find(o=>/^https?:/.test(o)),path=$('p-check-path').value.trim();if(!path)throw Error('Select an observed endpoint or enter an exact authorized path.');
 const spec={schema_version:1,kind:'check-spec',id:'headers-'+Date.now(),check_id:'misconfig.security_headers',version:'1.0.0',source_refs:[platform.endpoint?.endpoint_id||platform.record.assessment.scope.id],contract:{version:1,name:'Required response headers',target:origin,identities:{anonymous:{headers:{}}},cases:[{id:'baseline',identity:'anonymous',method:'GET',path,expect:{status:[Number($('p-baseline-status').value)]}},{id:'probe',identity:'anonymous',method:'GET',path,requires:['baseline'],expect:{status:[Number($('p-baseline-status').value)]}}]},controls:['baseline'],target_case:'probe',params:{required_headers:$('p-required-headers').value.split(',').map(s=>s.trim().toLowerCase()).filter(Boolean)}};
 pInvalidate();$('p-spec').value=pretty(spec);$('p-spec-disclosure').open=true;notify('Header check prepared. Preview its controls and exact request budget.');
});
$('p-use-contrast').onclick=()=>{if(!assessment.plan?.spec||assessment.plan.kind!=='experiment-plan'){notify('Prepare a Contrast specification in the existing Contrast view first.',true);return;}pInvalidate();$('p-spec').value=pretty({schema_version:1,kind:'check-spec',id:'contrast-'+Date.now(),check_id:$('p-check').value,version:'1.0.0',source_refs:[platform.id||'explicit-contrast-spec'],experiment_spec:assessment.plan.spec});$('p-spec-disclosure').open=true;};
$('p-use-workflow').onclick=()=>{if(!assessment.plan?.spec||assessment.plan.kind!=='workflow-plan'){notify('Prepare a Workflow specification in the existing Workflow view first.',true);return;}pInvalidate();$('p-spec').value=pretty({schema_version:1,kind:'check-spec',id:'workflow-'+Date.now(),check_id:$('p-check').value,version:'1.0.0',source_refs:[platform.id||'explicit-workflow-spec'],workflow_spec:assessment.plan.spec});$('p-spec-disclosure').open=true;};
$('p-spec-file').onchange=guarded(async()=>{const value=await readFile($('p-spec-file'));pInvalidate();$('p-spec').value=pretty(value);$('p-spec-disclosure').open=true;});
$('p-bind').onclick=guarded(async()=>{pRequire();const body={env:$('p-credential-ref').value.trim(),identity:$('p-credential-identity').value.trim(),target_origin:$('p-credential-origin').value.trim(),value:$('p-credential-value').value};$('p-credential-value').value='';try{await api('/api/assessment/credentials',body);pInvalidate();notify('Credential bound to this exact origin and identity for the server session.');}finally{body.value='';}});
$('p-check-plan').onclick=guarded(async()=>{pRequire();const revision=platform.revision,spec=await strictJSON($('p-spec').value);await pPresent(await api('/api/platform/check-plan',{assessment_id:platform.id,spec}),revision);});
$('p-playbook-plan').onclick=guarded(async()=>{pRequire();const selected=[...$('p-playbook-plans').querySelectorAll('input:checked')];if(!selected.length)throw Error('Select at least one retained plan.');const revision=platform.revision,steps=selected.map((node,index)=>({id:'step-'+(index+1),plan_id:node.dataset.planId,requires:index?['step-'+index]:[]}));await pPresent(await api('/api/platform/playbook-plan',{assessment_id:platform.id,steps}),revision);});
$('p-approved').onchange=()=>{const allowed=!!platform.review&&$('p-approved').checked&&!platform.busy;$('p-run').disabled=!allowed;$('p-schedule').disabled=!allowed;};
$('p-run').onclick=guarded(async()=>{if(!platform.review||!$('p-approved').checked||platform.busy)throw Error('Review and authorize the exact current plan first.');const job=await api('/api/platform/run',{review:platform.review,approve:platform.plan.plan_digest,authorized:true});await pWatch(job);});
$('p-plan-save').onclick=()=>{if(platform.plan)download(platform.plan,'assessment-plan.json');};
$('p-cancel').onclick=guarded(async()=>{if(platform.job){await api('/api/cancel',{id:platform.job});$('p-run-status').textContent='Stopping further ordinary requests. In-flight requests remain bounded by their timeout.';}});
$('p-reconnect').onclick=guarded(async()=>{if(platform.job)await pWatch({id:platform.job});});
$('p-recover').onclick=guarded(async()=>{pRequire();if(platform.busy)throw Error('Reconnect to the active job before attempting interrupted-work recovery.');await api('/api/platform/recover',{assessment_id:platform.id});pInvalidate();await pRefresh();$('p-run-status').textContent='Local interrupted-work state reconciled. No requests were sent and no uncertain execution was retried.';});
$('p-retest').onclick=guarded(async()=>{pRequire();if(!platform.selected)throw Error('Select retained check evidence first.');const revision=platform.revision,selected=platform.selected;await pPresent(await api('/api/platform/retest-plan',{assessment_id:platform.id,execution_id:selected.artifact.artifact_id,selection:selected.finding?[selected.finding.finding_id||selected.finding.id]:null}),revision);});
$('p-inspector-focus').onclick=()=>{$('a-inspector-disclosure').open=true;$('a-inspector-fields').focus();};
$('p-freeze').onclick=guarded(async()=>{pRequire();const revision=platform.revision,result=await api('/api/platform/freeze',{assessment_id:platform.id});if(revision!==platform.revision)throw Error('The assessment changed during snapshot preparation. Freeze it again.');platform.snapshot=result;$('p-report-status').textContent='Frozen snapshot · '+result.snapshot.snapshot_digest+' · Includes explicit coverage and not_retested states.';document.querySelectorAll('[data-platform-export]').forEach(b=>b.disabled=false);$('p-proof').disabled=false;pRenderAnnotations();pInspect('Frozen assessment','One evidence snapshot for every format',{Digest:result.snapshot.snapshot_digest,Coverage:result.snapshot.coverage,Scope:result.snapshot.assessment?.scope||platform.record.assessment.scope});});
$('p-annotation-finding').onchange=pAnnotationFields;
$('p-annotation-save').onclick=guarded(async()=>{if(!platform.snapshot||!$('p-annotation-finding').value)throw Error('Freeze and select an exact finding record first.');const rationale=$('p-annotation-rationale').value.trim();if(!rationale)throw Error('Provide a rationale for the review and technical severity.');const included=$('p-annotation-included').checked,annotation={included,severity:$('p-annotation-severity').value,review:$('p-annotation-review').value,rationale};if(!included){annotation.exclusion_reason=$('p-annotation-exclusion').value.trim();if(!annotation.exclusion_reason)throw Error('Excluded evidence requires a retained reason.');}const risk=$('p-annotation-risk').value.trim(),cvss=$('p-annotation-cvss').value.trim();if(risk)annotation.business_risk=risk;if(cvss)annotation.cvss_vector=cvss;const remediation=$('p-annotation-remediation').value.trim();if(remediation)annotation.remediation=remediation;const impact=$('p-annotation-impact').value.trim();if(impact)annotation.impact=impact;const annotations={...(platform.record.assessment.finding_annotations||{})},id=$('p-annotation-finding').value;annotations[id]={...(annotations[id]||{}),...annotation};if(included)delete annotations[id].exclusion_reason;await pSaveAnnotations(annotations);});
$('p-annotations-apply').onclick=guarded(async()=>{if(!platform.snapshot)throw Error('Freeze a snapshot before reviewing exact finding references.');await pSaveAnnotations(await strictJSON($('p-annotations-json').value));});
document.querySelectorAll('[data-platform-export]').forEach(button=>button.onclick=guarded(async()=>{if(!platform.snapshot)throw Error('Freeze an assessment first.');const format=button.dataset.platformExport;download(await api('/api/platform/export',{snapshot_id:platform.snapshot.snapshot_id,format},true),'authzledger-assessment.'+format);}));
$('p-signing').onclick=guarded(async()=>{const signing=await api('/api/assessment/signing',{create_session_key:true});$('p-fingerprint').textContent='Public key SHA-256 · '+signing.public_key_sha256;download(signing.public_key,'authzledger-verification-key.pem','application/x-pem-file');});
$('p-proof').onclick=guarded(async()=>{if(!platform.snapshot)throw Error('Freeze an assessment first.');download(await api('/api/platform/proof',{snapshot_id:platform.snapshot.snapshot_id},true),'authzledger-assessment-proof.zip');});
$('p-schedule').onclick=guarded(async()=>{if(!platform.review||!$('p-approved').checked)throw Error('Authorize the reviewed plan first.');const result=await api('/api/platform/schedule',{assessment_id:pRequire(),plan_id:platform.artifact.artifact_id,approve:platform.plan.plan_digest,authorized:true,interval_seconds:Number($('p-schedule-interval').value),iterations:Number($('p-schedule-iterations').value),request_budget:Number($('p-schedule-budget').value)});$('p-schedule-status').textContent='Registered '+result.schedule.id+' · '+result.schedule.iterations+' iterations. No background runner was started.';});
$('p-run-due').onclick=guarded(async()=>{pRequire();if(!$('p-due-authorized').checked)throw Error('Confirm execution of currently due approved work.');const job=await api('/api/platform/run-due',{assessment_id:platform.id,authorized:true});$('p-due-authorized').checked=false;await pWatch(job);});
$('p-delta').onclick=guarded(async()=>{pRequire();const result=await api('/api/platform/delta',{assessment_id:platform.id,baseline_catalog_id:$('p-delta-before').value,current_catalog_id:$('p-delta-after').value});pInvalidate();await pLoad(platform.id);$('p-delta-status').textContent='Surface comparison retained · '+result.delta.artifact_id;pInspect('Surface delta','Offline comparison; no behavior was retested',{Result:result.delta.value,'Check selection':result.check_plan?.value||'No new check plan requested','Retest coverage':'Unselected behavior remains not_retested'});});
$('p-knowledge').onclick=guarded(async()=>{pRequire();const observations=[{product:$('p-knowledge-product').value.trim(),version:$('p-knowledge-version').value.trim(),source_ref:$('p-knowledge-source').value.trim(),source_kind:$('p-knowledge-kind').value}],pack=$('p-knowledge-pack').value.trim()?await strictJSON($('p-knowledge-pack').value):null;const result=await api('/api/platform/knowledge',{assessment_id:platform.id,observations,pack});pInvalidate();await pLoad(platform.id);$('p-knowledge-status').textContent='Knowledge result retained · '+result.artifact.artifact_id;pInspect('Knowledge candidates','Evidence-bound hints; exploitability is not established',{Result:result.artifact.value});});
document.querySelectorAll('.platform-records').forEach(list=>list.addEventListener('keydown',event=>{if(!['ArrowDown','ArrowUp','j','k'].includes(event.key)||event.ctrlKey||event.metaKey)return;const rows=[...list.querySelectorAll('button')],i=rows.indexOf(document.activeElement);if(i<0)return;event.preventDefault();rows[(i+(['ArrowDown','j'].includes(event.key)?1:rows.length-1))%rows.length]?.focus();}));
for(const [label,view] of [['Engagement and authorization scope','scope'],['Discover assessment surface','surface'],['Assess with controlled checks','assess'],['Investigate retained assessment','investigate'],['Assessment platform report and proof','report']])commands.push([label,guarded(async()=>{if(!platform.loaded)await pRefresh();pPage(view);})]);
