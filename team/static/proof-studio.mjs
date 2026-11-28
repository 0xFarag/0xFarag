// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {proofText} from './proof-texts.mjs';
import {managementHtml} from './management-report.mjs';

const steps = ['scope','import','proof','retest','package'];
const controlIds = ['token','identity','owner','denial'];
const formats = {burp:'Burp',zap:'ZAP',har:'HAR',openapi:'OpenAPI',nmap:'Nmap XML',
  nuclei:'Nuclei HTTP JSONL',nessus:'Nessus (.nessus)',nikto:'Nikto XML',cobalt:'Cobalt Strike · EDR/SIEM JSON'};
const writerRoles = new Set(['admin','lead_pentester','pentester']);
const allowedLanguages = new Set(['de','en','fr']);

function element(tag, value, cls) {
  const node = document.createElement(tag);
  if (value !== undefined && value !== null) node.textContent = String(value);
  if (cls) node.className = cls;
  return node;
}
function selectOptions(entries, selected) {
  const select = element('select');
  for (const [value,text] of entries) select.add(new Option(text, value, false, value === selected));
  return select;
}
function field(name, input) {
  const label = element('label',null,'ps-field');
  input.setAttribute('aria-label',name);
  label.append(element('span',name),input);
  return label;
}
function button(text, click, cls='secondary', type='button') {
  const node = element('button',text,cls);
  node.type = type;
  if (click) node.addEventListener('click',click);
  return node;
}
function details(title, ...children) {
  const node = element('details',null,'ps-details');
  node.append(element('summary',title),...children);
  return node;
}
function table(headings,rows) {
  const scroll = element('div',null,'table-wrap'), node = element('table');
  const header = node.createTHead().insertRow();
  for (const text of headings) {
    const th = element('th',text);
    th.scope = 'col';
    header.append(th);
  }
  const body = node.createTBody();
  for (const row of rows) {
    const tr = body.insertRow();
    for (const value of row) {
      const td = tr.insertCell();
      if (value instanceof Node) td.append(value);
      else td.textContent = value == null ? '—' : String(value);
    }
  }
  scroll.append(node);
  return scroll;
}
function routeRef(obs) {
  return element('code',[obs.method,obs.host,obs.path].filter(Boolean).join(' '));
}
function disclosureValue(value) {
  return element('pre',JSON.stringify(value,null,2),'ps-json');
}
function secretBox(value, title) {
  const input = element('input');
  input.value = value;
  input.readOnly = true;
  input.spellcheck = false;
  input.autocomplete = 'off';
  input.addEventListener('focus',() => input.select());
  return field(title,input);
}

export function createProofStudio(root,{request,encodeFile,fileBytes,saveBlob,onUnauthorized}) {
  let lang = 'de', member, runs = [], active, stage = 0, generation = 0, busy = false, keys;
  const txt = key => proofText(key,lang);
  const say = (key,details='') => {
    const status = root.querySelector('.ps-notice');
    if (status) status.textContent = txt(key) + (details ? ' · '+details : '');
  };
  const writer = () => writerRoles.has(member?.role);
  const base = () => '/api/teams/'+encodeURIComponent(member.id)+'/proof';
  const runPath = () => base()+'/'+encodeURIComponent(active.id);
  const get = path => request(path,'GET');
  const post = (path,data) => request(path,'POST',data);
  function focusStage() {
    root.querySelector('.ps-stage')?.focus({preventScroll:true});
    root.querySelector('.ps-nav')?.scrollIntoView({block:'nearest'});
  }
  const note = msg => element('p',txt(msg),'fine');
  const yesNo = value => txt(value ? 'has' : 'lacks');

  function reportFailure(error,stamp) {
    if (stamp !== generation) return;
    if (error.status === 401 && error.message === 'unauthenticated') return onUnauthorized(error);
    const info = String(error.message || '').replace(/[\u0000-\u001f\u007f-\u009f]/g,' ').slice(0,190);
    const reason = {
      version_conflict:'reloadConflict',already_imported:'problemDuplicate',baseline_frozen:'problemLocked',
      closed_for_import:'problemLocked',badFile:'problemSize',invalid_size:'problemSize',
      'invalid or unsupported source document':'problemSource',forbidden:'noPermission'
    }[info];
    if (reason) say(reason); else say('requestFailed',info);
  }
  function perform(work, control) {
    return async event => {
      event?.preventDefault();
      if (busy || !member) return;
      const stamp = generation;
      busy = true;
      const trigger = control || event?.submitter || event?.currentTarget;
      if (trigger instanceof HTMLButtonElement) trigger.disabled = true;
      root.setAttribute('aria-busy','true');
      try { await work(stamp); }
      catch (error) { reportFailure(error,stamp); }
      finally {
        if (stamp === generation) {
          busy = false; root.removeAttribute('aria-busy');
          if (trigger instanceof HTMLButtonElement) trigger.disabled = false;
        }
      }
    };
  }
  function clear() {
    generation++;
    busy = false; runs = []; active = null; keys = null; member = null; stage = 0;
    root.removeAttribute('aria-busy'); root.replaceChildren();
  }
  async function bind(membership,language) {
    clear(); member = membership; lang = language;
    if (!member) return;
    const stamp = generation;
    root.textContent = txt('load');
    try {
      const list = await get(base());
      if (stamp !== generation) return;
      runs = list.runs;
      if (runs.length) {
        const response = await get(base()+'/'+encodeURIComponent(runs[0].id));
        if (stamp !== generation) return;
        active = response.run;
      }
      draw();
    } catch (error) {
      if (stamp !== generation) return;
      draw(); reportFailure(error,stamp);
    }
  }
  function language(value) { lang=value; if (member) draw(); }
  function clearSensitive() {
    // The import token and ZAP key live only in this view.
    for (const node of root.querySelectorAll('[data-sensitive]')) {
      if (node.matches('input')) node.value='';
      else node.replaceChildren();
    }
  }
  function toStage(index) {
    if (busy || (index && !active)) return;
    clearSensitive(); stage=index; draw(); focusStage();
  }
  function updateRun(run) {
    active = run;
    const prior = runs.findIndex(entry => entry.id === run.id);
    const item = {id:run.id,mode:run.mode,version:run.version};
    if (prior >= 0) runs[prior] = item;
    else runs.unshift(item);
  }
  function mutate(action, payload, next) {
    return perform(async stamp => {
      const version = active.version, path = runPath();
      const data = await payload();
      if (stamp !== generation) return;
      const {run} = await post(path+'/'+action,{...data,version});
      if (stamp !== generation) return;
      updateRun(run);
      if (next !== undefined) stage=next;
      draw();

      focusStage();
    });
  }
  async function loadKeys(stamp) {
    if (!active) return;
    const result = await get(base()+'/keys');
    if (stamp !== generation || stage !== 4) return;
    keys=result; drawKeyList();
  }
  function navigation() {
    const nav = element('nav',null,'ps-nav');
    nav.setAttribute('aria-label',txt('stage'));
    for (const [i,name] of steps.entries()) {
      const item=button(txt(name),() => toStage(i),'ps-step');
      item.prepend(element('span',String(i+1),'ps-no'));
      if (i === stage) item.setAttribute('aria-current','step');
      item.disabled=(!active && i > 0) || (i >= 2 && !active?.sources?.length);
      nav.append(item);
    }
    return nav;
  }
  function draw() {
    const stamp = generation;
    clearSensitive();
    root.replaceChildren();
    root.lang=allowedLanguages.has(lang) ? lang : 'en';
    root.dir='ltr';
    const top = element('div',null,'ps-toolbar');
    top.append(element('h2',txt('workbench')));
    const controls = element('div',null,'ps-pickers');
    const picker=selectOptions([['',txt('newRun')],...runs.map(r => [r.id,txt(r.mode)+' · '+r.id.slice(0,12)])],active?.id || '');
    picker.id='ps-case';
    if (!writer()) {
      picker.options[0].disabled=true;
      if (!runs.length) picker.disabled=true;
    }
    picker.addEventListener('change',perform(async stamp => {
      const id=picker.value;
      if (id) {
        const response = await get(base()+'/'+encodeURIComponent(id));
        if (stamp !== generation) return;
        updateRun(response.run);
      } else active=null;
      stage=0; keys=null; draw();
    }));
    controls.append(field(txt('selectRun'),picker),button(txt('refresh'),perform(async stamp => {
      const selected=active?.id;
      const list=await get(base());
      if (stamp!==generation) return;
      runs=list.runs;
      if (selected) {
        const {run}=await get(base()+'/'+encodeURIComponent(selected));
        if (stamp!==generation) return;
        updateRun(run);
      }
      draw(); say('refreshNotice');
    }),'plain slim'));
    if (active) controls.append(managementButton('html'),managementButton('json'));
    top.append(controls);
    const message=element('p',null,'ps-notice');
    message.setAttribute('role','status'); message.setAttribute('aria-live','polite');
    const panel=element('section',null,'ps-stage card'); panel.tabIndex=-1;
    const header=element('div',null,'section-heading');
    header.append(element('h3',txt(steps[stage])));
    if (active) header.append(element('span',txt(active.mode),'ps-mode '+(active.mode==='lab'?'ps-lab':'')));
    panel.append(header);
    root.append(top,navigation(),message,panel);
    if (stage===0) scopePanel(panel);
    else if (stage===1) importPanel(panel);
    else if (stage===2) proofPanel(panel);
    else if (stage===3) retestPanel(panel);
    else if (stage===4) {
      packagePanel(panel);
      if (!keys) loadKeys(stamp).catch(error => reportFailure(error,stamp));
    }
    if (active?.history?.length) root.append(details(txt('history'),historyList(active.history)));
    root.append(details(txt('help'),note('helpText')));
  }
  function historyList(history) {
    const list=element('ol',null,'ps-history');
    for (const item of history) {
      const row=element('li');
      const text=typeof item==='string' ? item : [new Date(item.at*1000).toLocaleString(root.lang),item.action || item.event,item.version!=null?'v'+item.version:null].filter(Boolean).join(' · ');
      row.append(text || disclosureValue(item));
      if (item.version >= active.managementReportFrom && item.version < active.version) {
        row.append(' ',managementButton('html',item.version));
      }
      list.append(row);
    }
    return list;
  }
  function managementButton(format,revision) {
    const label = txt(format === 'html' ? 'managementHtml' : 'managementJson');
    return button(revision ? label+' · v'+revision : label, perform(async stamp => {
      const url = runPath()+'/management-report'+(revision ? '/'+revision : '');
      const {report,filename} = await get(url);
      if (stamp !== generation) return;
      if (format === 'html') {
        const html = managementHtml(report,lang);
        saveBlob(new Blob([html],{type:'text/html;charset=utf-8'}),filename.replace(/\.json$/,'.html'));
      } else {
        saveBlob(new Blob([JSON.stringify(report,null,2)+'\n'],{type:'application/json'}),filename);
      }
    }),'secondary slim');
  }
  function form(parent, handler, label) {
    const node=element('form',null,'ps-form');
    node.addEventListener('submit',handler);
    const submit=button(txt(label),null,'primary','submit');
    parent.append(node);
    return {node,submit};
  }
  function scopePanel(panel) {
    if (active) {
      const scope=active.scope || {};
      panel.append(table([txt('hosts'),txt('roe'),txt('budget')],[[scope.hosts?.join(', '),scope.roe,scope.budget ?? active.report?.budget]]));
      if (active.locked) panel.append(note('locked'));
      panel.append(button(txt('continueTo')+' '+txt('import'),() => toStage(1),'primary'));
      return;
    }
    panel.append(note('scopeHint'));
    if (!writer()) { panel.append(note('readonly')); return; }
    const mode=selectOptions([['commercial',txt('commercial')],['lab',txt('lab')]],'commercial');
    mode.id='ps-mode';
    const hosts=element('textarea'); hosts.rows=2; hosts.required=true; hosts.placeholder='app.example.org';
    const roe=element('input'); roe.type='text'; roe.required=true; roe.maxLength=1200;
    const budget=element('input'); budget.type='number'; budget.min='0'; budget.max='1000000'; budget.step='1'; budget.required=true; budget.value='12';
    const values=element('div'); values.append(field(txt('hosts'),hosts),field(txt('roe'),roe),field(txt('budget'),budget));
    const labDescription=note('labHint'); labDescription.hidden=true;
    mode.addEventListener('change',() => {
      const isLab=mode.value==='lab';
      values.hidden=isLab;
      for (const input of [hosts,roe,budget]) input.disabled=isLab;
      labDescription.hidden=!isLab;
    });
    const {node,submit}=form(panel,perform(async stamp => {
      const payload=mode.value==='lab'?{mode:'lab'}:{mode:'commercial',hosts:hosts.value.split(/\r?\n/).map(v=>v.trim()).filter(Boolean),roe:roe.value.trim(),budget:Number(budget.value)};
      const {run}=await post(base(),payload);
      if (stamp!==generation) return;
      updateRun(run); stage=1; draw(); say('scopeSaved'); focusStage();
    }),'create');
    node.append(field(txt('mode'),mode),note('modeHint'),values,labDescription,submit);
  }
  function baselineRows() { return active.report?.findings ?? []; }
  function sourceRows() {
    const src=active.sources ?? active.report?.source ?? [];
    const list=element('ul',null,'records');
    for (const file of src) {
      const li=element('li');
      li.append(element('strong',file.format),element('small',file.sha256 || ''));
      if (Array.isArray(file.observations)) li.append(table([txt('observed'),'HTTP',txt('marker')],file.observations.map(obs=>[routeRef(obs),obs.status,yesNo(obs.marker)])));
      list.append(li);
    }
    return list.childElementCount?list:note('noFiles');
  }
  function pickFile(label) {
    const file=element('input'); file.type='file'; file.accept='.json,.xml,.nessus,.har,.jsonl,.ndjson,.txt,application/json,application/xml,text/plain';
    const format=selectOptions(Object.entries(formats),'har');
    const group=element('div',null,'pair');
    const hint=note('cobaltFormat');
    hint.hidden=true;
    format.addEventListener('change',()=>{hint.hidden=format.value!=='cobalt';});
    group.append(field(txt('format'),format),field(txt(label),file),hint);
    return {group,file,format};
  }
  async function readSource(input) {
    return {format:input.format.value,content_b64:encodeFile(await fileBytes(input.file.files[0],1024*1024))};
  }
  function importPanel(panel) {
    const lab=active.mode==='lab';
    panel.append(note(lab?'labLoaded':'importHelp'));
    if (!lab && writer() && !active.locked) {
      const input=pickFile('file'); input.file.required=true;
      const {node,submit}=form(panel,mutate('import',() => readSource(input),2),'addFile');
      node.append(input.group,submit);
      integrationOptions(panel);
    }
    panel.append(element('h4',txt('sources')),sourceRows());
    if (lab || active.locked || !writer()) panel.append(button(txt('continueTo')+' '+txt('proof'),() => toStage(2),'primary'));
  }
  function integrationOptions(panel) {
    const issued=element('div'); issued.dataset.sensitive='';
    const create=button(txt('issueToken'),perform(async stamp=>{
      const {token,expiresAt}=await post(runPath()+'/token',{});
      if (stamp!==generation || !issued.isConnected) return;
      issued.replaceChildren(secretBox(new URL('/api/proof-import',location.origin).href,txt('destination')),secretBox(token,'Token'),element('small',txt('expires')+' · '+new Date(expiresAt*1000).toLocaleString(root.lang)));
    }));
    panel.append(details(txt('tokenSetup'),note('tokenInfo'),create,issued));
    const key=element('input'); key.type='password'; key.autocomplete='off'; key.dataset.sensitive=''; key.maxLength=1024;
    const read=button(txt('zap'),mutate('zap',() => {
      const apiKey=key.value; key.value=''; return {apiKey};
    },2));
    panel.append(details(txt('zap'),note('zapHint'),field(txt('apiKey'),key),read));
  }
  function controlTable(initial,readOnly,effective=true) {
    const report=active.report?.controls || {};
    const inputControls={};
    const rows=controlIds.map(id=>{
      const raw=report[id] || {};
      const checkbox=element('input'); checkbox.type='checkbox'; checkbox.checked=initial[id]===true; checkbox.disabled=readOnly;
      checkbox.setAttribute('aria-label',id); checkbox.dataset.control=id; inputControls[id]=checkbox;
      const deps=raw.dependsOn || {token:[],identity:['token'],owner:['identity'],denial:['identity']}[id];
      const fields=[element('code',id),checkbox];
      if (effective) fields.push(yesNo(raw.effective));
      fields.push(deps.join(', ') || '—');
      return fields;
    });
    const headings=[txt('controls'),txt('intended')];
    if (effective) headings.push(txt('effective'));
    headings.push(txt('depends'));
    return {node:table(headings,rows),values:()=>Object.fromEntries(controlIds.map(id=>[id,inputControls[id].checked]))};
  }
  function resultsTable() {
    return table([txt('observed'),'HTTP',txt('marker'),txt('results')],baselineRows().map(row=>{
      const obs=row.observation;
      return [routeRef(obs),obs.status,yesNo(obs.marker),element('code',row.status)];
    }));
  }
  function proofPanel(panel) {
    panel.append(note('controlsHint'));
    const readOnly=!writer() || active.locked;
    const controls=controlTable(active.controls || {},readOnly);
    if (!readOnly) {
      const {node,submit}=form(panel,mutate('controls',() => ({controls:controls.values()}),3),'confirmProof');
      node.append(controls.node,submit);
    } else panel.append(controls.node,note(active.locked?'locked':'readonly'));
    panel.append(element('h4',txt('findings')),resultsTable());
    const report=active.report || {};
    if (report.budget!==undefined) {
      const spent=element('p',txt('spent')+' · '+report.spent+' / '+report.budget);
      panel.append(spent);
    }
    if (report.assurance?.stopReason) panel.append(element('p',txt('stopped')+' · '+report.assurance.stopReason));
    if (report.graph) {
      const graph=report.graph;
      const relations=new Map(graph.relationship.map(item=>[item.observationId,item]));
      const results=new Map(graph.result.map(item=>[item.observationId,item]));
      const rows=graph.intent.map(intent=>{
        const relation=relations.get(intent.observationId),result=results.get(intent.observationId);
        return [intent.observationId,intent.rule,relation?routeRef(relation):'—',result?.status];
      });
      const layers=details(txt('graph'),table(['ID',txt('intentLayer'),txt('relationLayer'),txt('resultLayer')],rows));
      for (const item of baselineRows().filter(item=>item.minimalReproducer)) {
        layers.append(details(txt('minimum')+' · '+item.id,disclosureValue(item.minimalReproducer)));
      }
      panel.append(layers);
    }
    if (readOnly) panel.append(button(txt('continueTo')+' '+txt('retest'),() => toStage(3),'primary'));
  }
  function retestPanel(panel) {
    panel.append(note('retestHint'));
    const report=active.report || {}, selected=new Set(active.selected || []), checkboxes=[];
    const prior=new Map((active.retests || []).map(row=>[row.id,row.status]));
    const rows=baselineRows().map(row=>{
      const input=element('input'); input.type='checkbox'; input.value=row.id;
      input.checked=selected.has(row.id); input.disabled=row.status!=='confirmed' || !writer();
      input.setAttribute('aria-label',row.id); checkboxes.push(input);
      return [input,routeRef(row.observation),element('code',row.status),element('code',prior.get(row.id) || (row.status==='confirmed'?'not_retested':'not_applicable'))];
    });
    const selection=table([txt('selected'),txt('observed'),txt('before'),txt('afterVerdict')],rows);
    if (writer()) {
      const after=pickFile('after');
      const labCheck=element('input'); labCheck.type='checkbox'; labCheck.checked=active.mode==='lab';
      const useFixture=active.mode==='lab';
      const labField=field(txt('useLab'),labCheck); labField.classList.add('ps-check');
      const updateFile=()=>{after.group.hidden=useFixture; after.file.disabled=after.group.hidden;};
      labCheck.addEventListener('change',updateFile); updateFile();
      const checks=controlTable({},false,false);
      const {node,submit}=form(panel,mutate('retest',async()=>{
        const body={selected:checkboxes.filter(input=>input.checked && !input.disabled).map(input=>input.value),controls:checks.values()};
        if (useFixture && labCheck.checked) body.labAfter=true;
        else if (after.file.files.length) Object.assign(body,await readSource(after));
        return body;
      },4),'record');
      node.append(selection);
      if (useFixture) node.append(labField);
      node.append(after.group);
      if (!useFixture) node.append(note('absentHint'));
      node.append(element('h4',txt('afterControls')),checks.node,submit);
    } else panel.append(selection,note('readonly'),button(txt('continueTo')+' '+txt('package'),()=>toStage(4),'primary'));
    if (report.evidenceRoot || report.contractRoot) {
      panel.append(details(txt('baseline'),element('p',report.evidenceRoot || '—','fingerprint'),element('h4',txt('contract')),element('p',report.contractRoot || '—','fingerprint')));
    }
  }
  function packagePanel(panel) {
    panel.append(note('packageHint'));
    const results=active.retests || [];
    if (results.length) {
      const counts=new Map();
      for (const item of results) counts.set(item.status,(counts.get(item.status) || 0)+1);
      const summary=element('p',Array.from(counts,([status,count])=>status+' · '+count).join('   /   '),'ps-coverage');
      panel.append(summary,details(txt('retests'),table([txt('observed'),txt('results'),txt('reason')],results.map(item=>[item.id,item.status,item.reason]))));
    }
    if (writer()) {
      const language=selectOptions([['de','Deutsch'],['en','English'],['fr','Français']],allowedLanguages.has(lang)?lang:'en');
      const {node,submit}=form(panel,mutate('sign',() => ({language:language.value}),4),'sign');
      node.append(field(txt('language'),language),submit);
    } else panel.append(note('readonly'));
    panel.append(element('h4',txt('packages')));
    const pkgs=active.signed || [];
    if (!pkgs.length) panel.append(note('noPackages'));
    else {
      const rows=pkgs.map(item=>{
        const fields=[element('code',item.keyId),item.language,element('code',item.id)];
        if (writer()) fields.push(button(txt('export'),perform(async stamp=>{
          const response=await post(runPath()+'/export',{packageId:item.id});
          if (stamp!==generation) return;
          const bytes=Uint8Array.from(atob(response.archive_b64),letter=>letter.charCodeAt(0));
          saveBlob(new Blob([bytes],{type:'application/zip'}),response.filename);
        }),'secondary slim'));
        return fields;
      });
      panel.append(table(['keyId',txt('language'),'ID',...(writer()?[txt('export')]:[])],rows));
    }
    const trust=element('section'); trust.className='ps-keys'; panel.append(trust); drawKeyList();
    const file=element('input'); file.type='file'; file.required=true; file.accept='.zip,application/zip';
    const verdict=element('p'); verdict.setAttribute('role','status');
    file.addEventListener('change',()=>verdict.replaceChildren());
    const verifier=element('form',null,'ps-form');
    verifier.append(note('verifyHint'),field(txt('verifyFile'),file),button(txt('verify'),null,'secondary','submit'),verdict);
    verifier.addEventListener('submit',perform(async stamp=>{
      verdict.replaceChildren();
      const selectedFile=file.files[0];
      const buffer=await fileBytes(selectedFile,3*1024*1024-4096);
      if (stamp!==generation) return;
      const result=await post(runPath()+'/verify',{archive_b64:encodeFile(buffer)});
      if (stamp!==generation || file.files[0]!==selectedFile) return;
      verdict.textContent=txt(result.valid?'valid':'invalid')+(result.keyId?' · '+result.keyId:'');
    }));
    panel.append(details(txt('verify'),verifier));
  }
  function drawKeyList() {
    const host=root.querySelector('.ps-keys'); if (!host) return;
    host.replaceChildren(element('h4',txt('keys')));
    if (!keys) { host.append(note('load')); return; }
    const list=element('ul',null,'records');
    for (const key of keys.keys || []) {
      const li=element('li');
      const id=key.keyId||key.kid; const jwk=key.publicJwk||key.jwk||key.publicKey;
      li.append(element('strong',(id===keys.activeKeyId?txt('active'):txt('historical'))+' · '+id),
        element('span',txt('fingerprint')+' · '+key.fingerprint,'fingerprint'));
      if (jwk) li.append(details('JWK',disclosureValue(jwk)));
      list.append(li);
    }
    host.append(list);
    if (member.role==='admin') host.append(button(txt('rotate'), perform(async stamp=>{
      if (!window.confirm(txt('confirmRotation'))) return;
      const result=await post(base()+'/rotate',{});
      if (stamp!==generation) return;
      keys=result; drawKeyList();
    }),'secondary slim'));
  }
  return {bind,clear,language,clearSensitive};
}
