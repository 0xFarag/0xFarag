// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {analysisInputs, act, download} from './ui.mjs';
import {POLICY_BYTES, readPolicy, sha256} from './retest.mjs';
import {assessment, axes, createMatrix} from './matrix.mjs';
import {matrixText} from './matrix-languages.mjs';

const byId = id => document.getElementById('matrix-' + id);
const t = key => matrixText(document.documentElement.lang,key);
const node = (tag,text) => {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  return element;
};
let source, matrix, selected, notice = '';

function button(label,action) {
  const item = node('button',label);
  item.type = 'button';
  item.className = 'secondary';
  item.onclick = action;
  return item;
}
function expectedLabel(value) { return t(value === 'grant' ? 'expectGrant' : 'expectNone'); }
function subject(q) {
  let who = q.kind + ' ' + (q.subjectNamespace ? q.subjectNamespace + '/' : '') + q.name;
  if (q.groups.length) who += ' · ' + t('groups') + ' (' + q.groups.join(', ') + ')';
  return who;
}
function request(q) {
  const parts = [q.verb + ' ' + (q.apiGroup || 'core') + '/' + q.resource + (q.subresource ? '/' + q.subresource : ''),q.namespace || t('cluster')];
  if (q.resourceName) parts.push(t('name') + ' ' + q.resourceName);
  if (q.fieldSelectorName) parts.push(t('selector') + ' ' + q.fieldSelectorName);
  return parts.join(' · ');
}
function announce(key) {
  notice = key;
  byId('status').textContent = key ? t(key) : '';
}
function summary(current) {
  const counts = {matches:0,differs:0,uncertain:0};
  for (const row of matrix.rows) counts[assessment(row[current],row.expected)]++;
  return [t(current),...Object.entries(counts).map(([key,count])=>t(key) + ' ' + count)].join(' · ');
}
function table() {
  const host = byId('table');
  host.replaceChildren();
  if (!matrix?.rows.length) return;
  host.append(node('p',t('summary') + ' · ' + matrix.rows.length + '/32'),node('p',summary('before')));
  if (matrix.after) host.append(node('p',summary('after')));
  const subjects = new Map(), requests = new Map(), cells = new Map();
  for (const row of matrix.rows) {
    const [s,r] = axes(row.query);
    subjects.set(s,subject(row.query)); requests.set(r,request(row.query));
    if (!cells.has(s)) cells.set(s,new Map());
    cells.get(s).set(r,row);
  }
  const wrap = node('div'); wrap.className = 'matrix-scroll'; wrap.tabIndex = 0;
  wrap.setAttribute('role','region'); wrap.setAttribute('aria-label',t('title'));
  const grid = node('table'); grid.append(node('caption',t('matrixHint')));
  const head = grid.createTHead().insertRow();
  for (const text of [t('subject'),...requests.values()]) {
    const th = node('th',text); th.scope = 'col'; head.append(th);
  }
  const body = grid.createTBody();
  for (const [s,name] of subjects) {
    const tr = body.insertRow();
    const th = node('th',name); th.scope = 'row'; tr.append(th);
    for (const [r,requestName] of requests) {
      const td = tr.insertCell(), row = cells.get(s).get(r);
      if (!row) {
        const dash = node('span','—'); dash.setAttribute('aria-hidden','true');
        td.append(dash,node('span',t('empty'))); td.lastChild.className = 'matrix-sr';
        continue;
      }
      const item = button('',()=>{ selected=row.key; render(); focusDetail(); });
      item.className = 'matrix-cell';
      item.setAttribute('aria-pressed',String(selected === row.key));
      const lines = [expectedLabel(row.expected),t('before') + ' · ' + t(row.before.status)];
      if (row.after) lines.push(t('after') + ' · ' + t(row.after.status));
      const state = assessment(row.after || row.before,row.expected);
      lines.push(t(state));
      item.dataset.assessment = state;
      item.setAttribute('aria-label',[name,requestName,...lines].join(' · '));
      for (const line of lines) item.append(node('span',line));
      td.append(item);
    }
  }
  wrap.append(grid); host.append(wrap);
}
function translatedReason(reason) {
  if (reason === 'Der Snapshot enthält eine nicht vollständig exportierte Liste.') return t('partial');
  if (reason.startsWith('Eine namensraumgebundene Regel passt.')) return t('unknownScope');
  for (const [ending,key] of [[' · Clusterrolle aggregiert.','aggregated'],[' · Rollenbeleg fehlt.','missingRole']]) {
    if (reason.endsWith(ending)) return reason.slice(0,-ending.length) + ' · ' + t(key);
  }
  // The engine's numeric truncation notice is rendered next to the proof list below.
  return reason.startsWith('Die ersten ') ? '' : reason;
}
function evidence(host,label,snapshot,outcome,expected) {
  host.append(node('h4',t(label)),node('p',[t(outcome.status),t(assessment(outcome,expected)),t('rules') + ' ' + outcome.matchCount].join(' · ')));
  for (const reason of outcome.reasons) {
    const value = translatedReason(reason);
    if (value) host.append(node('p',value));
  }
  if (!outcome.matches.length) return;
  const roles = new Map(snapshot.model.roles.map(role=>[role.objectIndex,role]));
  const list = node('ol'), count = node('p');
  let shown = 0;
  const more = button(t('more'),next);
  function next() {
    const end = Math.min(shown + 10,outcome.matches.length);
    for (;shown<end;shown++) {
      const m = outcome.matches[shown];
      const li = node('li',m.bindingKind + ' ' + (m.namespace ? m.namespace+'/' : '') + m.bindingName + ' (#' + m.bindingIndex + ') → ' +
        m.roleKind + ' ' + m.roleName + ' (#' + m.roleIndex + ') · ' + t('rule') + ' ' + m.ruleIndex);
      const raw = node('code',JSON.stringify(roles.get(m.roleIndex).rules[m.ruleIndex-1]));
      raw.dir = 'ltr'; li.append(raw); list.append(li);
    }
    count.textContent = t('shown') + ' ' + shown + ' / ' + outcome.matchCount;
    more.hidden = shown >= outcome.matches.length;
  }
  next(); host.append(list,count,more);
}
function focusDetail() { byId('detail').querySelector('h3')?.focus(); }
function details() {
  const host = byId('detail'); host.replaceChildren();
  const row = matrix?.rows.find(item=>item.key===selected);
  if (!row) return;
  const title = node('h3',t('detail')); title.tabIndex = -1;
  host.append(title,node('p',subject(row.query)),node('p',request(row.query)));
  const label = node('label',t('expected')), choice = node('select');
  label.htmlFor = choice.id = 'matrix-edit';
  for (const value of ['grant','no_grant']) choice.add(new Option(expectedLabel(value),value));
  choice.value = row.expected;
  choice.onchange = () => {
    matrix.setExpected(selected,choice.value); announce('updated'); render(); byId('edit').focus({preventScroll:true});
  };
  const remove = button(t('remove'),()=>{
    matrix.remove(selected); selected=null; announce('removed'); render(); byId('tools').querySelector('a').focus();
  });
  const controls = node('div'); controls.className='matrix-entry'; controls.append(label,choice,remove); host.append(controls);
  evidence(host,'before',source,row.before,row.expected);
  if (row.after) evidence(host,'after',matrix.after,row.after,row.expected);
}
function render() {
  for (const item of document.querySelectorAll('[data-matrix-text]')) item.textContent = t(item.dataset.matrixText);
  byId('tools').hidden = byId('entry').hidden = !source;
  byId('start').hidden = Boolean(source);
  byId('help').textContent = t(source ? 'guide' : 'start');
  byId('add').disabled = !analysisInputs().lastQuery;
  byId('save').disabled = !matrix?.rows.length;
  byId('clear-after').hidden = !matrix?.after;
  announce(notice);
  const hashes = byId('hashes'); hashes.replaceChildren();
  if (matrix?.after) {
    for (const [label,file] of [['before',source],['after',matrix.after]]) {
      const p = node('p',t(label) + ' SHA-256 '); p.append(node('code',file.digest)); hashes.append(p);
    }
    if (source.digest === matrix.after.digest) hashes.append(node('p',t('identical')));
  }
  table(); details();
}
function sync() {
  const inputs = analysisInputs();
  if (source !== inputs.original) {
    source = inputs.original;
    matrix = source ? createMatrix(source) : null;
    selected = null; notice = '';
    render();
  } else byId('add').disabled = !inputs.lastQuery;
}
byId('start').onclick = () => document.getElementById('original').click();
byId('add').onclick = () => {
  const query = analysisInputs().lastQuery;
  if (!query || !matrix) return;
  try {
    selected = matrix.add(query,byId('target').value); announce('added'); render(); focusDetail();
  } catch (error) { announce(error.message); byId('status').scrollIntoView({block:'nearest'}); }
};
function handleFile(inputId, buttonId, fallback, open) {
  const input = byId(inputId);
  byId(buttonId).onclick = ()=>input.click();
  input.onchange = () => {
    const file = input.files[0]; input.value = '';
    if (!file || !matrix) return;
    act('matrix-status',async ()=>{
      try {
        if (file.size > POLICY_BYTES || file.size < 1) throw Error(fallback);
        await open(new Uint8Array(await file.arrayBuffer()));
      } catch (error) {
        const key = ['wrongSource','duplicate'].includes(error.message) ? error.message : fallback;
        announce(key);
      }
      render();
    });
  };
}
handleFile('after','open-after','badSnapshot',async data=>{
  const model = readPolicy(data);
  matrix.compare({model,digest:await sha256(data)}); announce('compared');
});
handleFile('file','load','badFile',data=>{
  matrix.restore(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(data)));
  selected = matrix.rows[0].key; announce('loaded');
});
byId('clear-after').onclick = ()=>{ matrix.compare(null); announce('cleared'); render(); byId('open-after').focus(); };
byId('save').onclick = ()=>download(matrix.export(),'AuthzLedger-RBAC-Matrix.json');
window.addEventListener('rbacinputs',sync);
window.addEventListener('authzlanguage',render);
sync(); render();
