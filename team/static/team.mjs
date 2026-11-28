// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {languages, messages} from './texts.mjs';
import {createReviewPanel} from './review-record.mjs';
import {indexPanel} from './evidence-index.mjs';
import {createProofStudio} from './proof-studio.mjs';
import {createFileReputation} from './file-reputation.mjs';
import {createZapLead, zapRule} from './zap-lead.mjs';

const $ = id => document.getElementById(id);
const roles = ['admin','lead_pentester','pentester','reviewer','read_only'];
const writers = new Set(['admin','lead_pentester','pentester']);
const approvers = new Set(['admin','lead_pentester','reviewer']);
const refs = new Map();
let locale = 'de';
let session;
let membership;
let cases = [];
let detail;
let trust;
let trustRequest = 0;
let teamEpoch = 0;
let caseEpoch = 0;
let savedMessage;
let authenticating = false;
const proofStudio = createProofStudio($('view-proof'),{request,encodeFile,fileBytes,saveBlob,onUnauthorized:explain});
const reputation = createFileReputation({request,t,download,onUnauthorized:explain});
const zapLead = createZapLead(document,t);
const reviewPanel = createReviewPanel($('control-reviews'), {
  download, onError:explain, reload:() => selectCase(detail.case.id,false),
  async post(payload,requestId) {
    const team = teamEpoch, selected = caseEpoch, path = casePath();
    const result = await request(path+'/control-reviews','POST',{...payload,request_id:requestId});
    if (!scoped(team,selected)) return result;
    // A newly linked revision also changes the minimal index on its finding.
    const updated = await request(path);
    if (scoped(team,selected)) {
      detail = updated;
      listItems('findings',updated.findings.map(finding => renderRecord(finding,'finding')));
    }
    return result;
  }
});

function t(key) {
  return messages[key]?.[languages.indexOf(locale)] || key;
}
function node(tag, text) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = String(text);
  return el;
}
function labelled(tag, key) {
  const el = node(tag, t(key));
  el.dataset.key = key;
  return el;
}
function option(value, text) {
  const el = node('option', text);
  el.value = value;
  return el;
}
function roleOptions(selected) {
  return roles.map(role => {
    const opt = labelled('option',role);
    opt.value = role;
    opt.selected = role === selected;
    return opt;
  });
}
function notice(key, error = false, info = '') {
  savedMessage = {key, error, info};
  const out = $('message');
  out.textContent = key ? t(key) + (info ? ' (' + info + ')' : '') : '';
  out.dataset.error = String(error);
}
function translate(lang) {
  locale = languages.includes(lang) ? lang : 'de';
  document.documentElement.lang = locale === 'de' ? 'de-CH' : locale;
  document.documentElement.dir = locale === 'ar' ? 'rtl' : 'ltr';
  $('locale').value = locale;
  proofStudio.language(locale);
  reputation.render();
  for (const el of document.querySelectorAll('[data-key]')) el.textContent = t(el.dataset.key);
  for (const el of document.querySelectorAll('[data-aria]')) el.setAttribute('aria-label',t(el.dataset.aria));
  if (savedMessage) notice(savedMessage.key,savedMessage.error,savedMessage.info);
  if (membership) $('account-role').textContent = t(membership.role);
  if (trust) renderTrust($('trust-select').value);
}
const localError = key => Object.assign(new Error(key),{local:true});
async function request(path, method='GET', data) {
  const headers = {Accept:'application/json'};
  if (data !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && session?.csrf) headers['X-CSRF-Token'] = session.csrf;
  let response;
  try {
    response = await fetch(path,{method,headers,cache:'no-store',credentials:'same-origin',
      ...(data === undefined ? {} : {body:JSON.stringify(data)})});
  } catch { throw localError('networkError'); }
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error(result.error || 'http_' + response.status),{status:response.status});
  return result;
}
function explain(error) {
  if (error.local) return notice(error.message,true);
  if (error.status === 401) {
    if (session) { signedOut(); notice('signInAgain',true); }
    else notice('unauth',true);
    return;
  }
  const key = error.status === 403 ? 'denied' : error.status === 409 ? 'conflict' : 'requestError';
  const known = {'invalid_credentials':'unauth','invalid_password_length':'passwordLength','last_admin':'lastAdmin',
    'existing_account':'existingMember','already_member':'alreadyMember','login_rate_limited':'rateLimited',
    'ZAP instance and observation must share the same HTTP method and target':'zapMismatch',
    'ZAP lead must identify the same scoped asset':'zapMismatch',
    'Control expectation and observation do not match':'controlMismatch',
    'A confirmed observation and its control require captured HTTP exchanges':'controlHelp',
    'The control requires a distinct source observation':'controlHelp',
    'Both HTTP exchanges require a recorded response status':'controlHelp',
    'Evidence and control must both identify the scoped asset':'controlHelp',
    'Retest requires new source bytes and fresh observations':'retestHelp',
    'A fix or persistent finding requires a confirmed baseline':'retestBaseline',
    'Retest observation does not match the declared outcome':'retestMatch'};
  const code = error.message.replace(/[\u0000-\u001f\u007f-\u009f]/g,'').slice(0,180);
  notice(known[code] || key,true,known[code] ? '' : code);
}
function run(action) {
  return async event => {
    event?.preventDefault();
    const control = event?.submitter || (event?.currentTarget?.tagName === 'BUTTON' ? event.currentTarget : null);
    if (control?.disabled) return;
    if (control) control.disabled = true;
    try { await action(event); } catch (error) { explain(error); }
    finally { if (control) control.disabled = false; }
  };
}
function base() {
  return '/api/teams/' + encodeURIComponent(membership.id);
}
function casePath() {
  return base() + '/cases/' + encodeURIComponent(detail.case.id);
}
function scoped(epoch, selectedEpoch) {
  return epoch === teamEpoch && (selectedEpoch === undefined || selectedEpoch === caseEpoch);
}
function fileBytes(file, max) {
  if (!file?.size || file.size > max) throw localError('badFile');
  return file.arrayBuffer();
}
function encodeFile(buffer) {
  const bytes = new Uint8Array(buffer), parts = [];
  for (let offset = 0; offset < bytes.length; offset += 16384) {
    parts.push(String.fromCharCode(...bytes.subarray(offset,offset + 16384)));
  }
  return btoa(parts.join(''));
}
function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const link = node('a'); link.href = url; link.download = name; document.body.append(link); link.click(); link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function download(data, name) {
  saveBlob(new Blob([JSON.stringify(data,null,2) + '\n'],{type:'application/json'}),name);
}
function clearPrivate() {
  proofStudio.clear();
  reputation.clear();
  reviewPanel.clear();
  zapLead.refresh([],true); zapLead.mode(false);
  for (const form of document.forms) if (form.id !== 'login-form') form.reset();
  for (const id of ['case-list','imports','findings','retests','member-list','audit-list','asset','retest-finding','verify-result','detail-title','detail-scope']) $(id).replaceChildren();
  for (const id of ['case-detail','view-members','view-audit']) $(id).hidden = true;
  for (const panel of document.querySelectorAll('#workspace details')) panel.open = false;
  $('verified-report').hidden = true; $('verified-report').replaceChildren();
  detail = null; cases = []; clearTrust();
  for (const {source,record} of refs.values()) { source.replaceChildren(); record.replaceChildren(); }
}
function signedOut() {
  ++teamEpoch; ++caseEpoch;
  clearPrivate();
  session = null; membership = null;
  for (const id of ['team-select','account-name','account-role','team-heading']) $(id).replaceChildren();
  $('login-form').reset(); $('workspace').hidden = true; $('logout').hidden = true; $('login-panel').hidden = false;
  notice('');
}
function showView(view) {
  const allowed = view === 'members' ? membership?.role === 'admin' : view === 'audit' ? approvers.has(membership?.role) : true;
  if (!allowed || view === 'cases' && membership?.legacyCases === false) return;
  if (view !== 'proof') proofStudio.clearSensitive();
  for (const name of ['proof','reputation','cases','members','audit']) {
    $('view-' + name).hidden = view !== name;
    const btn = document.querySelector('[data-view="' + name + '"]');
    if (view === name) btn.setAttribute('aria-current','page'); else btn.removeAttribute('aria-current');
  }
}
function listItems(id, items) {
  const list = $(id);
  if (!items.length) { const entry = labelled('li','emptyRecords'); entry.className = 'empty'; list.replaceChildren(entry); }
  else list.replaceChildren(...items);
}
function setOptions(select, options, prior, placeholder = true) {
  const empty = labelled('option','choose'); empty.value = ''; empty.disabled = true;
  select.replaceChildren(...(placeholder ? [empty] : []), ...options);
  if (prior && options.some(opt => opt.value === prior)) select.value = prior;
  else if (!placeholder || options.length === 1) select.value = options[0]?.value || '';
  else select.value = '';
}
function buildRef(prefix, control) {
  const container = $(prefix);
  const block = node('div'), pos = node('div');
  const label = labelled('label',control ? 'control' : 'evidence'), source = node('select');
  label.htmlFor = source.id = prefix + '-file';
  const recordLabel = labelled('label','record'), record = node('select');
  recordLabel.htmlFor = record.id = prefix + '-record';
  block.append(label,source); pos.append(recordLabel,record); container.append(block,pos);
  const field = {source,record,container,inputs:[source,record]};
  if (control) {
    for (const [name,key] of [['expected','controlExpected'],['observed','controlObserved']]) {
      const wrap = node('div'), label = labelled('label',key), input = node('textarea');
      label.htmlFor = input.id = prefix + '-' + name;
      input.dir = 'auto'; input.rows = 2; input.maxLength = 2000;
      wrap.append(label,input); container.append(wrap); field[name] = input; field.inputs.push(input);
    }
  }
  source.addEventListener('change', () => fillPositions(field));
  refs.set(prefix,field);
}
function fillPositions(field, prior) {
  const evidence = detail?.imports.find(item => String(item.id) === field.source.value);
  const entries = evidence?.entries || [];
  setOptions(field.record,entries.map(item => option(String(item.record),
    '#' + item.record + ' · ' + item.kind + (item.status_code ? ' · HTTP ' + item.status_code : '') +
    (item.fingerprint ? ' · ' + item.fingerprint.slice(0,12) : ''))),prior);
}
function refRequired(key, on) {
  const r = refs.get(key); r.container.hidden = !on;
  for (const el of r.inputs) { el.disabled = !on; el.required = on; }
}
function updateModes() {
  zapLead.mode($('finding-status').value === 'confirmed');
  refRequired('finding-evidence',true);
  refRequired('finding-control',$('finding-status').value === 'confirmed');
  $('control-help').hidden = $('finding-status').value !== 'confirmed';
  const status = $('retest-status').value;
  $('retest-help').hidden = status === 'not_retested';
  $('retest-description').hidden = status === 'not_retested';
  $('retest-observed').required = status !== 'not_retested';
  refRequired('retest-evidence',status !== 'not_retested');
  refRequired('retest-control',status === 'persists' || status === 'fix_verified');
  const existing = $('member-mode').value === 'existing';
  $('create-account').hidden = existing; $('member-password').required = !existing;
}
function reference(prefix, control = false) {
  const r = refs.get(prefix);
  if (r.container.hidden) return {};
  if (control) return {control_evidence_id:r.source.value,control_record:Number(r.record.value),
    control_expected:r.expected.value.trim(),control_observed:r.observed.value.trim()};
  return {evidence_id:r.source.value,record:Number(r.record.value)};
}
function listCases() {
  $('cases-empty').hidden = cases.length !== 0;
  $('case-list').replaceChildren(...cases.map(item => {
    const li = node('li'), btn = node('button',item.title); btn.type = 'button'; btn.dir = 'auto';
    if (detail?.case.id === item.id) btn.setAttribute('aria-current','true');
    btn.addEventListener('click',run(() => selectCase(item.id)));
    li.append(btn); return li;
  }));
}
function renderImport(item) {
  const li = node('li'), title = node('strong',item.format + ' · ' + item.records + ' ' + t('records'));
  li.append(title,node('small','SHA-256 · ' + item.sha256));
  if (item.entries?.length) {
    const disclosure = node('details'), summary = labelled('summary','showRecords'), list = node('ol');
    disclosure.append(summary);
    disclosure.addEventListener('toggle', () => {
      if (!disclosure.open || list.childElementCount) return;
      for (const row of item.entries) {
        const entry = node('li',(row.kind === 'scanner_alert' ? zapRule(row,t) : row.kind) + (row.status_code ? ' · HTTP ' + row.status_code : '') + ' · ' + row.fingerprint);
        entry.value = row.record; list.append(entry);
      }
      disclosure.append(list);
    });
    li.append(disclosure);
  }
  if (writers.has(membership.role)) {
    const button = labelled('button','originalFile'); button.type = 'button'; button.className = 'plain slim';
    button.addEventListener('click',run(async () => {
      const epoch = teamEpoch, selected = caseEpoch;
      const payload = await request(casePath() + '/imports/' + encodeURIComponent(item.id) + '/attachment');
      if (!scoped(epoch,selected)) return;
      const bytes = Uint8Array.from(atob(payload.content_b64),ch => ch.charCodeAt(0));
      const actual = new Uint8Array(await crypto.subtle.digest('SHA-256',bytes));
      const hash = Array.from(actual,value => value.toString(16).padStart(2,'0')).join('');
      if (hash !== item.sha256 || payload.sha256 !== hash) throw localError('digestMismatch');
      const extension = {nmap:'xml',burp:'xml',zap:'json',har:'har',nuclei:'jsonl',openapi:'json'}[item.format] || 'bin';
      if (scoped(epoch,selected)) saveBlob(new Blob([bytes],{type:'application/octet-stream'}),item.format + '-' + hash.slice(0,16) + '.' + extension);
    }));
    li.append(button);
  }
  return li;
}
function sourceReference(obj, control = false) {
  const ref = control ? obj.control?.reference : obj.evidence;
  return ref ? ref.format + ' · ' + ref.sha256.slice(0,14) + ' · #' + ref.record : '';
}
function renderRecord(item, kind) {
  const li = node('li'), title = node('strong',kind === 'finding' ? item.title : (detail.findings.find(f => f.id === item.finding_id)?.title || item.finding_id));
  title.dir = 'auto'; li.append(title,labelled('span',item.status));
  const pairs = [['asset',item.asset],['expected',item.expected],['observed',item.observed],
    ['evidence',sourceReference(item)],['control',sourceReference(item,true)],
    ['controlExpected',item.control?.expected],['controlObserved',item.control?.observed]];
  for (const [key,value] of pairs) if (value) {
    const line = node('small'); line.className = 'user-text';
    line.append(labelled('span',key),document.createTextNode(' · ' + value)); li.append(line);
  }
  if (item.scanner_lead) li.append(node('small',t('zapLead') + ' · #' + item.scanner_lead.record + ' · ' + item.scanner_lead.sha256));
  if (kind === 'finding' && item.evidence_index) {
    const slim = {schema:detail.evidence_index_schema, signed:false, team_id:membership.id,
      case_id:detail.case.id, finding_id:item.id, finding_sha256:item.finding_sha256,
      evidence_index:item.evidence_index, rights:'© Nasser Aldin Farag (0xFarag). All rights reserved.'};
    li.append(indexPanel(item.evidence_index,locale,() => download(slim,'authzledger-index-' + item.id + '.json')));
  }
  return li;
}
function renderCase(fresh) {
  $('case-detail').hidden = !detail;
  if (!detail) { reviewPanel.clear(); return; }
  const {case:item,imports,findings,retests} = detail;
  if (fresh) {
    for (const id of ['finding-form','retest-form','import-form']) $(id).reset();
    for (const panel of document.querySelectorAll('#case-detail details')) panel.open = false;
  }
  $('detail-title').textContent = item.title; $('detail-scope').textContent = item.scope;
  $('import-count').textContent = imports.length; $('finding-count').textContent = findings.length; $('retest-count').textContent = retests.length;
  reviewPanel.render({teamId:membership.id,item,imports,findings,records:detail.control_reviews || [],lang:locale,
    canPlan:writers.has(membership.role),canReview:writers.has(membership.role) || approvers.has(membership.role)});
  zapLead.refresh(imports,fresh);
  listItems('imports',imports.map(renderImport));
  listItems('findings',findings.map(f => renderRecord(f,'finding')));
  listItems('retests',retests.map(r => renderRecord(r,'retest')));
  for (const field of refs.values()) {
    const prior = fresh ? '' : field.source.value, pos = fresh ? '' : field.record.value;
    const opts = imports.map((imp, i) => option(String(imp.id),String(i + 1) + ' · ' + imp.format + ' · ' + imp.sha256.slice(0,14)));
    setOptions(field.source,opts,prior); fillPositions(field,pos);
  }
  const assets = item.assets || [];
  setOptions($('asset'),assets.map(asset => option(asset,asset)),fresh ? '' : $('asset').value);
  setOptions($('retest-finding'),findings.map(f => option(String(f.id),f.title)),fresh ? '' : $('retest-finding').value);
  const canWrite = writers.has(membership.role);
  $('import-tool').hidden = !canWrite; $('finding-tool').hidden = !canWrite || !imports.length;
  $('retest-tool').hidden = !canWrite || !findings.length; $('handover-tool').hidden = !approvers.has(membership.role);
  updateModes(); listCases();
}
async function selectCase(id, fresh = true) {
  const team = teamEpoch, epoch = ++caseEpoch;
  const result = await request(base() + '/cases/' + encodeURIComponent(id));
  if (!scoped(team,epoch)) return;
  detail = result; renderCase(fresh);
}
async function caseList(selected) {
  const epoch = teamEpoch;
  const result = await request(base() + '/cases');
  if (!scoped(epoch)) return;
  cases = result.cases; listCases();
  const id = selected || detail?.case.id || cases[0]?.id;
  if (id && cases.some(item => item.id === id)) await selectCase(id,detail?.case.id !== id);
  else { detail = null; renderCase(false); }
}
function clearTrust() {
  trust = null;
  for (const id of ['trust-select','trust-policy','trust-fingerprint','trust-dates']) $(id).replaceChildren();
  $('trust-select').disabled = true; $('download-key').disabled = true;
}
function selectedKey() {
  return trust?.keys.find(key => key.fingerprint === $('trust-select').value);
}
function showKey() {
  const key = selectedKey();
  $('download-key').disabled = !key;
  if (!key) return;
  const fingerprint = node('bdi',key.fingerprint); fingerprint.dir = 'ltr';
  $('trust-fingerprint').replaceChildren(labelled('span','fingerprint'),document.createTextNode(' · SHA-256 · '),fingerprint);
  const dates = $('trust-dates'); dates.replaceChildren();
  const formatter = new Intl.DateTimeFormat(document.documentElement.lang,{
    dateStyle:'medium',timeStyle:'long',timeZone:'UTC'
  });
  for (const [label,stamp] of [['trustActivated',key.activated_at],['trustRetiredAt',key.retired_at],['trustDue',key.rotate_after]]) {
    if (!stamp) continue;
    const date = new Date(stamp);
    const time = node('time',formatter.format(date)); time.dateTime = stamp;
    const line = node('span');
    line.append(labelled('span',label),document.createTextNode(' · '),time);
    dates.append(line);
  }
}
function renderTrust(fingerprint) {
  const select = $('trust-select');
  select.replaceChildren(...trust.keys.map(key => {
    const status = t(key.status === 'active' ? 'active' : 'trustRetired');
    return option(key.fingerprint,status + ' · ' + key.fingerprint.slice(0,16));
  }));
  select.value = trust.keys.some(key => key.fingerprint === fingerprint) ? fingerprint : trust.active_fingerprint;
  select.disabled = false;
  const days = new Intl.NumberFormat(locale).format(trust.rotation_days);
  $('trust-policy').textContent = t('trustPolicy').replace('{days}',days);
  showKey();
}
async function loadTrust() {
  const epoch = teamEpoch, serial = ++trustRequest;
  try {
    const data = await request(base() + '/trust-keys');
    if (!scoped(epoch) || serial !== trustRequest) return;
    // Follow the current signer unless the reviewer explicitly selected an older key.
    const selected = $('trust-select').value;
    const historical = selected && selected !== trust?.active_fingerprint ? selected : null;
    trust = data;
    renderTrust(historical);
  } catch (error) {
    if (!scoped(epoch) || serial !== trustRequest) return;
    clearTrust();
    if (error.status === 401) throw error;
    $('trust-policy').replaceChildren(labelled('span','trustUnavailable'));
  }
}
async function selectTeam(id) {
  ++teamEpoch; ++caseEpoch;
  clearPrivate(); notice('');
  membership = session.teams.find(item => String(item.id) === String(id));
  $('team-heading').textContent = membership?.name || t('noTeam');
  $('account-role').textContent = membership ? t(membership.role) : '';
  $('team-select').value = membership?.id || '';
  for (const [view,visible] of [['members',membership?.role === 'admin'],['audit',approvers.has(membership?.role)]]) {
    document.querySelector('[data-view="' + view + '"]').hidden = !visible;
  }
  $('new-case').hidden = !writers.has(membership?.role);
  const legacy = Boolean(membership) && membership.legacyCases !== false && !session.user.username.includes('@');
  document.querySelector('[data-view=cases]').hidden = !legacy;
  document.querySelector('[data-view=reputation]').hidden = !membership;
  $('member-user').type = legacy ? 'text' : 'email';
  $('member-user').maxLength = legacy ? 80 : 254;
  $('view-cases').hidden = true;
  $('view-proof').hidden = true;
  $('view-reputation').hidden = true;
  $('output-language').value = locale;
  if (!membership) return;
  const existingAlias = legacy && !session.user.username.includes('@');
  showView(existingAlias ? 'cases' : 'proof');
  const loads = [proofStudio.bind(membership,locale)];
  if (legacy) loads.push(caseList(),loadTrust());
  await Promise.all(loads);
}
async function signedIn(result, preferTeam) {
  session = result; translate(session.user.locale); $('login-form').reset();
  $('login-panel').hidden = true; $('logout').hidden = false; $('workspace').hidden = false;
  $('account-name').textContent = session.user.username;
  $('team-select').replaceChildren(...session.teams.map(team => option(String(team.id),team.name)));
  await selectTeam(session.teams.some(team => team.id === preferTeam) ? preferTeam : session.teams[0]?.id);
}
async function loadMembers() {
  const epoch = teamEpoch;
  const data = await request(base() + '/members');
  if (!scoped(epoch)) return;
  listItems('member-list',data.members.map(person => {
    const li = node('li'), heading = node('strong',person.username); heading.dir = 'auto';
    const summary = node('small'); summary.append(labelled('span',person.active ? 'active' : 'inactive'),document.createTextNode(' · '),labelled('span',person.role),document.createTextNode(' · ' + person.locale));
    li.append(heading,summary);
    if (!person.active) return li;
    const form = node('form'); form.className = 'member-actions';
    const roleLabel = node('label'); roleLabel.append(labelled('span','role'));
    const select = node('select'); select.replaceChildren(...roleOptions(person.role)); roleLabel.append(select);
    const save = labelled('button','saveRole'); save.type = 'submit'; save.className = 'secondary slim';
    const revoke = labelled('button','removeMember'); revoke.type = 'button'; revoke.className = 'plain slim danger';
    const mutate = async body => {
      await request(base() + '/members/' + encodeURIComponent(person.id),'PATCH',body);
      if (!scoped(epoch)) return;
      if (person.id === session.user.id) {
        const team = membership.id;
        await signedIn(await request('/api/session'),team);
      } else await loadMembers();
      notice('success');
    };
    form.addEventListener('submit',run(() => mutate({role:select.value})));
    revoke.addEventListener('click',run(async () => {
      if (window.confirm(t('confirmRemove') + '\n' + person.username)) await mutate({active:false});
    }));
    form.append(roleLabel,save,revoke); li.append(form);
    return li;
  }));
}
async function loadAudit() {
  const epoch = teamEpoch;
  const data = await request(base() + '/audit');
  if (!scoped(epoch)) return;
  $('audit-list').replaceChildren(...data.events.map(event => {
    const row = node('tr');
    const instant = new Date(event.at);
    const when = Number.isNaN(instant.getTime()) ? event.at : instant.toLocaleString(locale);
    for (const value of [when,event.actor,event.action,event.resource,event.outcome]) row.append(node('td',value));
    return row;
  }));
}
function formData(id) { return Object.fromEntries(new FormData($(id))); }
async function mutateCase(action, prepare) {
  if (!detail) return;
  const epoch = teamEpoch, selected = caseEpoch, path = casePath(), id = detail.case.id;
  const body = await prepare();
  if (!scoped(epoch,selected)) return;
  const result = await request(path + '/' + action,'POST',body);
  if (!scoped(epoch,selected)) return;
  const form = $(action === 'imports' ? 'import-form' : action + '-form');
  form.reset();
  await selectCase(id,false);
  if (scoped(epoch)) notice(action === 'imports' && result.duplicate ? 'duplicate' : 'success');
}
for (const prefix of ['finding','retest']) {
  buildRef(prefix + '-evidence',false); buildRef(prefix + '-control',true);
}
$('member-role').replaceChildren(...roleOptions('read_only'));
$('login-form').addEventListener('submit',run(async () => {
  if (authenticating) return; authenticating = true;
  try { await signedIn(await request('/api/login','POST',formData('login-form'))); }
  finally { $('password').value = ''; authenticating = false; }
}));
$('logout').addEventListener('click',run(async () => {
  reputation.resetInputs();
  await request('/api/logout','POST',{});
  signedOut();
}));
$('locale').addEventListener('change',run(async () => {
  const selected = $('locale').value;
  if (session) {
    try {
      await request('/api/me','PATCH',{locale:selected});
      const updated = await request('/api/session');
      if (!session) return;
      session = updated;
    } catch (error) { $('locale').value = locale; throw error; }
  }
  translate(selected);
  if (detail) renderCase(false);
}));
$('team-select').addEventListener('change',run(() => selectTeam($('team-select').value)));
for (const btn of document.querySelectorAll('[data-view]')) {
  btn.addEventListener('click',run(async () => {
    const view = btn.dataset.view;
    showView(view);
    if (view === 'reputation' && membership) await reputation.open(base());
    else if (view === 'members') await loadMembers();
    else if (view === 'audit') await loadAudit();
  }));
}
$('cases-reload').addEventListener('click',run(() => caseList()));
$('members-reload').addEventListener('click',run(loadMembers));
$('audit-reload').addEventListener('click',run(loadAudit));
$('case-form').addEventListener('submit',run(async () => {
  const epoch = teamEpoch, assets = $('case-assets').value.split(/\r?\n/).map(item => item.trim()).filter(Boolean);
  if (assets.length < 1 || assets.length > 32 || assets.some(asset => asset.length > 200)) throw localError('emptyAssets');
  const result = await request(base() + '/cases','POST',{...formData('case-form'),assets});
  if (!scoped(epoch)) return;
  $('case-form').reset(); $('new-case').open = false; await caseList(result.case.id); notice('success');
}));
$('import-form').addEventListener('submit',run(() => mutateCase('imports',async () => {
  const format = $('import-format').value;
  const buffer = await fileBytes($('import-file').files[0],1024 * 1024);
  return {format,content_b64:encodeFile(buffer)};
})));
$('finding-form').addEventListener('submit',run(() => mutateCase('finding',() => ({
  ...formData('finding-form'),...reference('finding-evidence'),...reference('finding-control',true),...zapLead.reference()}))));
$('retest-form').addEventListener('submit',run(() => mutateCase('retest',() => {
  const {finding_id,status,observed} = formData('retest-form');
  return {finding_id,status,...(status === 'not_retested' ? {} : {observed,...reference('retest-evidence'),...reference('retest-control',true)})};
})));
for (const id of ['finding-status','retest-status','member-mode']) $(id).addEventListener('change',updateModes);
$('handover-form').addEventListener('submit',run(async () => {
  const epoch = teamEpoch, selected = caseEpoch, id = detail.case.id;
  const result = await request(casePath() + '/handover','POST',formData('handover-form'));
  if (!scoped(epoch,selected)) return;
  const stem = 'authzledger-handover-' + id;
  if (result.package) download(result.package,stem + '.json');
  else {
    const data = Uint8Array.from(atob(result.archive_b64),c => c.charCodeAt(0));
    saveBlob(new Blob([data],{type:'application/zip'}),stem + '-' + result.format + '.zip');
  }
  notice('signed');
  await loadTrust();
}));
$('verify-form').addEventListener('submit',run(async () => {
  const epoch = teamEpoch, file = $('verify-file').files[0];
  $('verified-report').hidden = true; $('verified-report').replaceChildren();
  $('verify-result').replaceChildren();
  const buffer = await fileBytes(file,4 * 1024 * 1024 - 1024);
  const bytes = new Uint8Array(buffer);
  let body;
  if (bytes[0] === 0x50 && bytes[1] === 0x4b) {
    if (bytes.length > 3 * 1024 * 1024 - 4096) throw localError('badFile');
    body = {archive_b64:encodeFile(buffer)};
  } else {
    try { body = {package:JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(buffer))}; }
    catch { throw localError('badJson'); }
  }
  if (!scoped(epoch)) return;
  const result = await request(base() + '/verify','POST',body);
  if (!scoped(epoch) || $('verify-file').files[0] !== file) return;
  const panel = $('verify-result'); panel.dataset.error = String(!result.valid);
  panel.replaceChildren(labelled('strong',result.valid ? 'valid' : 'invalid'));
  if (result.valid && result.fingerprint) {
    const fingerprint = node('bdi',result.fingerprint); fingerprint.dir = 'ltr';
    panel.append(document.createTextNode(' · '),fingerprint);
    if (result.document_sha256) panel.append(node('p','SHA-256 · ' + result.document_sha256));
    showVerifiedReport(result.report || body.package.report);
  }
}));
function showVerifiedReport(report) {
  const out = $('verified-report'); out.replaceChildren();
  if (!report || !Array.isArray(report.appendix) || !report.labels || !report.counts) return;
  out.lang = languages.includes(report.language) ? report.language : locale; out.dir = out.lang === 'ar' ? 'rtl' : 'ltr';
  out.append(node('h3',report.title),node('strong',report.summary_heading));
  const counts = node('ul');
  for (const [key,value] of Object.entries(report.counts)) counts.append(node('li',(report.labels[key] || key) + ' · ' + value));
  out.append(counts,node('p',report.limitations));
  const appendix = node('details'), list = node('ol'); appendix.append(node('summary',report.appendix_heading));
  for (const item of report.appendix) {
    const li = node('li');
    li.append(node('strong',item.status_label + ' · ' + item.retest_label));
    if (item.scanner_lead) li.append(node('p',messages.zapLead[languages.indexOf(out.lang)] + ' · #' + item.scanner_lead.record + ' · ' + item.scanner_lead.sha256));
    const references = [item.retest_evidence,item.retest_control];
    if (item.evidence_index) li.append(indexPanel(item.evidence_index,out.lang));
    else references.unshift(item.evidence,item.control);
    for (const evidence of references) if (evidence) {
      li.append(node('p',evidence.format + ' · #' + evidence.record + ' · SHA-256 ' + evidence.sha256));
    }
    list.append(li);
  }
  appendix.append(list); out.append(appendix); out.hidden = false;
}
$('verify-file').addEventListener('change',() => { $('verify-result').replaceChildren(); $('verified-report').hidden = true; $('verified-report').replaceChildren(); });
$('trust-select').addEventListener('change',showKey);
$('trust-reload').addEventListener('click',run(loadTrust));
$('download-key').addEventListener('click',() => {
  const key = selectedKey();
  if (!key) return;
  const {algorithm,public_key,fingerprint} = key;
  download({algorithm,public_key,fingerprint},'authzledger-trust-' + fingerprint + '.json');
});
$('password-form').addEventListener('submit',run(async () => {
  const result = await request('/api/me','PATCH',formData('password-form'));
  if (result.reauthenticate) { signedOut(); notice('passwordChanged'); }
}));
$('member-form').addEventListener('submit',run(async () => {
  const epoch = teamEpoch, {username,role,password,locale} = formData('member-form');
  const fresh = $('member-mode').value === 'new';
  await request(base() + '/members','POST',{username,role,...(fresh ? {password,locale} : {})});
  if (!scoped(epoch)) return;
  $('member-form').reset(); $('member-role').value = 'read_only'; updateModes(); await loadMembers(); notice('success');
}));
$('team-form').addEventListener('submit',run(async () => {
  const epoch = teamEpoch;
  const {team} = await request('/api/teams','POST',formData('team-form'));
  if (!scoped(epoch)) return;
  await signedIn(await request('/api/session'),team.id); notice('success');
}));
translate((navigator.language || '').slice(0,2));
try {
  const data = await request('/api/session');
  await signedIn(data);
} catch (error) {
  if (error.status === 401) signedOut();
  else { if (!session) signedOut(); explain(error); }
}
