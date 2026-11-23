// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {evaluateAccess} from './model.mjs';
import {CASE_LIMIT, POLICY_BYTES, makeBaseline, normalizeQuery, readPolicy, retestPolicy, sha256} from './retest.mjs';

const $ = id => document.getElementById(id);
const field = key => $('query-form').elements.namedItem(key);
const labels = {
  granted_in_snapshot:'Eine Regel im Snapshot gewährt diese Anfrage',
  no_grant_in_snapshot:'Im Snapshot wurde keine passende Erlaubnis gefunden',
  indeterminate:'Aus den vorhandenen Belegen nicht entscheidbar',
  not_retested:'Nicht erneut geprüft (not_retested)',
  snapshot_decision_changed:'Entscheidung im Snapshot geändert',
  snapshot_evidence_changed:'Regelbeleg oder Begründung für dieselbe Entscheidung geändert',
  snapshot_result_repeated:'Entscheidung und dokumentierter Regelbeleg wiederholt'
};
let original, current, basis, report, lastQuery, busy = false;
let queries = [];

// Bind interface text only. Original RBAC names, groups, hashes and rule values
// stay verbatim, including when their spelling coincides with a translated label.
const bindings = new WeakMap();
const namedButtons = new WeakMap();
const t = (source, params = {}) => window.AuthzI18n?.t(source, params) ??
  source.replace(/\{(\w+)\}/gu, (_, key) => String(params[key]));
const label = (source, params) => () => t(source, params);
function setText(item, content) {
  const render = typeof content === 'function' ? content : null;
  const text = document.createTextNode(render ? render() : content);
  item.replaceChildren(text);
  if (render) bindings.set(text, render);
}
window.addEventListener('authzlanguage', () => {
  const walker = document.createTreeWalker($('main'), NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const node = walker.currentNode;
    const render = bindings.get(node);
    if (render) node.data = render();
  }
  for (const button of $('queries').querySelectorAll('button')) {
    const render = namedButtons.get(button);
    if (render) button.setAttribute('aria-label', render());
  }
});

function message(source) {
  // Parameterized messages from the offline model: only the fixed text is translated.
  const patterns = [
    [/^(\d+) Bindungen verweisen auf fehlende Rollen\.$/u, '{n} Bindungen verweisen auf fehlende Rollen.', ['n']],
    [/^(\d+) aggregierte Clusterrollen benötigen einen separaten Nachweis\.$/u, '{n} aggregierte Clusterrollen benötigen einen separaten Nachweis.', ['n']],
    [/^Die ersten (\d+) von (\d+) Regelverweisen werden angezeigt\.$/u, 'Die ersten {shown} von {total} Regelverweisen werden angezeigt.', ['shown','total']],
    [/^(.+) · (Rollenbeleg fehlt\.|Clusterrolle aggregiert\.)$/u, '{binding} · {reason}', ['binding','reason']],
    [/^(.+) muss ein JSON-Objekt sein\.$/u, '{field} muss ein JSON-Objekt sein.', ['field']],
    [/^(.+) ist ungültig\.$/u, '{field} ist ungültig.', ['field']],
    [/^Ungültige Anzahl für (.+)\.$/u, 'Ungültige Anzahl für {field}.', ['field']],
    [/^(.+) benötigt einen konkreten API-Wert\.$/u, '{field} benötigt einen konkreten API-Wert.', ['field']],
    [/^(.+) enthält nicht unterstützte Felder\.$/u, '{field} enthält nicht unterstützte Felder.', ['field']]
  ];
  for (const [pattern, template, keys] of patterns) {
    const match = pattern.exec(source);
    if (!match) continue;
    return () => {
      const direct = t(source);
      if (direct !== source) return direct;
      const params = Object.fromEntries(keys.map((key, i) => [key, ['reason','field'].includes(key) ? t(match[i + 1]) : match[i + 1]]));
      return t(template, params);
    };
  }
  return label(source);
}

function el(tag, text) {
  const item = document.createElement(tag);
  setText(item, text);
  return item;
}
function dl(container, pairs) {
  const list = el('dl','');
  for (const [label,value] of pairs) {
    list.append(el('dt',() => t(label)),el('dd',value));
  }
  container.append(list);
}
function demo(later) {
  const group = 'rbac.authorization.k8s.io';
  const apiVersion = group + '/v1';
  const metadata = name => ({name,namespace:'atelier'});
  return new TextEncoder().encode(JSON.stringify({apiVersion:'v1',kind:'List',items:[
    {apiVersion,kind:'Role',metadata:metadata('leserolle'),rules:[{verbs:later ? ['list'] : ['get','list'],apiGroups:[''],resources:['pods']}]},
    {apiVersion,kind:'RoleBinding',metadata:metadata('team-lesezugriff'),subjects:[{kind:'User',name:'beispiel.nora'}],
      roleRef:{apiGroup:group,kind:'Role',name:'leserolle'}}
  ]}, null, 2));
}
async function bytes(file) {
  if (!file || file.size < 1 || file.size > POLICY_BYTES) throw Error('Wählen Sie eine UTF-8-JSON-Datei von 1 Byte bis 2 MiB.');
  return new Uint8Array(await file.arrayBuffer());
}
async function snapshot(content, example) {
  return {bytes:content, model:readPolicy(content), digest:await sha256(content), example};
}
function showSnapshot(target, value) {
  const box = $(target);
  box.replaceChildren();
  dl(box,[['Datei-SHA-256',value.digest],['Rollen und Bindungen',label('{roles} Rollen · {bindings} Bindungen', value.model.counts)]]);
  if (value.model.warnings.length) {
    const warnings = el('ul','');
    for (const warning of value.model.warnings) warnings.append(el('li',message(warning)));
    box.append(warnings);
  }
}
function queryLabel(q) {
  const who = q.kind + ' ' + (q.kind === 'ServiceAccount' ? q.subjectNamespace + '/' : '') + q.name;
  const attributes = [who, q.verb + ' ' + (q.apiGroup || 'core') + '/' + q.resource + (q.subresource ? '/' + q.subresource : ''), q.namespace || t('clusterweit')];
  if (q.resourceName) attributes.push(t('Name {value}', {value:q.resourceName}));
  if (q.fieldSelectorName) attributes.push(t('Namensselektor {value}', {value:q.fieldSelectorName}));
  if (q.groups.length) attributes.push(t('Gruppen {value}', {value:q.groups.join(', ')}));
  return attributes.join(' · ');
}
function clearReport() {
  report = null;
  $('save-result').hidden = true;
  $('results').replaceChildren();
  $('retest-status').textContent = '';
}
function listChoices() {
  $('selection').replaceChildren(el('legend',label('Fragen für diesen Retest')));
  if (!basis) return;
  for (const [index,c] of basis.cases.entries()) {
    const label = el('label','');
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.value = String(index);
    input.addEventListener('change',clearReport);
    label.append(input,el('span',() => (index+1) + '. ' + queryLabel(c.query)));
    $('selection').append(label);
  }
}
function clearBasis() {
  basis = current = null;
  $('save-basis').hidden = $('retest').hidden = true;
  $('compare').disabled = true;
  for (const id of ['basis-status','basis-hash','current-status','current-info']) $(id).replaceChildren();
  listChoices();
  clearReport();
}
function listQueries() {
  $('queries').replaceChildren();
  for (const [index,q] of queries.entries()) {
    const li = el('li',() => queryLabel(q));
    const remove = el('button',label('Entfernen'));
    remove.className = 'secondary inline';
    const name = label('Frage {n} entfernen', {n:index + 1});
    remove.setAttribute('aria-label', name());
    namedButtons.set(remove, name);
    remove.onclick = () => {
      if (busy) return;
      queries.splice(index,1);
      clearBasis();
      listQueries();
    };
    li.append(remove);
    $('queries').append(li);
  }
  $('make').disabled = !queries.length;
}
// The optional matrix reads the same validated input and source as the single-query view.
export function analysisInputs() { return {original, lastQuery}; }
function notifyInputs() { window.dispatchEvent(new Event('rbacinputs')); }
function clearQuery() {
  lastQuery = null;
  notifyInputs();
  $('keep').disabled = true;
  $('query-status').textContent = '';
  $('proofs').replaceChildren();
}
function subjectFields() {
  const account = field('kind').value === 'ServiceAccount';
  $('sa-label').hidden = !account;
  field('subjectNamespace').disabled = !account;
  field('subjectNamespace').required = account;
}
function reset() {
  original = null;
  queries = [];
  clearBasis();
  clearQuery();
  listQueries();
  $('clear').hidden = $('workspace').hidden = true;
  $('query-form').reset();
  subjectFields();
  $('source-info').replaceChildren();
}
async function openOriginal(file, example) {
  const next = await snapshot(example ? demo(false) : await bytes(file), example);
  reset();
  original = next;
  notifyInputs();
  $('clear').hidden = $('workspace').hidden = false;
  setText($('source-status'), label(example ? 'Synthetischer Beispiel-Snapshot geöffnet.' : 'Eigener Snapshot geöffnet.'));
  showSnapshot('source-info',original);
  if (example) {
    field('name').value = 'beispiel.nora';
    field('namespace').value = 'atelier';
    field('resource').value = 'pods';
  }
}
function readQuery() {
  const data = new FormData($('query-form'));
  const q = Object.fromEntries(data.entries());
  // Spaces inside a subject or group are significant; remove only input line delimiters.
  q.groups = q.groups.split(/\r?\n/).filter(Boolean);
  return normalizeQuery(q);
}
function runQuery() {
  clearQuery();
  const query = readQuery();
  const result = evaluateAccess(original.model,query);
  setText($('query-status'), () => t('{state} · {n} passende Regeln.', {state:t(labels[result.status]), n:result.matchCount}));
  const output = $('proofs');
  for (const reason of result.reasons) output.append(el('p',message(reason)));
  if (result.matches.length) {
    const list = el('ol','');
    const more = el('button',label('Weitere Regelbelege anzeigen'));
    more.type = 'button';
    more.className = 'secondary';
    let shown = 0;
    const roles = new Map(original.model.roles.map(r => [r.objectIndex,r]));
    function appendMatches() {
      const end = Math.min(shown + 20,result.matches.length);
      for (;shown < end;shown++) {
        const m = result.matches[shown];
        const rule = roles.get(m.roleIndex).rules[m.ruleIndex-1];
        const entry = el('li', label('{binding} (Objekt {b}) · {role} (Objekt {r}) · Regel {n}', {
          binding:m.bindingKind + ' ' + m.bindingName, b:m.bindingIndex, role:m.roleKind + ' ' + m.roleName, r:m.roleIndex, n:m.ruleIndex
        }));
        entry.append(el('p',() => t('Verben {verbs} · API-Gruppen {groups} · Ressourcen {resources}', {
          verbs:rule.verbs.join(', '), groups:rule.apiGroups.map(g => g || 'core').join(', '), resources:rule.resources.join(', ')
        }) + (rule.resourceNames.length ? ' · ' + t('Namen {names}', {names:rule.resourceNames.join(', ')}) : '')));
        list.append(entry);
      }
      more.hidden = shown >= result.matches.length;
    }
    more.onclick = appendMatches;
    output.append(list,more);
    appendMatches();
  }
  lastQuery = query;
  notifyInputs();
  $('keep').disabled = false;
}
function activateBasis(value) {
  clearBasis();
  basis = value;
  setText($('basis-status'), label('{n} Fragen an den ursprünglichen Snapshot gebunden.', {n:basis.cases.length}));
  dl($('basis-hash'),[['SHA-256 der Prüfbasis',basis.baseline_sha256]]);
  $('save-basis').hidden = $('retest').hidden = false;
  $('demo-current').hidden = !original.example;
  $('pick-current').hidden = original.example;
  listChoices();
}
async function restore(file) {
  const content = await bytes(file);
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(content)); }
  catch { throw Error('Die gespeicherte Basis ist kein gültiges UTF-8-JSON.'); }
  // Recompute each original decision and validate the entire unsigned baseline before reuse.
  await retestPolicy(value,original.bytes,original.bytes,[]);
  queries = value.cases.map(c=>normalizeQuery(c.query));
  listQueries();
  activateBasis(value);
}
async function openCurrent(file) {
  clearReport();
  current = null;
  $('current-info').replaceChildren();
  $('compare').disabled = true;
  listChoices();
  current = await snapshot(original.example ? demo(true) : await bytes(file), original.example);
  setText($('current-status'), label(original.example ? 'Geänderter Beispiel-Snapshot geöffnet.' : 'Späterer Snapshot geöffnet.'));
  showSnapshot('current-info',current);
  $('compare').disabled = false;
}
async function compare() {
  clearReport();
  const chosen = Array.from($('selection').querySelectorAll('input:checked'),item=>Number(item.value));
  report = await retestPolicy(basis,original.bytes,current.bytes,chosen);
  const {coverage} = report;
  const identical = report.identical_source_bytes;
  setText($('retest-status'), () => t('{retested} von {total} erneut geprüft · {not_retested} not_retested.', coverage) +
    (identical ? ' ' + t('Beide Snapshots haben identische Bytes.') : ''));
  const result = $('results');
  dl(result,[['Original-SHA-256',report.original_policy_sha256],['Späterer SHA-256',report.current_policy_sha256],['Basis-SHA-256',report.baseline_sha256]]);
  const list = el('ol','');
  for (const [i,entry] of report.cases.entries()) {
    const entryQuery = basis.cases[i].query;
    const item = el('li', () => queryLabel(entryQuery));
    item.append(el('p',() => t('{state} · Vorher: {before}', {state:t(labels[entry.status]), before:t(labels[entry.before.status])}) +
      (entry.after ? ' · ' + t('Danach: {after}', {after:t(labels[entry.after.status])}) : '')));
    list.append(item);
  }
  result.append(list);
  $('save-result').hidden = false;
}
export function download(data,name) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data,null,2)+'\n'],{type:'application/json'}));
  const link = el('a','');
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
}
export async function act(status,fn) {
  if (busy) return;
  busy = true;
  const focus = document.activeElement;
  $('main').setAttribute('aria-busy','true');
  $('main').inert = true;
  try { await fn(); }
  catch (error) { setText($(status), message(error.message)); }
  finally {
    $('main').inert = false;
    $('main').removeAttribute('aria-busy');
    busy = false;
    if (focus instanceof HTMLElement && focus !== document.body && focus.isConnected && focus.offsetParent !== null && !focus.disabled) {
      focus.focus({preventScroll:true});
    }
  }
}
function inputButton(id,picker,status,open) {
  $(picker).onclick = () => $(id).click();
  $(id).onchange = () => {
    const file = $(id).files[0];
    $(id).value = '';
    if (file) act(status,()=>open(file));
  };
}
inputButton('original','pick-original','source-status',file=>openOriginal(file,false));
inputButton('current','pick-current','current-status',openCurrent);
inputButton('basis-file','load-basis','basis-status',restore);
$('example').onclick = () => act('source-status',()=>openOriginal(null,true));
$('clear').onclick = () => {reset(); setText($('source-status'), label('Lokale Sitzung geleert.')); $('pick-original').focus();};
$('query-form').oninput = event => {
  if (event.target.closest('#matrix-entry')) return;
  subjectFields(); clearQuery();
};
$('query-form').onsubmit = event => {event.preventDefault(); act('query-status',runQuery);};
$('keep').onclick = () => act('query-status',() => {
  if (!lastQuery) return;
  if (queries.some(q=>JSON.stringify(q) === JSON.stringify(lastQuery))) throw Error('Diese Frage ist bereits in der Liste.');
  if (queries.length >= CASE_LIMIT) throw Error('Die Prüfbasis enthält bereits 32 Fragen.');
  queries.push(lastQuery);
  clearBasis();
  listQueries();
  $('keep').disabled = true;
  setText($('query-status'), label('Frage {n} übernommen.', {n:queries.length}));
});
$('make').onclick = () => act('basis-status',async ()=>activateBasis(await makeBaseline(original.digest,queries,original.model)));
$('save-basis').onclick = () => download(basis,'AuthzLedger-RBAC-Basis.json');
$('demo-current').onclick = () => act('current-status',()=>openCurrent(null));
$('compare').onclick = () => act('retest-status',compare);
$('save-result').onclick = () => download(report,'AuthzLedger-RBAC-Retest.json');
