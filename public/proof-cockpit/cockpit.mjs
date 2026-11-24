// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {readJson,sha256,verifyDelivery} from './verify.mjs';

const el = id => document.getElementById('proof-'+id);
const form = document.getElementById('beweis-cockpit');
const t = value => window.AuthzI18n?.t(value) || value;
const labels = {
  findings:'Befunde', confirmed:'Bestätigt', hint:'Hinweise', not_retested:'Nicht nachgeprüft', persists:'Besteht weiter',
  fix_verified:'Fix nachgeprüft', inconclusive:'Unklar', key:'Der Schlüssel oder sein Fingerabdruck passt nicht zur Übergabe.',
  structure:'Die Kontroll-, Quellen- oder Retest-Verweise im signierten Bericht sind widersprüchlich.',
  invalid:'Signatur oder Berichtsdigest ungültig.', documentMismatch:'Das Dokument stimmt nicht mit dem signierten Nachweis überein.',
  documentNeeded:'Wählen Sie zusätzlich das unveränderte PDF oder HTML aus dem ZIP.',
  profile:'Erwartet wird eine signierte Team-Übergabe oder die Datei proof.json aus dem Dokumentpaket.',
  unsupported:'Dieser Browser unterstützt die benötigte Ed25519-Prüfung nicht.',
  size:'Die Datei überschreitet die Grössenbegrenzung oder ist leer.', json:'Die Datei enthält kein eindeutiges UTF-8-JSON.',
  file:'Die Datei konnte nicht gelesen werden.', checking:'Signatur und Belegverweise werden geprüft.',
  valid:'Signatur und Belegverweise geprüft.', match:'Die Originaldatei entspricht einer signierten Quelle.',
  miss:'Die Datei stimmt mit keiner Quelle in dieser Übergabe überein.'
};
let result = null, selected = 0, generation = 0, originalJob = 0, status = '', match = '', busy = false;
function element(tag, text) {
  const item = document.createElement(tag);
  if (text !== undefined) item.textContent = text;
  return item;
}
function pair(dl, name, value) {
  dl.append(element('dt',t(name)),element('dd',value));
}
function renderCase() {
  const target = el('case');
  target.replaceChildren();
  const row = result?.rows[selected];
  if (!row) return;
  const detail = element('dl');
  pair(detail,'Befund-ID',row.id);
  pair(detail,'Befunddigest',row.finding_sha256);
  target.append(detail);
  for (const [field,label] of [['evidence','Beobachtung'],['control','Kontrolle'],['retest_evidence','Retest-Beobachtung'],['retest_control','Retest-Kontrolle']]) {
    const ref = row[field];
    if (!ref) continue;
    const section = element('details'), source = element('dl');
    section.append(element('summary',t(label) + ' · '+ref.format.toUpperCase()+' #'+ref.record),source);
    pair(source,'SHA-256 der Quelldatei',ref.sha256);
    pair(source,'Datensatz-Fingerabdruck',ref.fingerprint);
    target.append(section);
  }
}
function messages() {
  el('status').textContent = status ? t(labels[status]) : '';
  el('status').dataset.error = String(!!status && !['valid','checking'].includes(status));
  el('match').textContent = match ? t(labels[match]) : '';
}
function render() {
  messages();
  el('result').hidden = !result;
  el('counts').replaceChildren(); el('rows').replaceChildren(); el('digests').replaceChildren();
  if (!result) { el('case').replaceChildren(); return; }
  for (const key of ['confirmed','hint','fix_verified','persists','inconclusive','not_retested']) {
    const metric = element('div');
    metric.append(element('strong',String(result.counts[key])),element('span',t(labels[key])));
    el('counts').append(metric);
  }
  for (const [i,row] of result.rows.entries()) {
    const option = element('option','#'+(i+1)+' · '+t(labels[row.status])+' · '+t(labels[row.retest]));
    option.value = String(i); el('rows').append(option);
  }
  el('rows').disabled = !result.rows.length;
  if (result.rows.length) el('rows').value = String(selected);
  else el('rows').append(element('option',t('Keine Befunde in dieser Übergabe.')));
  const dl = element('dl');
  pair(dl,'Schlüssel-Fingerabdruck',result.fingerprint); pair(dl,'Scope-Digest',result.scope);
  if (result.format) pair(dl,'Dokumentformat',result.format.toUpperCase());
  el('digests').append(dl);
  renderCase();
}
function invalidate() {
  generation++; originalJob++; result = null; selected = 0; status = ''; match = ''; busy = false;
  el('original').value = ''; form.querySelector('button').disabled = false;
  render();
}
for (const id of ['package','key','document']) el(id).addEventListener('change',invalidate);
el('clear').addEventListener('click',()=>{form.reset(); invalidate(); el('package').focus();});
el('rows').addEventListener('change',()=>{ selected = el('rows').selectedIndex; renderCase(); });
async function bytes(file, limit) {
  if (!file || !file.size || file.size > limit) throw new Error('size');
  try { return new Uint8Array(await file.arrayBuffer()); }
  catch { throw new Error('file'); }
}
form.addEventListener('submit',async event=>{
  event.preventDefault();
  if (busy) return;
  invalidate();
  const revision = generation;
  busy = true; form.querySelector('button').disabled = true; status = 'checking'; messages();
  try {
    const [packageData,trustData,documentData] = await Promise.all([
      bytes(el('package').files[0],8*1024*1024), bytes(el('key').files[0],4096),
      el('document').files[0] ? bytes(el('document').files[0],32*1024*1024) : null
    ]);
    const value = await verifyDelivery(readJson(packageData,8*1024*1024),readJson(trustData,4096),documentData);
    if (revision !== generation) return;
    result = value; status = 'valid'; render(); el('result-title').focus();
  } catch (error) {
    if (revision !== generation) return;
    status = Object.hasOwn(labels,error.message) ? error.message : 'invalid';
    if (status === 'documentNeeded') el('document-options').open = true;
    render();
  } finally {
    if (revision === generation) { busy = false; form.querySelector('button').disabled = false; }
  }
});
el('original').addEventListener('change',async()=>{
  const revision = ++originalJob;
  match = ''; messages();
  if (!result || !el('original').files[0]) return;
  try {
    const hash = await sha256(await bytes(el('original').files[0],1048576));
    if (revision !== originalJob) return;
    match = result.sources.some(source=>source.sha256 === hash) ? 'match' : 'miss';
  } catch (error) { if (revision === originalJob) match = Object.hasOwn(labels,error.message) ? error.message : 'file'; }
  if (revision === originalJob) messages();
});
window.addEventListener('authzlanguage',render);
