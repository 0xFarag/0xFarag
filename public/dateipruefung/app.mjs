// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {
  MAX_FILE_BYTES, MAX_HASH_LIST_BYTES, MAX_REPORT_BYTES,
  inspectFile, parseHashList, matchKnownHash, checkVirusTotalReport
} from './model.mjs';

const $ = id => document.getElementById(id);
const labels = [
  ['malicious','Als schädlich gemeldet'], ['suspicious','Als verdächtig gemeldet'],
  ['harmless','Als unbedenklich gemeldet'], ['undetected','Keine Erkennung gemeldet'],
  ['timeout','Zeitüberschreitung'], ['confirmed-timeout','Bestätigte Zeitüberschreitung'],
  ['failure','Analyse fehlgeschlagen'], ['type-unsupported','Dateityp nicht unterstützt']
];
let session, listRevision = 0, reportRevision = 0;
const number = n => n.toLocaleString('de-CH');

function element(tag, text) {
  const result = document.createElement(tag);
  result.textContent = text;
  return result;
}

function feedback(id, text, error = false) {
  const target = $(id + '-status');
  target.textContent = text;
  target.toggleAttribute('data-error', error);
}

function reset() {
  session = null;
  $('clear').hidden = $('summary').hidden = $('sources').hidden = true;
  for (const id of ['file', 'list', 'vt']) {
    $(id).value = '';
    feedback(id,'');
  }
  for (const id of ['sha256', 'sha512', 'format', 'size', 'entropy', 'signals', 'vt-result']) $(id).replaceChildren();
}

async function openFile(file) {
  reset();
  if (!file || file.size > MAX_FILE_BYTES) {
    feedback('file', 'Wählen Sie eine Datei bis 16 MiB.', true);
    return;
  }
  const current = {model:null, list:null, report:null, readingList:false, readingReport:false};
  session = current;
  $('clear').hidden = false;
  feedback('file','Dateibytes werden lokal geprüft …');
  try {
    const model = await inspectFile(new Uint8Array(await file.arrayBuffer()), file.name);
    if (session !== current) return;
    current.model = model;
    $('sha256').textContent = model.sha256;
    $('sha512').textContent = model.sha512;
    $('format').textContent = model.format.label;
    $('size').textContent = number(model.size) + ' Bytes';
    $('entropy').textContent = model.size ? model.entropy.toLocaleString('de-CH', {maximumFractionDigits:3}) + ' Bit/Byte' : '0 (leere Datei)';
    if (model.signals.length) {
      const signals = element('ul','');
      for (const signal of model.signals) signals.append(element('li',signal.label));
      $('signals').append(signals);
    } else {
      $('signals').textContent = 'Für die geprüften Merkmale wurde kein Hinweis ausgelöst.';
    }
    $('summary').hidden = $('sources').hidden = false;
    $('export').disabled = false;
    const displayName = file.name.replace(/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu,
      char => '[U+' + char.codePointAt(0).toString(16).toUpperCase().padStart(4,'0') + ']');
    feedback('file','Lokal geprüft: ' + displayName);
  } catch {
    if (session === current) feedback('file','Die lokale Prüfung konnte die Datei nicht lesen oder ihre Hashwerte nicht berechnen.',true);
  }
}

async function textSource(file, maxBytes) {
  if (!file || file.size > maxBytes) throw new Error('size');
  const bytes = new Uint8Array(await file.arrayBuffer());
  const text = new TextDecoder('utf-8', {fatal:true}).decode(bytes);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256',bytes));
  return {text,sha256:Array.from(digest, b => b.toString(16).padStart(2,'0')).join('')};
}

async function openList(file) {
  const current = session;
  if (!current?.model) return;
  const version = ++listRevision;
  current.list = null;
  current.readingList = $('export').disabled = true;
  feedback('list','Hashliste wird lokal verglichen …');
  try {
    const {text,sha256} = await textSource(file,MAX_HASH_LIST_BYTES);
    if (session !== current || version !== listRevision) return;
    const hashes = parseHashList(text);
    const matched = matchKnownHash(current.model,hashes);
    current.list = {list_sha256:sha256, distinct_hashes:hashes.size, matched};
    const verdict = matched ? 'Der Dateihash ist in der Liste enthalten.' : 'In dieser Liste gibt es keinen Treffer für den Dateihash.';
    feedback('list',verdict + ' Verglichene SHA-256-Werte: ' + number(hashes.size) + '.');
  } catch {
    if (session === current && version === listRevision) feedback('list','Hashliste abgelehnt. Prüfen Sie das Textformat, die SHA-256-Werte und die Grössengrenze von 1 MiB.',true);
  } finally {
    if (session === current && version === listRevision) {
      current.readingList = false;
      $('export').disabled = current.readingReport;
    }
  }
}

function displayReport(report) {
  const target = $('vt-result');
  const table = document.createElement('table');
  const caption = element('caption','Zusammenfassung aus dem zugeordneten Bericht');
  caption.className = 'sr';
  table.append(caption);
  const head = table.createTHead().insertRow();
  for (const title of ['Berichtskategorie','Anzahl']) {
    const th = element('th',title);
    th.scope = 'col';
    head.append(th);
  }
  const body = table.createTBody();
  for (const [key,label] of labels) {
    const row = body.insertRow();
    row.insertCell().textContent = label;
    row.insertCell().textContent = number(report.stats[key]);
  }
  target.replaceChildren(table);
  if (report.analyzed_at) {
    target.append(element('p','Analysezeit laut Bericht: ' + new Date(report.analyzed_at).toLocaleString('de-CH',{timeZone:'Europe/Zurich'}) + ' Uhr (Schweiz).'));
  }
}

async function openReport(file) {
  const current = session;
  if (!current?.model) return;
  const version = ++reportRevision;
  current.report = null;
  current.readingReport = $('export').disabled = true;
  $('vt-result').replaceChildren();
  feedback('vt','Dateibezug wird geprüft …');
  try {
    const {text,sha256} = await textSource(file,MAX_REPORT_BYTES);
    if (session !== current || version !== reportRevision) return;
    const input = JSON.parse(text);
    const claimed = input?.data?.id;
    if (input?.data?.type === 'file' && typeof claimed === 'string' && /^[a-f\d]{64}$/i.test(claimed)
        && claimed.toLowerCase() !== current.model.sha256) {
      feedback('vt','Bericht abgelehnt. Sein SHA-256 gehört zu einer anderen Datei.', true);
      return;
    }
    const checked = checkVirusTotalReport(current.model,input);
    const stats = Object.fromEntries(labels.map(([key]) => [key,checked.stats[key]]));
    current.report = {report_sha256:sha256, file_sha256:checked.sha256, stats, total:checked.total,
      analyzed_at:checked.analyzedAt, provenance:'unverified_import'};
    displayReport(current.report);
    const count = checked.total ? number(checked.total) + ' gemeldete Engine-Ergebnisse.' : 'Der Bericht enthält keine Engine-Ergebnisse.';
    feedback('vt','Dateihash stimmt überein. ' + count);
  } catch {
    if (session === current && version === reportRevision) feedback('vt','Bericht abgelehnt. Prüfen Sie Format, Dateihash, vollständige Kategorien und die Grössengrenze von 2 MiB.',true);
  } finally {
    if (session === current && version === reportRevision) {
      current.readingReport = false;
      $('export').disabled = current.readingList;
    }
  }
}

function exportEvidence() {
  if (!session?.model || session.readingList || session.readingReport) return;
  const {model,list,report} = session;
  const output = {
    schema:'authzledger.file-triage.v1', rights:'© Nasser Aldin Farag (0xFarag). All rights reserved.',
    signed:false, malware_verdict:'not_assessed',
    file:{size_bytes:model.size, sha256:model.sha256, sha512:model.sha512, format:model.format.id,
      entropy_bits_per_byte:model.entropy, static_signals:model.signals.map(signal => signal.id)},
    local_hash_list:list, virustotal_report:report
  };
  const url = URL.createObjectURL(new Blob([JSON.stringify(output,null,2) + '\n'],{type:'application/json'}));
  const link = element('a','');
  link.href = url;
  link.download = 'AuthzLedger-Dateibeleg-' + model.sha256.slice(0,12) + '.json';
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

for (const [id,read] of [['file',openFile],['list',openList],['vt',openReport]]) {
  const input = $(id);
  $('choose-' + id).onclick = () => input.click();
  input.onchange = () => {
    const selected = input.files[0];
    input.value = '';
    if (selected) read(selected);
  };
}
$('clear').onclick = () => { reset(); feedback('file','Lokale Prüfung geleert.'); $('choose-file').focus(); };
$('export').onclick = exportEvidence;
if (globalThis.crypto?.subtle) $('choose-file').disabled = false;
else feedback('file','Zum lokalen Berechnen der Hashwerte benötigt dieser Browser HTTPS und WebCrypto.', true);
