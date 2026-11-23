// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {deviceKey, endpoint, publicApplication, signedRequest} from './device.mjs';

import '../i18n/tool-copy.js';
const {t, write, locale} = window.AuthzToolCopy;

const $ = id => document.getElementById(id);
const controls = [
  ['scope', 'Mandatsumfang', [['unknown','Ungeklärt'],['in_scope','Im Scope'],['out_of_scope','Ausserhalb']]],
  ['controls', 'Controls', [['missing','Beleg fehlt'],['failed','Fehlgeschlagen'],['passed','Bestanden']]],
  ['binding', 'Quellbezug', [['missing','Bezug fehlt'],['ambiguous','Mehrdeutig'],['matched','Eindeutig zugeordnet']]],
  ['retest', 'Retest', [['not_retested','Nicht erneut geprüft'],['inconclusive','Nicht eindeutig'],['still_present','Befund besteht weiter'],['change_observed','Änderung beobachtet']]]
];
const decisions = {
  excluded:'Aus Prüfmenge ausschliessen', clarify_scope:'Mandatsumfang klären', check_controls:'Kontrollbeleg prüfen',
  bind_source:'Quellbezug klären', schedule_retest:'Retest einplanen', review_inconclusive:'Uneindeutigen Retest prüfen',
  review_open:'Bestehenden Befund prüfen', review_change:'Beobachtete Änderung prüfen'
};
let pair, application;
function node(tag, text) {
  const el = document.createElement(tag);
  write(el, text);
  return el;
}
function presentKey() {
  $('generate').hidden = true;
  $('authenticate').hidden = $('registration').hidden = false;
  $('fingerprint').textContent = application.kid;
  $('application').value = JSON.stringify(application, null, 2);
  write($('access-status'), 'Prüfschlüssel in diesem Browser gefunden. Die persönliche Freigabe können Sie jetzt prüfen.');
}
function keyUnavailable() {
  write($('access-status'), 'Die lokale Schlüsselablage ist nicht verfügbar. Öffnen Sie diese Seite über HTTPS in einem aktuellen Browser mit erlaubten Websitedaten.');
}
async function loadKey(create) {
  $('generate').disabled = true;
  try {
    pair = await deviceKey(create);
    if (!pair) {
      write($('access-status'), 'Dieses Browserprofil hat noch keinen Prüfschlüssel.');
      $('generate').hidden = false;
      return;
    }
    application = await publicApplication(pair);
    presentKey();
  } catch {
    keyUnavailable();
  } finally {
    $('generate').disabled = false;
  }
}
function downloadApplication() {
  const blob = new Blob([JSON.stringify(application, null, 2) + '\n'], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const link = node('a','');
  link.href = url;
  link.download = 'AuthzLedger-Fachzugang-Antrag.json';
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function discardResult() {
  $('result').replaceChildren();
  write($('review-status'), '');
}
function labelRemoveButtons() {
  Array.from($('rows').children).forEach((row, index) => {
    row.querySelector('button').setAttribute('aria-label', t('Fall {n} entfernen', {n:index + 1}));
  });
}
window.addEventListener('authzlanguage', labelRemoveButtons);
function numberRows() {
  const rows = Array.from($('rows').children);
  for (const [i, row] of rows.entries()) {
    write(row.querySelector('legend'), 'Fall {n}', {n:i + 1});
    const remove = row.querySelector('button');
    remove.disabled = rows.length === 1;
  }
  labelRemoveButtons();
  $('add-case').disabled = rows.length >= 32;
  discardResult();
}
function addRow() {
  if ($('rows').childElementCount >= 32) return;
  const row = document.createElement('fieldset');
  row.className = 'case-row';
  row.append(node('legend',''));
  const choices = document.createElement('div');
  choices.className = 'choices';
  for (const [field, name, values] of controls) {
    const label = node('label', name);
    const select = document.createElement('select');
    select.name = field;
    for (const [value, title] of values) select.add(Object.assign(node('option', title), {value}));
    select.addEventListener('change', discardResult);
    label.append(select);
    choices.append(label);
  }
  const remove = node('button','Fall entfernen');
  remove.type = 'button';
  remove.className = 'secondary remove';
  remove.onclick = () => { row.remove(); numberRows(); };
  row.append(choices, remove);
  $('rows').append(row);
  numberRows();
}
function selectedCases() {
  return Array.from($('rows').children, row => Object.fromEntries(
    Array.from(row.querySelectorAll('select'), select => [select.name, select.value])
  ));
}
function reviewResult(result, count) {
  if (result?.total !== count || !Array.isArray(result.actions) || result.actions.length !== count
      || ![result.eligible,result.conclusive,result.notRetested].every(n => Number.isInteger(n) && n >= 0 && n <= count)) {
    throw new Error('response');
  }
  const list = document.createElement('ol');
  const seen = new Set();
  for (const action of result.actions) {
    if (!Number.isInteger(action?.index) || action.index < 1 || action.index > count || seen.has(action.index)
        || !Object.hasOwn(decisions, action.decision)) throw new Error('response');
    seen.add(action.index);
    const item = node('li', decisions[action.decision]);
    item.value = action.index;
    list.append(item);
  }
  $('result').replaceChildren(node('h3','Nächster Prüfschritt je Fall'), list);
  write($('review-status'), '{total} Fälle ausgewertet · {eligible} mit Scope, Controls und Quellbezug · {untested} ohne Retest.', {total:count, eligible:result.eligible, untested:result.notRetested});
}
async function review(checkOnly) {
  const status = $(checkOnly ? 'access-status' : 'review-status');
  $('authenticate').disabled = $('evaluate').disabled = true;
  const cases = checkOnly ? [] : selectedCases();
  const rows = Array.from($('rows').children);
  rows.forEach(row => { row.disabled = true; });
  $('add-case').disabled = true;
  if (!checkOnly) discardResult();
  write(status, checkOnly ? 'Freigabe wird geprüft …' : 'Prüfmerkmale werden ausgewertet …');
  try {
    const payload = await signedRequest(pair, application.kid, cases, location.origin);
    const response = await fetch(endpoint, {method:'POST', mode:'same-origin', redirect:'error', credentials:'omit', referrerPolicy:'same-origin',
      cache:'no-store', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload),
      signal:AbortSignal.timeout(15000)});
    if (response.status === 403) {
      $('review-panel').hidden = true;
      $('result').replaceChildren();
      write($('access-status'), 'Für diese Anfrage wurde keine Freigabe bestätigt. Prüfen Sie Ihre Gerätezeit und den Stand Ihres persönlichen Antrags.');
      return;
    }
    if (!response.ok) throw new Error('service');
    const data = await response.json();
    if (data?.state !== 'approved' || !Number.isSafeInteger(data.expiresAt)
        || data.expiresAt <= Math.floor(Date.now()/1000)) throw new Error('response');
    if (!checkOnly) reviewResult(data.review, cases.length);
    $('review-panel').hidden = false;
    write($('access-status'), () => t('Persönliche Freigabe bestätigt bis {time} Uhr (Schweiz).', {time:new Date(data.expiresAt * 1000).toLocaleString(locale(), {timeZone:'Europe/Zurich'})}));
    if (!$('rows').childElementCount) addRow();
    if (checkOnly) $('review-title').focus();
  } catch {
    write(status, 'Die Prüfung konnte nicht abgeschlossen werden. Prüfen Sie die Verbindung und versuchen Sie es erneut.');
  } finally {
    rows.forEach(row => { row.disabled = false; });
    $('add-case').disabled = $('rows').childElementCount >= 32;
    $('authenticate').disabled = $('evaluate').disabled = false;
  }
}
$('generate').onclick = () => loadKey(true);
$('download').onclick = downloadApplication;
$('authenticate').onclick = () => review(true);
$('add-case').onclick = addRow;
$('evaluate').onclick = () => review(false);
loadKey(false);
