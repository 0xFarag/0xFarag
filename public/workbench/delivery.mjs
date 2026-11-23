// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {makeTicket, makeCustomerReport} from './exports.mjs';
import {tr as t, rowTitle} from './language.mjs';

const languages = ['de', 'en', 'fr', 'it', 'ar'];
const languageKey = 'authzledger.output-language';
const fields = ['subject', 'owner', 'due', 'remediation', 'acceptance'];
const $ = id => document.getElementById(id);

export function saveFile(file) {
  const url = URL.createObjectURL(new Blob([file.text], {type:file.mime}));
  const link = document.createElement('a');
  link.href = url;
  link.download = file.filename;
  document.body.append(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1500);
}

export function setupDelivery() {
  let doc;
  let row;
  let chosenLanguage;
  let ticket;
  let report;
  const drafts = new WeakMap();
  const languageSelector = $('export-language');
  try { chosenLanguage = localStorage.getItem(languageKey); } catch {}
  function outputLanguage() {
    if (languages.includes(chosenLanguage)) return chosenLanguage;
    const page = window.AuthzI18n?.lang || document.documentElement.lang.split('-')[0];
    return languages.includes(page) ? page : 'de';
  }
  function reportOptions(format) {
    return {language:outputLanguage(), format, reviews:doc.reviews};
  }
  function showPreview(id, result) {
    const preview = $(id);
    preview.value = result?.text || '';
    preview.lang = outputLanguage();
    preview.dir = preview.lang === 'ar' ? 'rtl' : 'ltr';
  }
  function showTicket() {
    ticket = null;
    if (row && $('ticket-tools').open) {
      const draft = drafts.get(doc)?.get(row.id) || {};
      try {
        if (!$('ticket-due').validity.valid) throw Error('Ungültiges Fälligkeitsdatum.');
        ticket = makeTicket(doc.model, doc.selected, {...draft, format:$('ticket-format').value,
          language:outputLanguage(), reviewState:doc.reviews.get(row.id)?.state ?? 'todo'});
      } catch (error) {
        $('ticket-status').textContent = t(error.message);
      }
    }
    $('download-ticket').disabled = !ticket;
    $('copy-ticket').disabled = !ticket;
    showPreview('ticket-preview', ticket);
  }
  function showReport() {
    report = doc && $('report-tools').open ? makeCustomerReport(doc.model, reportOptions('markdown')) : null;
    showPreview('report-preview', report);
  }
  function render(nextDoc, nextRow) {
    doc = nextDoc;
    row = nextRow;
    $('ticket-tools').hidden = !row;
    languageSelector.value = outputLanguage();
    const draft = row && drafts.get(doc)?.get(row.id);
    for (const field of fields) $('ticket-' + field).value = draft?.[field] || '';
    $('ticket-case').textContent = row ? t('Ausgewählter Fall {n}', {n:doc.selected + 1}) + ' · ' + rowTitle(doc.model, row) : '';
    $('ticket-status').textContent = '';
    $('report-status').textContent = '';
    showTicket();
    showReport();
  }
  function edit() {
    if (!row) return;
    if (!drafts.has(doc)) drafts.set(doc, new Map());
    const values = Object.fromEntries(fields.map(field => [field, $('ticket-' + field).value]));
    drafts.get(doc).set(row.id, values);
    $('ticket-status').textContent = '';
    showTicket();
  }
  for (const name of fields) $('ticket-' + name).addEventListener('input', edit);
  $('ticket-format').addEventListener('change', showTicket);
  $('ticket-tools').addEventListener('toggle', showTicket);
  $('report-tools').addEventListener('toggle', showReport);
  languageSelector.addEventListener('change', () => {
    chosenLanguage = languageSelector.value;
    try { localStorage.setItem(languageKey, chosenLanguage); } catch {}
    render(doc, row);
  });
  window.addEventListener('authzlanguage', () => render(doc, row));
  $('download-ticket').addEventListener('click', () => { if (ticket) saveFile(ticket); });
  $('download-report').addEventListener('click', () => { if (doc) saveFile(makeCustomerReport(doc.model, reportOptions('html'))); });
  $('markdown-report').addEventListener('click', () => { if (report) saveFile(report); });
  async function copy(which) {
    const preview = $(which + '-preview');
    if (!preview.value) return;
    const status = $(which + '-status');
    try {
      await navigator.clipboard.writeText(preview.value);
      status.textContent = t('Vorschau in die Zwischenablage kopiert.');
    } catch {
      preview.focus(); preview.select();
      status.textContent = t('Vorschau markiert. Verwenden Sie den Kopierbefehl Ihres Geräts.');
    }
  }
  $('copy-ticket').addEventListener('click', () => copy('ticket'));
  $('copy-report').addEventListener('click', () => copy('report'));
  languageSelector.value = outputLanguage();
  return {render};
}
