// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {MAX_BYTES, originalFileChecks, parseProjection, statusLabels} from './model.mjs';
import {renderComparison} from './compare-view.mjs';
import {saveFile, setupDelivery} from './delivery.mjs';
import {rowSummary, rowTitle, tr} from './language.mjs';
import {detailValue, indexLocator, normalizedText, sourceLabel} from './model-language.mjs';

const demos = new Map([
  ['demo-c', {name: 'Demo C', file: 'mixed-c-result.json', digest: 'e88fa8b182ad1d7b3477516c1432e24a919d1882a4221bf2cb8e25265cff4bd8'}],
  ['demo-b', {name: 'Demo B', file: 'mixed-b-result.json', digest: '81d604114d57d05e3a8c34117ecb0810e2bd5c7b326d1e539d3bd47540786632'}],
  ['demo-index', {name: 'Mischindex', file: 'mixed-index.json', digest: 'a04266ba908014fcd7a12a09545f62f8b38dce9d07ad077b124ea9089895e1e2'}],
  ['demo-blue', {name: 'SOC-Signale', file: 'blue-evidence-example.json', digest: 'fee007d0005cab05c797d00cd6c5157d2f4a1611679e22c1ebcc89f731ac12c6'}]
]);
const dispositions = {todo: 'Offen', follow_up: 'Rückfrage nötig', reviewed: 'Gesichtet'};
const sourceLimit = 16;
const pageSize = 40;
const documents = new Map();
const $ = id => document.getElementById(id);
const tabs = Array.from(document.querySelectorAll('[role=tab]'));
let active;
let selectionVersion = 0;
let searchResults = [];
let visibleCount = pageSize;
let pickerValue = '';
let tabName = 'decision';
const delivery = setupDelivery();
const notices = new Map();

function element(tag, text) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  return node;
}

function formatMessage(text) {
  return text === 'Diese Sitzung enthält bereits {n} eigene Quellen.' ? tr(text, {n:sourceLimit}) : normalizedText(text);
}

function notice(text, error = false, target = 'feedback') {
  notices.set(target, {text, error});
  $(target).textContent = typeof text === 'function' ? text() : text ? formatMessage(text) : '';
  $(target).dataset.level = error ? 'error' : 'ok';
}

function option(value, label) {
  const el = element('option', label);
  el.value = value;
  return el;
}

function humanStatus(status) {
  return tr(statusLabels[status]);
}

function getReview(doc, id) {
  return doc.reviews.get(id) || {state: 'todo', note: ''};
}

function register(model, name) {
  if (!documents.has(model.digest)) {
    const known = [...demos.values()].find(d => d.digest === model.digest);
    // Open the bundled partial-coverage sample directly. Imported reports retain their original order.
    const partialWindow = known && model.kind === 'blue' ? model.rows.findIndex(row =>
      row.signalCoverage.linked > 0 && row.signalCoverage.linked < row.signalCoverage.eligible) : -1;
    const originals = model.importIndex ? originalFileChecks(model.importIndex.sources) : null;
    documents.set(model.digest, {model, originals, name: known?.name || name, known, reviews: new Map(), selected: Math.max(0, partialWindow)});
  }
  return documents.get(model.digest);
}

function updateComparison() {
  renderComparison($('snapshot-comparison'), [...documents.values()].map(({model, name, known}) => ({model, name, translateName:Boolean(known)})));
}

function showDocument(doc, key, refresh = false) {
  if (!refresh) active?.originals?.cancel();
  const filter = refresh ? $('filter').value : '';
  active = doc;
  pickerValue = key;
  $('source').value = key;
  if (!refresh) $('search').value = '';
  $('filter').replaceChildren(option('', tr('Alle Ergebnisse')));
  for (const status of new Set(doc.model.rows.map(row => row.status))) {
    $('filter').append(option(status, humanStatus(status)));
  }
  $('filter').value = filter;
  $('summary-title').textContent = tr(doc.model.title);
  $('save-manual').hidden = !doc.manualBytes;
  $('origin').textContent = tr(doc.known ? 'Mitgeliefertes Beispiel' : doc.model.importIndex?.workspace === 'example'
    ? 'Belegindex aus dem Beispielbereich' : doc.model.kind === 'manual' ? 'Privat erfasster Fall' : 'Lokale Belegdatei');
  $('identity').textContent = (doc.known ? tr(doc.name) : doc.name) + ' · ' + tr(doc.known ? 'Beispieldatei per SHA-256 abgeglichen' : 'Dateimuster geprüft');
  const index = doc.model.importIndex;
  $('import-registry').hidden = !index;
  if (!refresh) $('import-registry').open = false;
  renderOriginalChecks();
  $('cases-title').textContent = tr(index ? 'Importbeleg auswählen' : doc.model.kind === 'blue' ? 'Signalprobe auswählen' : 'Fallauswahl');
  $('cases').setAttribute('aria-label', tr(index ? 'Importbelege' : doc.model.kind === 'blue' ? 'Signalproben' : 'Fälle'));
  $('sample-sources').hidden = doc.known?.file !== 'blue-evidence-example.json';
  $('document').hidden = false;
  renderMetrics();
  if (refresh) {
    renderList();
    if (searchResults.length) renderCase(true);
    else delivery.render(active, null);
  } else {
    visibleCount = Math.ceil((doc.selected + 1) / pageSize) * pageSize;
    applyFilter();
  }
  updateComparison();
}

function renderOriginalChecks() {
  const sources = active?.model.importIndex?.sources || [];
  const checks = active?.originals;
  const last = checks?.last;
  const outcomes = last?.outcomes || [];
  $('import-sources').replaceChildren(...sources.map(file => {
    const li = element('li', file.label + ' · ' + tr('{n} Beobachtungen', {n:file.count}) + ' · ');
    li.append(element('code', file.sha256), document.createTextNode(checks.has(file.sha256)
      ? ' · ' + tr('Originalbytes abgeglichen') : ' · ' + tr('Originalbytes ausstehend')));
    return li;
  }));
  const explanations = {unmatched: 'Kein registrierter SHA-256 passt.', size: 'Zulässig sind 1 Byte bis 1 MiB.',
    unreadable: 'Die Datei konnte nicht gelesen oder gehasht werden.'};
  $('original-outcomes').replaceChildren(...outcomes.map(result => {
    const labels = sources.filter(source => source.sha256 === result.sha256).map(source => source.label);
    const message = result.status === 'matched' ? tr('SHA-256 stimmt mit {sources} überein.', {sources:labels.join(', ')}) : tr(explanations[result.status]);
    return element('li', tr('Datei {n}', {n:result.position}) + ' · ' + message + (result.duplicate ? ' ' + tr('Identische Bytes in dieser Auswahl.') : ''));
  }));
  const matches = outcomes.filter(result => result.status === 'matched').length;
  notice(last?.error || (outcomes.length ? () => tr('{matched} von {total} ausgewählten Dateien passen zu einem registrierten SHA-256.', {matched:matches, total:outcomes.length}) : ''),
    Boolean(last?.error), 'original-status');
}

function cancelOriginalChecks() {
  if (active?.originals) {
    active.originals.cancel();
    renderOriginalChecks();
  }
}

async function selectOriginals(files) {
  const doc = active;
  if (!files.length || !doc?.originals) return;
  $('original-outcomes').replaceChildren();
  notice('SHA-256 der ausgewählten Dateien wird lokal berechnet.', false, 'original-status');
  const result = await doc.originals.verify(files);
  if (!result || active !== doc) return;
  renderOriginalChecks();
  if (searchResults.length) renderCase();
}

async function selectSource(key) {
  cancelOriginalChecks();
  const version = ++selectionVersion;
  try {
    const demo = demos.get(key);
    let doc;
    if (demo) {
      doc = documents.get(demo.digest);
      if (!doc) {
        notice('Beispiel wird geladen und mit dem erwarteten SHA-256 verglichen.');
        const response = await fetch('/proof/' + demo.file, {credentials: 'omit', redirect: 'error'});
        if (!response.ok) throw Error('Die Beispieldatei konnte nicht geladen werden.');
        const model = await parseProjection(await response.arrayBuffer());
        if (model.digest !== demo.digest) throw Error('Der SHA-256 des Beispiels weicht vom erwarteten Wert ab.');
        doc = register(model, demo.name);
      }
    } else {
      doc = documents.get(key.slice(5));
      if (!doc) throw Error('Die gewählte Belegdatei ist in dieser Sitzung nicht verfügbar.');
    }
    if (version !== selectionVersion) return;
    showDocument(doc, key);
    notice(doc.known ? 'Beispiel geöffnet. Die übrigen Quellen stehen in der Auswahl.' : 'Belegdatei im Browser geöffnet.');
  } catch (err) {
    if (version !== selectionVersion) return;
    if (active) $('source').value = pickerValue;
    else $('source').selectedIndex = -1;
    notice(err.message, true);
  }
}

async function importFiles(fileList) {
  const files = [...fileList];
  if (!files.length) return;
  if (files.length > sourceLimit) {
    notice(() => tr('Öffnen Sie höchstens {n} Dateien auf einmal.', {n:sourceLimit}), true);
    return;
  }
  cancelOriginalChecks();
  const version = ++selectionVersion;
  const errors = [];
  let last;
  let accepted = 0;
  $('add-file').disabled = true;
  for (const file of files) {
    try {
      if (file.size > MAX_BYTES || !file.size) throw Error('Zulässig sind 1 Byte bis 2 MiB.');
      const original = await file.arrayBuffer();
      const model = await parseProjection(original);
      const knownKey = [...demos.keys()].find(key => demos.get(key).digest === model.digest);
      const key = knownKey || 'file:' + model.digest;
      if (!documents.has(model.digest) && !knownKey && $('local-options').children.length >= sourceLimit) {
        throw Error('Diese Sitzung enthält bereits {n} eigene Quellen.');
      }
      const name = file.name.replace(/[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/gu, '').slice(0, 150);
      const doc = register(model, name);
      if (model.kind === 'manual') doc.manualBytes = original;
      if (!knownKey && ![...$('local-options').children].some(o => o.value === key)) {
        $('local-options').append(option(key, name + ' · ' + model.digest.slice(0, 8)));
      }
      last = {doc, key};
      accepted++;
    } catch (err) {
      errors.push({position:accepted + errors.length + 1, message:err.message});
    }
  }
  $('add-file').disabled = false;
  if (version !== selectionVersion) {
    updateComparison();
    return;
  }
  if (last) showDocument(last.doc, last.key);
  else if (active) $('source').value = pickerValue;
  notice(() => {
    const count = accepted === 1 ? tr('1 Datei geöffnet.') : tr('{n} Dateien geöffnet.', {n:accepted});
    const details = errors.map(({position, message}) => tr('Datei {n}', {n:position}) + ' – ' + formatMessage(message));
    return [count, ...details].join(' ');
  }, Boolean(errors.length));
}

function renderMetrics() {
  const {coverage, rows, signalCoverage, importIndex} = active.model;
  const entries = [[importIndex ? 'Importbelege' : signalCoverage ? 'Signalproben' : 'Fälle gesamt', rows.length]];
  $('metric-note').hidden = !signalCoverage && !importIndex;
  if (importIndex) {
    entries.push(['Quelldateien', importIndex.sources.length], ['Asset-IDs', importIndex.assets], ['Belege ohne Host', importIndex.unassigned]);
    $('metric-note').textContent = tr('Gezählt werden die Verweise aller aufgeführten Quelldateien, einschliesslich mehrfacher Beobachtungen. Die Abdeckung des Mandats ist unbekannt.');
  } else if (signalCoverage) {
    entries.push(['Mit Alarm', signalCoverage.observedWindows], ['Nur Telemetrie', signalCoverage.telemetryOnlyWindows]);
    $('metric-note').textContent = tr('{unknown} nicht vergleichbare und {missing} unbelegte Signalproben. Die Ereignisabdeckung steht bei der jeweiligen Probe.', {unknown:signalCoverage.incomparableWindows, missing:signalCoverage.unavailableWindows});
  } else if (coverage) {
    entries.push(['Nachgeprüft', coverage.reviewed], ['Fix belegt', rows.filter(r => r.status === 'fix_verified').length], ['Ausgelassen', coverage.open]);
  } else {
    entries.push(['Gesichtet', [...active.reviews.values()].filter(r => r.state === 'reviewed').length],
      ['Rückfragen', [...active.reviews.values()].filter(r => r.state === 'follow_up').length]);
  }
  $('metrics').replaceChildren(...entries.map(([label, value]) => {
    const wrap = element('div');
    wrap.append(element('dt', tr(label)), element('dd', value));
    return wrap;
  }));
}

function displayTitle(row) {
  if (active?.known?.file === 'mixed-c-result.json') {
    if (row.title === 'Retest-Fall one') return tr('Retest-Fall {id}', {id:1});
    if (row.title === 'Retest-Fall two') return tr('Retest-Fall {id}', {id:2});
  }
  return rowTitle(active.model, row);
}

function applyFilter() {
  const text = $('search').value.trim().toLocaleLowerCase(document.documentElement.lang);
  const status = $('filter').value;
  searchResults = [];
  active.model.rows.forEach((row, i) => {
    if ((!status || row.status === status) && [row.id, row.title, displayTitle(row), row.source].some(v => v.toLocaleLowerCase(document.documentElement.lang).includes(text))) {
      searchResults.push(i);
    }
  });
  if (searchResults.length && !searchResults.includes(active.selected)) active.selected = searchResults[0];
  $('inspector').hidden = !searchResults.length;
  $('reset-filter').hidden = !(status || text) || Boolean(searchResults.length);
  renderList();
  if (searchResults.length) renderCase();
  else delivery.render(active, null);
}

function renderList() {
  $('count').textContent = tr('{visible} von {total} sichtbar', {visible:searchResults.length, total:active.model.rows.length});
  const displayed = searchResults.slice(0, visibleCount);
  const fragment = document.createDocumentFragment();
  for (const index of displayed) {
    const row = active.model.rows[index];
    const li = element('li');
    const btn = element('button');
    btn.type = 'button';
    btn.className = 'case-link';
    btn.dataset.index = index;
    if (active.selected === index) btn.setAttribute('aria-current', 'true');
    const state = getReview(active, row.id).state;
    const stateLabel = state === 'todo' ? '' : ' · ' + tr(dispositions[state]);
    btn.append(element('strong', displayTitle(row)), element('span', humanStatus(row.status) + stateLabel));
    li.append(btn);
    fragment.append(li);
  }
  $('cases').replaceChildren(fragment);
  $('more').hidden = displayed.length >= searchResults.length;
}

function fields(id, entries) {
  $(id).replaceChildren(...entries.map(({label, value}) => {
    const line = element('div');
    const detail = element('dd', value);
    if (/^[a-f0-9]{64}$/.test(value)) detail.className = 'mono';
    line.append(element('dt', tr(label)), detail);
    return line;
  }));
}

function activateTab(name, focus = false) {
  tabName = name;
  for (const tab of tabs) {
    const selected = tab.id === 'tab-' + name;
    tab.setAttribute('aria-selected', selected);
    tab.tabIndex = selected ? 0 : -1;
    $(tab.getAttribute('aria-controls')).hidden = !selected;
    if (selected && focus) tab.focus();
  }
}

function extent(row) {
  if (row.signalCoverage) {
    if (!row.signalCoverage.eligible) return 'Diese Probe enthält kein passend zugeordnetes Ereignis. Ein Abdeckungsgrad ist nicht bestimmbar.';
    return 'Die Zuordnung gilt für die dokumentierte Regel, die gebundene Quelle und das Zeitfenster dieser Probe.';
  }
  if (row.status === 'import_unassessed') return 'Scope und Kontrollen sind ungeprüft. Ein bestätigter Befund oder eine Aussage zur Behebung erfordert eigene Belege.';
  if (row.status === 'not_retested') return 'Für eine Fix-Bestätigung ist eine eigene Nachprüfung dieses Falls offen.';
  if (row.status === 'confirmed') return 'Die Kontrolle belegt die Header-Konfiguration. Die Ausnutzbarkeit bleibt offen.';
  if (row.status === 'not_verified' || row.status === 'hint') return 'Für eine fachliche Bestätigung braucht dieser Hinweis einen eigenen Kontrollbeleg.';
  if (row.details.some(d => d.label === 'Prüfmethode' && d.value === 'captured_inputs_replayed')) {
    return 'Der Retest verwendete wiedergegebene Aufzeichnungen. Die Aussage bezieht sich auf den dokumentierten Stand.';
  }
  if (row.status === 'observed') return 'Die Aussage beschreibt die Beobachtung der angegebenen Quelle.';
  if (row.status === 'excluded') return 'Der Datensatz bleibt im Inventar sichtbar. Für die fachliche Bewertung wurde er ausgelassen.';
  return 'Die Einordnung gilt für den dokumentierten Fall und die angegebenen Quellbelege.';
}

function renderCase(preserveFeedback = false) {
  const model = active.model;
  const row = model.rows[active.selected];
  $('case-position').textContent = tr('{kind} {index} von {total}', {kind:tr(model.importIndex ? 'Importbeleg' : model.kind === 'blue' ? 'Signalprobe' : 'Fall'), index:active.selected + 1, total:model.rows.length});
  $('case-title').textContent = displayTitle(row);
  $('case-status').textContent = humanStatus(row.status);
  const good = ['confirmed', 'fix_verified', 'soc_observed'];
  const attention = ['not_verified', 'not_retested', 'inconclusive', 'regression', 'violation_persists', 'soc_telemetry_only', 'soc_unavailable', 'soc_incomparable'];
  $('case-status').dataset.tone = good.includes(row.status) ? 'good' : attention.includes(row.status) ? 'attention' : 'neutral';
  $('decision').textContent = rowSummary(model, row);
  $('technical').hidden = !row.details.length;
  $('extent').textContent = tr(extent(row));
  $('window-coverage').hidden = !row.signalCoverage;
  if (row.signalCoverage) $('window-coverage').textContent = signalRatio(row.signalCoverage);
  fields('fields', row.details.map(detail => ({label:detail.label, value:detailValue(model, row, detail)})));
  const provenance = [['Datensatz', active.known ? tr(active.name) : active.name], ['Quelle', sourceLabel(model, row)], ['Fall-ID', row.id],
    ['SHA-256 der geöffneten Datei', model.digest]];
  if (row.reference) {
    provenance.push(['Quelldatei laut Index', row.reference.file_sha256], ['Position laut Index', indexLocator(row.reference.locator)],
      ['Datensatz-Fingerabdruck laut Index', row.reference.fingerprint],
      ['Originalbytes', tr(active.originals.has(row.reference.file_sha256) ? 'SHA-256 in dieser Sitzung abgeglichen' : 'Abgleich ausstehend')],
      ['Scope und Controls', tr('Ungeprüft')]);
  } else if (model.kind !== 'manual') {
    provenance.push(['Assessment', model.assessment], ['Scope-Digest', model.scope]);
  }
  fields('provenance', provenance.map(([label, value]) => ({label, value})));
  $('trust').textContent = tr(model.importIndex
    ? 'Ein erfolgreicher Byteabgleich bestätigt die Übereinstimmung der Datei mit dem registrierten SHA-256. Datensatzinhalt, Urheberschaft und Befundstatus erfordern eigene Nachweise.'
    : active.known
    ? 'Die Dateibytes stimmen mit dem hinterlegten Beispiel überein. Die fachliche Aussage stammt aus dieser Projektion.'
    : 'Der Fingerabdruck bezeichnet die hier geöffneten Dateibytes. Herkunft, Signatur und tatsächliche Ausführung benötigen eigene Nachweise.');
  const review = getReview(active, row.id);
  $('disposition').value = review.state;
  $('note').value = review.note;
  if (!preserveFeedback) notice('', false, 'draft-status');
  activateTab(tabName);
  delivery.render(active, row);
}

function selectCase(index, focusButton) {
  active.selected = index;
  for (const button of $('cases').querySelectorAll('button')) {
    if (Number(button.dataset.index) === index) {
      button.setAttribute('aria-current', 'true');
      if (focusButton) button.focus();
    } else button.removeAttribute('aria-current');
  }
  renderCase();
}

function updateReview() {
  const {id} = active.model.rows[active.selected];
  const review = {state: $('disposition').value, note: $('note').value};
  if (review.state !== 'todo' || review.note) active.reviews.set(id, review);
  else active.reviews.delete(id);
}

function downloadJSON(object, name) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(object, null, 2) + '\n'], {type: 'application/json'}));
  const link = element('a');
  link.href = url;
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}

function signalRatio(signal) {
  const ratio = signal.eligible ? tr('{linked} von {eligible} passenden Ereignissen mit zugeordnetem Alarm', signal) : tr('Keine passenden Ereignisse für eine Alarmzuordnung');
  return ratio + ' · ' + tr('{excluded} ausgeschlossen', signal);
}

function redactedReview() {
  const {model} = active;
  return {schema: 'authzledger.workbench.review/v1', rights: '© Nasser Aldin Farag (0xFarag). All rights reserved.', signed: false, created_at: new Date().toISOString(),
    source_sha256: model.digest, projection: model.kind, total: model.rows.length,
    ...(model.importIndex ? {import_index: {workspace: model.importIndex.workspace, scope: 'unverified', controls: 'unverified',
      coverage: 'unknown', findings: 'not_assessed', retest: 'not_assessed', asset_ids: model.importIndex.assets,
      observations_without_host: model.importIndex.unassigned,
      sources: model.importIndex.sources.map(({source, sha256, count}) => ({source, sha256, observations: count}))}} : {}),
    ...(model.signalCoverage ? {signal_coverage: model.signalCoverage} : {retest_coverage: model.coverage}),
    cases: model.rows.map((row, i) => ({case_number: i + 1, evidence_status: row.status, review_state: getReview(active, row.id).state,
      ...(row.reference ? {source_reference: row.reference} : {}),
      ...(row.signalCoverage ? {signal_coverage: row.signalCoverage} : {})}))};
}

function preparePrint() {
  const area = $('print-report');
  area.replaceChildren(element('h1', tr('AuthzLedger · Fallübersicht')), element('small', '© Nasser Aldin Farag (0xFarag). All rights reserved.'));
  if (!active) {
    area.append(element('p', tr('Keine Belegquelle geöffnet.')));
    return;
  }
  const review = redactedReview();
  const date = new Date(review.created_at).toLocaleString(document.documentElement.lang, {timeZone: 'Europe/Zurich'});
  const unit = tr(review.import_index ? 'Importbelege' : review.signal_coverage ? 'Signalproben' : 'Fälle');
  area.append(element('p', tr('Unsignierte, redigierte Übersicht') + ' · ' + tr(active.model.title)),
    element('p', tr('Erstellt am {date}', {date}) + ' (Europe/Zurich)'),
    element('p', tr('SHA-256 der Quelle') + ' · ' + review.source_sha256),
    element('p', tr('Gesamtumfang') + ' · ' + unit + ' · ' + review.total));
  if (review.import_index) {
    const info = review.import_index;
    area.append(element('p', tr(info.workspace === 'example' ? 'Beispieldaten' : 'Eigene Dateien') + ' · ' +
      tr('Quelldateien') + ' ' + info.sources.length + ' · ' + tr('Asset-IDs') + ' ' + info.asset_ids + ' · ' +
      tr('Belege ohne Host') + ' ' + info.observations_without_host + '. ' + tr('Scope und Kontrollen ungeprüft. Abdeckung unbekannt.')));
  }
  if (review.retest_coverage) {
    area.append(element('p', tr('Nachgeprüft') + ' ' + review.retest_coverage.reviewed + ' · ' +
      tr('Fix belegt') + ' ' + review.cases.filter(r => r.evidence_status === 'fix_verified').length + ' · ' +
      tr('Ausgelassen') + ' ' + review.retest_coverage.open));
  }
  if (review.signal_coverage) {
    const c = review.signal_coverage;
    area.append(element('p', tr('Mit Alarm') + ' ' + c.observedWindows + ' · ' + tr('Nur Telemetrie') + ' ' + c.telemetryOnlyWindows + ' · ' +
      tr('Nicht vergleichbar') + ' ' + c.incomparableWindows + ' · ' + tr('Ohne Daten') + ' ' + c.unavailableWindows),
      element('p', tr('Über alle Proben wurden {linked} von {eligible} passenden Ereignisvorkommen einem Alarm zugeordnet. Dieselbe Ereignis-ID kann in mehreren Proben vorkommen.', {linked:c.linkedOccurrences, eligible:c.eligibleOccurrences})));
  }
  const table = element('table'), head = table.createTHead().insertRow(), body = table.createTBody();
  const titles = [review.import_index ? 'Importbeleg' : review.signal_coverage ? 'Signalprobe' : 'Fall', 'Prüfergebnis', 'Bearbeitungsstand'];
  if (review.signal_coverage) titles.push('Ereignisabdeckung je Probe');
  for (const title of titles) {
    const th = element('th', tr(title)); th.scope = 'col'; head.append(th);
  }
  for (const row of review.cases) {
    const tableRow = body.insertRow();
    const cells = [row.case_number, humanStatus(row.evidence_status), tr(dispositions[row.review_state])];
    if (row.signal_coverage) cells.push(signalRatio(row.signal_coverage));
    for (const cell of cells) tableRow.append(element('td', cell));
  }
  area.append(table);
}

const notesSchema = 'authzledger.workbench.private-notes/v1';
function saveDraft() {
  const {model, reviews} = active;
  const notes = model.rows.flatMap((row, i) => reviews.has(row.id) ? [{case_number: i + 1, ...reviews.get(row.id)}] : []);
  downloadJSON({schema: notesSchema, source_sha256: model.digest, notes}, 'authzledger-private-notes-' + model.digest.slice(0, 12) + '.json');
  notice('Privater Arbeitsstand mit Fallnotizen zum Download bereitgestellt.', false, 'draft-status');
}

async function loadDraft(file) {
  if (!file || !active) return;
  const doc = active;
  try {
    // JSON escaping can use six bytes per character in a 2,000-character note.
    const maxDraftBytes = doc.model.importIndex ? 32 * 1024 * 1024 : 16 * 1024 * 1024;
    if (file.size > maxDraftBytes || !file.size) throw Error('Ungültige Grösse des Arbeitsstands.');
    const data = JSON.parse(await file.text());
    if (data?.schema !== notesSchema || data.source_sha256 !== doc.model.digest || !Array.isArray(data.notes) ||
      data.notes.length > doc.model.rows.length) throw Error('Dieser Arbeitsstand gehört nicht zu dieser Belegdatei.');
    const incoming = new Map();
    for (const n of data.notes) {
      if (!Number.isInteger(n?.case_number) || n.case_number < 1 || n.case_number > doc.model.rows.length ||
        typeof n.state !== 'string' || !Object.hasOwn(dispositions, n.state) || typeof n.note !== 'string' || n.note.length > 2000) {
        throw Error('Der Arbeitsstand enthält einen ungültigen Falleintrag.');
      }
      const id = doc.model.rows[n.case_number - 1].id;
      if (incoming.has(id)) throw Error('Ein Fall ist im Arbeitsstand mehrfach vorhanden.');
      const previous = doc.reviews.get(id);
      if (previous && (previous.state !== n.state || previous.note !== n.note)) {
        throw Error('Der Arbeitsstand kollidiert mit vorhandenen Notizen. Öffnen Sie die Belegdatei in einem neuen Fenster, um beide Stände zu behalten.');
      }
      incoming.set(id, {state: n.state, note: n.note});
    }
    if (active !== doc) return;
    for (const [id, review] of incoming) doc.reviews.set(id, review);
    renderMetrics();
    renderList();
    renderCase();
    notice(() => tr('Arbeitsstand geladen. {n} Einträge zugeordnet.', {n:incoming.size}), false, 'draft-status');
  } catch (err) {
    if (active === doc) notice(err instanceof SyntaxError ? 'Der Arbeitsstand enthält kein gültiges JSON.' : err.message, true, 'draft-status');
  }
}

$('source').addEventListener('change', () => selectSource($('source').value));
$('add-file').addEventListener('click', () => $('files').click());
$('verify-originals').addEventListener('click', () => $('original-files').click());
$('original-files').addEventListener('change', () => {
  const files = [...$('original-files').files];
  $('original-files').value = '';
  selectOriginals(files);
});
$('files').addEventListener('change', () => {const files = [...$('files').files]; $('files').value = ''; importFiles(files);});
for (const [id, event] of [['search', 'input'], ['filter', 'change']]) {
  $(id).addEventListener(event, () => {visibleCount = pageSize; applyFilter();});
}
$('reset-filter').addEventListener('click', () => {
  $('search').value = ''; $('filter').value = ''; visibleCount = pageSize; applyFilter(); $('search').focus();
});
$('more').addEventListener('click', () => {
  const next = searchResults[visibleCount]; visibleCount += pageSize; renderList();
  $('cases').querySelector('[data-index="' + next + '"]')?.focus();
});
$('cases').addEventListener('click', event => {
  const button = event.target.closest('button[data-index]');
  if (button) {selectCase(Number(button.dataset.index), false); if (matchMedia('(max-width:700px)').matches) $('tab-' + tabName).focus();}
});
$('cases').addEventListener('keydown', event => {
  const button = event.target.closest('button[data-index]');
  if (!button || !['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
  event.preventDefault();
  const pos = searchResults.indexOf(Number(button.dataset.index));
  const last = searchResults.length - 1;
  const target = event.key === 'Home' ? 0 : event.key === 'End' ? last : Math.min(last, Math.max(0, pos + (event.key === 'ArrowDown' ? 1 : -1)));
  if (target >= visibleCount) {visibleCount = Math.ceil((target + 1) / pageSize) * pageSize; renderList();}
  selectCase(searchResults[target], true);
});
for (const [index, tab] of tabs.entries()) {
  tab.addEventListener('click', () => activateTab(tab.id.slice(4)));
  tab.addEventListener('keydown', event => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return;
    event.preventDefault();
    const next = event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 :
      (index + (event.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
    activateTab(tabs[next].id.slice(4), true);
  });
}
$('inspector').addEventListener('keydown', event => {
  if (event.key === 'Escape') $('cases').querySelector('[aria-current="true"]')?.focus();
});
$('note').addEventListener('input', updateReview);
$('disposition').addEventListener('change', () => {updateReview(); renderMetrics(); renderList(); delivery.render(active, active.model.rows[active.selected]);});
$('save-notes').addEventListener('click', saveDraft);
$('load-notes').addEventListener('click', () => $('draft-file').click());
$('draft-file').addEventListener('change', () => {const file = $('draft-file').files[0]; $('draft-file').value = ''; loadDraft(file);});
$('download').addEventListener('click', () => {
  downloadJSON(redactedReview(), 'authzledger-review-' + active.model.digest.slice(0, 12) + '.json');
  notice('Redigierte Übersicht mit allen Fällen dieser Quelle zum Download bereitgestellt.');
});
$('print').addEventListener('click', () => {preparePrint(); window.print();});
window.addEventListener('beforeprint', preparePrint);
$('add-file').disabled = false;
$('new-case-form').addEventListener('submit', async event => {
  event.preventDefault();
  const version = ++selectionVersion;
  const title = $('new-title').value.trim();
  const observation = $('new-summary').value.trim();
  const source = {schema:'authzledger.workbench.manual-case/v1', title, observation};
  const bytes = new TextEncoder().encode(JSON.stringify(source, null, 2) + '\n');
  try {
    const model = await parseProjection(bytes);
    if (version !== selectionVersion) return;
    const key = 'file:' + model.digest;
    if (!documents.has(model.digest) && $('local-options').children.length >= sourceLimit) {
      throw Error('Diese Sitzung enthält bereits {n} eigene Quellen.');
    }
    const doc = register(model, title);
    doc.manualBytes = bytes;
    if (![...$('local-options').children].some(o => o.value === key)) {
      $('local-options').append(option(key, title + ' · ' + model.digest.slice(0, 8)));
    }
    showDocument(doc, key);
    $('new-case-form').reset();
    $('new-source').open = false;
    notice('Privater Fall in dieser Sitzung geöffnet.');
  } catch (error) {
    if (version === selectionVersion) notice(error.message, true);
  }
});
$('save-manual').addEventListener('click', () => {
  if (active?.manualBytes) saveFile({text:active.manualBytes, mime:'application/json', filename:'authzledger-case-' + active.model.digest.slice(0, 12) + '.json'});
});
window.addEventListener('authzlanguage', () => {
  if (active) showDocument(active, pickerValue, true);
  for (const [target, {text, error}] of notices) notice(text, error, target);
});
