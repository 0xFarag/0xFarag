// © Nasser Aldin Farag (0xFarag). All rights reserved.
const checks = {hsts: 'Strict-Transport-Security', nosniff: 'X-Content-Type-Options'};
const statuses = {met: 'Erfüllt', deviation: 'Abweichung', unknown: 'Unbestimmt'};
const reasons = {
  valid: 'Vorgabe erfüllt',
  'absent-in-capture': 'Header fehlt im Mitschnitt',
  'invalid-value': 'Headerwert entspricht der Vorgabe nicht',
  disabled: 'HSTS ist deaktiviert',
  'headers-unavailable': 'Headerdaten fehlen oder sind unvollständig',
  ambiguous: 'Headerangaben sind mehrdeutig',
  'ip-host': 'Host ist eine IP-Adresse'
};

function summarize(files) {
  const totals = {hsts: {met: 0, deviation: 0, unknown: 0}, nosniff: {met: 0, deviation: 0, unknown: 0}};
  const sources = [];
  for (const file of files) {
    if (file.source !== 'har') continue;
    if (!/^[a-f0-9]{64}$/.test(file.digest)) throw Error('Ungültige HAR-Prüfsumme.');
    const groups = new Map();
    for (const row of file.rows) {
      const seen = new Set();
      for (const {id, status, reason} of row.controls || []) {
        const position = /^Datensatz ([1-9]\d{0,5})$/.exec(row.locator);
        if (!Object.hasOwn(checks, id) || !Object.hasOwn(statuses, status) || !Object.hasOwn(reasons, reason) ||
            !position || seen.has(id)) throw Error('Ungültiger HAR-Prüfbeleg.');
        seen.add(id);
        totals[id][status]++;
        const key = [id, status, reason].join('/');
        if (!groups.has(key)) groups.set(key, {id, status, reason, records: []});
        groups.get(key).records.push(Number(position[1]));
      }
    }
    sources.push({sha256: file.digest, groups});
  }
  return {totals, sources};
}

function ranges(records) {
  const spans = [];
  let start = records[0], end = start;
  for (const n of records.slice(1)) {
    if (n === end + 1) { end = n; continue; }
    spans.push(start === end ? String(start) : start + '–' + end);
    start = end = n;
  }
  spans.push(start === end ? String(start) : start + '–' + end);
  return spans.join(', ');
}

export function renderHarChecks(section, files, t, printable = false) {
  const {totals, sources} = summarize(files);
  section.replaceChildren();
  section.hidden = sources.length === 0;
  if (section.hidden) return;
  const doc = section.ownerDocument;
  function append(parent, name, text) {
    const node = doc.createElement(name);
    node.textContent = text;
    parent.append(node);
    return node;
  }
  const heading = append(section, 'h2', t('Headerprüfung im HAR-Mitschnitt'));
  if (section.id) {
    heading.id = section.id + '-title';
    section.setAttribute('aria-labelledby', heading.id);
  }
  append(section, 'p', t('Geprüft werden aufgezeichnete HTML-Antworten auf HTTPS-GET-Anfragen mit Status 2xx. Einträge mit Weiterleitungsziel, widersprüchlichem Inhaltstyp oder Status 204, 205 und 206 bleiben ausgenommen. Die Zahlen gelten für diesen Mitschnitt.'));
  const table = doc.createElement('table');
  section.append(table);
  const header = table.createTHead().insertRow();
  for (const label of ['Prüfung', ...Object.values(statuses)]) append(header, 'th', t(label)).scope = 'col';
  const body = table.createTBody();
  for (const [id, label] of Object.entries(checks)) {
    const row = body.insertRow();
    append(row, 'th', label).scope = 'row';
    for (const status of Object.keys(statuses)) row.insertCell().textContent = totals[id][status];
  }
  const evidence = append(section, 'details', '');
  evidence.open = printable;
  append(evidence, 'summary', t('Quellstellen je Prüfung'));
  for (const {sha256, groups} of sources) {
    const title = append(evidence, 'p', 'SHA-256 · ');
    append(title, 'code', sha256);
    if (!groups.size) {
      append(evidence, 'p', t('Keine Antwort dieser Datei erfüllt das Prüfprofil.'));
      continue;
    }
    const list = append(evidence, 'ul', '');
    for (const {id, reason, status, records} of groups.values()) {
      const result = [checks[id], t(statuses[status])];
      if (status !== 'met') result.push(t(reasons[reason]));
      result.push(t('Datensätze {positions}', {positions: ranges(records)}));
      append(list, 'li', result.join(' · '));
    }
  }
}

// Only the portal has locally parsed HAR rows. A reopened evidence index contains references alone.
export function withHarChecks(report, files, t) {
  if (!files.some(file => file.source === 'har')) return report;
  const doc = new DOMParser().parseFromString(report.text, 'text/html');
  const section = doc.createElement('section');
  section.className = 'har-checks';
  renderHarChecks(section, files, t, true);
  doc.querySelector('main').prepend(section);
  return {...report, text: '<!doctype html>' + doc.documentElement.outerHTML + '\n'};
}
