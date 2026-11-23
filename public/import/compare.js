// © Nasser Aldin Farag (0xFarag). All rights reserved.
const AuthzCompare = (() => {
  'use strict';

  const statusNames = {
    repeated: 'Gleicher Beobachtungsbeleg',
    different: 'Beobachtungsbelege weichen ab',
    earlier_only: 'Nur früher belegt · not_retested',
    later_only: 'Nur im späteren Import belegt',
    ambiguous: 'Mehrdeutiger Bezug · ungeprüft',
    unknown: 'Zuordnung unklar · ungeprüft'
  };
  const validHash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
  const validAsset = value => typeof value === 'string' && /^[a-f0-9]{16}$/.test(value);

  function compare(earlier, later) {
    if (!earlier || !later) return { message: 'Zwei Quelldateien auswählen.' };
    if (!Object.hasOwn(AuthzImport.definitions, earlier.source) || earlier.source !== later.source) {
      return { message: 'Die beiden Importe müssen aus demselben Werkzeug stammen.' };
    }
    if (typeof earlier.example !== 'boolean' || earlier.example !== later.example) {
      return { message: 'Beispieldaten und eigene Mandatsdaten werden getrennt verglichen.' };
    }
    if (!validHash(earlier.digest) || !validHash(later.digest)
        || !Array.isArray(earlier.rows) || !Array.isArray(later.rows)) {
      return { message: 'Für diesen Vergleich fehlen ein Dateinachweis oder die Beobachtungen.' };
    }
    if (earlier.digest === later.digest) {
      return { message: 'Beide Importe haben denselben Datei-Hash. Damit liegt nur ein eigenständiger Dateibeleg vor.' };
    }

    const groups = new Map();
    const entries = [];
    function add(file, side) {
      file.rows.forEach((row, index) => {
        const asset = row && validAsset(row.asset) ? row.asset : '';
        const identity = row && validHash(row.identity) ? row.identity : '';
        const ref = { position: index + 1, locator: row?.locator, fingerprint: row?.fingerprint };
        if (!asset || !identity || !validHash(ref.fingerprint)) {
          entries.push({ status: 'unknown', asset, identity: '', earlier: [], later: [], [side]: [ref] });
          return;
        }
        const key = JSON.stringify([file.source, asset, identity]);
        if (!groups.has(key)) {
          const group = { asset, identity, earlier: [], later: [] };
          groups.set(key, group);
          entries.push(group);
        }
        groups.get(key)[side].push(ref);
      });
    }
    add(earlier, 'earlier');
    add(later, 'later');
    for (const group of groups.values()) {
      const a = group.earlier;
      const b = group.later;
      if (a.length > 1 || b.length > 1) group.status = 'ambiguous';
      else if (!b.length) group.status = 'earlier_only';
      else if (!a.length) group.status = 'later_only';
      else group.status = a[0].fingerprint === b[0].fingerprint ? 'repeated' : 'different';
    }
    return { source: earlier.source, entries, beforeCount: earlier.rows.length, afterCount: later.rows.length };
  }

  function element(tag, text) {
    const node = document.createElement(tag);
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function locations(refs) {
    if (!refs.length) return '—';
    const visible = refs.slice(0, 3).map(ref =>
      /^(?:record|line|row|datensatz|zeile) [0-9]+$/i.test(ref.locator) ? ref.locator : 'Datensatz ' + ref.position);
    if (refs.length > visible.length) visible.push('+' + (refs.length - visible.length));
    return visible.join(', ');
  }

  function showResult(target, result) {
    target.replaceChildren();
    if (result.message) {
      target.append(element('p', result.message));
      return;
    }
    const summary = result.beforeCount + ' Datensätze früher, ' + result.afterCount + ' später. '
      + 'Der Vergleich ordnet Importbelege zu. Eine Korrektur ist erst durch einen belegten Retest prüfbar.';
    target.append(element('p', summary));
    if (!result.entries.length) return;
    const table = element('table');
    const caption = element('caption', 'Vergleich je Asset und Fallbezug · ' + AuthzImport.definitions[result.source].label);
    table.append(caption);
    const header = table.createTHead().insertRow();
    for (const title of ['Asset / Fallbezug', 'Frühere Quelle', 'Spätere Quelle', 'Belegstatus']) {
      const th = element('th', title);
      th.scope = 'col';
      header.append(th);
    }
    const body = table.createTBody();
    const scroller = element('div');
    scroller.className = 'table-wrap';
    scroller.append(table);
    target.append(scroller);
    const more = element('button', 'Weitere 40 Vergleichszeilen anzeigen');
    more.type = 'button';
    target.append(more);
    let shown = 0;
    function appendNext() {
      const limit = Math.min(shown + 40, result.entries.length);
      for (; shown < limit; shown++) {
        const entry = result.entries[shown];
        const row = body.insertRow();
        const subject = row.insertCell();
        subject.textContent = entry.asset ? entry.asset : 'Unbekanntes Asset';
        if (entry.identity) {
          subject.append(element('br'));
          const check = element('small', entry.identity.slice(0, 12));
          check.title = entry.identity;
          subject.append(check);
        }
        row.insertCell().textContent = locations(entry.earlier);
        row.insertCell().textContent = locations(entry.later);
        row.insertCell().textContent = statusNames[entry.status];
      }
      if (shown === result.entries.length) more.remove();
    }
    more.addEventListener('click', appendNext);
    appendNext();
  }

  function render(container, files) {
    const previousCheck = container.querySelector('#authz-compare-scope')?.checked;
    const previousA = container.querySelector('[data-snapshot="earlier"]')?.value;
    const previousB = container.querySelector('[data-snapshot="later"]')?.value;
    container.replaceChildren(element('h2', 'Zwei Importstände vergleichen'));
    container.append(element('p', 'Wähle die zeitliche Reihenfolge selbst. Der Vergleich benötigt zwei Dateien desselben Werkzeugs mit eindeutigem Asset- und Fallbezug.'));
    if (files.length < 2) {
      container.append(element('p', 'Für den Vergleich mindestens zwei Quelldateien laden.'));
      return;
    }
    const controls = element('div');
    controls.className = 'row controls';
    const fileByKey = new Map(files.map(file => [JSON.stringify([file.id, file.digest]), file]));
    function selector(side, name, previous) {
      const label = element('label', name + ' ');
      const select = element('select');
      select.dataset.snapshot = side;
      const placeholder = element('option', 'Datei wählen');
      placeholder.value = '';
      select.append(placeholder);
      for (const [key, file] of fileByKey) {
        const source = Object.hasOwn(AuthzImport.definitions, file.source) ? AuthzImport.definitions[file.source].label : 'Unbekannt';
        const id = /^S\d+$/.test(file.id) ? file.id : 'Quelle';
        const digest = validHash(file.digest) ? file.digest.slice(0, 12) : 'Hash fehlt';
        const option = element('option', id + ' · ' + source + ' · ' + digest + (file.example ? ' · Beispiel' : ''));
        option.value = key;
        option.selected = previous !== undefined && previous === option.value;
        select.append(option);
      }
      label.append(select);
      controls.append(label, document.createTextNode(' '));
      return select;
    }
    const a = selector('earlier', 'Früher', previousA);
    const b = selector('later', 'Später', previousB);
    const confirmation = element('div');
    confirmation.className = 'row';
    const check = element('input');
    check.type = 'checkbox';
    check.id = 'authz-compare-scope';
    check.checked = Boolean(previousCheck && a.value && b.value && a.value === previousA && b.value === previousB);
    const checkLabel = element('label', 'Beide Exporte stammen aus demselben freigegebenen Mandat und derselben Quell- oder Projektinstanz. Die Exportkonfiguration stimmt überein.');
    checkLabel.htmlFor = check.id;
    confirmation.append(check, checkLabel);
    container.append(controls, confirmation);
    const results = element('div');
    results.setAttribute('aria-live', 'polite');
    container.append(results);
    function update() {
      if (a.value === '' || b.value === '') {
        results.replaceChildren();
        return;
      }
      const result = compare(fileByKey.get(a.value), fileByKey.get(b.value));
      if (result.message || check.checked) showResult(results, result);
      else results.replaceChildren(element('p', 'Bestätige Mandat, Quellinstanz und Exportkonfiguration, um die Belege zu vergleichen.'));
    }
    for (const select of [a, b]) select.addEventListener('change', () => { check.checked = false; update(); });
    check.addEventListener('change', update);
    update();
  }

  return Object.freeze({ compare, render });
})();
