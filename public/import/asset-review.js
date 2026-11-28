// © Nasser Aldin Farag (0xFarag). All rights reserved.
const AuthzAssets = (() => {
  'use strict';

  const hash = /^[a-f0-9]{64}$/;
  const hostId = /^[a-f0-9]{16}$/;
  const locator = /^(?:Datensatz|Zeile) [1-9][0-9]{0,6}$/;
  const pageSize = 12;
  const byText = (a, b) => a < b ? -1 : a > b ? 1 : 0;

  function createIndex(files) {
    if (!Array.isArray(files) || files.length > AuthzImport.limits.files) {
      throw new Error('Das Dateiregister ist ungültig.');
    }
    const index = {
      schema: 'authzledger.evidence-index.v1',
      rights: '© Nasser Aldin Farag (0xFarag). All rights reserved.',
      workspace: files.length ? (files[0]?.example ? 'example' : 'real') : null,
      signature: 'unsigned',
      assessment: {scope: 'unverified', controls: 'unverified', coverage: 'unknown', findings: 'not_assessed', retest: 'not_assessed'},
      files: []
    };
    const registered = new Set();
    let total = 0;
    for (const file of files) {
      if (typeof file?.example !== 'boolean' || (file.example ? 'example' : 'real') !== index.workspace) {
        throw new Error('Eigene Dateien und Beispiele benötigen getrennte Belegindizes.');
      }
      if (typeof file.source !== 'string' || !Object.hasOwn(AuthzImport.definitions, file.source)
          || typeof file.digest !== 'string' || !hash.test(file.digest) || !Array.isArray(file.rows)
          || file.rows.length > AuthzImport.limits.rows) {
        throw new Error('Ein Quelldateibeleg ist unvollständig.');
      }
      const key = file.source + '/' + file.digest;
      if (registered.has(key)) continue;
      registered.add(key);
      total += file.rows.length;
      if (total > AuthzImport.limits.totalRows) throw new Error('Der Index enthält zu viele Datensätze.');
      const observations = file.rows.map(row => {
        if (typeof row?.locator !== 'string' || !locator.test(row.locator)
            || typeof row.fingerprint !== 'string' || !hash.test(row.fingerprint)
            || (row.asset !== '' && (typeof row.asset !== 'string' || !hostId.test(row.asset)))) {
          throw new Error('Ein Datensatz enthält einen ungültigen Quellverweis.');
        }
        return {locator: row.locator, asset_id: row.asset || null, fingerprint: row.fingerprint};
      });
      index.files.push({source: file.source, sha256: file.digest, observations});
    }
    index.files.sort((a, b) => byText(a.source, b.source) || byText(a.sha256, b.sha256));
    return index;
  }

  function groupIndex(index) {
    const hosts = new Map();
    const unassigned = [];
    for (const file of index.files) {
      for (const record of file.observations) {
        const ref = {source: file.source, fileHash: file.sha256, record};
        if (record.asset_id === null) {
          unassigned.push(ref);
          continue;
        }
        if (!hosts.has(record.asset_id)) {
          hosts.set(record.asset_id, {asset: record.asset_id, sources: new Map(), refs: []});
        }
        const host = hosts.get(record.asset_id);
        host.sources.set(file.source, (host.sources.get(file.source) || 0) + 1);
        host.refs.push(ref);
      }
    }
    const sorted = Array.from(hosts.values()).sort((a, b) =>
      b.sources.size - a.sources.size || byText(a.asset, b.asset));
    return {hosts: sorted, unassigned};
  }

  function element(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined) {
      if (tag === 'code') node.textContent = text;
      else AuthzToolCopy.write(node, text);
    }
    if (className) node.className = className;
    return node;
  }

  function button(label, click) {
    const node = element('button', label);
    node.type = 'button';
    node.addEventListener('click', click);
    return node;
  }

  function table(container, caption, labels) {
    const wrapper = element('div', undefined, 'table-wrap');
    const grid = element('table');
    grid.append(element('caption', caption, 'sr'));
    const header = grid.createTHead().insertRow();
    for (const label of labels) {
      const column = element('th', label);
      column.scope = 'col';
      header.append(column);
    }
    wrapper.append(grid);
    container.append(wrapper);
    return grid.createTBody();
  }

  function pagedRows(container, body, records, show, pageLabel) {
    let page = 0;
    const maxPage = Math.max(0, Math.ceil(records.length / pageSize) - 1);
    const nav = element('div', undefined, 'row pagination');
    const status = element('span');
    status.setAttribute('aria-live', 'polite');
    const back = button('Zurück', () => { if (page > 0) page--; update(); });
    const next = button('Weiter', () => { if (page < maxPage) page++; update(); });
    AuthzToolCopy.attr(back, 'aria-label', () => AuthzToolCopy.t('{label} – vorherige Seite', {label:AuthzToolCopy.t(pageLabel)}));
    AuthzToolCopy.attr(next, 'aria-label', () => AuthzToolCopy.t('{label} – nächste Seite', {label:AuthzToolCopy.t(pageLabel)}));
    if (maxPage) {
      nav.append(status, back, next);
      container.append(nav);
    }
    function update() {
      body.replaceChildren();
      for (const entry of records.slice(page * pageSize, (page + 1) * pageSize)) {
        show(body.insertRow(), entry);
      }
      AuthzToolCopy.write(status, 'Seite {page} von {total}', {page:page+1, total:maxPage+1});
      back.disabled = !page;
      next.disabled = page === maxPage;
    }
    update();
  }

  function serializeIndex(index) {
    return JSON.stringify(index, null, 2) + '\n';
  }

  function saveIndex(index) {
    const contents = new Blob([serializeIndex(index)], {type: 'application/json'});
    const url = URL.createObjectURL(contents);
    const link = element('a');
    link.href = url;
    link.download = 'AuthzLedger-' + (index.workspace === 'example' ? 'Beispiel-' : '') + 'Belegindex.json';
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function render(container, files) {
    const heading = element('h2', 'Werkzeugübergreifende Asset-Ansicht');
    container.replaceChildren(heading);
    let index;
    try {
      index = createIndex(files);
    } catch (error) {
      const warning = element('p', error.message);
      warning.setAttribute('role', 'alert');
      container.append(warning);
      return;
    }
    if (!index.files.length) {
      container.append(element('p', 'Importiere eine Quelldatei, um ihre Hostbezüge zu sehen.'));
      return;
    }
    const {hosts, unassigned} = groupIndex(index);
    const sharedCount = hosts.filter(host => host.sources.size > 1).length;
    container.append(element('p', () => AuthzToolCopy.t('Hostkennungen: {hosts} · In mehreren Werkzeugen: {shared} · Datensätze ohne Hostbezug: {unassigned}.', {hosts:hosts.length, shared:sharedCount, unassigned:unassigned.length})));
    const details = element('div');
    function showRefs(title, refs) {
      const heading = element('h3', title);
      heading.tabIndex = -1;
      details.replaceChildren(heading);
      const body = table(details, title, ['Werkzeug', 'Position', 'SHA-256 der Datei', 'Fingerabdruck des Datensatzes']);
      pagedRows(details, body, refs, (row, ref) => {
        AuthzToolCopy.write(row.insertCell(), AuthzImport.definitions[ref.source].label);
        row.insertCell().textContent = ref.record.locator;
        row.insertCell().append(element('code', ref.fileHash));
        row.insertCell().append(element('code', ref.record.fingerprint));
      }, 'Quellverweise');
      heading.focus();
    }
    if (hosts.length) {
      const body = table(container, 'Beobachtungen nach gemeldeter Hostkennung', ['Asset-ID', 'Datensätze je Werkzeug', 'Herkunft']);
      pagedRows(container, body, hosts, (row, host) => {
        row.insertCell().append(element('code', host.asset));
        AuthzToolCopy.write(row.insertCell(), () => Array.from(host.sources, ([source, count]) =>
          AuthzToolCopy.t(AuthzImport.definitions[source].label) + ' (' + count + ')').join(' · '));
        const drilldown = button(() => AuthzToolCopy.t('Belege ({count})', {count:host.refs.length}), () => showRefs(() => AuthzToolCopy.t('Quellverweise für {asset}', {asset:host.asset}), host.refs));
        AuthzToolCopy.attr(drilldown, 'aria-label', () => AuthzToolCopy.t('Belege für Asset {asset} anzeigen', {asset:host.asset}));
        row.insertCell().append(drilldown);
      }, 'Assets');
    }
    if (unassigned.length) {
      container.append(button(() => AuthzToolCopy.t('Belege ohne Hostbezug ({count})', {count:unassigned.length}),
        () => showRefs('Datensätze ohne zugeordneten Host', unassigned)));
    }
    container.append(details);
    container.append(element('p', 'Gleiche Hostkennungen verbinden Beobachtungen innerhalb dieses Arbeitsbereichs. Jede Quellenposition bleibt einzeln nachvollziehbar. Mandatsumfang, Controls und Abdeckung sind ungeprüft.'));
    const exportLabel = index.workspace === 'example' ? 'Beispiel-Belegindex als JSON speichern' : 'Belegindex als JSON speichern';
    container.append(button(exportLabel, () => saveIndex(index)));
    container.append(element('p', 'Der unsignierte Index enthält Werkzeugnamen, Hashwerte, Asset-IDs und Quellenpositionen. Bewahre ihn zusammen mit den Originalexporten auf.'));
  }

  return Object.freeze({createIndex, groupIndex, serializeIndex, render});
})();
