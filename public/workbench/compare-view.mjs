// ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
import { compareProjections } from './compare.mjs';
import { statusLabels } from './model.mjs';
import { exampleSnapshots } from './compare-example.mjs';

const stateLabels = {
  changed:'Fall geändert', contextOnly:'Nur Belegstand geändert', leftOnly:'Nur im ersten Stand', rightOnly:'Nur im zweiten Stand',
  unbound:'Bindung ungeklärt', same:'Gleich'
};
const explanations = {
  same:'Alle vom Reader angezeigten Felder stimmen überein.',
  leftOnly:'Die ID erscheint nur im ersten Stand. Der Behebungsstatus bleibt offen.',
  rightOnly:'Die ID erscheint erstmals in diesem Vergleich. Wann der Befund entstanden ist, bleibt offen.',
  unbound:'Die Fall-ID stimmt überein. Der zusätzliche Bindungsnachweis fehlt oder unterscheidet sich.'
};
const pageSize = 20;
const views = new WeakMap();

function node(tag, text, className) {
  const el = document.createElement(tag);
  if (text !== undefined) el.textContent = text;
  if (className) el.className = className;
  return el;
}
function option(value, text) {
  const el = node('option', text);
  el.value = value;
  return el;
}
function labelForStatus(value) {
  return Object.hasOwn(statusLabels, value) ? statusLabels[value] : value;
}
function listField(value, field) {
  if (!value.length) return 'Feld fehlt';
  return value.map(v => field === 'status' ? labelForStatus(v) : String(v)).join(' · ');
}
function detailsForRow(record) {
  const item = node('li');
  const details = node('details');
  const title = record.after?.title || record.before.title;
  const heading = node('summary');
  heading.append(node('span', title), node('span', stateLabels[record.state], 'cmp-tag'));
  details.append(heading, node('code', record.id, 'cmp-id'));
  if (record.state === 'changed' || record.state === 'contextOnly') {
    const dl = node('dl', undefined, 'cmp-diff');
    for (const {field, label, before, after} of record.changes) {
      const pair = node('div');
      pair.append(node('dt', label));
      for (const [period, values] of [['Erster Stand', before], ['Zweiter Stand', after]]) {
        const dd = node('dd');
        dd.append(node('span', period), node('strong', listField(values, field)));
        pair.append(dd);
      }
      dl.append(pair);
    }
    details.append(dl);
  } else {
    details.append(node('p', explanations[record.state]));
    if (record.state === 'unbound') {
      details.append(node('p', 'Bindungsnachweis im ersten und zweiten Stand'),
        node('code', record.before.binding || 'Fehlt', 'cmp-id'),
        node('code', record.after.binding || 'Fehlt', 'cmp-id'));
    }
  }
  item.append(details);
  return item;
}

function buildView(root) {
  const panel = node('details', undefined, 'cmp-panel');
  const open = node('summary');
  open.append(node('span', 'Belegstände vergleichen'));
  panel.append(open);
  const body = node('div', undefined, 'cmp-body');
  body.append(node('p', 'Vergleichen Sie denselben Quellentyp aus demselben Assessment und Scope. Der Vergleich zeigt, welche dokumentierten Felder sich geändert haben.'));
  const example = node('button', 'Beispielvergleich öffnen', 'cmp-example');
  example.type = 'button';
  example.setAttribute('aria-pressed', 'false');
  const mode = node('p', undefined, 'cmp-mode');
  mode.hidden = true;
  const inputs = node('div', undefined, 'cmp-inputs');
  const selectors = ['Erster Stand', 'Zweiter Stand'].map(name => {
    const label = node('label', name);
    const select = node('select');
    label.append(select);
    inputs.append(label);
    return select;
  });
  const announcement = node('p', undefined, 'cmp-message');
  announcement.setAttribute('role', 'status');
  const content = node('div');
  body.append(example, mode, inputs, announcement, content);
  panel.append(body);
  root.replaceChildren(panel);
  const state = {selectors, entries:[], workspace:[], examples:null, demo:false, filter:'all', page:0, result:null};
  function drawRows(list, footer, back, more, pageStatus) {
    const rows = state.result.rows.filter(record => state.filter === 'all' || record.state === state.filter);
    const first = state.page * pageSize;
    list.replaceChildren(...rows.slice(first, first + pageSize).map(detailsForRow));
    pageStatus.textContent = rows.length ? (first + 1) + '–' + Math.min(first + pageSize,rows.length) + ' von ' + rows.length : 'Keine Einträge';
    back.disabled = state.page === 0;
    more.disabled = first + pageSize >= rows.length;
    footer.hidden = rows.length <= pageSize;
  }
  function update() {
    state.page = 0;
    state.filter = 'all';
    content.replaceChildren();
    const entries = selectors.map(select => state.entries.find(item => item.key === select.value));
    if (state.entries.length < 2 || !entries.every(Boolean)) {
      announcement.textContent = 'Laden Sie zwei passende Belegstände in den Arbeitsbereich.';
      return;
    }
    if (entries[0].key === entries[1].key) {
      announcement.textContent = 'Wählen Sie zwei verschiedene Einträge.';
      return;
    }
    const result = compareProjections(entries[0].model, entries[1].model);
    state.result = result;
    if (!result.comparable) {
      announcement.textContent = 'Vergleich nicht möglich. ' + result.message;
      return;
    }
    announcement.textContent = (result.sameFile ? 'Die Datei-Fingerabdrücke stimmen überein. ' : '') +
      result.leftCount + ' Einträge im ersten, ' + result.rightCount + ' im zweiten Stand. ' +
      'Insgesamt ' + result.rows.length + ' unterschiedliche IDs.';
    const ledger = node('dl', undefined, 'cmp-counts');
    for (const [code, label] of Object.entries(stateLabels)) {
      const pair = node('div');
      pair.append(node('dt', label), node('dd', String(result.counts[code])));
      ledger.append(pair);
    }
    content.append(ledger);
    if (!result.rows.length) return;
    const filterLabel = node('label', 'Angezeigte IDs', 'cmp-filter');
    const filter = node('select');
    filter.append(option('all', 'Alle Einträge'));
    for (const [code, label] of Object.entries(stateLabels)) {
      if (result.counts[code]) filter.append(option(code, label));
    }
    filterLabel.append(filter);
    const list = node('ul', undefined, 'cmp-rows');
    const footer = node('div', undefined, 'cmp-pages');
    const pageStatus = node('span');
    pageStatus.setAttribute('role','status');
    const back = node('button', 'Zurück');
    const more = node('button', 'Weiter');
    back.type = more.type = 'button';
    footer.append(back, pageStatus, more);
    const draw = () => drawRows(list, footer, back, more, pageStatus);
    filter.addEventListener('change', () => { state.filter = filter.value; state.page = 0; draw(); });
    back.addEventListener('click', () => { state.page--; draw(); if (back.disabled) more.focus(); });
    more.addEventListener('click', () => { state.page++; draw(); if (more.disabled) back.focus(); });
    content.append(filterLabel, list, footer);
    draw();
  }
  for (const select of selectors) select.addEventListener('change', update);
  function showEntries(entries) {
    if (entries.length === state.entries.length && entries.every((item, i) =>
      item.key === state.entries[i].key && item.name === state.entries[i].name)) return;
    state.entries = entries;
    const oldKeys = selectors.map(s => s.value);
    for (const select of selectors) {
      select.replaceChildren(...entries.map(({key,name}) => option(key,name)));
      select.disabled = entries.length < 2;
    }
    const left = entries.find(item => item.key === oldKeys[0]) || entries[0];
    const compatible = left && entries.find(item => item.key !== left.key && item.model.kind === left.model.kind &&
      item.model.assessment === left.model.assessment && item.model.scope === left.model.scope);
    const right = entries.find(item => item.key === oldKeys[1] && item.key !== left?.key) ||
      compatible || entries.find(item => item.key !== left?.key);
    if (left) selectors[0].value = left.key;
    if (right) selectors[1].value = right.key;
    update();
  }
  state.setEntries = entries => {
    state.workspace = entries;
    if (!state.demo) showEntries(entries);
  };
  example.addEventListener('click', async () => {
    example.disabled = true;
    try {
      if (!state.demo && !state.examples) state.examples = await exampleSnapshots();
      state.demo = !state.demo;
      example.setAttribute('aria-pressed', String(state.demo));
      example.textContent = state.demo ? 'Zu meinen Belegständen' : 'Beispielvergleich öffnen';
      mode.hidden = !state.demo;
      mode.textContent = state.demo ? 'Synthetisches Beispiel. Ein Fall wechselt im zweiten Stand den Status. Der zweite Fall bleibt ungeprüft und ist in beiden Ständen sichtbar.' : '';
      showEntries(state.demo ? state.examples : state.workspace);
    } catch {
      announcement.textContent = 'Die Übungsbelege konnten nicht gelesen werden.';
    } finally {
      example.disabled = false;
      example.focus();
    }
  });
  update();
  return state;
}

export function renderComparison(root, models) {
  if (!root) return;
  if (!views.has(root)) views.set(root, buildView(root));
  const occurrences = new Map();
  const entries = models.map(entry => {
    const model = entry.model || entry;
    const count = occurrences.get(model.digest) || 0;
    occurrences.set(model.digest, count + 1);
    return {
      model, key:model.digest + ':' + count,
      name:(entry.name || model.title) + ' · ' + model.digest.slice(0,10)
    };
  });
  views.get(root).setEntries(entries);
}
