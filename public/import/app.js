// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {parseProjection} from '../workbench/model.mjs';
import {makeCustomerReport} from '../workbench/exports.mjs';
import {saveFile} from '../workbench/delivery.mjs';
import {renderHarChecks, withHarChecks} from './control-summary.mjs';
(() => {
  const {limits, definitions, samples, parse, ImportError} = AuthzImport;
  const {t, write} = AuthzToolCopy;
  const $ = id => document.getElementById(id);
  const element = (tag, value) => {const e = document.createElement(tag); e.textContent = value; return e;};
  const stores = {real: [], examples: []};
  let mode = 'real', page = 0, busy = false, sequence = 0;
  let reportVersion = 0, preparingReport = false;
  function invalidateReport() {
    reportVersion++;
    preparingReport = false;
    $('report-status').replaceChildren();
  }
  for (const [key, info] of Object.entries(definitions)) {
    for (const id of ['adapter','filter']) {
      const option = new Option('',key); write(option, info.label); $(id).add(option);
    }
  }
  const autoOption = new Option('', 'auto');
  write(autoOption, 'Automatisch erkennen');
  $('adapter').add(autoOption, 0);
  $('adapter').value = 'auto';
  function updateHint() {
    const key = $('adapter').value;
    const automatic = key === 'auto';
    $('sample-detail').hidden = automatic;
    if (automatic) {
      $('file').accept = [...new Set(Object.values(definitions).flatMap(def => def.accept.split(',')))].join(',');
      write($('hint'), 'Sie können Exporte verschiedener Werkzeuge zusammen auswählen. Das Format wird am Dateiinhalt erkannt. Jede Datei wird einzeln geprüft.');
      $('follow').hidden = true;
      return;
    }
    $('file').accept = definitions[key].accept;
    write($('hint'), definitions[key].hint);
    $('sample').textContent = key === 'ffuf' || key === 'cobalt' ? JSON.stringify(JSON.parse(samples[key]),null,2) : samples[key];
    $('follow').hidden = mode !== 'examples' || key !== 'ffuf';
  }
  function refresh() {
    const example = mode === 'examples';
    const files = stores[mode];
    const unique = new Map();
    const selected = [];
    for (const f of files) for (const r of f.rows) {
      const prior = unique.get(r.fingerprint);
      if (!prior) unique.set(r.fingerprint, f.id + ' · ' + r.locator);
      if (!$('filter').value || $('filter').value === f.source) selected.push({f,r,prior});
    }
    const pages = Math.max(1,Math.ceil(selected.length / 50));
    page = Math.min(page,pages-1);
    $('real').setAttribute('aria-pressed',String(!example));
    $('examples').setAttribute('aria-pressed',String(example));
    write($('context'), example ? 'Beispieldaten mit frei erfundenen Datensätzen. Ihre eigenen Dateien liegen im separaten Arbeitsbereich.' : 'Wählen Sie Dateien aus demselben Mandat. Alle Importe bleiben lokal in diesem Tab.');
    write($('add'), example ? 'Beispiel hinzufügen' : 'Dateien auswählen');
    $('clear').disabled = busy || !files.length;
    $('save-report').disabled = $('clear').disabled || preparingReport;
    write($('save-report'), example ? 'Beispielbericht als HTML speichern' : 'Bericht als HTML speichern');
    $('add').disabled = $('adapter').disabled = $('real').disabled = $('examples').disabled = $('follow').disabled = busy;
    $('prev').disabled = !page; $('next').disabled = page+1 >= pages;
    write($('totals'), '{files} Dateien · {observations} Beobachtungen in der Auswahl', {files:files.length, observations:selected.length});
    write($('page'), 'Seite {page} von {total}', {page:page+1, total:pages});
    $('body').replaceChildren();
    for (const {f,r,prior} of selected.slice(page*50,(page+1)*50)) {
      const tr = document.createElement('tr');
      write(tr.insertCell(), definitions[f.source].label);
      tr.insertCell().textContent = f.id + ' · ' + r.locator;
      const host = tr.insertCell();
      if (r.asset) host.textContent = r.asset;
      else write(host, 'Kein Hostbezug');
      write(tr.insertCell(), r.detail);
      write(tr.insertCell(), prior ? 'Duplikat zu {prior} · ungeprüft' : 'Scope und Controls ungeprüft', {prior});
      $('body').append(tr);
    }
    if (!selected.length) {
      const tr = document.createElement('tr'); const td = tr.insertCell(); write(td, files.length ? 'Für diese Auswahl liegen keine Beobachtungen vor.' : 'Dieser Arbeitsbereich enthält noch keine Dateien.');
      td.className = 'empty'; td.colSpan=5; $('body').append(tr);
    }
    $('files').replaceChildren();
    for (const f of files) {
      const li = document.createElement('li');
      write(li, () => f.id+' · '+t(definitions[f.source].label)+' · '+t('{records} Datensätze · {bytes} Bytes · SHA-256', {records:f.rows.length, bytes:f.bytes})+' ');
      li.append(element('code', f.digest)); $('files').append(li);
    }
    if (!files.length) {const item=document.createElement('li'); write(item, 'Keine Quelldateien.'); $('files').append(item);}
    updateHint();
    if (typeof AuthzCompare !== 'undefined') AuthzCompare.render($('comparison'), files);
    AuthzAssets.render($('asset-review'), files);
    renderHarChecks($('har-checks'), files, t);
  }
  function fileList() { return [...stores.real, ...stores.examples]; }
  function errorText(error) {
    if (!(error instanceof ImportError)) return t('Die Datei lässt sich in diesem Format nicht verarbeiten.');
    const line = error.message.match(/^(.* in Zeile )(\d+)\.$/);
    return line ? t(line[1] + '{n}.', {n:line[2]}) : t(error.message);
  }
  async function add(inputs) {
    if (busy) return;
    const source = $('adapter').value;
    busy = true; invalidateReport(); refresh(); write($('status'), 'Dateien werden lokal geprüft …');
    const messages = [];
    try {
      if (inputs.length > limits.files) { messages.push(() => t('Pro Auswahl sind höchstens 20 Dateien zulässig.')); return; }
      for (const [index, item] of inputs.entries()) {
        try {
          if (!item.size || item.size > limits.bytes) throw new ImportError('Die Datei muss zwischen 1 Byte und 1 MiB gross sein.');
          const parsed = await parse(source, await item.arrayBuffer());
          const duplicate = stores[mode].find(f => f.digest === parsed.digest);
          if (duplicate) {messages.push(() => t('Datei {n} ist bereits als {id} enthalten (identische Bytes).', {n:index+1, id:duplicate.id})); continue;}
          const all = fileList();
          if (all.length >= limits.files || all.reduce((s,f) => s+f.bytes,0)+parsed.bytes > limits.totalBytes || all.reduce((s,f) => s+f.rows.length,0)+parsed.rows.length > limits.totalRows) throw new ImportError('Die gemeinsame Dateigrenze ist erreicht. Leere bei Bedarf einen Arbeitsbereich.');
          const id = 'S'+String(++sequence).padStart(2,'0');
          stores[mode].push({...parsed, id, example:mode==='examples'});
          messages.push(() => t('{id} eingelesen · {tool} · {count} Beobachtungen.', {id, tool:t(definitions[parsed.source].label), count:parsed.rows.length}));
        } catch (e) { messages.push(() => t('Datei {n} abgelehnt. {reason}', {n:index+1, reason:errorText(e)})); }
      }
    } finally {
      busy=false; $('file').value=''; write($('status'), () => messages.map(render => render()).join('\n')); refresh();
    }
  }
  async function saveReport() {
    if (busy || preparingReport || !stores[mode].length) return;
    const version = reportVersion;
    preparingReport = true;
    $('save-report').disabled = true;
    try {
      const index = AuthzAssets.createIndex(stores[mode]);
      const data = new TextEncoder().encode(AuthzAssets.serializeIndex(index));
      const model = await parseProjection(data);
      if (version !== reportVersion) return;
      const language = window.AuthzI18n?.lang || document.documentElement.lang.split('-')[0];
      saveFile(withHarChecks(makeCustomerReport(model, {language}), stores[mode], t));
      write($('report-status'), 'Der HTML-Bericht ist zum Speichern bereit.');
    } catch {
      if (version !== reportVersion) return;
      write($('report-status'), 'Der Bericht konnte aus diesen Quelldateien nicht erstellt werden.');
    } finally {
      if (version === reportVersion) {
        preparingReport = false;
        $('save-report').disabled = busy || !stores[mode].length;
      }
    }
  }
  $('save-report').onclick = saveReport;
  window.addEventListener('authzlanguage', () => renderHarChecks($('har-checks'), stores[mode], t));
  function switchMode(next) {
    if (busy || mode === next) return;
    mode = next;
    autoOption.disabled = mode === 'examples';
    $('adapter').value = autoOption.disabled ? 'ffuf' : 'auto';
    page = 0;
    $('filter').value = '';
    $('status').textContent = '';
    invalidateReport();
    refresh();
  }
  $('real').onclick=()=>switchMode('real'); $('examples').onclick=()=>switchMode('examples');
  $('adapter').onchange=updateHint; $('filter').onchange=()=>{page=0;refresh();};
  $('file').onchange=()=>add(Array.from($('file').files));
  $('add').onclick=()=> mode==='examples' ? add([new Blob([samples[$('adapter').value]])]) : $('file').click();
  $('follow').onclick=()=>add([new Blob(['{"results":[{"url":"https://training.example/first","status":403},{"url":"https://training.example/third","status":200}]}'])]);
  $('clear').onclick=()=>{if(busy)return;stores[mode]=[]; page=0; invalidateReport(); write($('status'), 'Arbeitsbereich geleert.');refresh();};
  $('prev').onclick=()=>{if(page>0)page--;refresh();}; $('next').onclick=()=>{page++;refresh();};
  refresh();
})();
