// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
(() => {
  const {limits, definitions, samples, parse, ImportError} = AuthzImport;
  const $ = id => document.getElementById(id);
  const element = (tag, value) => {const e = document.createElement(tag); e.textContent = value; return e;};
  const stores = {real: [], examples: []};
  let mode = 'real', page = 0, busy = false, sequence = 0;
  for (const [key, info] of Object.entries(definitions)) {
    for (const id of ['adapter','filter']) $(id).add(new Option(info.label,key));
  }
  const autoOption = new Option('Automatisch erkennen', 'auto');
  $('adapter').add(autoOption, 0);
  $('adapter').value = 'auto';
  function updateHint() {
    const key = $('adapter').value;
    const automatic = key === 'auto';
    $('sample-detail').hidden = automatic;
    if (automatic) {
      $('file').accept = [...new Set(Object.values(definitions).flatMap(def => def.accept.split(',')))].join(',');
      $('hint').textContent = 'Du kannst Exporte verschiedener Werkzeuge zusammen auswählen. Das Format wird am Dateiinhalt erkannt. Jede Datei wird einzeln geprüft.';
      $('follow').hidden = true;
      return;
    }
    $('file').accept = definitions[key].accept;
    $('hint').textContent = definitions[key].hint;
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
    $('context').textContent = example ? 'Beispieldaten mit frei erfundenen Datensätzen. Deine eigenen Dateien liegen im separaten Arbeitsbereich.' : 'Wähle Dateien aus demselben Mandat. Alle Importe bleiben lokal in diesem Tab.';
    $('add').textContent = example ? 'Beispiel hinzufügen' : 'Dateien auswählen';
    $('clear').disabled = busy || !files.length;
    $('add').disabled = $('adapter').disabled = $('real').disabled = $('examples').disabled = $('follow').disabled = busy;
    $('prev').disabled = !page; $('next').disabled = page+1 >= pages;
    $('totals').textContent = files.length + ' Dateien · ' + selected.length + ' Beobachtungen in der Auswahl';
    $('page').textContent = 'Seite ' + (page+1) + ' von ' + pages;
    $('body').replaceChildren();
    for (const {f,r,prior} of selected.slice(page*50,(page+1)*50)) {
      const tr = document.createElement('tr');
      for (const v of [definitions[f.source].label, f.id+' · '+r.locator, r.asset || 'Kein Hostbezug', r.detail, prior ? 'Duplikat zu '+prior+' · ungeprüft' : 'Scope und Controls ungeprüft']) tr.append(element('td', v));
      $('body').append(tr);
    }
    if (!selected.length) {
      const tr = document.createElement('tr'); const td = element('td', files.length ? 'Für diese Auswahl liegen keine Beobachtungen vor.' : 'Dieser Arbeitsbereich enthält noch keine Dateien.');
      td.className = 'empty'; td.colSpan=5; tr.append(td); $('body').append(tr);
    }
    $('files').replaceChildren();
    for (const f of files) {
      const li = element('li', f.id+' · '+definitions[f.source].label+' · '+f.rows.length+' Datensätze · '+f.bytes+' Bytes · SHA-256 ');
      li.append(element('code', f.digest)); $('files').append(li);
    }
    if (!files.length) $('files').append(element('li','Keine Quelldateien.'));
    updateHint();
    if (typeof AuthzCompare !== 'undefined') AuthzCompare.render($('comparison'), files);
    AuthzAssets.render($('asset-review'), files);
  }
  function fileList() { return [...stores.real, ...stores.examples]; }
  async function add(inputs) {
    if (busy) return;
    const source = $('adapter').value;
    busy = true; refresh(); $('status').textContent = 'Dateien werden lokal geprüft …';
    const messages = [];
    try {
      if (inputs.length > limits.files) { messages.push('Pro Auswahl sind höchstens 20 Dateien zulässig.'); return; }
      for (const [index, item] of inputs.entries()) {
        try {
          if (!item.size || item.size > limits.bytes) throw new ImportError('Die Datei muss zwischen 1 Byte und 1 MiB gross sein.');
          const parsed = await parse(source, await item.arrayBuffer());
          const duplicate = stores[mode].find(f => f.digest === parsed.digest);
          if (duplicate) {messages.push('Datei '+(index+1)+' ist bereits als '+duplicate.id+' enthalten (identische Bytes).'); continue;}
          const all = fileList();
          if (all.length >= limits.files || all.reduce((s,f) => s+f.bytes,0)+parsed.bytes > limits.totalBytes || all.reduce((s,f) => s+f.rows.length,0)+parsed.rows.length > limits.totalRows) throw new ImportError('Die gemeinsame Dateigrenze ist erreicht. Leere bei Bedarf einen Arbeitsbereich.');
          const id = 'S'+String(++sequence).padStart(2,'0');
          stores[mode].push({...parsed, id, example:mode==='examples'});
          messages.push(id+' eingelesen · '+definitions[parsed.source].label+' · '+parsed.rows.length+' Beobachtungen.');
        } catch (e) { messages.push('Datei '+(index+1)+' abgelehnt. '+(e instanceof ImportError ? e.message : 'Die Datei lässt sich in diesem Format nicht verarbeiten.')); }
      }
    } finally {
      busy=false; $('file').value=''; $('status').textContent=messages.join('\n'); refresh();
    }
  }
  function switchMode(next) {
    if (busy || mode === next) return;
    mode = next;
    autoOption.disabled = mode === 'examples';
    $('adapter').value = autoOption.disabled ? 'ffuf' : 'auto';
    page = 0;
    $('filter').value = '';
    $('status').textContent = '';
    refresh();
  }
  $('real').onclick=()=>switchMode('real'); $('examples').onclick=()=>switchMode('examples');
  $('adapter').onchange=updateHint; $('filter').onchange=()=>{page=0;refresh();};
  $('file').onchange=()=>add(Array.from($('file').files));
  $('add').onclick=()=> mode==='examples' ? add([new Blob([samples[$('adapter').value]])]) : $('file').click();
  $('follow').onclick=()=>add([new Blob(['{"results":[{"url":"https://training.example/first","status":403},{"url":"https://training.example/third","status":200}]}'])]);
  $('clear').onclick=()=>{if(busy)return;stores[mode]=[]; page=0; $('status').textContent='Arbeitsbereich geleert.';refresh();};
  $('prev').onclick=()=>{if(page>0)page--;refresh();}; $('next').onclick=()=>{page++;refresh();};
  refresh();
})();
