// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const AuthzDirectoryProfiles = (() => {
  const dirHeader = ['Found', 'Response Code', 'Content Length'];
  const sqlHeader = ['Target URL', 'Place', 'Parameter', 'Technique(s)', 'Note(s)'];
  const dirBanner = 'DirBuster 1.0-RC1 - Report';
  const dirProject = 'http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project';
  const separator = '--------------------------------';
  const invalidCsv = 'Ungültiger CSV-Datensatz.';
  const invalidDir = 'Ungültiger DirBuster-Bericht.';
  const invalidSql = 'Ungültiger sqlmap-Ergebnisbericht.';
  const invalidUrl = 'Der Bericht benötigt eine gültige HTTP(S)-Adresse ohne Zugangsdaten.';
  const definitions = {
    dirbuster: {label: 'DirBuster', format: 'DirBuster 1.0-RC1 · CSV / TXT', accept: '.csv,.txt',
      hint: 'DirBuster 1.0-RC1 als CSV oder vollständiger Textbericht. Die Tabelle zeigt den HTTP-Status. Der Volltext enthält zusätzlich Host und Ergebnistyp. Pfade und Fehlermeldungen bleiben verborgen.'},
    sqlmap: {label: 'sqlmap', format: 'sqlmap · CSV',
      accept: '.csv', hint: 'Mehrziel-Ergebnisdatei mit den fünf Standardspalten ab Target URL. Angezeigt werden der pseudonymisierte Host und die Einstufung des Werkzeugs. Parameter, Pfade und Notizen bleiben verborgen.'}
  };
  const samples = {
    dirbuster: '"Found","Response Code","Content Length"\n"/example/","200","42"\n',
    sqlmap: sqlHeader.join(',') + '\nhttps://training.example/,GET,example,B,\n'
  };
  function detect(text) {
    const first = text.split(/[\r\n]/, 1)[0];
    if (first === dirBanner || first === '"Found","Response Code","Content Length"' || first === dirHeader.join(',')) return 'dirbuster';
    if (first === sqlHeader.join(',') || first === '"Target URL","Place","Parameter","Technique(s)","Note(s)"') return 'sqlmap';
    return null;
  }
  // Read quoted fields without splitting multiline CSV records. Bound the number of
  // columns before storing any extra fields; the caller enforces the file/row budget.
  function* csvRows(text, header, requireThat) {
    let offset = 0;
    let line = 1;
    let isHeader = true;
    while (offset < text.length) {
      const start = line;
      const fields = [];
      while (true) {
        requireThat(fields.length < header.length, invalidCsv);
        let value = '';
        if (text[offset] === '"') {
          offset++;
          let closed = false;
          while (offset < text.length) {
            const next = text.indexOf('"', offset);
            requireThat(next >= 0, invalidCsv);
            const part = text.slice(offset, next);
            line += (part.match(/\r\n|[\n\r]/g) || []).length;
            value += part;
            offset = next + 1;
            if (text[offset] !== '"') { closed = true; break; }
            value += '"'; offset++;
          }
          requireThat(closed, invalidCsv);
        } else {
          const begin = offset;
          while (offset < text.length && ![',','\r','\n'].includes(text[offset])) {
            requireThat(text[offset] !== '"', invalidCsv);
            offset++;
          }
          value = text.slice(begin, offset);
        }
        fields.push(value);
        if (text[offset] === ',') { offset++; continue; }
        requireThat(offset === text.length || text[offset] === '\r' || text[offset] === '\n', invalidCsv);
        if (offset < text.length) {
          offset += text.startsWith('\r\n', offset) ? 2 : 1;
          line++;
        }
        break;
      }
      requireThat(fields.length === header.length, invalidCsv);
      if (isHeader) {
        requireThat(header.every((name, index) => fields[index] === name), invalidCsv);
        isHeader = false;
      } else yield {fields, line: start};
    }
    requireThat(!isHeader, invalidCsv);
  }
  function targetUrl(raw, requireThat) {
    requireThat(raw.length <= 8192 && /^https?:\/\/[^/?#]+(?:[/?#]|$)/i.test(raw) && !/[\x00-\x20\x7f\\]/.test(raw), invalidUrl);
    let url;
    try { url = new URL(raw); } catch { requireThat(false, invalidUrl); }
    requireThat(!url.username && !url.password && url.hostname && url.port !== '0'
      && !/%|@/.test(raw.split(/[/?#]/, 3)[2]), invalidUrl);
    return url;
  }
  function isPath(value) {
    return value.startsWith('/') && value.length <= 8192 && !/[\x00-\x1f\x7f]/.test(value);
  }
  function validStatus(value) { return /^[1-5][0-9]{2}$/.test(value); }
  // Matches ReportWriter.writeCSV and .writeReport from the OWASP DirBuster
  // 1.0-RC1 source distribution. The CSV writer emits only the path, never a host.
  function dirCsv(input, add, requireThat) {
    for (const {fields, line} of csvRows(input, dirHeader, requireThat)) {
      const [path, status, length] = fields;
      requireThat(isPath(path) && validStatus(status) && /^\d{1,10}$/.test(length), invalidDir);
      add('', 'HTTP ' + status, JSON.stringify(fields), null, 'Zeile ' + line);
    }
  }
  function dirText(input, add, requireThat) {
    const lines = input.split(/\r\n|[\r\n]/, 16385);
    requireThat(lines.length <= 16384 && lines[0] === dirBanner && lines[1] === dirProject
      && /^Report produced on [^\x00-\x1f\x7f]{1,128}$/.test(lines[2]) && lines[3] === separator
      && lines[4] === '' && typeof lines[5] === 'string' && lines[6] === separator, invalidDir);
    const origin = targetUrl(lines[5], requireThat);
    requireThat(origin.pathname === '/' && !origin.hash && !origin.search, invalidDir);
    let section = '', status = '';
    for (let i = 7; i < lines.length; i++) {
      const text = lines[i];
      if (section === 'errors' || !text) continue;
      if (text === separator) { section = ''; status = ''; continue; }
      if (text === 'Errors encountered during testing:') { section = 'errors'; continue; }
      if (text === 'Directories found during testing:' || text === 'Files found during testing:') {
        section = text.startsWith('Directories') ? 'Dir' : 'File'; status = ''; continue;
      }
      // RC1 spells the status heading for files "responce".
      const heading = /^(Dirs|Files) found with a ([1-5][0-9]{2}) (?:response|responce):$/.exec(text);
      if (heading) {
        requireThat(section === (heading[1] === 'Dirs' ? 'Dir' : 'File'), invalidDir);
        status = heading[2]; continue;
      }
      requireThat(status && isPath(text), invalidDir);
      add(origin.hostname, section + ' · HTTP ' + status, JSON.stringify([origin.origin,section,text,status]),
        [origin.origin,section,text], 'Zeile ' + (i + 1));
    }
  }
  function sqlCsv(input, add, requireThat) {
    let count = 0;
    for (const {fields, line} of csvRows(input, sqlHeader, requireThat)) {
      const [target, place, parameter, techniques, notes] = fields;
      const url = targetUrl(target, requireThat);
      let detail = 'Keine Technik gemeldet';
      if (techniques) {
        requireThat(place && parameter && /^[BEUSTQ]+$/.test(techniques), invalidSql);
        const disputed = notes.split(';').some(value => value.trim().toLowerCase() === 'false positive or unexploitable');
        detail = disputed ? 'Vom Werkzeug angezweifelter Hinweis' : 'Vom Werkzeug gemeldeter Hinweis';
      } else requireThat(!place && !parameter && !notes, invalidSql);
      // The input tuple is only used by the parent to compute the record fingerprint.
      add(url.hostname, detail, JSON.stringify(fields), null, 'Zeile ' + line);
      count++;
    }
    requireThat(count > 0, invalidSql);
  }
  function parse(source, input, add, {requireThat}) {
    if (source === 'sqlmap') sqlCsv(input, add, requireThat);
    else if (source === 'dirbuster' && input.startsWith(dirBanner)) dirText(input, add, requireThat);
    else if (source === 'dirbuster') dirCsv(input, add, requireThat);
    else requireThat(false, 'Unbekannte Quelle.');
  }
  return Object.freeze({definitions, samples, detect, parse});
})();
