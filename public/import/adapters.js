// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const AuthzImport = (() => {
  const limits = Object.freeze({bytes: 1048576, rows: 1000, files: 20, totalBytes: 5242880, totalRows: 2500});
  const utf8 = new TextEncoder();
  const definitions = Object.freeze({
    nikto: {label: 'Nikto', format: 'XML · Nikto-Einträge', accept: '.xml', hint: 'UTF-8-XML mit niktoscans/niktoscan oder niktoscan als Wurzel, ohne DTD. Gelesen werden scandetails/item, Host oder IP und numerische Item-ID. Die Tabelle blendet Beschreibung, URI und Header aus.'},
    ffuf: {label: 'ffuf', format: 'JSON · ffuf-Ergebnisse', accept: '.json', hint: 'UTF-8-JSON mit results-Liste. Jeder Datensatz benötigt eine absolute HTTP(S)-Adresse in url und einen numerischen HTTP-Status in status. Eingaben, Antwortinhalte, Pfade und Query-Parameter werden ausgeblendet.'},
    gobuster: {label: 'Gobuster', format: 'Text · dir-Ergebniszeilen', accept: '.txt,.log', hint: 'UTF-8-Klartext mit einem dir-Ergebnis pro Zeile, etwa dashboard (Status: 200), optional mit [Size: N] und [--> …]. Relative Pfade haben keinen Hostbezug. Banner, Farbcodes und andere Modi werden abgelehnt.'},
    nmap: {label: 'Nmap', format: 'XML · explizite Ports', accept: '.xml', hint: 'UTF-8-XML mit nmaprun als Wurzel. Die einfache Deklaration <!DOCTYPE nmaprun> ist zulässig. Gelesen werden explizite host/ports/port-Einträge mit IPv4- oder IPv6-Adresse. Zusammengefasste Ports und Skriptausgaben erscheinen nicht in der Tabelle.'},
    burp: {label: 'Burp Suite', format: 'XML · issues-Bericht', accept: '.xml', hint: 'UTF-8-XML mit issues als Wurzel und direkten issue-Einträgen. Eine interne Schema-Deklaration aus einfachen ELEMENT- und ATTLIST-Einträgen wird entfernt. Entitäten, externe DTD, Verlaufs-XML und Projektdateien werden abgelehnt. Requests und Responses werden ausgeblendet.'},
    nessus: {label: 'Nessus', format: 'XML · .nessus v2', accept: '.nessus,.xml', hint: 'UTF-8-XML mit NessusClientData_v2 als Wurzel, ohne DTD. Gelesen werden Report/ReportHost/ReportItem-Metadaten. Plugin-Ausgaben und Policy-Inhalte bleiben ausgeblendet.'},
    cobalt: {label: 'Cobalt-Strike-Telemetrie', format: 'JSON · normalisierte defensive Ereignisse', accept: '.json', hint: 'Nur kundenseitig normalisierte EDR-/SIEM-Ereignisse im unten gezeigten JSON-Format. Jedes Ereignis enthält genau record_id, asset, observed_at (UTC) und event_type (detection, containment oder review). Native Cobalt-Strike-Logs und Operator-Daten werden abgelehnt.'}
  });
  const samples = Object.freeze({
    nikto: '<niktoscan><scandetails targethostname="training.example"><item id="000017"><description>Fixture</description></item></scandetails></niktoscan>',
    ffuf: '{"results":[{"url":"https://training.example/first","status":200},{"url":"https://training.example/second","status":403},{"url":"https://training.example/first","status":200}]}',
    gobuster: '/first (Status: 200) [Size: 18]\n/second (Status: 403) [Size: 32]\n',
    nmap: '<nmaprun><host><address addr="192.0.2.12" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>',
    burp: '<issues burpVersion="example"><issue><serialNumber>1001</serialNumber><type>1234</type><host>https://training.example</host><severity>Information</severity></issue></issues>',
    nessus: '<NessusClientData_v2><Report name="Example"><ReportHost name="training.example"><ReportItem pluginID="123" port="443" protocol="tcp" severity="0"/></ReportHost></Report></NessusClientData_v2>',
    cobalt: '{"schema":"authzledger.defensive-telemetry.v1","source":"cobalt-strike","events":[{"record_id":"example-1","asset":"training.example","observed_at":"2026-01-15T10:00:00Z","event_type":"detection"}]}'
  });
  class ImportError extends Error {}
  function requireThat(condition, message) {
    if (!condition) throw new ImportError(message);
  }
  function integer(value, max, min = 0) {
    const s = String(value ?? '');
    requireThat(/^\d{1,12}$/.test(s) && +s >= min && +s <= max, 'Ein numerisches Pflichtfeld fehlt oder liegt ausserhalb des zulässigen Bereichs.');
    return s;
  }
  function choice(value, allowed) {
    requireThat(allowed.includes(value), 'Ein Pflichtfeld enthält einen unbekannten Wert.');
    return value;
  }
  function id(value) {
    requireThat(typeof value === 'string' && value.length > 0 && value.length <= 255 && !/[\x00-\x20\x7f]/.test(value), 'Eine benötigte Kennung fehlt oder ist ungültig.');
    return value;
  }
  function urlHost(input) {
    requireThat(typeof input === 'string' && /^https?:\/\//i.test(input), 'Der Datensatz benötigt eine absolute HTTP(S)-Adresse.');
    let result;
    try { result = new URL(input); } catch { throw new ImportError('Eine HTTP(S)-Adresse ist ungültig.'); }
    return id(result.hostname);
  }
  function validUtc(value) {
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) return false;
    const instant = new Date(value);
    const canonical = value.includes('.') ? value : value.slice(0,-1) + '.000Z';
    return Number.isFinite(instant.getTime()) && instant.toISOString() === canonical;
  }
  function json(input) {
    try { return JSON.parse(input); } catch { throw new ImportError('Ungültiges JSON.'); }
  }
  function safeXmlBody(input, roots) {
    // Discard the prolog before parsing. A stylesheet PI never reaches the DOM parser.
    let pos=0;
    const spaces = /\s+/y;
    const skipSpace = () => {spaces.lastIndex=pos; const m=spaces.exec(input); if(m) pos=spaces.lastIndex;};
    function discardPrologTrivia() {
      while (true) {
        skipSpace();
        const term = input.startsWith('<?',pos) ? '?>' : input.startsWith('<!--',pos) ? '-->' : '';
        if (!term) break;
        const end=input.indexOf(term,pos+2);
        requireThat(end>=0,'Unvollständiger XML-Prolog.');
        pos=end+term.length;
      }
    }
    discardPrologTrivia();
    if (input.startsWith('<!DOCTYPE',pos)) {
      const prefix = /^<!DOCTYPE[\x20\t\r\n]+(nmaprun|issues)\s*(>|\[)/.exec(input.slice(pos,pos+160));
      requireThat(prefix && roots.includes(prefix[1]),'Externe oder unbekannte DTD abgelehnt.');
      pos+=prefix[0].length;
      if (prefix[2] === '[') {
        requireThat(prefix[1] === 'issues','Interne DTD nur für das unterstützte Burp-Schema zulässig.');
        // Validate declarations without interpreting them. No entities, references, URL,
        // parameter expansion, conditionals or processing instructions enter the parser.
        const declaration = /<!(?:ELEMENT\s+[A-Za-z][\w.-]*\s+(?:EMPTY|ANY|\([a-zA-Z0-9_#|,.?*+()\s-]*\)[?*+]?)|ATTLIST\s+[A-Za-z][\w.-]*\s+[A-Za-z][\w.-]*\s+(?:CDATA|\(true\|false\))\s+(?:#IMPLIED|#REQUIRED|"[\w.-]{0,32}"|'[\w.-]{0,32}'))\s*>/y;
        const start=pos;
        while(true) {
          skipSpace();
          if(input[pos] === ']') break;
          requireThat(pos-start < 32768,'Burp-Schema zu gross.');
          declaration.lastIndex=pos;
          requireThat(declaration.test(input),'Unbekannte oder aktive interne DTD-Deklaration abgelehnt.');
          pos=declaration.lastIndex;
        }
        pos++; skipSpace();
        requireThat(input[pos] === '>','Fehlerhafter DTD-Abschluss.'); pos++;
      }
    }
    discardPrologTrivia();
    const body=input.slice(pos);
    // Fail closed on declaration-like literal text as well as actual declarations.
    requireThat(!/<!\s*(?:DOCTYPE|ENTITY)\b|<\?/i.test(body),'Weitere DTD, Entitäten und Verarbeitungsanweisungen werden abgelehnt, auch als Literaltext.');
    return body;
  }
  function xml(input, rootNames) {
    const roots=Array.isArray(rootNames) ? rootNames : [rootNames];
    const body=safeXmlBody(input,roots);
    requireThat((body.match(/</g) || []).length <= 40000, 'Das XML überschreitet die zulässige Strukturgrösse.');
    const doc = new DOMParser().parseFromString(body,'application/xml');
    requireThat(!doc.doctype && !doc.querySelector('parsererror') && roots.includes(doc.documentElement?.tagName),'Ungültiges XML oder unbekanntes Wurzelelement.');
    return doc.documentElement;
  }
  function ipAddress(value,type) {
    if(type==='ipv4') {
      const parts=String(value).split('.');
      requireThat(parts.length===4 && parts.every(p => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p)<=255),'Ungültige IPv4-Adresse.');
      return value;
    }
    requireThat(typeof value==='string' && /^[a-f\d:.]+$/i.test(value),'Ungültige IPv6-Adresse.');
    try {return new URL('http://['+value+']/').hostname.slice(1,-1);} catch {throw new ImportError('Ungültige IPv6-Adresse.');}
  }
  const attribute = (el, name) => el.getAttribute(name);
  const children = (el, name) => Array.from(el.children).filter(child => child.tagName === name);
  const first = (el, name) => children(el, name)[0];
  const field = (el, name) => first(el, name)?.textContent.trim();
  const xmlRecord = el => new XMLSerializer().serializeToString(el);
  async function digest(bytes) {
    const buffer = typeof bytes === 'string' ? utf8.encode(bytes) : bytes;
    return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', buffer)), byte => byte.toString(16).padStart(2, '0')).join('');
  }
  function parseRecords(source, input) {
    let position = 0;
    const records = [];
    function add(asset, detail, raw, identity, locator) {
      position++;
      requireThat(position <= limits.rows, 'Mehr als 1’000 Datensätze. Teile den Export lokal auf.');
      records.push({asset, detail, raw, identity, locator: locator || 'Datensatz ' + position});
    }
    if (source === 'ffuf') {
      const report = json(input);
      requireThat(Array.isArray(report?.results), 'Eine ffuf-Liste unter results fehlt.');
      for (const item of report.results) {
        requireThat(item && typeof item === 'object', 'Ungültiger ffuf-Datensatz.');
        requireThat(Number.isInteger(item.status),'Der ffuf-Status muss eine ganze JSON-Zahl sein.');
        add(urlHost(item.url), 'HTTP ' + integer(item.status, 599, 100), JSON.stringify(item), item.url);
      }
    } else if (source === 'gobuster') {
      for (const [index, line] of input.split(/\r?\n/).entries()) {
        if (!line.trim()) continue;
        const m = /^(\S+)\s+\(Status:\s*(\d{3})\)(?:\s+\[Size:\s*\d+\])?(?:\s+\[-->\s+[^\]\r\n]+\])?\s*$/i.exec(line.trim());
        requireThat(m, 'Unerwartete Gobuster-Syntax in Zeile ' + (index + 1) + '.');
        requireThat(!/[\u0000-\u001f\u007f]/.test(line) && (!m[1].includes('://') || /^https?:\/\//i.test(m[1])), 'Ungültiger Gobuster-Pfad.');
        const absolute=/^https?:\/\//i.test(m[1]);
        add(absolute ? urlHost(m[1]) : '', 'HTTP ' + integer(m[2], 599, 100), line.trim(), absolute ? m[1] : null, 'Zeile ' + (index + 1));
      }
      requireThat(records.length, 'Mindestens eine Gobuster-dir-Ergebniszeile wird benötigt.');
    } else if (source === 'cobalt') {
      const report = json(input);
      requireThat(report?.schema === 'authzledger.defensive-telemetry.v1' && report.source === 'cobalt-strike' && Array.isArray(report.events) && Object.keys(report).length === 3, 'Erwartet wird das dokumentierte JSON-Format für normalisierte defensive Telemetrie.');
      for (const event of report.events) {
        requireThat(event && Object.keys(event).sort().join(',') === 'asset,event_type,observed_at,record_id', 'Jedes defensive Ereignis benötigt genau die vier dokumentierten Felder.');
        id(event.record_id);
        const kind = choice(event.event_type, ['detection', 'containment', 'review']);
        requireThat(validUtc(event.observed_at), 'Ereignisse benötigen einen gültigen UTC-Zeitstempel im ISO-Format.');
        add(id(event.asset), kind + ' · ' + event.observed_at, JSON.stringify([event.record_id,event.asset,event.observed_at,kind]), event.record_id);
      }
    } else if (source === 'nmap') {
      const root = xml(input, 'nmaprun');
      for (const host of children(root, 'host')) {
        const addr = children(host, 'address').find(a => ['ipv4','ipv6'].includes(attribute(a,'addrtype')));
        for (const ports of children(host,'ports')) for (const port of children(ports,'port')) {
          requireThat(addr && first(port,'state'), 'Explizite Nmap-Ports benötigen eine Host-IP und einen Zustand.');
          const protocol = choice(attribute(port,'protocol'), ['tcp','udp','sctp','ip']);
          const state = choice(attribute(first(port,'state'),'state'), ['open','closed','filtered','unfiltered','open|filtered','closed|filtered']);
          add(ipAddress(attribute(addr,'addr'),attribute(addr,'addrtype')), protocol.toUpperCase() + ' ' + integer(attribute(port,'portid'),65535) + ' · ' + state, xmlRecord(port), [protocol, attribute(port,'portid')]);
        }
      }
    } else if (source === 'burp') {
      const root = xml(input, 'issues');
      for (const issue of children(root,'issue')) {
        integer(field(issue,'type'), 999999999999);
        const severity = choice((field(issue,'severity') || '').toLowerCase(), ['information','low','medium','high','false positive']);
        add(urlHost(field(issue,'host')), 'Gemeldeter Schweregrad · ' + severity, xmlRecord(issue), field(issue,'serialNumber') ? [new URL(field(issue,'host')).origin,field(issue,'serialNumber'),field(issue,'type'),field(issue,'path') || ''] : null);
      }
    } else if (source === 'nikto') {
      const root = xml(input,['niktoscans','niktoscan']);
      const runs = root.tagName === 'niktoscans' ? children(root,'niktoscan') : [root];
      for (const run of runs) for (const scan of children(run,'scandetails')) for (const item of children(scan,'item')) {
        const host = id(attribute(scan,'targethostname') || attribute(scan,'targetip'));
        add(host,'Item ' + integer(attribute(item,'id'),999999999999),JSON.stringify([attribute(scan,'targetport'),xmlRecord(item)]), field(item,'uri') && attribute(item,'method') && attribute(scan,'targetport') ? [attribute(scan,'targetport'), attribute(item,'id'), attribute(item,'method'),field(item,'uri')] : null);
      }
    } else if (source === 'nessus') {
      const root = xml(input,'NessusClientData_v2');
      for (const report of children(root,'Report')) for (const host of children(report,'ReportHost')) for (const item of children(host,'ReportItem')) {
        const plugin = integer(attribute(item,'pluginID'),999999999999);
        const port = integer(attribute(item,'port'),65535);
        const severity = integer(attribute(item,'severity'),4);
        add(id(attribute(host,'name')),'Plugin ' + plugin + ' · Port ' + port + ' · Schweregrad ' + severity,xmlRecord(item), attribute(item,'protocol') ? [plugin, port, attribute(item,'protocol')] : null);
      }
    } else throw new ImportError('Unbekannte Quelle.');
    return records;
  }
  async function parse(source, buffer) {
    requireThat(Object.hasOwn(definitions, source), 'Unbekannte Quelle.');
    requireThat(buffer.byteLength > 0 && buffer.byteLength <= limits.bytes, 'Wähle eine nicht leere UTF-8-Datei bis 1 MiB.');
    requireThat(globalThis.crypto?.subtle, 'Für SHA-256 wird HTTPS oder localhost benötigt.');
    let input;
    try { input = new TextDecoder('utf-8',{fatal:true}).decode(buffer); } catch { throw new ImportError('Ungültiger UTF-8-Text.'); }
    requireThat(!input.includes('\0'), 'Binärdateien werden abgelehnt.');
    const records = parseRecords(source,input);
    const assetHashes = new Map();
    const normalised = await Promise.all(records.map(async ({asset,detail,raw,identity,locator}) => {
      const key = asset.toLowerCase();
      if (key && !assetHashes.has(key)) assetHashes.set(key,digest(key));
      return {identity: identity ? await digest(JSON.stringify([source,key,identity])) : null, asset: key ? (await assetHashes.get(key)).slice(0,16) : '', detail, locator, fingerprint: await digest(JSON.stringify([source,key,raw]))};
    }));
    return {source, bytes:buffer.byteLength, digest:await digest(buffer), rows:normalised};
  }
  return Object.freeze({limits,definitions,samples,parse,digest,ImportError});
})();
