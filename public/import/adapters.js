// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const AuthzImport = (() => {
  const limits = Object.freeze({bytes: 1048576, rows: 1000, files: 20, totalBytes: 5242880, totalRows: 2500});
  const utf8 = new TextEncoder();
  const definitions = Object.freeze({
    nikto: {label: 'Nikto', format: 'XML · Nikto-Einträge', accept: '.xml', hint: 'UTF-8-XML mit niktoscans/niktoscan oder niktoscan als Wurzel, ohne DTD. Gelesen werden scandetails/item, Host oder IP und numerische Item-ID. Die Tabelle blendet Beschreibung, URI und Header aus.'},
    ffuf: {label: 'ffuf', format: 'JSON · ffuf-Ergebnisse', accept: '.json', hint: 'UTF-8-JSON mit results-Liste. Jeder Datensatz benötigt eine absolute HTTP(S)-Adresse in url und einen numerischen HTTP-Status in status. Eingaben, Antwortinhalte, Pfade und Query-Parameter werden ausgeblendet.'},
    feroxbuster: {label: 'feroxbuster', format: 'NDJSON · HTTP-Antworten', accept: '.json,.jsonl,.ndjson', hint: 'Ein JSON-Objekt je Zeile. Antwortzeilen liefern Methode, HTTP-Status und den Host der gemeldeten Antwort-URL. Konfiguration, Statistik und Logmeldungen zählen nicht als Beobachtungen. Mindestens eine Antwort und höchstens 4’096 Zeilen. Pfade, Weiterleitungsziele und Header bleiben ausgeblendet.'},
    gobuster: {label: 'Gobuster', format: 'Text · dir-Ergebniszeilen', accept: '.txt,.log', hint: 'UTF-8-Klartext mit einem dir-Ergebnis pro Zeile, etwa dashboard (Status: 200), optional mit [Size: N] und [--> …]. Relative Pfade haben keinen Hostbezug. Banner, Farbcodes und andere Modi werden abgelehnt.'},
    nmap: {label: 'Nmap', format: 'XML · explizite Ports', accept: '.xml', hint: 'UTF-8-XML mit nmaprun als Wurzel. Die einfache Deklaration <!DOCTYPE nmaprun> ist zulässig. Gelesen werden explizite host/ports/port-Einträge mit IPv4- oder IPv6-Adresse. Zusammengefasste Ports und Skriptausgaben erscheinen nicht in der Tabelle.'},
    burp: {label: 'Burp Suite', format: 'XML · issues-Bericht', accept: '.xml', hint: 'UTF-8-XML mit issues als Wurzel und direkten issue-Einträgen. Eine interne Schema-Deklaration aus einfachen ELEMENT- und ATTLIST-Einträgen wird entfernt. Entitäten, externe DTD, Verlaufs-XML und Projektdateien werden abgelehnt. Requests und Responses werden ausgeblendet.'},
    nessus: {label: 'Nessus', format: 'XML · .nessus v2', accept: '.nessus,.xml', hint: 'UTF-8-XML mit NessusClientData_v2 als Wurzel, ohne DTD. Gelesen werden Report/ReportHost/ReportItem-Metadaten. Plugin-Ausgaben und Policy-Inhalte bleiben ausgeblendet.'},
    zap: {label: 'OWASP ZAP', format: 'Traditional JSON · Alert-Instanzen', accept: '.json', hint: 'Traditional-JSON-Bericht mit site/alerts/instances. Pro Instanz erscheinen Plugin-ID und gemeldete Risikostufe. URI, Parameterwerte und Beweisinhalte bleiben verborgen. Gezählt werden nur die im Bericht enthaltenen Instanzen.'},
    har: {label: 'HAR', format: 'HAR 1.2 · HTTP-Austausch', accept: '.har,.json', hint: 'HAR 1.2 als UTF-8-JSON mit log.entries. Pro HTTP(S)-Eintrag erscheinen Methode und Antwortstatus. Status 0 bezeichnet einen Eintrag ohne HTTP-Antwort. URL, Cookies, Header und Inhalte werden nicht angezeigt.'},
    openapi: {label: 'OpenAPI', format: 'OpenAPI 3.0–3.2 · JSON', accept: '.json', hint: 'Inventar direkt deklarierter Operationen unter paths (JSON). Ein eindeutiger absoluter HTTP(S)-Server ergibt einen Hostbezug. Dokumentation, Webhooks, Callbacks und Inhalte referenzierter Objekte werden nicht ausgewertet. Pfade mit $ref bitte vor dem Import lokal auflösen.'},
    nuclei: {label: 'Nuclei', format: 'JSONL · HTTP-Match-Ereignisse', accept: '.jsonl,.ndjson', hint: 'Ein JSON-Objekt pro Zeile, Typ http, mit template-id, info.severity, absoluter HTTP(S)-Adresse in matched-at und matcher-status true. Andere Ergebnisarten sowie gemischte Dateien werden abgelehnt. Requests, Responses und extrahierte Inhalte werden ausgeblendet.'},
    cobalt: {label: 'Cobalt-Strike-Telemetrie', format: 'JSON · normalisierte defensive Ereignisse', accept: '.json', hint: 'Nur kundenseitig normalisierte EDR-/SIEM-Ereignisse im unten gezeigten JSON-Format. Jedes Ereignis enthält genau record_id, asset, observed_at (UTC) und event_type (detection, containment oder review). Native Cobalt-Strike-Logs und Operator-Daten werden abgelehnt.'}
  });
  const samples = Object.freeze({
    nikto: '<niktoscan><scandetails targethostname="training.example"><item id="000017"><description>Fixture</description></item></scandetails></niktoscan>',
    ffuf: '{"results":[{"url":"https://training.example/first","status":200},{"url":"https://training.example/second","status":403},{"url":"https://training.example/first","status":200}]}',
    feroxbuster: '{"type":"response","url":"https://training.example/profile","original_url":"https://training.example/","path":"/profile","wildcard":false,"status":200,"method":"GET","content_length":64,"line_count":1,"word_count":4,"headers":{},"extension":"","truncated":false,"timestamp":1767225600}',
    gobuster: '/first (Status: 200) [Size: 18]\n/second (Status: 403) [Size: 32]\n',
    nmap: '<nmaprun><host><address addr="192.0.2.12" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>',
    burp: '<issues burpVersion="example"><issue><serialNumber>1001</serialNumber><type>1234</type><host>https://training.example</host><severity>Information</severity></issue></issues>',
    nessus: '<NessusClientData_v2><Report name="Example"><ReportHost name="training.example"><ReportItem pluginID="123" port="443" protocol="tcp" severity="0"/></ReportHost></Report></NessusClientData_v2>',
    zap: '{"@version":"2.15.0","site":[{"@name":"https://training.example","alerts":[{"pluginid":"10001","riskcode":"1","instances":[{"uri":"https://training.example/profile","method":"GET","param":""}]}]}]}',
    har: '{"log":{"version":"1.2","creator":{"name":"Beispiel","version":"1"},"entries":[{"request":{"method":"GET","url":"https://training.example/profile"},"response":{"status":200}}]}}',
    openapi: '{"openapi":"3.1.0","info":{"title":"Beispiel","version":"1"},"servers":[{"url":"https://training.example"}],"paths":{"/profile":{"get":{"responses":{"200":{"description":"OK"}}}}}}',
    nuclei: '{"template-id":"example-observation","info":{"severity":"info"},"type":"http","matched-at":"https://training.example/profile","matcher-status":true}',
    cobalt: '{"schema":"authzledger.defensive-telemetry.v1","source":"cobalt-strike","events":[{"record_id":"example-1","asset":"training.example","observed_at":"2026-01-15T10:00:00Z","event_type":"detection"}]}'
  });
  class ImportError extends Error {}
  function requireThat(condition, message) {
    if (!condition) throw new ImportError(message);
  }
  function integer(value, max, min = 0) {
    requireThat(typeof value === 'string' || Number.isSafeInteger(value), 'Ein numerisches Pflichtfeld fehlt oder ist ungültig.');
    const s = String(value);
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
  const httpMethods = ['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH', 'TRACE', 'CONNECT', 'QUERY'];
  const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  function httpMethod(value) {
    requireThat(typeof value === 'string' && /^[!#$%&'*+.^_`|~a-zA-Z0-9-]{1,64}$/.test(value), 'Ungültige HTTP-Methode.');
    return httpMethods.includes(value) ? value : 'Weitere HTTP-Methode';
  }
  function httpAddress(value) {
    requireThat(typeof value === 'string' && value.length <= 8192 && /^https?:\/\/[^/\\\s?#]+(?:[/?#]|$)/i.test(value)
      && !/[\x00-\x20\x7f\\]/.test(value), 'Für dieses Profil ist eine absolute HTTP(S)-Adresse erforderlich.');
    try { return new URL(value); } catch { throw new ImportError('Ungültige HTTP(S)-Adresse.'); }
  }
  function serialise(value) {
    try { return JSON.stringify(value); } catch { throw new ImportError('Der JSON-Datensatz ist zu tief verschachtelt.'); }
  }
  function zapRecords(input, add) {
    const report = json(input);
    requireThat(typeof report?.['@version'] === 'string' && report['@version'].trim().length > 0 && Array.isArray(report.site), 'Ein ZAP Traditional-JSON-Bericht mit site-Liste wird benötigt.');
    for (const site of report.site) {
      const origin = httpAddress(site?.['@name']).origin;
      requireThat(Array.isArray(site.alerts), 'Eine ZAP-Site benötigt die Liste alerts.');
      for (const alert of site.alerts) {
        const plugin = integer(alert?.pluginid, 999999999999);
        const risk = integer(alert.riskcode, 3);
        const rule = alert.alertRef === undefined ? plugin : id(alert.alertRef);
        requireThat(Array.isArray(alert.instances), 'Ein ZAP-Alert benötigt die Liste instances.');
        for (const instance of alert.instances) {
          const url = httpAddress(instance?.uri);
          requireThat(url.origin === origin, 'ZAP-Instanz und gemeldete Site widersprechen sich.');
          httpMethod(instance.method);
          requireThat(instance.param === undefined || typeof instance.param === 'string', 'Ungültiger ZAP-Parameter.');
          const identity = [rule, plugin, instance.method, instance.uri, instance.param ?? null];
          add(url.hostname, 'Plugin ' + plugin + ' · gemeldete Risikostufe ' + risk,
            serialise([identity, risk, instance]), identity);
        }
      }
    }
  }
  function harRecords(input, add) {
    const log = json(input)?.log;
    requireThat(log?.version === '1.2' && Array.isArray(log.entries), 'Erwartet wird HAR 1.2 mit log.entries.');
    for (const entry of log.entries) {
      const request = entry?.request;
      const url = httpAddress(request?.url);
      const method = httpMethod(request.method);
      requireThat(request.postData === undefined || object(request.postData), 'Ungültiger HAR-Requestinhalt.');
      const status = entry.response?.status;
      requireThat(Number.isInteger(status) && (status === 0 || (status >= 100 && status <= 599)), 'Ungültiger HAR-Antwortstatus.');
      const detail = method + ' · ' + (status === 0 ? 'Keine HTTP-Antwort' : 'HTTP ' + status);
      // Headers and bodies may contain credentials. They contribute to digests only.
      const identity = [request.method, request.url, request.postData ?? null];
      add(url.hostname, detail, serialise(entry), serialise(identity));
    }
  }
  function openapiServer(servers) {
    if (servers === undefined) return null;
    requireThat(Array.isArray(servers) && servers.every(server => object(server) && typeof server.url === 'string' && server.url.length > 0 && server.url.length <= 8192), 'Ungültige OpenAPI-Serverliste.');
    if (servers.length !== 1) return null;
    const url = servers[0].url;
    if (/[{}]/.test(url) || !/^https?:\/\//i.test(url)) return null;
    return httpAddress(url);
  }
  function openapiRecords(input, add) {
    const doc = json(input);
    requireThat(typeof doc?.openapi === 'string' && /^3\.[0-2]\.\d+$/.test(doc.openapi) && object(doc.info) && object(doc.paths),
      'Benötigt wird ein OpenAPI-3.0-, 3.1- oder 3.2-Dokument mit info und paths im JSON-Format.');
    const supports32 = doc.openapi.startsWith('3.2.');
    const rootServer = openapiServer(doc.servers);
    const methods = ['get','put','post','delete','options','head','patch','trace'];
    if (supports32) methods.push('query');
    for (const [path, item] of Object.entries(doc.paths)) {
      if (path.startsWith('x-')) continue;
      requireThat(path.startsWith('/') && path.length <= 8192 && !/[?#\x00-\x20\x7f]/.test(path) && object(item), 'Ungültiger OpenAPI-Pfadeintrag.');
      requireThat(!Object.hasOwn(item, '$ref'), 'Ein OpenAPI-Pfad enthält $ref. Bitte den Pfad vor dem Import lokal auflösen.');
      const pathServer = item.servers === undefined ? rootServer : openapiServer(item.servers);
      function operation(method, spec) {
        const label = httpMethod(method);
        requireThat(object(spec) && !Object.hasOwn(spec, '$ref'), 'Eine direkte OpenAPI-Operationsdefinition fehlt.');
        const server = spec.servers === undefined ? pathServer : openapiServer(spec.servers);
        const identity = server ? [server.href, path, method] : null;
        const raw = serialise([server?.href ?? null, path, method, spec]);
        add(server?.hostname ?? '', 'Deklarierte Operation · ' + label, raw, identity);
      }
      for (const [key, value] of Object.entries(item)) {
        if (methods.includes(key)) operation(key.toUpperCase(), value);
        else if (supports32 && key === 'additionalOperations') {
          requireThat(object(value), 'Ungültige OpenAPI-Operationsliste.');
          for (const [method, spec] of Object.entries(value)) {
            requireThat(!methods.includes(method.toLowerCase()), 'Eine zusätzliche Methode kollidiert mit einer Standardoperation.');
            operation(method, spec);
          }
        } else requireThat(['servers','parameters','summary','description'].includes(key) || key.startsWith('x-'), 'Unbekanntes Feld am OpenAPI-Pfad.');
      }
    }
  }
  function nucleiRecords(input, add) {
    let count = 0;
    for (const [index, line] of input.split(/\r?\n/).entries()) {
      if (!line.trim()) continue;
      const event = json(line);
      requireThat(event?.type === 'http' && event['matcher-status'] === true, 'Erwartet wird ein Nuclei-HTTP-Ereignis mit matcher-status true in Zeile ' + (index + 1) + '.');
      const template = id(event['template-id']);
      const severity = choice(event.info?.severity, ['info','low','medium','high','critical','unknown']);
      const url = httpAddress(event['matched-at']);
      const matcher = event['matcher-name'] === undefined ? null : id(event['matcher-name']);
      const extractor = event['extractor-name'] === undefined ? null : id(event['extractor-name']);
      add(url.hostname, 'HTTP-Match · gemeldeter Schweregrad ' + severity, line.trim(),
        [template, matcher, extractor, event['matched-at']], 'Zeile ' + (index + 1));
      count++;
    }
    requireThat(count > 0, 'Die Nuclei-Datei enthält kein auswertbares JSONL-Ereignis.');
  }
  // Native Rust serializers: feroxbuster 2.14.0, src/response.rs, src/message.rs,
  // src/config/container.rs and src/statistics/container.rs.
  function feroxbusterRecords(input, add) {
    const text = input.endsWith('\n') ? input.slice(0, -1) : input;
    const lines = text.split(/\r?\n/, 4097);
    requireThat(lines.length <= 4096, 'Ein feroxbuster-Export darf höchstens 4’096 Zeilen enthalten.');
    let responses = 0;
    for (const [index, line] of lines.entries()) {
      if (!line.trim()) continue;
      const event = json(line);
      requireThat(object(event), 'Ungültiger feroxbuster-Datensatz in Zeile ' + (index + 1) + '.');
      if (event.type === 'configuration') {
        requireThat(typeof event.target_url === 'string', 'Ungültiger feroxbuster-Konfigurationseintrag.');
        continue;
      }
      if (event.type === 'statistics') {
        requireThat(Number.isSafeInteger(event.requests) && event.requests >= 0, 'Ungültiger feroxbuster-Statistikeintrag.');
        continue;
      }
      if (event.type === 'log') {
        requireThat(typeof event.message === 'string' && typeof event.level === 'string', 'Ungültiger feroxbuster-Logeintrag.');
        continue;
      }
      requireThat(event.type === 'response', 'Unbekannter feroxbuster-Eintrag in Zeile ' + (index + 1) + '.');
      const url = httpAddress(event.url);
      const method = httpMethod(event.method);
      requireThat(Number.isInteger(event.status) && event.status >= 100 && event.status <= 599, 'Ungültiger feroxbuster-Antwortstatus.');
      requireThat(event.wildcard === undefined || typeof event.wildcard === 'boolean', 'Ungültiger feroxbuster-Wildcardstatus.');
      requireThat(event.original_url === undefined || typeof event.original_url === 'string', 'Ungültiger feroxbuster-Quellbezug.');
      if (event.original_url) httpAddress(event.original_url);
      for (const key of ['content_length', 'line_count', 'word_count']) {
        requireThat(event[key] === undefined || (Number.isSafeInteger(event[key]) && event[key] >= 0), 'Ungültige feroxbuster-Antwortmetrik.');
      }
      const identity = event.original_url && event.wildcard === false ? [event.original_url, event.method, event.url] : null;
      const detail = method + ' · HTTP ' + event.status + (event.wildcard === true ? ' · Wildcard' : '');
      add(url.hostname, detail, line.trim(), identity, 'Zeile ' + (index + 1));
      responses++;
    }
    requireThat(responses > 0, 'Der feroxbuster-Export enthält keine Antwortzeile.');
  }
  const jsonProfiles = Object.freeze({zap: zapRecords, har: harRecords, openapi: openapiRecords, nuclei: nucleiRecords, feroxbuster: feroxbusterRecords});
  function parseRecords(source, input) {
    let position = 0;
    const records = [];
    function add(asset, detail, raw, identity, locator) {
      position++;
      requireThat(position <= limits.rows, 'Mehr als 1’000 Datensätze. Teile den Export lokal auf.');
      records.push({asset, detail, raw, identity, locator: locator || 'Datensatz ' + position});
    }
    if (Object.hasOwn(jsonProfiles, source)) {
      jsonProfiles[source](input, add);
    } else if (source === 'ffuf') {
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
  function detectSource(input) {
    const text = input.trimStart();
    const feroxTypes = ['response','configuration','statistics','log'];
    if (text.startsWith('<')) {
      const body = safeXmlBody(text, ['nmaprun', 'issues']);
      const root = /^<([\w.-]+)(?=[\s/>])/.exec(body)?.[1];
      const xmlFormats = new Map([['issues', 'burp'], ['nmaprun', 'nmap'], ['niktoscan', 'nikto'],
        ['niktoscans', 'nikto'], ['NessusClientData_v2', 'nessus']]);
      if (xmlFormats.has(root)) return xmlFormats.get(root);
    } else if (text.startsWith('{')) {
      let envelope;
      try { envelope = JSON.parse(text); } catch {
        const firstLine = text.split(/\r?\n/, 1)[0];
        try { envelope = JSON.parse(firstLine); } catch { throw new ImportError('Ungültiges JSON oder JSONL.'); }
        if (typeof envelope?.['template-id'] === 'string') return 'nuclei';
        if (feroxTypes.includes(envelope?.type)) return 'feroxbuster';
        throw new ImportError('Unbekanntes JSONL-Profil.');
      }
      const markers = [['results','ffuf'], ['site','zap'], ['log','har'], ['openapi','openapi'],
        ['template-id','nuclei'], ['events','cobalt']];
      const matches = markers.filter(([key]) => Object.hasOwn(envelope, key));
      if (feroxTypes.includes(envelope.type)) matches.push(['type','feroxbuster']);
      if (matches.length === 1) return matches[0][1];
      if (matches.length > 1) throw new ImportError('Das JSON enthält Kennzeichen mehrerer Formate. Wähle das Quellformat ausdrücklich.');
    } else if (/^\S+[^\S\r\n]+\(Status:\s*\d{3}\)/i.test(text)) {
      return 'gobuster';
    }
    throw new ImportError('Quellformat nicht erkannt. Prüfe den Export oder wähle das Quellformat ausdrücklich.');
  }
  async function parse(source, buffer) {
    requireThat(source === 'auto' || Object.hasOwn(definitions, source), 'Unbekannte Quelle.');
    requireThat(buffer.byteLength > 0 && buffer.byteLength <= limits.bytes, 'Wähle eine nicht leere UTF-8-Datei bis 1 MiB.');
    requireThat(globalThis.crypto?.subtle, 'Für SHA-256 wird HTTPS oder localhost benötigt.');
    let input;
    try { input = new TextDecoder('utf-8',{fatal:true}).decode(buffer); } catch { throw new ImportError('Ungültiger UTF-8-Text.'); }
    requireThat(!input.includes('\0'), 'Binärdateien werden abgelehnt.');
    if (source === 'auto') source = detectSource(input);
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
