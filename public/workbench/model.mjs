// © Nasser Aldin Farag (0xFarag). All rights reserved.
export const MAX_BYTES = 2 * 1024 * 1024;
const MAX_ROWS = 1024;
const retestLabels = {
  not_retested: 'Nicht erneut geprüft',
  fix_verified: 'Fix im Retest bestätigt',
  inconclusive: 'Retest ohne eindeutiges Ergebnis',
  violation_persists: 'Befund besteht weiter',
  testability_restored: 'Wieder prüfbar',
  regression: 'Regression',
  unchanged: 'Unverändert'
};

export const statusLabels = Object.freeze({
  ...retestLabels,
  confirmed: 'Konfigurationsbefund bestätigt',
  not_verified: 'Unbestätigter Scannerhinweis',
  hint: 'Quellhinweis',
  observed: 'Beobachtung',
  import_unassessed: 'Ungeprüfter Importbeleg',
  excluded: 'Ausgelassen',
  soc_observed: 'Alarm zugeordnet',
  soc_telemetry_only: 'Nur Telemetrie',
  soc_incomparable: 'Nicht zuordenbar',
  soc_unavailable: 'Keine Signaldaten'
});

function requireField(ok, message) {
  if (!ok) throw new Error(message);
}

function object(value) {
  requireField(value !== null && typeof value === 'object' && !Array.isArray(value),
    'Ein erforderliches Datenobjekt fehlt.');
  return value;
}

function records(value, field, min = 0, max = MAX_ROWS) {
  requireField(Array.isArray(value) && value.length >= min && value.length <= max,
    'Ungültige Anzahl Einträge für «' + field + '» (erlaubt ' + min + ' bis ' + max + ').');
  return value;
}

function string(value, field, max = 512) {
  requireField(typeof value === 'string' && value.trim().length > 0 && value.length <= max &&
    !/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(value),
  'Ungültiger Text für «' + field + '».');
  return value;
}

function identifier(value, field) {
  requireField(typeof value === 'string' && /^[A-Za-z0-9_.:/-]{1,160}$/.test(value), 'Ungültige ID für «' + field + '».');
  return value;
}

function digest(value, field) {
  requireField(typeof value === 'string' && /^[a-f0-9]{64}$/.test(value), 'Ungültiger SHA-256-Wert für «' + field + '».');
  return value;
}

function unique(values, field) {
  const set = new Set(values);
  requireField(set.size === values.length, 'Mehrdeutige Kennung in «' + field + '».');
  return set;
}

function identifierList(value, field) {
  const ids = records(value, field, 1, 64).map(v => identifier(v, field));
  unique(ids, field);
  return ids;
}

function details(entries) {
  return entries.map(([label, value]) => ({label, value}));
}

// JSON.parse validates the grammar but silently discards duplicate object keys.
// Inspect keys in the input text so escaped duplicates are caught before projection.
export function checkKeys(text) {
  const stack = [];
  const tokens = /"(?:[^"\\]|\\.)*"\s*:?|[{}\[\]]/g;
  for (const match of text.matchAll(tokens)) {
    const token = match[0];
    if (token === '{' || token === '[') {
      requireField(stack.length < 32, 'Die JSON-Struktur ist zu tief verschachtelt.');
      stack.push(token === '{' ? new Set() : null);
    } else if (token === '}' || token === ']') {
      stack.pop();
    } else if (token.endsWith(':')) {
      const key = JSON.parse(token.slice(0, -1));
      const keys = stack.at(-1);
      requireField(keys instanceof Set && !keys.has(key), 'Die Datei enthält einen doppelten JSON-Schlüssel.');
      keys.add(key);
    }
  }
}

function findingProjection(input) {
  const f = object(input.finding);
  const scanner = object(input.external_scanner);
  const binding = digest(f.rule_digest, 'Prüfregel');
  const controls = identifierList(f.control_refs, 'Kontrollen');
  const sources = identifierList(f.source_refs, 'Quellen');
  const scannerId = identifier(scanner.entry_id, 'Scannerquelle');
  const scannerHash = digest(scanner.original_sha256, 'Scannerexport');
  const execution = digest(input.native_execution, 'Ausführung');
  const limitations = records(f.limitations, 'Aussagegrenzen', 1, 16).map(v => string(v, 'Aussagegrenze'));
  requireField(f.schema_version === 1 && f.kind === 'detection-finding' && f.check_id === 'misconfig.security_headers' &&
    input.native_check === f.check_id && f.status === 'confirmed' && f.evidence_level === 'confirmed' &&
    f.interpretation === 'violation' && f.reason === 'predicate_violated', 'Unbekanntes oder widersprüchliches Befundprofil.');
  requireField(input.scanner_assertion_unchanged === true && sources.includes(scannerId) && sources.includes(execution) &&
    !controls.includes(identifier(f.local_id, 'Prüffall')), 'Quellen- oder Kontrollbindung des Befunds ist unvollständig.');
  const observations = records(f.observation_refs, 'Beobachtungen', 1, 64).map(v => digest(v, 'Beobachtung'));
  const rows = [{
    id: identifier(f.id, 'Befund'), binding, title: 'Vorgeschriebener Antwortheader fehlt',
    status: 'confirmed', source: 'Nativer Konfigurationscheck',
    summary: 'Die Projektion meldet einen fehlenden, ausdrücklich geforderten Header.',
    details: details([['Check', f.check_id], ['Kontrollen', controls.join(', ')], ['Beobachtungen', observations.join(', ')],
      ['Befund-Digest', digest(f.finding_digest, 'Befund')], ['Kontrollregel', binding],
      ['Ausführung', execution], ['Mitschnitt', digest(input.external_capture_sha256, 'Mitschnitt')],
      ['Aussagegrenze der Quelle', limitations.join(' ')]])
  }];
  for (const a of records(scanner.assertions, 'Scanneraussagen', 1, 64)) {
    object(a);
    const plugin = identifier(a.plugin_id, 'Regel-ID');
    requireField(a.kind === 'source_assertion' && a.verification === 'not_verified' && a.tool === 'ZAP',
      'Nicht unterstützte oder widersprüchliche Scanneraussage.');
    rows.push({
      id: 'zap:' + scannerId + ':' + plugin, binding: scannerHash, title: 'ZAP-Regel ' + plugin, status: 'not_verified',
      source: 'OWASP ZAP', summary: 'Die importierte Meldung hat den Status eines unbestätigten Hinweises.',
      details: details([['Regel-ID', plugin], ['Quelle', scannerId], ['Scannerexport', scannerHash],
        ['Quellklassifikation', identifier(a.risk_code, 'Quellklassifikation')]])
    });
  }
  unique(rows.map(r => r.id), 'Befunde');
  return {kind: 'finding', title: 'Konfigurationsbefund', rows, coverage: null};
}

function retestProjection(input) {
  const baseline = digest(input.baseline_execution_digest, 'Baseline-Ausführung');
  const current = digest(input.current_execution_digest, 'Retest-Ausführung');
  const snapshot = digest(input.snapshot_digest, 'Snapshot');
  const sources = identifierList(input.sources, 'Quellen').join(', ');
  const rows = records(input.transitions, 'Retest-Fälle', 1).map(raw => {
    const t = object(raw);
    const id = identifier(t.finding_id, 'Befund');
    const status = t.status;
    requireField(typeof status === 'string' && Object.hasOwn(retestLabels, status), 'Unbekannter Retest-Status.');
    const skipped = status === 'not_retested';
    if (skipped) requireField(t.current_finding_digest === null, 'Ein ausgelassener Fall trägt einen aktuellen Befund-Digest.');
    const binding = digest(t.baseline_finding_digest, 'Baseline-Befund');
    const caseId = identifier(t.case_id, 'Fall');
    return {
      id, binding, title: 'Retest-Fall ' + caseId, status, source: 'Retest-Projektion',
      summary: skipped ? 'Der Fall bleibt im Umfang der Baseline. Ein neuer Befundbeleg fehlt.' :
        'Die Projektion verknüpft den Baseline-Befund mit dem Ergebnis der erneuten Prüfung.',
      details: details([['Baseline-Befund', binding], ['Aktueller Befund', skipped ? 'Kein neuer Beleg' : digest(t.current_finding_digest, 'Aktueller Befund')],
        ['Prüfmethode', identifier(t.verification_level, 'Prüfmethode')], ['Quellverweise', sources],
        ['Baseline-Ausführung', baseline], ['Retest-Ausführung', current], ['Snapshot', snapshot]])
    };
  });
  unique(rows.map(r => r.id), 'Retest-Fälle');
  const open = rows.filter(r => r.status === 'not_retested').length;
  return {kind: 'retest', title: 'Selektiver Retest', baselineExecution: baseline, rows, coverage: {total: rows.length, reviewed: rows.length - open, open}};
}

const legacySources = {import: 'Importierte Beobachtung', openapi: 'OpenAPI',
  'http-discovery': 'HTTP-Inventar', 'service-discovery': 'Dienstinventar', 'nmap-import': 'Nmap-Import',
  'scanner-import': 'Scanner-Import', 'scanner-origin-import': 'Scanner-Ursprung'};
const federationSources = {nuclei: 'Nuclei', ffuf: 'ffuf', nmap: 'Nmap'};


function inventorySource(record) {
  const ref = object(record.source_ref);
  const source = identifier(record.source_kind, 'Quellprofil');
  const legacy = record.source_family === 'legacy_surface';
  const sourceNames = legacy ? legacySources : federationSources;
  requireField(Object.hasOwn(sourceNames, source), 'Unbekanntes Inventar-Quellprofil.');
  requireField(legacy || (record.source_family === 'offline_federation' && ref.profile === source),
    'Quellfamilie und Profil passen nicht zusammen.');
  const binding = legacy ? digest(ref.observation_digest, 'Importbeobachtung') : digest(ref.sha256, 'Quelldatei');
  const locator = legacy ? digest(ref.source_refs_digest, 'Importverweise') : string(ref.locator, 'Position');
  const artifacts = records(record.artifact_refs, 'Artefaktbelege', 1, 16).map(a => {
    object(a);
    return [identifier(a.artifact_id, 'Artefakt-ID'), string(a.pointer, 'Position'), digest(a.artifact_digest, 'Artefakt')].join(' · ');
  });
  return {binding, source: sourceNames[source], details: details([['Quellverweis', locator], ['Quell-Digest', binding], ['Artefakte', artifacts.join(' | ')]])};
}

function inventoryLinks(input, observations) {
  const groups = {};
  for (const [key, ref] of [['services', 'service_id'], ['endpoints', 'endpoint_id']]) {
    const entries = records(input[key], key);
    requireField(input.summary[key] === entries.length, 'Der Nenner für «' + key + '» stimmt nicht.');
    const byId = new Map();
    for (const row of entries) {
      object(row);
      const id = digest(row.id, key);
      requireField(!byId.has(id), 'Mehrdeutige Inventargruppe.');
      const ids = records(row.observation_ids, 'Inventarverweise').map(v => digest(v, 'Beobachtungs-ID'));
      byId.set(id, {ids: unique(ids, 'Inventarverweise'), row});
    }
    const referenced = new Set();
    for (const obs of observations) {
      if (key === 'endpoints' && obs[ref] === null) continue;
      const group = byId.get(obs[ref]);
      requireField(group?.ids.has(obs.id), 'Eine Beobachtung ist keiner passenden Inventargruppe zugeordnet.');
      referenced.add(obs.id);
    }
    let count = 0;
    for (const group of byId.values()) count += group.ids.size;
    requireField(count === referenced.size, 'Das Inventar enthält verwaiste oder mehrfache Verweise.');
    groups[key] = byId;
  }
  for (const group of groups.endpoints.values()) {
    requireField(groups.services.has(group.row.service_id), 'Der Dienst eines Endpunkts fehlt.');
  }
  for (const obs of observations) {
    if (obs.endpoint_id !== null)
      requireField(groups.endpoints.get(obs.endpoint_id).row.service_id === obs.service_id, 'Endpunkt und Dienst widersprechen sich.');
  }
}

function inventoryProjection(input) {
  requireField(input.schema_version === 1, 'Diese Inventarversion wird nicht unterstützt.');
  digest(input.index_digest, 'Index');
  digest(input.snapshot_digest, 'Snapshot');
  const summary = object(input.summary);
  const observations = records(input.observations, 'Beobachtungen');
  const omissions = records(input.omissions, 'Auslassungen');
  requireField(summary.observations === observations.length && summary.omissions === omissions.length &&
    observations.length + omissions.length <= MAX_ROWS, 'Die Inventarzähler oder die Anzahl Datensätze sind ungültig.');
  const rows = observations.map(raw => {
    const obs = object(raw);
    const record = inventorySource(obs);
    const hint = obs.evidence_level === 'hint';
    requireField(hint || obs.evidence_level === null, 'Unzulässiges Belegniveau im Quelleninventar.');
    const a = object(obs.asserted);
    let title = 'Quellbeobachtung';
    let detail = 'Die Quelle enthält eine Beobachtung zu einem Dienst oder Endpunkt.';
    if (obs.source_kind === 'nuclei') {
      requireField(typeof a.matched === 'boolean' && a.matched === hint, 'Matchergebnis und Belegniveau widersprechen sich.');
      title = a.matched ? 'Regel hat zugetroffen' : 'Regel traf nicht zu';
      detail = 'Das Matchergebnis stammt aus dem Nuclei-Export.';
    } else if (obs.source_kind === 'nmap') {
      title = 'Dienstzustand';
      detail = 'Gemeldeter Zustand: ' + identifier(a.state, 'Dienstzustand') + '.';
    } else {
      const status = obs.source_kind === 'ffuf' ? a.status : a.source_status;
      if (status !== null && status !== undefined) {
        requireField(Number.isInteger(status) && status >= 100 && status <= 599, 'Ungültiger HTTP-Status.');
        title = 'HTTP-Beobachtung'; detail = 'Die Quelle meldet HTTP ' + status + '.';
      }
    }
    return {...record, id: digest(obs.id, 'Beobachtungs-ID'), title, status: hint ? 'hint' : 'observed', summary: detail};
  });
  for (const raw of omissions) {
    const omission = object(raw);
    const reason = identifier(omission.reason, 'Auslassungsgrund');
    if (reason === 'excluded_artifact') {
      const kind = identifier(omission.source_kind, 'Artefakttyp');
      const family = identifier(omission.source_family, 'Quellfamilie');
      requireField(['legacy_surface', 'offline_federation'].includes(family) &&
        Object.keys(object(omission.source_ref)).length === 0, 'Ungültige Quellenangabe beim ausgeschlossenen Artefakt.');
      for (const ref of records(omission.artifact_refs, 'Artefaktbelege', 1, 64)) {
        object(ref);
        requireField(ref.pointer === '', 'Ungültiger Verweis für ein vollständig ausgeschlossenes Artefakt.');
        const artifact = identifier(ref.artifact_id, 'Artefakt-ID');
        const binding = digest(ref.artifact_digest, 'Artefakt-Digest');
        rows.push({id: 'omission:' + artifact, binding, source: kind, status: 'excluded',
          title: 'Ausgeschlossenes Artefakt', summary: 'Das Quellartefakt wurde aus dem Snapshot-Umfang ausgeschlossen.',
          details: details([['Artefakt-ID', artifact], ['Artefakt-Digest', binding], ['Quellfamilie', family]])});
      }
      continue;
    }
    const record = inventorySource(omission);
    const ref = object(omission.source_ref);
    const position = ref.locator || ref.source_refs_digest;
    rows.push({...record, id: 'omission:' + omission.source_kind + ':' + record.binding + ':' + position, title: 'Ausgelassener Datensatz',
      status: 'excluded', summary: reason === 'out_of_scope' ? 'Die Quelle liegt ausserhalb des deklarierten Umfangs.' : 'Auslassungsgrund der Quelle: ' + reason + '.'});
  }
  requireField(rows.length <= MAX_ROWS, 'Das Inventar enthält zu viele Einträge.');
  unique(rows.map(r => r.id), 'Inventareinträge');
  inventoryLinks(input, observations);
  return {kind: 'inventory', title: 'Quelleninventar', rows, coverage: null};
}

const socStatusOrder = ['observed', 'telemetry_only', 'incomparable', 'unavailable'];
const syntheticWindowLabels = {matched: 'Alarm und Telemetrie', telemetry_only: 'Telemetrie ohne Alarm',
  foreign: 'Fremder Geltungsbereich', no_data: 'Fehlende Telemetrie'};

function exactFields(record, names) {
  const keys = Object.keys(record);
  requireField(keys.length === names.length && names.every(key => Object.hasOwn(record, key)),
    'Das Datenobjekt enthält unbekannte oder fehlende Felder.');
}

export const importSources = Object.freeze({
  nikto: 'Nikto', ffuf: 'ffuf', gobuster: 'Gobuster', feroxbuster: 'feroxbuster', nmap: 'Nmap', burp: 'Burp Suite', nessus: 'Nessus',
  cobalt: 'Cobalt-Strike-Telemetrie (EDR/SIEM)', zap: 'OWASP ZAP', har: 'HAR', openapi: 'OpenAPI', nuclei: 'Nuclei',
  neo4j: 'Neo4j', bloodhound: 'BloodHound', sqlmap: 'sqlmap', dirbuster: 'DirBuster', falco: 'Falco'
});

function evidenceIndexProjection(input) {
  exactFields(input, ['schema', 'rights', 'workspace', 'signature', 'assessment', 'files']);
  requireField(input.rights === '© Nasser Aldin Farag (0xFarag). All rights reserved.' &&
    ['real', 'example'].includes(input.workspace) && input.signature === 'unsigned',
    'Herkunftsangabe oder Signaturstatus des Belegindexes ist ungültig.');
  const assessment = object(input.assessment);
  exactFields(assessment, ['scope', 'controls', 'coverage', 'findings', 'retest']);
  requireField(assessment.scope === 'unverified' && assessment.controls === 'unverified' &&
    assessment.coverage === 'unknown' && assessment.findings === 'not_assessed' && assessment.retest === 'not_assessed',
    'Der Belegindex darf keine geprüfte Abdeckung, Freigabe oder fachliche Bestätigung ausweisen.');

  const rows = [];
  const sources = [];
  const fileKeys = new Set();
  const assets = new Set();
  let unassigned = 0;
  for (const file of records(input.files, 'Quelldateien', 1, 20)) {
    exactFields(object(file), ['source', 'sha256', 'observations']);
    requireField(typeof file.source === 'string' && Object.hasOwn(importSources, file.source), 'Unbekanntes Werkzeug im Belegindex.');
    const hash = digest(file.sha256, 'Quelldatei');
    const fileKey = file.source + ':' + hash;
    requireField(!fileKeys.has(fileKey), 'Eine Quelldatei ist im selben Quellformat mehrfach aufgeführt.');
    fileKeys.add(fileKey);
    const observations = records(file.observations, 'Beobachtungen je Datei', 0, 1000);
    requireField(rows.length + observations.length <= 2500, 'Der Belegindex überschreitet 2’500 Beobachtungen.');
    const label = importSources[file.source];
    sources.push({source: file.source, label, sha256: hash, count: observations.length});
    observations.forEach((obs, position) => {
      exactFields(object(obs), ['asset_id', 'locator', 'fingerprint']);
      const locator = string(obs.locator, 'Position', 24);
      const match = /^(?:Zeile|Datensatz) ([1-9][0-9]{0,6})$/.exec(locator);
      requireField(match && Number(match[1]) <= 1048576, 'Ungültige Zeile oder Position im Belegindex.');
      const fingerprint = digest(obs.fingerprint, 'Datensatz-Fingerabdruck');
      const asset = obs.asset_id;
      requireField(asset === null || typeof asset === 'string' && /^[a-f0-9]{16}$/.test(asset),
        'Ungültige pseudonyme Asset-ID im Belegindex.');
      if (asset === null) unassigned++;
      else assets.add(asset);
      rows.push({
        id: fileKey + ':' + (position + 1), binding: hash, source: label,
        title: label + ' · ' + locator + (asset ? ' · ' + asset : ' · ohne Hostbezug'),
        status: 'import_unassessed', summary: 'Der Belegindex verweist auf eine Beobachtung aus ' + label + '.',
        reference: {source: file.source, file_sha256: hash, locator, fingerprint},
        details: details([['Asset-ID', asset || 'Kein Hostbezug'], ['Quellposition', locator],
          ['SHA-256 der Quelldatei laut Index', hash], ['Datensatz-Fingerabdruck laut Index', fingerprint]])
      });
    });
  }
  return {kind: 'evidence_index', title: 'Werkzeugübergreifender Belegindex', assessment: null, scope: null, rows, coverage: null,
    importIndex: {workspace: input.workspace, sources, assets: assets.size, unassigned}};
}

function boundedCount(value) {
  requireField(Number.isInteger(value) && value >= 0 && value <= 4096, 'Ungültiger Ereignis- oder Alarmzähler.');
  return value;
}

function eventSet(value, field) {
  return unique(records(value, field, 0, 4096).map(id => identifier(id, field)), field);
}

function instant(value) {
  const match = typeof value === 'string' && /^(\d{4}-\d\d-\d\d)T(\d\d:\d\d:\d\d)(?:\.(\d{1,6}))?(Z|[+-]\d\d:\d\d)$/.exec(value);
  requireField(match, 'Das Zeitfenster erfordert zwei Zeitpunkte mit expliziter Zeitzone.');
  const local = new Date(match[1] + 'T' + match[2] + 'Z');
  const actual = Date.parse(match[1] + 'T' + match[2] + match[4]);
  requireField(Number.isFinite(actual) && Number.isFinite(local.valueOf()) && !value.startsWith('0000') &&
    local.toISOString().slice(0, 19) === match[1] + 'T' + match[2], 'Ungültiger Zeitpunkt im SOC-Bericht.');
  return BigInt(actual) * 1000n + BigInt((match[3] || '').padEnd(6, '0'));
}

function blueProjection(input) {
  exactFields(input, ['schema','rights','signed','synthetic','source_assertions_verified','input_profile',
    'retest_sha256','signals_sha256','source_snapshot_digest','binding','window','source_retest_status','source_coverage','samples']);
  const synthetic = input.input_profile === 'authzledger.website-lab.v1';
  requireField((synthetic || input.input_profile === 'authzledger.control-signals.v1') && synthetic === input.synthetic &&
    input.signed === false && input.source_assertions_verified === false, 'Unbekanntes SOC-Profil oder widersprüchliche Vertrauensangabe.');
  const ctx = object(input.binding);
  exactFields(ctx, ['assessment','scope','finding','source','rule']);
  const assessment = identifier(ctx.assessment, 'Assessment');
  const scope = digest(ctx.scope, 'Scope');
  const finding = identifier(ctx.finding, 'Quellbefund');
  const source = identifier(ctx.source, 'Signalquelle');
  const rule = identifier(ctx.rule, 'Erkennungsregel');
  const snapshot = digest(input.source_snapshot_digest, 'Quellsnapshot');
  const signalHash = digest(input.signals_sha256, 'Signaldatei');
  const retestHash = digest(input.retest_sha256, 'Retest-Datei');
  const window = object(input.window);
  exactFields(window, ['from', 'until']);
  requireField(instant(window.from) < instant(window.until), 'Das SOC-Zeitfenster ist leer oder rückwärts angegeben.');

  const sourceStatuses = object(input.source_coverage);
  const entries = records(Object.entries(sourceStatuses), 'Retest-Abdeckung', 1, 4096);
  let skipped = 0;
  for (const [id, status] of entries) {
    identifier(id, 'Quellbefund');
    requireField(typeof status === 'string' && Object.hasOwn(retestLabels, status), 'Unbekannter Status im ursprünglichen Retest.');
    if (status === 'not_retested') skipped++;
  }
  requireField(Object.hasOwn(sourceStatuses, finding) && sourceStatuses[finding] === input.source_retest_status,
    'Der gebundene Befund fehlt oder widerspricht der Retest-Abdeckung.');
  const samples = records(Object.entries(object(input.samples)), 'Signalfenster', 1, 32);
  const detailed = Object.hasOwn(object(samples[0][1]), 'alert_coverage');
  const signalCoverage = {windows: samples.length, observedWindows: 0, telemetryOnlyWindows: 0, incomparableWindows: 0,
    unavailableWindows: 0, eventOccurrences: 0, eligibleOccurrences: 0, linkedOccurrences: 0, excludedOccurrences: 0, detailed};
  const counterKeys = {observed: 'observedWindows', telemetry_only: 'telemetryOnlyWindows',
    incomparable: 'incomparableWindows', unavailable: 'unavailableWindows'};
  const rows = samples.map(([name, raw]) => {
    identifier(name, 'Signalfenster');
    const sample = object(raw);
    const fields = ['status','event_count','alert_count','matching_events','alerted_events'];
    exactFields(sample, detailed ? [...fields, 'alert_coverage'] : fields);
    const count = boundedCount(sample.event_count);
    const alerts = boundedCount(sample.alert_count);
    const eligible = eventSet(sample.matching_events, 'Passende Ereignisse');
    const linked = eventSet(sample.alerted_events, 'Ereignisse mit Alarm');
    requireField(eligible.size <= count && linked.size <= alerts && [...linked].every(id => eligible.has(id)),
      'Ereignismengen und Zähler des Signalfensters widersprechen sich.');
    const state = linked.size ? 'observed' : eligible.size ? 'telemetry_only' : count || alerts ? 'incomparable' : 'unavailable';
    requireField(sample.status === state, 'Der SOC-Status widerspricht den dokumentierten Ereignissen und Alarmen.');
    const excluded = count - eligible.size;
    const unlinked = [...eligible].filter(id => !linked.has(id));
    if (detailed) {
      const coverage = object(sample.alert_coverage);
      exactFields(coverage, ['eligible_events','linked_events','excluded_events','unlinked_event_ids']);
      const missing = eventSet(coverage.unlinked_event_ids, 'Passende Ereignisse ohne Alarm');
      requireField(coverage.eligible_events === eligible.size && coverage.linked_events === linked.size &&
        coverage.excluded_events === excluded && missing.size === unlinked.length && unlinked.every(id => missing.has(id)),
        'Die angegebene Alarmabdeckung passt nicht zu den Ereignis-IDs.');
    }
    signalCoverage[counterKeys[state]]++;
    signalCoverage.eventOccurrences += count;
    signalCoverage.eligibleOccurrences += eligible.size;
    signalCoverage.linkedOccurrences += linked.size;
    signalCoverage.excludedOccurrences += excluded;
    const title = synthetic && Object.hasOwn(syntheticWindowLabels, name) ? syntheticWindowLabels[name] : 'Signalfenster ' + name;
    const summary = eligible.size ? linked.size + ' von ' + eligible.size + ' passenden Ereignissen sind einem Alarm zugeordnet.' :
      count || alerts ? 'Ereignisse oder Alarme liegen vor. Die erwartete Zuordnung fehlt.' :
      'Das Fenster enthält keine Ereignisse und keine Alarme.';
    return {id: 'soc:' + name, binding: signalHash, title, source, status: 'soc_' + state, summary,
      signalCoverage: {eligible: eligible.size, linked: linked.size, excluded, detailed},
      details: details([['Signalfenster', name], ['Regel', rule], ['Zeitraum', window.from + ' bis ' + window.until + ' (Ende exklusiv)'],
        ['Ereignisse / Alarme', count + ' / ' + alerts], ['Passend / mit Alarm / ausgeschlossen', eligible.size + ' / ' + linked.size + ' / ' + excluded],
        ['Passende Ereignisse ohne Alarm', unlinked.length ? unlinked.join(', ') : 'Keine'],
        ['Abdeckung im Bericht', detailed ? 'Explizite Zähler und IDs abgeglichen' : 'Älteres Format. Werte aus den gespeicherten Ereignislisten abgeleitet.'],
        ['Quellbefund', finding], ['Retest-Status laut Quelle', retestLabels[input.source_retest_status]],
        ['Ursprünglicher Retest-Umfang', entries.length + ' Befunde, davon ' + skipped + ' ausgelassen'],
        ['Retest-Digest laut Bericht', retestHash], ['Signal-Digest laut Bericht', signalHash], ['Quellsnapshot laut Bericht', snapshot],
        ['Belegdaten', synthetic ? 'Synthetische Signaldaten' : 'Vom Betreiber bereitgestellte Signaldaten'],
        ['Aussagegrenze', 'Unsignierter Bericht. Die Rohdateien und die zugrunde liegenden Ereignisse werden bei diesem Import nicht verifiziert.']])};
  });
  rows.sort((a,b) => socStatusOrder.indexOf(a.status.slice(4)) - socStatusOrder.indexOf(b.status.slice(4)) ||
    (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  return {kind: 'blue', title: 'SOC-Signalbericht', assessment, scope, rows, coverage: null, signalCoverage};
}

async function sha256(bytes) {
  requireField(globalThis.crypto?.subtle, 'Für die lokale SHA-256-Prüfung ist ein sicherer Browserkontext erforderlich.');
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(hash, b => b.toString(16).padStart(2, '0')).join('');
}

// Per-index session state. Local File objects never leave a pending call.
export function originalFileChecks(sources) {
  const known = new Set(sources.map(file => file.sha256));
  const matched = new Set();
  let generation = 0;
  let last = null;
  const maximumBytes = 1048576;
  const validSize = file => Number.isInteger(file?.size) && file.size > 0 && file.size <= maximumBytes;

  async function verify(files) {
    const current = ++generation;
    if (!Array.isArray(files) || !files.length || files.length > 20 ||
        files.reduce((total, file) => total + (validSize(file) ? file.size : 0), 0) > 5 * maximumBytes) {
      last = {error: 'Wählen Sie 1 bis 20 Dateien mit zusammen höchstens 5 MiB.'};
      return last;
    }
    const outcomes = [];
    const seen = new Set();
    for (const [i, file] of files.entries()) {
      let result = {position: i + 1, status: 'size'};
      if (validSize(file)) {
        try {
          const bytes = await file.arrayBuffer();
          if (current !== generation) return null;
          if (!(bytes instanceof ArrayBuffer) || bytes.byteLength !== file.size) throw Error();
          const hash = await sha256(bytes);
          const matches = known.has(hash);
          result = {position: i + 1, status: matches ? 'matched' : 'unmatched', duplicate: seen.has(hash)};
          if (matches) result.sha256 = hash;
          seen.add(hash);
        } catch {
          result = {position: i + 1, status: 'unreadable'};
        }
      }
      if (current !== generation) return null;
      outcomes.push(result);
    }
    // A superseded read must commit neither a partial match nor a stale status.
    for (const result of outcomes) if (result.status === 'matched') matched.add(result.sha256);
    last = {outcomes};
    return last;
  }

  return {verify, cancel() { generation++; }, has(hash) { return matched.has(hash); }, get last() { return last; }};
}

// Mirrors the v1 producer's sorted, ASCII-escaped JSON for these projections.
// Restrict numbers to exact integers to avoid treating rounded input as identical.
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    requireField(keys.every(key => /^[ -~]+$/.test(key)), 'Unbekanntes Schlüsselformat für die Digestprüfung.');
    return '{' + keys.map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  }
  if (typeof value === 'number') requireField(Number.isSafeInteger(value), 'Zahlen ausserhalb des unterstützten Digestprofils.');
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

async function verifySeal(value, kind, field) {
  const content = {...value};
  delete content[field];
  const bytes = new TextEncoder().encode('AuthzLedger:' + kind + ':v1\n' + canonical(content));
  requireField(await sha256(bytes) === value[field], 'Der interne Digest stimmt nicht mit dem dokumentierten Inhalt überein.');
}

export async function parseProjection(inputBytes) {
  requireField(inputBytes instanceof ArrayBuffer || inputBytes instanceof Uint8Array, 'Erwartet werden die unveränderten Dateibytes.');
  requireField(inputBytes.byteLength > 0 && inputBytes.byteLength <= MAX_BYTES, 'Die JSON-Datei muss zwischen 1 Byte und 2 MiB gross sein.');
  const bytes = Uint8Array.from(inputBytes instanceof Uint8Array ? inputBytes : new Uint8Array(inputBytes));
  let text, input;
  try {
    text = new TextDecoder('utf-8', {fatal: true}).decode(bytes);
    input = JSON.parse(text);
  } catch {
    throw new Error('Die Datei enthält kein gültiges UTF-8-JSON.');
  }
  object(input);
  checkKeys(text);
  if (input.schema === 'authzledger.workbench.manual-case/v1') {
    requireField(Object.keys(input).length === 3, 'Ungültige Felder im manuellen Fall.');
    const title = string(input.title, 'Fallbezeichnung', 160);
    const summary = input.observation;
    requireField(typeof summary === 'string' && summary.trim().length > 0 && summary.length <= 1600 &&
      !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(summary),
    'Ungültige Beobachtung im manuellen Fall.');
    const fingerprint = await sha256(bytes);
    return {kind:'manual', title:'Manuell erfasster Fall', assessment:null, scope:null,
      digest:fingerprint, coverage:null, rows:[{id:'manual-1', title, summary, binding:fingerprint,
        source:'Eigene Beobachtung', status:'hint', details:[]}]};
  }
  const profiles = [input.demo === 'B', input.demo === 'C', input.kind === 'federated-surface-index', input.schema === 'authzledger.blue-evidence.v1',
    input.schema === 'authzledger.evidence-index.v1'];
  requireField(profiles.filter(Boolean).length === 1, 'Erwartet wird ein AuthzLedger-Befund B, Retest C, Quelleninventar, Belegindex oder SOC-Signalbericht.');
  if (profiles[4]) return {...evidenceIndexProjection(input), digest: await sha256(bytes)};
  if (profiles[3]) return {...blueProjection(input), digest: await sha256(bytes)};
  const assessment = identifier(input.assessment_id, 'Assessment');
  const scope = digest(input.scope_digest, 'Scope');
  const projection = profiles[0] ? findingProjection(input) : profiles[1] ? retestProjection(input) : inventoryProjection(input);
  if (profiles[0]) await verifySeal(input.finding, 'detection-finding', 'finding_digest');
  if (profiles[2]) await verifySeal(input, 'federated-surface-index', 'index_digest');
  return {...projection, assessment, scope, digest: await sha256(bytes)};
}
