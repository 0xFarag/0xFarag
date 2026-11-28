// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const AuthzGraphProfiles = (() => {
  const definitions = Object.freeze({
    bloodhound: {
      label: 'BloodHound', format: 'JSON · Gruppen und Mitgliedschaften', accept: '.json',
      hint: 'Gruppenberichte der Version 5 oder 6. Gruppen und ihre Mitglieder erhalten dateigebundene Kennungen. «ref» bezeichnet ein Mitglied, das nur in einer Mitgliederliste vorkommt.'
    },
    neo4j: {
      label: 'Neo4j', format: 'APOC JSONL · Verzeichnisinventar', accept: '.jsonl,.ndjson,.json',
      hint: 'APOC JSON Lines mit Verzeichnisobjekten und expliziter Domäne. MemberOf und Contains verbinden deklarierte Objekte derselben Domäne. Kennungen gelten innerhalb einer Datei.'
    }
  });
  const samples = Object.freeze({
    bloodhound: JSON.stringify({meta: {type: 'groups', version: 6, count: 1}, data: [{
      ObjectIdentifier: 'S-1-5-21-10-20-30-1600', Properties: {domain: 'training.example'},
      Members: [{ObjectIdentifier: 'S-1-5-21-10-20-30-1500', ObjectType: 'User'}]
    }]}),
    neo4j: [
      {type: 'node', id: '1', labels: ['User'], properties: {domain: 'training.example'}},
      {type: 'node', id: '2', labels: ['Group'], properties: {domain: 'training.example'}},
      {type: 'relationship', id: '3', label: 'MemberOf', start: {id: '1'}, end: {id: '2'}}
    ].map(item => JSON.stringify(item)).join('\n')
  });
  const memberTypes = new Set(['User', 'Group', 'Computer']);
  const containerTypes = new Set(['Domain', 'OU', 'Container']);
  const nodeTypes = new Set([...memberTypes, ...containerTypes]);
  const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const invalid = 'Das Verzeichnisinventar ist unvollständig oder widersprüchlich.';
  const unsupported = 'Dieses Inventar enthält einen nicht unterstützten Objekt- oder Beziehungstyp.';
  const overLimit = 'Ein Verzeichnisinventar darf höchstens 1’000 Objekte und Beziehungen enthalten.';

  function detect(item) {
    if (!object(item)) return null;
    if (item.meta?.type === 'groups' && Array.isArray(item.data)) return 'bloodhound';
    if (Object.hasOwn(item, 'id') && ['node', 'relationship'].includes(item.type)) return 'neo4j';
    return null;
  }

  async function records(source, text, {fileDigest, digest, ImportError}) {
    function need(condition, message = invalid) {
      if (!condition) throw new ImportError(message);
    }
    function readJson(input) {
      let parsed;
      try { parsed = JSON.parse(input); } catch { throw new ImportError(invalid); }
      // JSON.parse silently overwrites duplicate keys. Check the original object keys,
      // including escaped spellings, before accepting a directory or endpoint claim.
      const keys = [];
      const tokens = /"(?:\\[\s\S]|[^"\\])*"|[{}\[\]]/g;
      const colon = /\s*:/y;
      for (const token of input.matchAll(tokens)) {
        const value = token[0];
        if (value === '{' || value === '[') {
          need(keys.length < 128);
          keys.push(value === '{' ? new Set() : null);
        } else if (value === '}' || value === ']') {
          keys.pop();
        } else if (keys.at(-1)) {
          colon.lastIndex = token.index + value.length;
          if (!colon.test(input)) continue;
          const key = JSON.parse(value);
          need(!keys.at(-1).has(key));
          keys.at(-1).add(key);
        }
      }
      return parsed;
    }
    function domainName(value) {
      need(typeof value === 'string' && value.length <= 254);
      const domain = value.toLowerCase().replace(/\.$/, '');
      const labels = domain.split('.');
      need(domain.length <= 253 && labels.length > 1 &&
        labels.every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) &&
        !/^\d+$/.test(labels.at(-1)));
      return domain;
    }
    function sidDomain(value) {
      const match = typeof value === 'string' && /^(S-1-5-21-\d{1,10}-\d{1,10}-\d{1,10})-\d{1,10}$/.exec(value);
      need(match && value.split('-').slice(4).every(part => Number(part) <= 4294967295));
      return match[1];
    }
    function apocId(value) {
      need(typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(value));
      return value;
    }
    function nodeType(labels) {
      need(Array.isArray(labels) && labels.length >= 1 && labels.length <= 2);
      const kinds = labels.filter(label => label !== 'Base');
      need(kinds.length === 1 && nodeTypes.has(kinds[0]), unsupported);
      return kinds[0];
    }

    const nodes = new Map();
    const edges = new Map();
    function bound() { need(nodes.size + edges.size <= 1000, overLimit); }
    function addNode(id, domain, kind, reference, locator) {
      const prior = nodes.get(id);
      need(!prior || (prior.domain === domain && prior.kind === kind && (prior.reference || reference)));
      if (!prior || (prior.reference && !reference)) nodes.set(id, {id, domain, kind, reference, locator});
      bound();
    }
    function addEdge(start, end, relation, locator) {
      need(['Contains', 'MemberOf'].includes(relation), unsupported);
      const key = JSON.stringify([start.id, end.id, relation]);
      need(start.id !== end.id && !edges.has(key));
      edges.set(key, {start, end, relation, locator});
      bound();
    }
    function endpoint(value) {
      need(object(value));
      const id = apocId(value.id);
      const kind = Object.hasOwn(value, 'labels') ? nodeType(value.labels) : null;
      const props = Object.hasOwn(value, 'properties') ? value.properties : {};
      need(object(props));
      const domain = Object.hasOwn(props, 'domain') ? domainName(props.domain) : null;
      return {id, kind, domain};
    }

    if (source === 'bloodhound') {
      const report = readJson(text);
      need(detect(report) === 'bloodhound' && [5, 6].includes(report.meta.version));
      need(report.meta.count === report.data.length && report.data.length <= 1000);
      const domainSids = new Map();
      const sidDomains = new Map();
      for (const [index, group] of report.data.entries()) {
        need(object(group) && object(group.Properties) && Array.isArray(group.Members) && group.Members.length <= 1000);
        const id = group.ObjectIdentifier;
        const domainSid = sidDomain(id);
        const domain = domainName(group.Properties.domain);
        need(!Object.hasOwn(group.Properties, 'domainsid') || group.Properties.domainsid === domainSid);
        need(!domainSids.has(domain) || domainSids.get(domain) === domainSid);
        need(!sidDomains.has(domainSid) || sidDomains.get(domainSid) === domain);
        domainSids.set(domain, domainSid);
        sidDomains.set(domainSid, domain);
        const locator = 'Datensatz ' + (index + 1);
        addNode(id, domain, 'Group', false, locator);
        for (const member of group.Members) {
          need(object(member) && memberTypes.has(member.ObjectType), unsupported);
          const memberId = member.ObjectIdentifier;
          need(sidDomain(memberId) === domainSid);
          addNode(memberId, domain, member.ObjectType, true, locator);
          addEdge({id: memberId}, {id}, 'MemberOf', locator);
        }
      }
    } else {
      need(source === 'neo4j');
      const relationshipIds = new Set();
      for (const [index, line] of text.split(/\r?\n/).entries()) {
        if (!line.trim()) continue;
        const item = readJson(line);
        need(object(item));
        const id = apocId(item.id);
        const locator = 'Zeile ' + (index + 1);
        if (item.type === 'node') {
          need(object(item.properties));
          addNode(id, domainName(item.properties.domain), nodeType(item.labels), false, locator);
        } else {
          need(item.type === 'relationship' && !relationshipIds.has(id));
          relationshipIds.add(id);
          addEdge(endpoint(item.start), endpoint(item.end), item.label, locator);
        }
      }
    }
    function resolve(claim) {
      const node = nodes.get(claim.id);
      need(node && (!claim.kind || node.kind === claim.kind) && (!claim.domain || node.domain === claim.domain));
      return node;
    }
    need(nodes.size > 0);
    for (const {start, end, relation} of edges.values()) {
      const from = resolve(start), to = resolve(end);
      need(from.domain === to.domain);
      if (relation === 'MemberOf') need(memberTypes.has(from.kind) && to.kind === 'Group' && !to.reference);
      else need(containerTypes.has(from.kind));
    }
    await Promise.all([...nodes.values()].map(async node => {
      node.alias = (await digest(JSON.stringify([source, fileDigest, node.domain, node.id]))).slice(0, 32);
    }));
    const rows = [];
    for (const {domain, kind, alias, locator, reference} of nodes.values()) {
      const detail = kind + (reference ? ' · ref · ' : ' · ') + alias;
      rows.push({asset: domain, detail, raw: JSON.stringify(['node', kind, alias, reference]), identity: null, locator});
    }
    for (const {start, end, relation, locator} of edges.values()) {
      const from = nodes.get(start.id), to = nodes.get(end.id);
      const detail = relation + ' · ' + from.alias + ' → ' + to.alias;
      rows.push({asset: from.domain, detail, raw: JSON.stringify([relation, from.alias, to.alias]), identity: null, locator});
    }
    return rows;
  }
  return Object.freeze({definitions, samples, detect, records});
})();
