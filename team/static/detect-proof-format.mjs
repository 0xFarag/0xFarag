// © Nasser Aldin Farag (0xFarag). All rights reserved.
const maxBytes = 1024 * 1024;
const xmlFormats = new Map([
  ['NessusClientData_v2', 'nessus'], ['niktoscan', 'nikto'],
  ['niktoscans', 'nikto'], ['nmaprun', 'nmap']
]);
const sqlmapHeader = 'Target URL,Place,Parameter,Technique(s),Note(s)';

function recordFormat(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return null;
  const candidates = [];
  if (record.type === 'http' && typeof record['matcher-status'] === 'boolean'
      && typeof record['template-id'] === 'string' && typeof record['matched-at'] === 'string') candidates.push('nuclei');
  if ((record.type === 'node' && Array.isArray(record.labels) && record.id != null)
      || (record.type === 'relationship' && typeof record.label === 'string'
          && record.start?.id != null && record.end?.id != null)) candidates.push('neo4j');
  if (record.meta?.type === 'groups' && Array.isArray(record.data)) candidates.push('bloodhound');
  if (Array.isArray(record.site) && record.site.length && record.site.every(site => Array.isArray(site?.alerts))) candidates.push('zap');
  if (['1.1','1.2'].includes(record.log?.version) && Array.isArray(record.log.entries)) candidates.push('har');
  if (typeof record.openapi === 'string' && /^3\./.test(record.openapi) && record.paths && record.info) candidates.push('openapi');
  if (record.schema === 'authzledger.defensive-telemetry.v1' && record.source === 'cobalt-strike'
      && Array.isArray(record.events)) candidates.push('cobalt');
  return candidates.length === 1 ? candidates[0] : null;
}

function xmlFormat(text) {
  // Inspect only the preamble and root. No XML parser receives external identifiers.
  let offset = 0, declared;
  while (offset < text.length) {
    while (/\s/.test(text.charAt(offset)) && offset < text.length) offset++;
    if (text.startsWith('<!--',offset) || text.startsWith('<?xml',offset)) {
      const end = text.startsWith('<!--',offset) ? '-->' : '?>';
      const close = text.indexOf(end,offset+2);
      if (close < 0) return null;
      offset = close+end.length;
      continue;
    }
    if (text.startsWith('<!DOCTYPE',offset)) {
      const decl = /^<!DOCTYPE\s+(issues|items|nmaprun)\s*(>|\[)/.exec(text.slice(offset,offset+100));
      if (!decl || declared) return null;
      declared = decl[1];
      offset += decl[0].length;
      if (decl[2] === '[') {
        const close = /\]\s*>/.exec(text.slice(offset,offset+32768));
        if (!close) return null;
        offset += close.index+close[0].length;
      }
      continue;
    }
    break;
  }
  const root = /^<([\w:.-]+)(?=[\s/>])([^>]*)>/.exec(text.slice(offset,offset+4096));
  if (!root || (declared && declared !== root[1])) return null;
  if (['issues','items'].includes(root[1])) {
    const child = text.slice(offset+root[0].length,offset+root[0].length+8192).trimStart();
    if (declared || /\sburpVersion\s*=/.test(root[2])
        || (root[1] === 'issues' && /^<issue[\s>]/.test(child) && child.includes('<host'))
        || (root[1] === 'items' && /^<item[\s>]/.test(child) && child.includes('<url>') && child.includes('<method>'))) return 'burp';
    return null;
  }
  return xmlFormats.get(root[1]) ?? null;
}

function detectText(input) {
  const text = input.trim();
  if (text.split(/\r?\n/, 1)[0] === sqlmapHeader) return 'sqlmap';
  if (text.startsWith('<')) return /<!\s*ENTITY\b/i.test(text) ? null : xmlFormat(text);
  if (!text.startsWith('{')) return null;
  try {
    return recordFormat(JSON.parse(text));
  } catch {
    // Only APOC and Nuclei use a series of separate JSON objects here.
    const lines = text.split(/\r?\n/).filter(line => line.trim());
    if (lines.length < 2 || lines.length > 2000) return null;
    let format;
    for (const line of lines) {
      const kind = recordFormat(JSON.parse(line));
      if (!['neo4j','nuclei'].includes(kind) || (format && format !== kind)) return null;
      format = kind;
    }
    return format;
  }
}

export async function detectProofFile(file) {
  if (!file || !file.size || file.size > maxBytes) return null;
  try {
    return detectText(new TextDecoder('utf-8', {fatal:true}).decode(await file.arrayBuffer()));
  } catch {
    return null;
  }
}
