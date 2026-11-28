// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const AuthzHarControls = (() => {
  const headerName = /^:?[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
  const ows = text => text.replace(/^[ \t]+|[ \t]+$/g, '');
  const ipHost = hostname => hostname.startsWith('[') || /^\d+\.\d+\.\d+\.\d+$/.test(hostname);
  const isHtml = text => typeof text === 'string' && ows(text.split(';', 1)[0]).toLowerCase() === 'text/html';
  const result = (id, status, reason) => ({id, status, reason});

  // RFC 6797 §§6.1, 8.1. Unknown well-formed directives do not change max-age.
  // Tokenize quoted strings so commas and semicolons in extensions remain data.
  function hsts(value) {
    const directive = /[ \t]*([!#$%&'*+.^_`|~0-9A-Za-z-]+)(?:[ \t]*=[ \t]*([!#$%&'*+.^_`|~0-9A-Za-z-]+|"(?:[^"\\\x00-\x08\x0a-\x1f\x7f]|\\[\t\x20-\x7e])*"))?[ \t]*/y;
    const names = new Set();
    let active;
    let pos = 0;
    while (pos < value.length) {
      if (value[pos] === ';' || value[pos] === ' ' || value[pos] === '\t') { pos++; continue; }
      if (value[pos] === ',') return result('hsts', 'unknown', 'ambiguous');
      directive.lastIndex = pos;
      const match = directive.exec(value);
      if (!match) return result('hsts', 'deviation', 'invalid-value');
      const name = match[1].toLowerCase();
      let argument = match[2];
      pos = directive.lastIndex;
      if (value[pos] === ',') return result('hsts', 'unknown', 'ambiguous');
      if (pos < value.length && value[pos] !== ';') return result('hsts', 'deviation', 'invalid-value');
      if (names.has(name)) return result('hsts', 'deviation', 'invalid-value');
      names.add(name);
      if (name === 'includesubdomains' && argument !== undefined) return result('hsts', 'deviation', 'invalid-value');
      if (name === 'max-age') {
        if (argument?.startsWith('"')) argument = argument.slice(1,-1).replace(/\\([\t\x20-\x7e])/g, '$1');
        if (!argument || !/^\d+$/.test(argument)) return result('hsts', 'deviation', 'invalid-value');
        active = /[1-9]/.test(argument);
      }
    }
    if (active === undefined) return result('hsts', 'deviation', 'invalid-value');
    return active ? result('hsts','met','valid') : result('hsts','deviation','disabled');
  }
  function check(id, name, headers) {
    if (!headers) return result(id, 'unknown', 'headers-unavailable');
    const fields = headers.filter(header => header.name.toLowerCase() === name);
    // Even a well-formed capture may have been filtered. This status describes
    // the exported list exclusively, never the live host or its effective policy.
    if (!fields.length) return result(id, 'deviation', 'absent-in-capture');
    if (fields.length !== 1) return result(id, 'unknown', 'ambiguous');
    const value = ows(fields[0].value);
    if (value.length > 8192 || /\[redacted\]|<redacted>|\(redacted\)|^redacted$|^\*{3,}$/i.test(value))
      return result(id, 'unknown', 'ambiguous');
    if (id === 'hsts') return hsts(value);
    if (value.includes(',')) return result(id, 'unknown', 'ambiguous');
    return /^nosniff$/i.test(value) ? result(id,'met','valid') : result(id,'deviation','invalid-value');
  }
  function assess(entry) {
    const request = entry?.request;
    const response = entry?.response;
    // 204/205 have no representation. Partial responses fall outside this profile.
    if (request?.method !== 'GET' || typeof request.url !== 'string' || !/^https:\/\//i.test(request.url)
        || !Number.isInteger(response?.status) || response.status < 200 || response.status > 299
        || [204,205,206].includes(response.status) || response.redirectURL || !isHtml(response.content?.mimeType)) return null;
    let url;
    try { url = new URL(request.url); } catch { return null; }
    if (url.protocol !== 'https:' || !url.hostname) return null;
    const raw = response.headers;
    const headers = Array.isArray(raw) && raw.length && raw.length <= 1024 && raw.every(field =>
      typeof field?.name === 'string' && headerName.test(field.name) && typeof field.value === 'string') ? raw : null;
    if (headers?.some(field => field.name.toLowerCase() === 'content-type' && !isHtml(field.value))) return null;
    return [
      check('nosniff', 'x-content-type-options', headers),
      ipHost(url.hostname) ? result('hsts','unknown','ip-host') : check('hsts','strict-transport-security',headers)
    ];
  }
  return Object.freeze({assess});
})();
