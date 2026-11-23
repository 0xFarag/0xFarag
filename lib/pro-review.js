// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';

const { createHash, createPublicKey, verify } = require('node:crypto');

const ROUTE = '/api/pro-review';
const PROTOCOL = 'authzledger.pro-review.v1';
const MAX_BODY_BYTES = 8192;
const MAX_CASES = 32;
const FIELDS = {
  scope: ['in_scope', 'out_of_scope', 'unknown'],
  controls: ['passed', 'failed', 'missing'],
  binding: ['matched', 'ambiguous', 'missing'],
  retest: ['not_retested', 'inconclusive', 'still_present', 'change_observed']
};

function hasExactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

function decodeBase64url(value, bytes) {
  if (typeof value !== 'string' || value.length !== Math.ceil(bytes * 4 / 3) || !/^[\w-]+$/.test(value)) return null;
  const buffer = Buffer.from(value, 'base64url');
  return buffer.length === bytes && buffer.toString('base64url') === value ? buffer : null;
}

// Ed25519 compresses y in little-endian order and uses the high bit for the x sign.
// Exclude noncanonical y and all small-order points, independently of the OpenSSL version.
function admissibleEd25519Key(bytes) {
  const y = Buffer.from(bytes);
  y[31] &= 0x7f;
  const littleEndian = y.toString('hex');
  if (littleEndian === '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05' ||
      littleEndian === 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a') return false;
  const coordinate = BigInt('0x' + y.reverse().toString('hex'));
  const fieldPrime = (1n << 255n) - 19n;
  return coordinate > 1n && coordinate < fieldPrime - 1n;
}

function validTimestamp(value) {
  return Number.isSafeInteger(value) && value >= 0 && value <= 253402300799;
}

function approvedKeys(config) {
  if (typeof config !== 'string' || !config || Buffer.byteLength(config) > 32768) return null;
  let entries;
  try { entries = JSON.parse(config); } catch { return null; }
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > 128) return null;
  const keys = new Map();
  for (const entry of entries) {
    if (!hasExactKeys(entry, ['jwk', 'expiresAt']) || !validTimestamp(entry.expiresAt) ||
        !hasExactKeys(entry.jwk, ['kty', 'crv', 'x']) || entry.jwk.kty !== 'OKP' || entry.jwk.crv !== 'Ed25519') return null;
    const raw = decodeBase64url(entry.jwk.x, 32);
    if (!raw || !admissibleEd25519Key(raw)) return null;
    const kid = createHash('sha256').update(raw).digest('base64url');
    if (keys.has(kid)) return null;
    keys.set(kid, entry);
  }
  return keys;
}

function validOrigin(value) {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.origin === value;
  } catch { return false; }
}

class RequestError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function readRequest(req) {
  if (!/^application\/json(?:\s*;\s*charset\s*=\s*utf-8)?$/i.test(req.headers['content-type'] || '') ||
      (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity')) {
    throw new RequestError(415, 'invalid_request');
  }
  const length = req.headers['content-length'];
  if (length !== undefined) {
    if (typeof length !== 'string' || !/^\d+$/.test(length)) throw new RequestError(400, 'invalid_request');
    if (Number(length) > MAX_BODY_BYTES) throw new RequestError(413, 'invalid_request');
  }
  let body = req.body;
  if (Buffer.isBuffer(body) || typeof body === 'string') {
    if (Buffer.byteLength(body) > MAX_BODY_BYTES) throw new RequestError(413, 'invalid_request');
    try {
      if (Buffer.isBuffer(body)) body = new TextDecoder('utf-8', {fatal:true}).decode(body);
      body = JSON.parse(body);
    } catch { throw new RequestError(400, 'invalid_request'); }
  }
  if (!hasExactKeys(body, ['kid', 'issuedAt', 'cases', 'signature']) ||
      !decodeBase64url(body.kid, 32) || !validTimestamp(body.issuedAt) || !Array.isArray(body.cases)) {
    throw new RequestError(400, 'invalid_request');
  }
  if (body.cases.length > MAX_CASES) throw new RequestError(413, 'invalid_request');
  const fields = Object.keys(FIELDS);
  for (const row of body.cases) {
    if (!hasExactKeys(row, fields) || fields.some(field => !FIELDS[field].includes(row[field]))) {
      throw new RequestError(400, 'invalid_request');
    }
  }
  const signature = decodeBase64url(body.signature, 64);
  if (!signature) throw new RequestError(400, 'invalid_request');
  return { kid: body.kid, issuedAt: body.issuedAt, cases: body.cases, signature };
}

function review(cases) {
  let eligible = 0, conclusive = 0, notRetested = 0;
  const actions = cases.map((row, index) => {
    if (row.retest === 'not_retested') notRetested++;
    let decision;
    if (row.scope === 'out_of_scope') decision = 'excluded';
    else if (row.scope !== 'in_scope') decision = 'clarify_scope';
    else if (row.controls !== 'passed') decision = 'check_controls';
    else if (row.binding !== 'matched') decision = 'bind_source';
    else {
      eligible++;
      switch (row.retest) {
        case 'not_retested': decision = 'schedule_retest'; break;
        case 'inconclusive': decision = 'review_inconclusive'; break;
        case 'still_present': decision = 'review_open'; conclusive++; break;
        case 'change_observed': decision = 'review_change'; conclusive++; break;
      }
    }
    return {index: index + 1, decision};
  });
  return {total: cases.length, eligible, conclusive, notRetested, actions};
}

function makeProReview({env = process.env, now = Date.now} = {}) {
  return function proReview(req, res) {
    res.setHeader('Cache-Control', 'private, no-store, max-age=0');
    res.setHeader('CDN-Cache-Control', 'no-store');
    res.setHeader('Vercel-CDN-Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    const fail = (status, error) => res.status(status).json({error});
    if (req.method !== 'POST') {
      res.setHeader('Allow', 'POST');
      return fail(405, 'method_not_allowed');
    }
    if (typeof req.url === 'string' && req.url.includes('?')) return fail(400, 'invalid_request');
    const origin = env.AUTHZ_PRO_ORIGIN ?? 'https://authzledger.com';
    if (!validOrigin(origin) || req.headers.origin !== origin || req.headers.host !== new URL(origin).host) {
      return fail(403, 'access_denied');
    }
    const approvals = approvedKeys(env.AUTHZ_PRO_APPROVALS);
    if (!approvals) return fail(403, 'access_denied');
    try {
      const { kid, issuedAt, cases, signature } = readRequest(req);
      const time = Math.floor(now() / 1000);
      const entry = approvals.get(kid);
      if (!entry || entry.expiresAt <= time || Math.abs(time - issuedAt) > 60) return fail(403, 'access_denied');
      const rows = cases.map(row => [row.scope, row.controls, row.binding, row.retest]);
      const message = JSON.stringify([PROTOCOL, 'POST', ROUTE, origin, kid, issuedAt, rows]);
      const key = createPublicKey({key:entry.jwk, format:'jwk'});
      if (!verify(null, Buffer.from(message, 'utf8'), key, signature)) return fail(403, 'access_denied');
      return res.status(200).json({state:'approved', expiresAt:entry.expiresAt, review:review(cases)});
    } catch (error) {
      if (error instanceof RequestError) return fail(error.status, error.message);
      return fail(403, 'access_denied');
    }
  };
}

module.exports = { makeProReview };
