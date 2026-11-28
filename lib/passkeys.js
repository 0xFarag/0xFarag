// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const {createHash, createHmac, randomBytes, timingSafeEqual} = require('node:crypto');

const SESSION = '__Host-authz-account';
const CEREMONY = '__Host-authz-ceremony';
const MINUTE = 60_000;
const CEREMONY_LIFE = 5 * MINUTE;
const SESSION_LIFE = 8 * 60 * MINUTE;
const DAY = 24 * 60 * MINUTE;
const MAX_BODY = 65_536;
const DAILY_ENROLMENTS = 256;

class AccountError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
function reject(status, message) { throw new AccountError(status, message); }
const digest = value => createHash('sha256').update(value).digest('base64url');
const random = () => randomBytes(32).toString('base64url');
const token32 = value => typeof value === 'string' && /^[\w-]{43}$/.test(value);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
function equal(a,b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x,y);
}
function cookie(name, value, seconds) {
  return name + '=' + value + '; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=' + seconds;
}
function readBody(req) {
  if (!/^application\/json(?:\s*;\s*charset\s*=\s*utf-8)?$/i.test(req.headers['content-type'] || '') ||
      (req.headers['content-encoding'] && req.headers['content-encoding'] !== 'identity')) reject(415,'invalid_request');
  const length = req.headers['content-length'];
  if (length !== undefined && (!/^\d+$/.test(String(length)) || Number(length) > MAX_BODY)) reject(413,'invalid_request');
  let body = req.body;
  if (object(body) && !Buffer.isBuffer(body)) {
    if (Buffer.byteLength(JSON.stringify(body)) > MAX_BODY) reject(413,'invalid_request');
  } else {
    if (typeof body !== 'string' && !Buffer.isBuffer(body)) reject(400,'invalid_request');
    if (Buffer.byteLength(body) > MAX_BODY) reject(413,'invalid_request');
    try { body = JSON.parse(body.toString('utf8')); } catch { reject(400,'invalid_request'); }
  }
  if (!object(body) || typeof body.action !== 'string') reject(400,'invalid_request');
  const finish = body.action === 'register-finish' || body.action === 'login-finish';
  if (Object.keys(body).length !== (finish ? 2 : 1) || (finish && !object(body.response))) reject(400,'invalid_request');
  return body;
}

// The enrolment ticket, account and session live in separate namespaces. Registration never assigns Team privileges.
function makeHandler({store, secret, origin, now = Date.now, webAuthn}) {
  const site = new URL(origin);
  if (site.origin !== origin || (site.protocol !== 'https:' && !(site.protocol === 'http:' && site.hostname === 'localhost')))
    throw new Error('Invalid account origin');
  if (!(typeof secret === 'string' || Buffer.isBuffer(secret)) || Buffer.byteLength(secret) < 32)
    throw new Error('An account signing secret is required');
  const auth = webAuthn || require('@simplewebauthn/server');

  function mac(name, data) {
    return createHmac('sha256',secret).update(['authz-account-v1',origin,name,data].join('\n')).digest('base64url');
  }
  function signedCookie(name, record, ms) {
    const data = Buffer.from(JSON.stringify(record)).toString('base64url');
    return cookie(name, data + '.' + mac(name,data), ms / 1000);
  }
  function ticket(req, name, time) {
    const matches = (req.headers.cookie || '').split(';').map(p=>p.trim()).filter(p=>p.startsWith(name+'='));
    if (matches.length !== 1) return null;
    const value = matches[0].slice(name.length+1);
    if (value.length > 2048 || !/^[\w-]+\.[\w-]{43}$/.test(value)) return null;
    const [data, signature] = value.split('.');
    if (!equal(mac(name,data),signature)) return null;
    try {
      const result = JSON.parse(Buffer.from(data,'base64url').toString('utf8'));
      return object(result) && Number.isSafeInteger(result.exp) && result.exp > time ? result : null;
    } catch { return null; }
  }
  function keyFor(id) { return 'credentials/' + digest(id); }
  function session(key, time) {
    const token = random();
    return {hash:digest(token), cookie:signedCookie(SESSION,{key,token,exp:time+SESSION_LIFE},SESSION_LIFE)};
  }
  function profile(row) {
    return {authenticated:true, account:{id:row.id, createdAt:row.createdAt}};
  }
  async function getSession(req,time) {
    const state = ticket(req,SESSION,time);
    if (!state || !token32(state.token) || !token32(state.key)) return null;
    const path = 'credentials/' + state.key;
    const entry = await store.read(path);
    if (!entry || !equal(entry.value.sessionHash,digest(state.token))) return null;
    return {path,entry,state};
  }

  // Two alternating UTC-day buckets keep spend and the number of objects bounded. Consume before
  // creating the account so a captured registration response cannot recreate a deleted account.
  async function consumeRegistration(ceremony) {
    const day = Math.floor((ceremony.exp - CEREMONY_LIFE)/DAY);
    const path = 'limits/registration-' + (day%2);
    const claim = digest(ceremony.challenge);
    for (let attempt=0; attempt<4; attempt++) {
      const record = await store.read(path);
      if (record && record.value.day > day) reject(410,'challenge_expired');
      const spent = record?.value.day === day ? record.value.spent : [];
      if (spent.includes(claim)) reject(409,'conflict');
      if (spent.length >= DAILY_ENROLMENTS) reject(429,'rate_limited');
      const value = {day, spent:[...spent, claim]};
      const saved = record ? await store.replace(path,value,record.etag) : await store.create(path,value);
      if (saved) return;
    }
    reject(409,'conflict');
  }
  async function begin(action, res, time) {
    const register = action === 'register-options';
    const uid = register ? random() : undefined;
    const rpID = site.hostname;
    const options = register ? await auth.generateRegistrationOptions({
      rpName:'AuthzLedger', rpID, userID:Buffer.from(uid,'base64url'), userName:'AuthzLedger ' + uid.slice(0,8),
      timeout:CEREMONY_LIFE, attestationType:'none', supportedAlgorithmIDs:[-7,-257],
      authenticatorSelection:{residentKey:'required',requireResidentKey:true,userVerification:'required'}
    }) : await auth.generateAuthenticationOptions({rpID, userVerification:'required', timeout:CEREMONY_LIFE});
    const record = {action:register ? 'register-finish' : 'login-finish', challenge:options.challenge, uid, exp:time+CEREMONY_LIFE};
    res.setHeader('Set-Cookie',signedCookie(CEREMONY,record,CEREMONY_LIFE));
    return {options};
  }
  async function finish(req, body, res, time) {
    const ceremony = ticket(req,CEREMONY,time);
    if (!ceremony || ceremony.action !== body.action) reject(410,'challenge_expired');
    const response = body.response;
    if (response.type !== 'public-key' || typeof response.id !== 'string' || response.id.length > 1366 ||
        !/^[\w-]+$/.test(response.id) || response.rawId !== response.id || !object(response.response))
      reject(400,'invalid_request');
    // The rawId must have a single canonical spelling: its digest is the account's lookup key.
    if (Buffer.from(response.id,'base64url').toString('base64url') !== response.id) reject(400,'invalid_request');
    let clientData;
    try { clientData = JSON.parse(Buffer.from(response.response.clientDataJSON,'base64url').toString('utf8')); }
    catch { reject(403,'verification_failed'); }
    if (!object(clientData) || (clientData.crossOrigin !== undefined && clientData.crossOrigin !== false) ||
        (clientData.topOrigin !== undefined && clientData.topOrigin !== origin)) reject(403,'verification_failed');
    const path = keyFor(response.id);
    const entry = await store.read(path);
    const check = {response, expectedChallenge:ceremony.challenge, expectedOrigin:origin,
      expectedRPID:site.hostname, requireUserVerification:true};
    const next = session(digest(response.id),time);
    let row;
    if (body.action === 'register-finish') {
      if (entry) reject(409,'conflict');
      let registration;
      try { registration = await auth.verifyRegistrationResponse({...check,supportedAlgorithmIDs:[-7,-257]}); }
      catch { reject(403,'verification_failed'); }
      const credential = registration.registrationInfo?.credential;
      if (!registration.verified || !credential || credential.id !== response.id) reject(403,'verification_failed');
      await consumeRegistration(ceremony);
      row = {id:ceremony.uid, createdAt:new Date(time).toISOString(), credentialID:credential.id,
        publicKey:Buffer.from(credential.publicKey).toString('base64url'), counter:credential.counter,
        recent:[], sessionHash:next.hash};
      if (!await store.create(path,row)) reject(409,'conflict');
    } else {
      if (!entry || !equal(response.response.userHandle,entry.value.id)) reject(403,'verification_failed');
      const prior = entry.value;
      const recent = prior.recent.filter(r=>r.exp>time);
      const hash = digest(ceremony.challenge);
      if (recent.some(r=>r.hash===hash)) reject(409,'conflict');
      // Do not evict a live challenge to make room, even on zero-counter synced passkeys.
      if (recent.length >= 32) reject(429,'rate_limited');
      let authentication;
      try {
        authentication = await auth.verifyAuthenticationResponse({...check, credential:{
          id:prior.credentialID, publicKey:new Uint8Array(Buffer.from(prior.publicKey,'base64url')), counter:prior.counter
        }});
      } catch { reject(403,'verification_failed'); }
      if (!authentication.verified) reject(403,'verification_failed');
      row = {...prior, counter:authentication.authenticationInfo.newCounter,
        recent:[...recent,{hash,exp:ceremony.exp}], sessionHash:next.hash};
      if (!await store.replace(path,row,entry.etag)) reject(409,'conflict');
    }
    res.setHeader('Set-Cookie',[next.cookie,cookie(CEREMONY,'',0)]);
    return profile(row);
  }
  return async function account(req,res) {
    res.setHeader('Cache-Control','private, no-store, max-age=0');
    res.setHeader('Vary','Cookie');
    res.setHeader('CDN-Cache-Control','no-store');
    res.setHeader('Vercel-CDN-Cache-Control','no-store');
    res.setHeader('X-Content-Type-Options','nosniff');
    res.setHeader('Referrer-Policy','no-referrer');
    try {
      if (req.headers.host !== site.host || (req.headers.origin && req.headers.origin !== origin)) reject(403,'invalid_origin');
      if (req.method !== 'GET' && req.method !== 'POST') {
        res.setHeader('Allow','GET, POST');
        reject(405,'invalid_request');
      }
      const time = now();
      if (req.method === 'GET') {
        const current = await getSession(req,time);
        return current ? res.status(200).json(profile(current.entry.value)) : res.status(401).json({authenticated:false});
      }
      if (req.headers.origin !== origin || req.headers['sec-fetch-site'] === 'cross-site') reject(403,'invalid_origin');
      const body = readBody(req);
      if (body.action === 'register-options' || body.action === 'login-options')
        return res.status(200).json(await begin(body.action,res,time));
      if (body.action === 'register-finish' || body.action === 'login-finish')
        return res.status(200).json(await finish(req,body,res,time));
      if (body.action !== 'logout' && body.action !== 'delete-account') reject(400,'invalid_request');
      const current = await getSession(req,time);
      if (!current && body.action === 'delete-account') reject(401,'unauthenticated');
      if (current) {
        const {entry, path, state} = current;
        if (body.action === 'delete-account' && time >= state.exp-SESSION_LIFE+CEREMONY_LIFE) reject(401,'reauthenticate');
        const saved = body.action === 'logout' ? await store.replace(path,{...entry.value,sessionHash:null},entry.etag)
          : await store.remove(path,entry.etag);
        if (!saved) reject(409,'conflict');
      }
      res.setHeader('Set-Cookie',[cookie(SESSION,'',0),cookie(CEREMONY,'',0)]);
      return res.status(200).json({authenticated:false});
    } catch (error) {
      if (error instanceof AccountError) return res.status(error.status).json({error:error.message});
      return res.status(503).json({error:'unavailable'});
    }
  };
}
module.exports = {makeHandler};
