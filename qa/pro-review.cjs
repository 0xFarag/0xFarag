// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync, createHash, sign, webcrypto } = require('node:crypto');
const { makeProReview } = require('../lib/pro-review');

const origin = 'https://authzledger.com';
const now = 1824000000;
const expiresAt = now + 300;
const row = Object.freeze({scope:'in_scope', controls:'passed', binding:'matched', retest:'not_retested'});

function applicant() {
  const {publicKey, privateKey} = generateKeyPairSync('ed25519');
  const jwk = publicKey.export({format:'jwk'});
  const kid = createHash('sha256').update(Buffer.from(jwk.x, 'base64url')).digest('base64url');
  return {jwk, kid, privateKey};
}
const alice = applicant(), bob = applicant();
const approved = (key, end = expiresAt) => JSON.stringify([{jwk:key.jwk, expiresAt:end}]);

function transcript(kid, cases, issuedAt = now, audience = origin) {
  const rows = cases.map(({scope, controls, binding, retest}) => [scope, controls, binding, retest]);
  return Buffer.from(JSON.stringify(['authzledger.pro-review.v1', 'POST', '/api/pro-review', audience, kid, issuedAt, rows]));
}

function request(key = alice, cases = [], time = now, audience = origin) {
  const signature = sign(null, transcript(key.kid, cases, time, audience), key.privateKey).toString('base64url');
  return {kid:key.kid, issuedAt:time, cases, signature};
}

function call(body, options = {}) {
  const handler = makeProReview({env:options.env || {AUTHZ_PRO_APPROVALS:approved(alice)}, now:()=>now*1000});
  const req = {url:'/api/pro-review', method:'POST', ...options.req,
    headers:{host:new URL(origin).host, origin, 'content-type':'application/json', ...options.req?.headers}, body};
  const headers = {};
  return handler(req, {
    setHeader(key, value) {headers[key] = value;},
    status(code) {return {json: value => ({code, headers, value})};}
  });
}

test('approval requires an explicitly configured key, correct signature and an active time window', () => {
  for (const config of ['', '[]', undefined, 'null', '{}', '{', approved(bob), approved(alice, now), approved(alice,now-1)]) {
    const result = call(request(), {env:{AUTHZ_PRO_APPROVALS:config}});
    assert.equal(result.code, 403);
    assert.deepEqual(result.value, {error:'access_denied'});
  }
  for (const offset of [-61,61]) assert.equal(call(request(alice, [], now+offset)).code, 403);
  for (const offset of [-60,0,60]) {
    const reply = call(request(alice, [], now+offset));
    assert.equal(reply.code, 200);
    assert.equal(reply.value.state, 'approved');
    assert.equal(reply.value.expiresAt, expiresAt);
    assert.deepEqual(reply.value.review.actions, []);
  }
});

test('invalid entries or duplicate public keys close the allowlist including other valid entries', () => {
  const entry = {jwk:alice.jwk,expiresAt};
  for (const invalid of [entry, {...entry,expiresAt:0.1}, {...entry,jwk:{...alice.jwk, d:'private'}},
    {...entry,jwk:{...alice.jwk, crv:'X25519'}}, {...entry,jwk:{...alice.jwk, x:'bad'}},
    {...entry,jwk:{...alice.jwk, x:Buffer.alloc(32).toString('base64url')}}, {jwk:alice.jwk}]) {
    assert.equal(call(request(),{env:{AUTHZ_PRO_APPROVALS:JSON.stringify([entry,invalid])}}).code, 403);
  }
});

test('a key signs only its own device ID, origin, timestamp, cases, field values and case order', () => {
  const body = request(alice, [row,{...row,retest:'inconclusive'}]);
  for (const tamper of [{kid:bob.kid}, {issuedAt:now+1}, {cases:[]}, {cases:[...body.cases].reverse()},
    {cases:[{...row,controls:'failed'},body.cases[1]]}, {signature:request(bob,body.cases).signature}]) {
    assert.equal(call({...body,...tamper}).code, 403);
  }
  assert.equal(call(request(alice, [], now, 'https://not-the-service.example')).code, 403);
  assert.equal(call({...body, cases: body.cases.map(c=>({retest:c.retest, scope:c.scope, controls:c.controls, binding:c.binding}))}).code, 200);
});

test('canonical origin is independent of forwarding headers and must be an exact HTTPS origin', () => {
  const body = request();
  for (const headers of [{origin:'https://www.authzledger.com'}, {host:'preview.example','x-forwarded-host':'authzledger.com'},
    {origin:undefined}, {origin:'null'}]) assert.equal(call(body,{req:{headers}}).code, 403);
  for (const value of ['http://authzledger.com','https://authzledger.com/x','https://user@authzledger.com','']) {
    assert.equal(call(body,{env:{AUTHZ_PRO_ORIGIN:value, AUTHZ_PRO_APPROVALS:approved(alice)}}).code,403);
  }
  const alt = 'https://review.example';
  assert.equal(call(request(alice,[],now,alt),{req:{headers:{host:'review.example',origin:alt}},
    env:{AUTHZ_PRO_APPROVALS:approved(alice), AUTHZ_PRO_ORIGIN:alt}}).code,200);
});

test('categorical portfolio review includes open work and protects inconclusive or unbound outcomes', () => {
  const cases = [row,{...row,scope:'out_of_scope',retest:'change_observed'},{...row,scope:'unknown'},
    {...row,controls:'missing',retest:'still_present'},{...row,binding:'ambiguous',retest:'change_observed'},
    {...row,retest:'change_observed'},{...row,retest:'inconclusive'},{...row,retest:'still_present'}];
  const {code,value} = call(request(alice,cases));
  assert.equal(code,200);
  const expected = ['schedule_retest','excluded','clarify_scope','check_controls','bind_source','review_change','review_inconclusive','review_open'];
  assert.deepEqual(value.review,{total:8, eligible:4, conclusive:2, notRetested:2,
    actions:expected.map((decision,i)=>({index:i+1,decision}))});
});

test('reject PII, raw evidence, unknown fields, malformed encodings and oversized payloads', () => {
  const good = request(alice,[row]);
  for (const invalid of [{...good,email:'someone@example.invalid'}, {...good,cases:[{...row,path:'/raw'}]},
    {...good,cases:[{...row,controls:'confirmed'}]}, {...good,signature:good.signature+'='}, {...good,kid:'!'},
    {...good,cases:[null]}, Buffer.from([255]), '{broken']) assert.equal(call(invalid).code, 400);
  for (const raw of [JSON.stringify(good), Buffer.from(JSON.stringify(good))]) assert.equal(call(raw).code, 200);
  assert.equal(call({...good,cases:Array(33).fill(row)}).code, 413);
  assert.equal(call(request(alice,Array(32).fill(row))).code,200);
  assert.equal(call(' '.repeat(8193)).code,413);
  assert.equal(call(good,{req:{headers:{'content-length':'65536'}}}).code,413);
  assert.equal(call(good,{req:{headers:{'content-type':'text/plain'}}}).code,415);
  assert.equal(call(good,{req:{headers:{'content-encoding':'gzip'}}}).code,415);
});

test('no response is cached, protected result is read-only and revocation applies to retry', () => {
  const env = {AUTHZ_PRO_APPROVALS:approved(alice)};
  const body = request(alice,[row]);
  const ok = call(body,{env});
  assert.deepEqual(call(body,{env}).value,ok.value);
  env.AUTHZ_PRO_APPROVALS = '[]';
  const denied = call(body,{env});
  const method = call(body,{req:{method:'GET'}});
  assert.equal(denied.code,403);
  assert.equal(method.code,405);
  for (const reply of [ok,denied,method]) {
    assert.match(reply.headers['Cache-Control'], /no-store/);
    assert.equal(reply.headers['Vercel-CDN-Cache-Control'],'no-store');
  }
});

test('non-exportable browser WebCrypto signing keys interoperate with the Node verifier', async () => {
  const device = await webcrypto.subtle.generateKey('Ed25519', false, ['sign','verify']);
  const exported = await webcrypto.subtle.exportKey('jwk', device.publicKey);
  const jwk = {kty:exported.kty, crv:exported.crv, x:exported.x};
  const raw = await webcrypto.subtle.exportKey('raw', device.publicKey);
  const kid = Buffer.from(await webcrypto.subtle.digest('SHA-256', raw)).toString('base64url');
  const signature = Buffer.from(await webcrypto.subtle.sign('Ed25519', device.privateKey,transcript(kid,[row]))).toString('base64url');
  const body = {kid,issuedAt:now,cases:[row],signature};
  const result = call(body,{env:{AUTHZ_PRO_APPROVALS:JSON.stringify([{jwk,expiresAt}])}});
  assert.equal(result.code,200);
  await assert.rejects(webcrypto.subtle.exportKey('jwk',device.privateKey));
});
