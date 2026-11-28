// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {randomBytes} = require('node:crypto');
const {makeHandler} = require('../lib/passkeys.js');

const origin = 'https://authzledger.example';
const credentialID = Buffer.from('private fixture credential ID').toString('base64url');
const token = () => randomBytes(32).toString('base64url');
const cookiePairs = result => [].concat(result.headers['set-cookie'] || []).map(s=>s.split(';')[0]);
const signed = result => cookiePairs(result).find(s=>s.startsWith('__Host-authz-account='));
const challengeCookie = result => cookiePairs(result).find(s=>s.startsWith('__Host-authz-ceremony='));
function makeFixture() {
  const records = new Map();
  let now = Date.UTC(2026,0,1);
  let revision = 0;
  const write = (p,v) => { records.set(p,{value:structuredClone(v),etag:String(++revision)}); return true; };
  const store = {
    async read(p) {return structuredClone(records.get(p) || null);},
    async create(p,v) {return !records.has(p) && write(p,v);},
    async replace(p,v,tag) {return records.get(p)?.etag === tag && write(p,v);},
    async remove(p,tag) {return records.get(p)?.etag === tag && records.delete(p);}
  };
  const webAuthn = {
    async generateRegistrationOptions(options) {
      assert.equal(options.authenticatorSelection.userVerification,'required');
      assert.equal(options.authenticatorSelection.residentKey,'required');
      return {challenge:token(),user:{id:Buffer.from(options.userID).toString('base64url')}};
    },
    async generateAuthenticationOptions(options) {
      assert.equal(options.rpID,'authzledger.example');
      assert.equal(options.userVerification,'required');
      return {challenge:token()};
    },
    async verifyRegistrationResponse(options) {
      assert.equal(options.expectedRPID,'authzledger.example');
      assert.equal(options.expectedOrigin,origin);
      assert.equal(options.requireUserVerification,true);
      return {verified:options.expectedChallenge === options.response.proof,registrationInfo:{
        credential:{id:options.response.id, publicKey:Buffer.from('fixture-key'), counter:0}
      }};
    },
    async verifyAuthenticationResponse(options) {
      assert.equal(options.expectedRPID,'authzledger.example');
      assert.equal(options.expectedOrigin,origin);
      assert.equal(options.requireUserVerification,true);
      assert.equal(Buffer.from(options.credential.publicKey).toString(),'fixture-key');
      return {verified:options.expectedChallenge === options.response.proof, authenticationInfo:{newCounter:0}};
    }
  };
  const handler = makeHandler({store,secret:randomBytes(32),origin,now:()=>now,webAuthn});
  async function request(body, cookie, headers = {}) {
    const res = {headers:{}, setHeader(k,v) {this.headers[k.toLowerCase()]=v;},
      status(status) {this.code=status;return this;}, json(obj) {this.body=obj;return this;}};
    await handler({method:body ? 'POST' : 'GET',headers:{host:'authzledger.example',origin,'content-type':'application/json',
      cookie:cookie || '',...headers},body},res);
    return res;
  }
  return {request,records,store,advance:ms=>{now+=ms;}};
}
function responseFor(begin,id=credentialID,uid=begin.body.options.user?.id) {
  return {id,rawId:id,type:'public-key',proof:begin.body.options.challenge,
    response:{clientDataJSON:Buffer.from(JSON.stringify({origin,crossOrigin:false})).toString('base64url'),userHandle:uid}};
}
async function register(f) {
  const begin = await f.request({action:'register-options'});
  const body = {action:'register-finish',response:responseFor(begin)};
  const done = await f.request(body,challengeCookie(begin));
  assert.equal(done.code,200);
  return {begin,body,done,uid:done.body.account.id};
}
async function signIn(f,uid) {
  const begin = await f.request({action:'login-options'});
  const body = {action:'login-finish',response:responseFor(begin,credentialID,uid)};
  return {begin,body,done:await f.request(body,challengeCookie(begin))};
}
test('HTTP boundary requires an exact origin; anonymous inspection is private and storage failures disclose no data',async()=>{
  const f=makeFixture();
  const guest = await f.request();
  assert.equal(guest.code,401); assert.deepEqual(guest.body,{authenticated:false});
  assert.match(guest.headers['cache-control'],/no-store/);
  for(const headers of [{origin:''},{origin:'https://different.example'},{host:'different.example'},{'sec-fetch-site':'cross-site'}])
    assert.equal((await f.request({action:'register-options'},null,headers)).code,403);
  assert.equal((await f.request({action:'register-options'},null,{'content-type':'text/plain'})).code,415);
  assert.equal((await f.request({action:'register-options',unexpected:true})).code,400);
  assert.equal((await f.request({action:'register-options'},null,{'content-length':'70000'})).code,413);
  const begin = await f.request({action:'register-options'});
  assert.equal(f.records.size,0);
  f.store.create = async()=>{ throw Error('store private details'); };
  const bad = await f.request({action:'register-finish',response:responseFor(begin)},challengeCookie(begin));
  assert.equal(bad.code,503);assert.deepEqual(bad.body,{error:'unavailable'});assert(!signed(bad));
});
test('one active session: authenticated reload, fresh sign-in invalidates older cookie, logout revokes copied session',async()=>{
  const f=makeFixture(), user=await register(f);
  assert.equal(user.uid.length,43);
  for(const c of user.done.headers['set-cookie'])assert.match(c,/Path=\/; HttpOnly; Secure; SameSite=Strict/);
  assert.deepEqual((await f.request(null,signed(user.done))).body,user.done.body);
  const login=await signIn(f,user.uid);
  assert.equal(login.done.code,200);assert.deepEqual(login.done.body,user.done.body);
  assert.equal((await f.request(null,signed(user.done))).code,401);
  assert.equal((await f.request(null,signed(login.done)+'; '+signed(login.done))).code,401);
  assert.equal((await f.request({action:'logout'},signed(login.done))).code,200);
  assert.equal((await f.request(null,signed(login.done))).code,401);
  assert.equal((await f.request(login.body,challengeCookie(login.begin))).code,409);
});
test('only a verified, correctly bound ceremony makes changes; wrong handles, cross-origin assertions and expired cookies fail',async()=>{
  const f=makeFixture(), begin=await f.request({action:'register-options'}), response=responseFor(begin);
  const wrong={...response,proof:token()};
  assert.equal((await f.request({action:'register-finish',response:wrong},challengeCookie(begin))).code,403);
  const cross={...response,response:{...response.response,clientDataJSON:Buffer.from('{"crossOrigin":true}').toString('base64url')}};
  assert.equal((await f.request({action:'register-finish',response:cross},challengeCookie(begin))).code,403);
  assert.equal(f.records.size,0);
  const expired=challengeCookie(begin);
  f.advance(300_001);
  assert.equal((await f.request({action:'register-finish',response},expired)).code,410);
  const user=await register(f);
  assert.equal((await signIn(f,token())).done.code,403);
  assert.equal((await f.request(null,signed(user.done))).code,200);
  f.advance(8*3600_000);
  assert.equal((await f.request(null,signed(user.done))).code,401);
});
test('concurrent assertion and enrolment replay are single-use; deletion cannot resurrect enrolment',async()=>{
  const f=makeFixture(), begin=await f.request({action:'register-options'});
  const ids=[credentialID,Buffer.from('alternative credential id').toString('base64url')];
  const bodies=ids.map(id=>({action:'register-finish',response:responseFor(begin,id)}));
  const registrations=await Promise.all(bodies.map(body=>f.request(body,challengeCookie(begin))));
  assert.deepEqual(registrations.map(x=>x.code).sort(),[200,409]);
  const win=registrations.findIndex(x=>x.code===200), uid=registrations[win].body.account.id;
  const auth=await f.request({action:'login-options'}), login={action:'login-finish',response:responseFor(auth,ids[win],uid)};
  const logins=await Promise.all([f.request(login,challengeCookie(auth)),f.request(login,challengeCookie(auth))]);
  assert.deepEqual(logins.map(x=>x.code).sort(),[200,409]);
  const cookie=signed(logins.find(x=>x.code===200));
  assert.equal((await f.request({action:'delete-account'},cookie)).code,200);
  assert.equal((await f.request(null,cookie)).code,401);
  assert.equal((await f.request(bodies[win],challengeCookie(begin))).code,409);
  assert.equal([...f.records.keys()].filter(k=>k.startsWith('credentials/')).length,0);
});
test('deletion requires recent user verification; spending limit survives session changes and resets for a new UTC day',async()=>{
  const f=makeFixture(), user=await register(f);
  f.advance(300_001);
  const stale=await f.request({action:'delete-account'},signed(user.done));
  assert.equal(stale.code,401);assert.equal(stale.body.error,'reauthenticate');
  const key=[...f.records.keys()].find(k=>k.startsWith('limits/'));
  const record=f.records.get(key);record.value.spent=Array(256).fill('occupied');
  const begin=await f.request({action:'register-options'});
  const payload={action:'register-finish',response:responseFor(begin,Buffer.from('other').toString('base64url'))};
  assert.equal((await f.request(payload,challengeCookie(begin))).code,429);
  f.advance(86400_000);
  const next=await f.request({action:'register-options'});
  assert.equal((await f.request({action:'register-finish',response:responseFor(next,Buffer.from('other').toString('base64url'))},challengeCookie(next))).code,200);
});
