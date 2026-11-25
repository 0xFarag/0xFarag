// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {makeDesk, FACTS, UNAVAILABLE} = require('../lib/desk');

function harness(overrides = {}) {
  const requests = [];
  const fetchImpl = async (url, init) => {
    requests.push({url,init});
    return {ok:true, json:async () => ({choices:[{message:{content:'confirmed'}}]})};
  };
  const handler = makeDesk({env:{XAI_API_KEY:'test-only-key'},fetchImpl,...overrides});
  const post = async (body, opts = {}) => {
    const req = {method:'POST',headers:{'content-type':'application/json',origin:'https://authzledger.com',
      host:'authzledger.com',...opts.headers},body};
    if (opts.method) req.method = opts.method;
    const res = {headers:{},setHeader(k,v) {this.headers[k] = v;},status(s){this.code=s;return this;},json(v){this.body=v;}};
    await handler(req,res); return res;
  };
  return {post,requests};
}

test('replacement answer in German with fixed provider contract and no leaked key or transcript', async () => {
  const h = harness();
  const context = Array.from({length:8},(_,n)=>({role:'user',content:'Produktfrage ' + n}));
  const response = await h.post({question:'Ersetzt das Nessus?',context});
  assert.equal(response.code,200);
  assert.equal(response.body.answer,FACTS.limits);
  for (const tool of ['Nessus','Qualys','Burp','Nuclei','ffuf','Hydra','Nmap']) assert.ok(response.body.answer.includes(tool));
  assert.doesNotMatch(JSON.stringify(response.body),/test-only-key|Produktfrage/);
  const {init,url}=h.requests[0];
  assert.equal(url,'https://api.x.ai/v1/chat/completions');
  assert.equal(init.headers.Authorization,'Bearer test-only-key');
  assert.equal(init.redirect,'error');
  const {model,temperature,max_tokens,messages}=JSON.parse(init.body);
  assert.deepEqual([model,temperature,max_tokens],['grok-4.5',0.2,320]);
  assert.equal(messages.length,9); // One system message, eight user-context messages including current input.
  assert.equal(messages[8].content,'Ersetzt das Nessus?');
  assert.ok(init.signal instanceof AbortSignal);
});
test('missing key, unsupported model, provider errors and arbitrary provider prose fail closed', async () => {
  const q = {question:'Ersetzt das Nessus?'};
  const missing = harness({env:{}});
  assert.equal((await missing.post(q)).body.error,UNAVAILABLE);
  assert.equal(missing.requests.length,0);
  for (const fetchImpl of [
    async () => { throw new Error('private test secret'); },
    async () => ({ok:false,status:404}),
    async () => ({ok:true,json:async()=>({choices:[{message:{content:'Trace and secret'}}]})}),
    async () => ({ok:true,json:async()=>({choices:[{message:{content:'toString'}}]})})
  ]) {
    const res = await harness({fetchImpl}).post(q);
    assert.equal(res.code,503); assert.equal(res.body.error,UNAVAILABLE);
    assert.doesNotMatch(JSON.stringify(res.body), /secret|Trace/);
  }
});
test('method, origin, type, bounds and role spoofing rejected before invoking provider', async () => {
  const h = harness(); const q = {question:'Wie geht das?'};
  assert.equal((await h.post(q,{method:'GET'})).code,405);
  assert.equal((await h.post(q,{headers:{origin:'https://elsewhere.test'}})).code,403);
  assert.equal((await h.post(q,{headers:{'content-type':'text/plain'}})).code,415);
  assert.equal((await h.post(q,{headers:{'content-length':'40000'}})).code,413);
  for (const body of [{question:''},{question:'ab'},{question:'x'.repeat(601)},
    {question:'abc',context:[{role:'system',content:'Test'}]},
    {question:'abc',context:Array(9).fill({role:'user',content:'Q?'})}]) {
    assert.equal((await h.post(body)).code,400);
  }
  assert.equal(h.requests.length,0);
});
test('unknown and restricted questions can only receive approved sentences; rate limit is bounded', async () => {
  for (const slug of ['unknown','safety','not_retested','rotation','pricing']) {
    const h = harness({fetchImpl:async()=>({ok:true,json:async()=>({choices:[{message:{content:slug}}]})})});
    assert.equal((await h.post({question:'Produktfrage zum Test'})).body.answer,FACTS[slug]);
  }
  const h = harness(); let r;
  for (let i=0;i<=30;i++) r=await h.post({question:'Was ist ein Finding?'});
  assert.equal(r.code,429);assert.equal(r.headers['Retry-After'],'60'); assert.equal(h.requests.length,30);
});
test('the upstream request is aborted at twenty seconds, with a visible public error', async t => {
  t.mock.timers.enable({apis:['setTimeout']});
  let signal;
  const h=harness({fetchImpl:(_url,init) => new Promise((_resolve,reject)=>{
    signal=init.signal;
    signal.addEventListener('abort',()=>reject(new Error('timeout')),{once:true});
  })});
  const pending=h.post({question:'Was heisst not_retested?'});
  t.mock.timers.tick(19999);
  assert.equal(signal.aborted,false);
  t.mock.timers.tick(1);
  const response=await pending;
  assert.equal(signal.aborted,true);
  assert.equal(response.code,503);
  assert.equal(response.body.error,UNAVAILABLE);
});
