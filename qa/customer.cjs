// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../public/konto/kundenbereich.js'), 'utf8');
const open = {state:'live',checkout:{solo:true,team:true},portal:true,publishableKey:'pk_live_fixture'};
const testMode = {...open,state:'test',publishableKey:'pk_test_fixture'};
const offline = {state:'offline',checkout:{solo:false,team:false},portal:false,publishableKey:null};

async function visit(page, url, status, options = {}) {
  const ids = ['status','price','plan-title','portal','checkout-start','embedded','enquiry'];
  const elements = Object.fromEntries(ids.map(id => [id,{hidden:true,textContent:'',addEventListener(_,fn) {this.click=fn;}}]));
  const calls = [], scripts = [], mounts = [];
  let key, removed = 0, currentFailures = options.failPosts || 0;
  const context = {
    document: {
      body:{dataset:{page}},
      getElementById:id=>elements[id],
      createElement:()=>({remove(){removed++;}}),
      head:{append(script) {scripts.push(script.src); if(options.failJs) script.onerror(); else script.onload();}}
    },
    location:new URL(url),
    URL, crypto:require('node:crypto').webcrypto, AbortSignal, setTimeout, clearTimeout,
    window:{Stripe(k) {
      key=k;
      return {async createEmbeddedCheckoutPage({fetchClientSecret}) {
        const secret=await fetchClientSecret(); assert.equal(secret,'mock-secret');
        return {mount(el){mounts.push(el);},destroy(){}};
      }};
    }},
    fetch:async(p,init)=>{
      calls.push([p,init]);
      if(p==='/api/billing-status') {
        if(options.networkFail) throw new Error('network');
        return {ok:true,json:async()=>status};
      }
      assert.equal(p,'/api/create-checkout');
      if(currentFailures-->0) return {ok:false,status:429};
      return {ok:true,json:async()=>({clientSecret:'mock-secret'})};
    }
  };
  await vm.runInNewContext(source,context);
  return {elements,calls,scripts,mounts,get key(){return key;},get removed(){return removed;}};
}
test('invalid plan never calls billing or a third party',async()=>{
  const {elements,calls}=await visit('kasse','https://authzledger.com/kasse/?plan=pilot',open);
  assert.match(elements.status.textContent,/Solo oder Team/); assert.equal(calls.length,0);
  assert.equal(elements['checkout-start'].hidden,true);
});
test('offline shows the personal-offer fallback without loading Stripe',async()=>{
  const {elements,calls,scripts}=await visit('kasse','https://authzledger.com/kasse/?plan=solo',offline);
  assert.match(elements.status.textContent,/Offerte/); assert.equal(elements.price.textContent,'CHF 1’200 / Jahr');
  assert.equal(elements['checkout-start'].hidden,true); assert.deepEqual(scripts,[]); assert.equal(calls.length,1);
});
test('a test merchant remains inactive on the public production domain and aliases',async()=>{
  for(const h of ['authzledger.com','www.authzledger.com','authzledger.vercel.app']){
    const result=await visit('kasse','https://'+h+'/kasse/?plan=solo',testMode);
    assert.equal(result.elements['checkout-start'].hidden,true);assert.deepEqual(result.scripts,[]);
  }
});
test('missing tariff, cross-mode key and unrecognized status all fail closed',async()=>{
  for(const status of [{...open,checkout:{solo:true}}, {...open,publishableKey:'pk_test_example'}, {state:'typo'}]) {
    const {elements}=await visit('kasse','https://authzledger.com/kasse/?plan=team',status);
    assert.equal(elements['checkout-start'].hidden,true);
  }
});
test('network error leaves portal unavailable without collecting personal information',async()=>{
  const {elements}=await visit('konto','https://authzledger.com/konto/',null,{networkFail:true});
  assert.equal(elements.portal.hidden,true); assert.match(elements.status.textContent,/erneut/);
});
test('portal navigation always passes the same-origin provider check',async()=>{
  const active=await visit('konto','https://authzledger.com/konto/',open);
  assert.equal(active.elements.portal.href,'/api/customer-portal');
  assert.equal(active.elements.portal.hidden,false);
  const unavailable=await visit('konto','https://authzledger.com/konto/?status=unavailable',open);
  assert.equal(unavailable.elements.portal.hidden,true);
});
test('plan listing distinguishes available plans and unpublished ones',async()=>{
  const {elements}=await visit('abos','https://authzledger.com/abos/',{...open,checkout:{team:true}});
  assert.match(elements.status.textContent,/Team/); assert.doesNotMatch(elements.status.textContent,/Solo/);
});
test('previews expose a labelled test checkout and only load Stripe upon explicit action',async()=>{
  const state=await visit('kasse','https://example.test/kasse/?plan=team',testMode);
  assert.equal(state.elements['checkout-start'].hidden,false);assert.match(state.elements.status.textContent,/Testumgebung/);
  assert.equal(state.calls.length,1); assert.deepEqual(state.scripts,[]);
  await state.elements['checkout-start'].click();
  assert.deepEqual(state.scripts,['https://js.stripe.com/endive/stripe.js']);assert.equal(state.key,'pk_test_fixture');
  assert.deepEqual(state.mounts,['#embedded']);assert.match(state.elements.status.textContent,/Testumgebung/);
});
test('a recoverable checkout error reuses the attempt UUID and never forwards client price or customer email',async()=>{
  const state=await visit('kasse','https://authzledger.com/kasse/?plan=solo&price=1&email=foreign',open,{failPosts:1});
  const button=state.elements['checkout-start'];
  await button.click(); assert.equal(button.disabled,false); assert.match(state.elements.status.textContent,/Zu viele/);
  await button.click(); await button.click();
  const posts=state.calls.filter(([p])=>p==='/api/create-checkout');
  assert.equal(posts.length,2);
  const fields=JSON.parse(posts[0][1].body);
  assert.deepEqual(Object.keys(fields).sort(),['plan','requestId']);assert.equal(fields.plan,'solo');
  assert.match(fields.requestId,/^[0-9a-f-]{36}$/); assert.equal(posts[0][1].body,posts[1][1].body);
  assert.equal(button.hidden,true);assert.equal(state.mounts.length,1);
});
test('blocked third-party JavaScript never causes a checkout POST',async()=>{
  const state=await visit('kasse','https://authzledger.com/kasse/?plan=solo',open,{failJs:true});
  await state.elements['checkout-start'].click(); assert.deepEqual(state.mounts,[]);assert.equal(state.calls.length,1);
  assert.equal(state.removed,1); assert.equal(state.elements['checkout-start'].disabled,false);
});
test('return page does not declare payment, charge or access successful from a URL',()=>{
  const html=fs.readFileSync(path.join(__dirname,'../public/kasse/abschluss/index.html'),'utf8');
  assert.doesNotMatch(html,/bezahlt|erfolgreich|freigeschaltet|<script|session_id/i);
  assert.match(html,/href="\/konto\/"/);
});
