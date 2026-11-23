// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';

const assert = require('node:assert/strict');
const {test} = require('node:test');
const {makeBilling} = require('../lib/billing');

const ID = 'c6fce282-d613-4080-ae49-61af16cb0012';
const origin = 'https://authzledger.com';
const testOrigin = 'https://authzledger-qa.example';
const offline = {state:'offline',checkout:{solo:false,team:false},portal:false,publishableKey:null};
function fixture({mode='live', env={}, merchant={}, override={}, host, now=()=>0}={}) {
  const test = mode === 'test';
  const config = {
    AUTHZ_BILLING_MODE:mode, AUTHZ_BILLING_TEST_ORIGIN:testOrigin, VERCEL_ENV:test ? 'preview' : 'production',
    STRIPE_SECRET_KEY:'rk_'+mode+'_placeholder', STRIPE_PUBLISHABLE_KEY:'pk_'+mode+'_placeholder',
    STRIPE_MERCHANT_ACCOUNT_ID:'acct_own',STRIPE_PRICE_SOLO:'price_solo',STRIPE_PRICE_TEAM:'price_team',
    STRIPE_PORTAL_CONFIGURATION:'bpc_own', ...env
  };
  host ||= new URL(test ? testOrigin : origin).host;
  const calls = [];
  async function fetcher(url,options) {
    const parsed = new URL(url);
    assert.equal(parsed.origin,'https://api.stripe.com');
    assert.equal(options.headers.Authorization,'Bearer '+config.STRIPE_SECRET_KEY);
    assert.equal(options.headers['Stripe-Version'],'2026-11-18.endive');
    const path = parsed.pathname.replace(/^\/v1\//,'');
    const params = Object.fromEntries(options.body || []);
    calls.push({path,params,method:options.method,idempotency:options.headers['Idempotency-Key']});
    const amount = path.endsWith('team') ? 480000 :120000;
    const sessionAmount = params['line_items[0][price]'] === 'price_team' ? 480000 :120000;
    const sid='cs_'+mode+'_example';
    let response;
    if (path === 'account') response={object:'account', id:'acct_own', country:'CH', charges_enabled:true,payouts_enabled:true,...merchant};
    else if (path.startsWith('prices/')) response={id:path.split('/')[1],object:'price',active:true,product:{object:'product',active:true,livemode:!test},livemode:!test,currency:'chf',type:'recurring',billing_scheme:'per_unit',unit_amount:amount,unit_amount_decimal:String(amount),recurring:{interval:'year',interval_count:1,usage_type:'licensed'}};
    else if (path.startsWith('billing_portal/configurations/')) response={object:'billing_portal.configuration',id:'bpc_own',active:true,livemode:!test,login_page:{enabled:true,url:'https://billing.stripe.com/p/login/'+(test?'test_':'')+'example'}};
    else if (path === 'checkout/sessions') response={object:'checkout.session',id:sid,client_secret:'example-client-only',mode:'subscription',ui_mode:'embedded_page',currency:'chf',amount_subtotal:sessionAmount,livemode:!test,status:'open'};
    else throw Error('Unknown Stripe endpoint');
    const result=override[path]?.(response,params) ?? response;
    if (typeof result === 'number') return {ok:false,status:result};
    return {ok:true,status:200,json:async()=>result};
  }
  const handle = makeBilling({env:config,fetcher,now});
  async function call(operation, params={}) {
    const req={method:operation==='checkout'?'POST':'GET',headers:{host,origin:'https://'+host,'content-type':'application/json',...params.headers},body:{plan:'solo',requestId:ID},...params};
    req.headers={host,origin:'https://'+host,'content-type':'application/json',...params.headers};
    const response = {headers:{},setHeader(k,v){this.headers[k]=v;},status(code){this.code=code;return this;},json(value){this.body=value;return this;},redirect(code,href){this.code=code;this.href=href;return this;}};
    await handle(operation)(req,response);
    assert.match(response.headers['Cache-Control'],/no-store/);
    return response;
  }
  return {calls,call};
}

test('unconfigured route is safe and issues no Stripe requests', async () => {
  const {calls,call}=fixture({env:{STRIPE_SECRET_KEY:''}});
  assert.deepEqual((await call('status')).body,offline);
  assert.equal((await call('checkout')).code,503);
  assert.equal((await call('portal')).code,503);
  assert.equal((await call('portal',{headers:{accept:'text/html'}})).href,'/konto/?status=unavailable');
  assert.deepEqual(calls,[]);
});

test('the status exposes capability flags only, coalesces concurrent safe reads',async()=>{
  const {calls,call}=fixture();
  const [first, second] = await Promise.all([call('status'),call('status')]);
  assert.deepEqual(first.body,{state:'live',checkout:{solo:true,team:true},portal:true,publishableKey:'pk_live_placeholder'});
  assert.deepEqual(first.body,second.body);
  assert.equal(calls.length,4);
  assert(!JSON.stringify(first.body).includes('rk_'));
});

for (const plan of ['solo','team']) test(plan+' purchases are quantity 1 in CHF under the verified account',async()=>{
  const {calls,call}=fixture();
  const args={body:{plan,requestId:ID}};
  const first=await call('checkout',args);
  assert.equal(first.code,200);
  assert.deepEqual(first.body,{clientSecret:'example-client-only'});
  const post=calls.find(x=>x.method==='POST');
  assert.equal(post.params['line_items[0][price]'],'price_'+plan);
  assert.equal(post.params['line_items[0][quantity]'],'1');
  assert.equal(post.params.currency,'chf');
  assert.equal(post.params.ui_mode,'embedded_page');
  assert.equal(post.params['consent_collection[terms_of_service]'],'required');
  assert.equal(post.params.return_url,origin+'/kasse/abschluss/');
  assert(!Object.keys(post.params).some(k=>k.includes('transfer_data') || k.includes('application_fee')));
  await call('checkout',args);
  const posts=calls.filter(c=>c.method==='POST');
  assert.equal(posts[1].idempotency,posts[0].idempotency);
});

for (const [label,options] of Object.entries({
  'foreign merchant':{merchant:{id:'acct_foreign'}},
  'non-Swiss merchant':{merchant:{country:'DE'}},
  'test keys on live':{env:{STRIPE_SECRET_KEY:'sk_test_other'}},
  'test mode in production':{mode:'test',env:{VERCEL_ENV:'production'}},
  'test mode at public origin':{mode:'test',host:'authzledger.com',env:{AUTHZ_BILLING_TEST_ORIGIN:origin}},
  'live mode in preview':{env:{VERCEL_ENV:'preview'}},
  'live keys on unrelated hostname':{host:'other.example'},
  'unavailable Stripe API':{override:{account:()=>503}},
})) test(label+' fails closed',async()=>{
  const {call,calls}=fixture(options);assert.deepEqual((await call('status')).body,offline);
  assert.equal((await call('checkout')).code,503);assert.equal((await call('portal')).code,503);
  assert(!calls.some(item=>item.method==='POST'));
});

for(const field of ['charges_enabled','payouts_enabled'])test(field+' disabled preserves existing account access only',async()=>{
  const {call}=fixture({merchant:{[field]:false}});
  const status=(await call('status')).body;assert.equal(status.portal,true);
  assert.deepEqual(status.checkout,{solo:false,team:false});assert.equal(status.publishableKey,null);
  assert.equal((await call('checkout')).code,503);
  assert.equal((await call('portal')).href,'https://billing.stripe.com/p/login/example');
});

test('test mode is confined to the exact staging origin',async()=>{
  const {call,calls}=fixture({mode:'test',merchant:{payouts_enabled:false}});
  assert.equal((await call('status')).body.state,'test');
  assert.equal((await call('checkout')).code,200);
  assert.equal(calls.find(item=>item.method==='POST').params.return_url,testOrigin+'/kasse/abschluss/');
  assert.match((await call('portal')).href,/\/test_/);
});

for (const [label, change] of Object.entries({
  currency:p=>({...p,currency:'usd'}), precision:p=>({...p,unit_amount_decimal:'120000.5'}),
  amount:p=>({...p,unit_amount:119999}), transformed:p=>({...p,transform_quantity:{divide_by:5}}),
  monthly:p=>({...p,recurring:{...p.recurring,interval:'month'}}), twoYears:p=>({...p,recurring:{...p.recurring,interval_count:2}}),
  metered:p=>({...p,recurring:{...p.recurring,usage_type:'metered'}}),oldProduct:p=>({...p,product:{...p.product,active:false}}),
  inactive:p=>({...p,active:false}),wrongMode:p=>({...p,livemode:false}),wrongPrice:p=>({...p,id:'price_wrong'})
})) test('ineligible price: '+label,async()=>{
  const {call,calls}=fixture({override:{'prices/price_solo':change}});
  assert.deepEqual((await call('status')).body.checkout,{solo:false,team:true});
  assert.equal((await call('checkout')).code,503);
  assert(!calls.some(r=>r.method==='POST'));
});

for(const addr of ['https://billing.stripe.com.evil.example/p/login/fake','https://billing.stripe.com/p/login/test_wrong',
  'https://billing.stripe.com/p/login/abc?redirect=foreign','https://billing.stripe.com@else.example/p/login/x'])test('portal rejects '+addr,async()=>{
    const {call}=fixture({override:{'billing_portal/configurations/bpc_own':p=>({...p,login_page:{enabled:true,url:addr}})}});
    assert.equal((await call('status')).body.portal,false);
    assert.equal((await call('portal')).code,503);
  });

test('stale account readiness is rechecked before any new checkout',async()=>{
  let ready=true;
  const {call,calls}=fixture({override:{account:p=>({...p,payouts_enabled:ready})}});
  assert.equal((await call('status')).body.checkout.solo,true);
  ready=false;assert.equal((await call('checkout')).code,503);
  assert(!calls.some(item=>item.method==='POST'));
});

test('invalid origin, payload, method or purchase amount have no effects',async()=>{
  const {call,calls}=fixture();
  for(const r of [
    {method:'GET'},{headers:{origin:'https://bad.example'}},{headers:{origin:''}}, {headers:{'sec-fetch-site':'cross-site'}},
    {headers:{'content-type':'text/plain'}},{body:{plan:'pilot',requestId:ID}},{body:{plan:'__proto__',requestId:ID}},
    {body:{plan:'solo',requestId:ID,amount:5}},{body:{plan:'solo',requestId:'not-uuid'}},
    {body:'}{'},{body:'X'.repeat(1025)},{headers:{'content-length':'1025'}},
  ]) assert((await call('checkout',r)).code>=400);
  assert.equal(calls.length,0);
});

test('per-instance burst limiter resets after one minute and Stripe errors stay opaque',async()=>{
  let stamp=0;
  const {call,calls}=fixture({now:()=>stamp});
  for(let i=0;i<10;i++) assert.equal((await call('checkout')).code,200);
  assert.equal((await call('checkout')).code,429);assert.equal(calls.length,30);
  stamp=60001;assert.equal((await call('checkout')).code,200);
  const limited=fixture({override:{account:()=>429}});
  const response=await limited.call('checkout');assert.equal(response.code,429);assert.deepEqual(response.body,{error:'rate_limited'});
});
