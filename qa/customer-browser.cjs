// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const { chromium } = require('playwright');
const root = path.resolve(__dirname, '../public');
const origin = 'https://authzledger.com';
const mime = {'.html':'text/html','.css':'text/css','.js':'text/javascript','.png':'image/png'};
const offline = {state:'offline',checkout:{solo:false,team:false},portal:false,publishableKey:null};
const live = {state:'live',checkout:{solo:true,team:true},portal:true,publishableKey:'pk_live_fixture'};
let browser;
before(async()=>{browser=await chromium.launch({executablePath:process.env.CHROMIUM_BIN || undefined});});
after(async()=>{if(browser) await browser.close();});
async function openPage(t, status, width=1100){
  const context=await browser.newContext({viewport:{width,height:900}});
  t.after(()=>context.close());
  const page=await context.newPage();
  const hosts=[], posts=[], errors=[];
  page.on('pageerror',e=>errors.push(String(e)));
  await context.route('**/*',async route=>{
    const request=route.request(), url=new URL(request.url());
    hosts.push(url.host);
    if(request.url()==='https://js.stripe.com/endive/stripe.js'){
      return route.fulfill({contentType:mime['.js'],body:`window.Stripe=()=>({async createEmbeddedCheckoutPage({fetchClientSecret}){const secret=await fetchClientSecret();if(secret!=='mock-secret')throw new Error('test session');return {mount(target){document.querySelector(target).textContent='Stripe fixture mounted';}}}});`});
    }
    if(url.origin!==origin) return route.abort();
    if(url.pathname==='/api/billing-status') return route.fulfill({json:status});
    if(url.pathname==='/api/create-checkout'){posts.push(request.postDataJSON());return route.fulfill({json:{clientSecret:'mock-secret'}});}
    const file=path.resolve(root,'.'+url.pathname+(url.pathname.endsWith('/')?'index.html':''));
    if(!file.startsWith(root+path.sep)) return route.abort();
    try{return await route.fulfill({contentType:mime[path.extname(file)]||'text/plain',body:await fs.readFile(file)});}
    catch{return route.fulfill({status:404,body:'Not found'});}
  });
  return {page,hosts,posts,errors};
}
for(const width of [320,1280]) test('offline customer navigation and responsive layout at '+width+' px',async t=>{
  const {page,hosts,posts,errors}=await openPage(t,offline,width);
  await page.goto(origin+'/abos/');
  await page.getByRole('status').filter({hasText:'persönliche Offerte'}).waitFor();
  await page.getByRole('link',{name:'Solo auswählen'}).click();
  await page.getByRole('status').filter({hasText:'noch nicht freigeschaltet'}).waitFor();
  assert.equal(await page.getByRole('button',{name:'Zahlungsformular öffnen'}).count(),0);
  assert.equal(await page.locator('#price').innerText(),'CHF 1’200 / Jahr');
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  await page.getByRole('link',{name:'Kundenkonto',exact:true}).click();
  await page.getByRole('status').filter({hasText:'noch nicht freigeschaltet'}).waitFor();
  assert.equal(await page.locator('input,form').count(),0);
  assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
  assert.deepEqual(posts,[]);assert.deepEqual([...new Set(hosts)],['authzledger.com']);assert.deepEqual(errors,[]);
});
test('enabled checkout asks for an intentional start, sends one plan, then mounts Stripe',async t=>{
  const {page,hosts,posts,errors}=await openPage(t,live);
  await page.goto(origin+'/kasse/?plan=team&amount=10');
  const start=page.getByRole('button',{name:'Zahlungsformular öffnen'});
  await start.waitFor();assert.deepEqual(posts,[]);assert.equal(hosts.includes('js.stripe.com'),false);
  await start.click();await page.getByText('Stripe fixture mounted').waitFor();
  assert.equal(posts.length,1);assert.equal(posts[0].plan,'team');assert.deepEqual(Object.keys(posts[0]).sort(),['plan','requestId']);
  assert.equal(await start.count(),0);assert.deepEqual(errors,[]);
});
test('portal access requires the verified status and stays behind the server redirect',async t=>{
  const {page,posts,errors}=await openPage(t,live);
  await page.goto(origin+'/konto/');
  const portal=page.getByRole('link',{name:'Zum Kundenportal'});
  await portal.waitFor();assert.equal(await portal.getAttribute('href'),'/api/customer-portal');
  await page.goto(origin+'/konto/?status=unavailable');await page.getByRole('status').filter({hasText:'nicht erreichbar'}).waitFor();
  assert.equal(await portal.count(),0);assert.deepEqual(posts,[]);assert.deepEqual(errors,[]);
});
