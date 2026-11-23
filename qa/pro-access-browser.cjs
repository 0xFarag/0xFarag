// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs/promises');
const path = require('node:path');
const {createHash, webcrypto} = require('node:crypto');
const {chromium} = require('playwright');
const {makeProReview} = require('../lib/pro-review.js');
const origin = 'https://professional.example';
const endpoint = '/api/pro-review';
const root = path.join(__dirname, '../public');
const httpHeaders = {host:'professional.example',origin,'content-type':'application/json'};
const sample = {scope:'in_scope',controls:'passed',binding:'matched',retest:'not_retested'};

function runApi(env, payload, headers = httpHeaders) {
  const res = {code:200, setHeader() {}, status(code) { this.code = code; return this; }, json(body) { this.body = body; }};
  makeProReview({env})({url:endpoint, method:'POST', headers, body:payload}, res);
  return res;
}

test('Browser key format and signed payload interoperate with the production verifier', async () => {
  const {publicApplication,signedRequest} = await import('../public/fachzugang/device.mjs');
  const pair = await webcrypto.subtle.generateKey('Ed25519', false, ['sign','verify']);
  const {kid,jwk} = await publicApplication(pair);
  assert.equal(kid, createHash('sha256').update(Buffer.from(jwk.x,'base64url')).digest('base64url'));
  assert.deepEqual(Object.keys(jwk).sort(), ['crv','kty','x']);
  await assert.rejects(webcrypto.subtle.exportKey('jwk',pair.privateKey));
  const expiresAt = Math.floor(Date.now()/1000) + 300;
  const env = {AUTHZ_PRO_ORIGIN:origin, AUTHZ_PRO_APPROVALS:JSON.stringify([{jwk,expiresAt}])};
  const payload = await signedRequest(pair,kid,[sample],origin);
  const allowed = runApi(env,payload);
  assert.equal(allowed.code,200);
  assert.deepEqual(allowed.body.review.actions,[{index:1,decision:'schedule_retest'}]);
  assert.equal(runApi(env,{...payload,cases:[{...sample,controls:'missing'}]}).code,403);
  assert.equal(runApi({AUTHZ_PRO_ORIGIN:origin},payload).code,403);
});

test('Browser retains its nonexportable key across reloads and opens protected review only for a manually approved public key', async () => {
  const browser = await chromium.launch({executablePath:process.env.CHROMIUM_BIN || undefined});
  try {
    const page = await browser.newPage();
    const env = {AUTHZ_PRO_ORIGIN:origin};
    const sent = [];
    const resources = {
      '/fachzugang/':['fachzugang/index.html','text/html'],
      '/fachzugang/app.mjs':['fachzugang/app.mjs','text/javascript'],
      '/fachzugang/device.mjs':['fachzugang/device.mjs','text/javascript'],
      '/fachzugang/access.css':['fachzugang/access.css','text/css'],
      '/konto/kundenbereich.css':['konto/kundenbereich.css','text/css'],
      '/assets/authzledger-logo.png':['assets/authzledger-logo.png','image/png'],
      '/assets/authzledger-icon.png':['assets/authzledger-icon.png','image/png']
    };
    await page.route('**/*',async route => {
      const request = route.request();
      const url = new URL(request.url());
      if (url.origin !== origin) return route.abort();
      if (url.pathname === endpoint && request.method() === 'POST') {
        const payload = request.postDataJSON();
        sent.push(payload);
        const headers = await request.allHeaders();
        const result = runApi(env,payload,{...headers,host:url.host});
        return route.fulfill({status:result.code,contentType:'application/json',body:JSON.stringify(result.body)});
      }
      const resource = resources[url.pathname];
      if (!resource) return route.fulfill({status:404,body:''});
      return route.fulfill({status:200,contentType:resource[1],body:await fs.readFile(path.join(root,resource[0]))});
    });
    await page.goto(origin + '/fachzugang/');
    await page.getByRole('button',{name:'Prüfschlüssel erstellen'}).click();
    await page.locator('#authenticate').waitFor({state:'visible'});
    const registered = JSON.parse(await page.locator('#application').inputValue());
    assert.equal(sent.length,0);
    assert.deepEqual(Object.keys(registered).sort(),['jwk','kid']);
    assert.deepEqual(Object.keys(registered.jwk).sort(),['crv','kty','x']);
    assert.equal(await page.locator('#fingerprint').innerText(),registered.kid);
    assert.equal(await page.evaluate(async () => {
      const {deviceKey} = await import('./device.mjs');
      const {privateKey} = await deviceKey();
      if (privateKey.extractable || privateKey.type !== 'private') return false;
      try { await crypto.subtle.exportKey('pkcs8',privateKey); return false; } catch { return true; }
    }),true);
    const exported = page.waitForEvent('download');
    await page.locator('#download').click();
    assert.deepEqual(JSON.parse(await fs.readFile(await (await exported).path(),'utf8')),registered);
    await page.reload();
    await page.locator('#authenticate').waitFor({state:'visible'});
    assert.equal(await page.locator('#fingerprint').innerText(), registered.kid);
    assert.equal(await page.locator('#review-panel').isVisible(),false);
    await page.locator('#authenticate').click();
    await page.getByRole('status').filter({hasText:'keine Freigabe bestätigt'}).waitFor();
    assert.equal(await page.locator('#review-panel').isVisible(),false);
    env.AUTHZ_PRO_APPROVALS = JSON.stringify([{jwk:registered.jwk,expiresAt:Math.floor(Date.now()/1000)+300}]);
    await page.locator('#authenticate').click();
    await page.locator('#review-panel').waitFor({state:'visible'});
    await page.locator('#add-case').click();
    const second = page.locator('.case-row').nth(1);
    for (const [field,value] of Object.entries(sample)) {
      await second.locator('select[name="' + field + '"]').selectOption(value);
    }
    await page.locator('#evaluate').click();
    await page.getByText('Retest einplanen',{exact:true}).waitFor();
    assert.match(await page.locator('#result').innerText(),/Mandatsumfang klären/);
    assert.deepEqual(sent.at(-1).cases[1],sample);
    assert.deepEqual(Object.keys(sent.at(-1)).sort(),['cases','issuedAt','kid','signature']);
    delete env.AUTHZ_PRO_APPROVALS;
    await page.locator('#evaluate').click();
    await page.locator('#review-panel').waitFor({state:'hidden'});
    assert.equal(await page.locator('#result').innerText(),'');
  } finally {
    await browser.close();
  }
});
