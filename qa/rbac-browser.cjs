// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {createHash} = require('node:crypto');
const {chromium} = require('playwright');
const root = path.join(__dirname, '../public');
const origin = 'https://rbac.example';
const hash = value => createHash('sha256').update(value).digest('hex');
const upload = (data,name='snapshot.json') => ({name,mimeType:'application/json',buffer:Buffer.from(data)});

test('Native RBAC browser flow preserves original bytes, role/binding/rule provenance and selective coverage', async () => {
  const browser = await chromium.launch({executablePath:process.env.CHROMIUM_BIN || undefined});
  try {
    const page = await browser.newPage({viewport:{width:390,height:840}});
    const assets = {
      '/rbac/':['rbac/index.html','text/html'], '/rbac/ui.mjs':['rbac/ui.mjs','text/javascript'],
      '/rbac/model.mjs':['rbac/model.mjs','text/javascript'], '/rbac/retest.mjs':['rbac/retest.mjs','text/javascript'],
      '/rbac/style.css':['rbac/style.css','text/css'], '/konto/kundenbereich.css':['konto/kundenbereich.css','text/css'],
      '/assets/authzledger-logo.png':['assets/authzledger-logo.png','image/png'], '/assets/authzledger-icon.png':['assets/authzledger-icon.png','image/png']
    };
    await page.route('**/*',async route => {
      const url = new URL(route.request().url());
      const entry = assets[url.pathname];
      if (url.origin !== origin || route.request().method() !== 'GET' || !entry) return route.abort();
      return route.fulfill({contentType:entry[1],body:await fs.readFile(path.join(root,entry[0]))});
    });
    await page.goto(origin + '/rbac/', {waitUntil:'load'});
    const requests = [];
    page.on('request',req => { if (/^https?:/.test(req.url())) requests.push(req.url()); });
    await page.locator('#example').click();
    await page.locator('#run').click();
    await page.locator('#proofs li').first().waitFor();
    assert.match(await page.locator('#proofs').innerText(),/RoleBinding team-lesezugriff.*Role leserolle.*Regel 1/s);
    await page.locator('#keep').click();
    await page.getByLabel('Verb',{exact:true}).fill('list');
    await page.locator('#run').click();
    await page.locator('#keep').click();
    await page.locator('#make').click();
    await page.locator('#demo-current').click();
    const cases = page.locator('#selection input');
    assert.equal(await cases.count(),2);
    assert.equal(await cases.first().isChecked(),false);
    await cases.first().check();
    await page.locator('#compare').click();
    await page.locator('#results li').first().waitFor();
    assert.match(await page.locator('#results li').first().innerText(),/Entscheidung im Snapshot geändert/);
    assert.match(await page.locator('#results li').nth(1).innerText(),/not_retested/);
    async function exported(id) {
      const download = page.waitForEvent('download');
      await page.locator('#'+id).click();
      return JSON.parse(await fs.readFile(await (await download).path(),'utf8'));
    }
    const report = await exported('save-result');
    assert.deepEqual(report.coverage,{total:2,retested:1,not_retested:1});
    assert.equal(report.signature,'unsigned');
    assert.equal(report.cases[1].after,null);

    // Real JSON bytes, persisted basis, source mismatch, identical-snapshot retest.
    const source = JSON.stringify({apiVersion:'v1',kind:'List',items:[]},null,2)+'\n';
    await page.locator('#original').setInputFiles(upload(source));
    await page.locator('#source-info').filter({hasText:hash(source)}).waitFor();
    assert.equal(await page.locator('#retest').isVisible(),false);
    await page.getByLabel('Subjekttyp').selectOption('ServiceAccount');
    await page.getByLabel('Subjektname',{exact:true}).fill('auditor');
    await page.getByLabel('Namespace des ServiceAccounts').fill('ops');
    await page.getByLabel('Anfrage-Namespace').fill('ops');
    await page.getByLabel('Ressource (Plural)').fill('pods');
    await page.locator('#run').click();
    await page.locator('#keep').click();
    await page.locator('#make').click();
    const baseline = await exported('save-basis');
    assert.equal(baseline.policy_sha256,hash(source));
    assert.equal(baseline.cases[0].query.kind,'ServiceAccount');
    await page.locator('#clear').click();
    await page.locator('#original').setInputFiles(upload(source + ' '));
    await page.locator('#source-info').filter({hasText:hash(source + ' ')}).waitFor();
    await page.locator('#basis-file').setInputFiles(upload(JSON.stringify(baseline)));
    await page.locator('#basis-status').filter({hasText:'passt nicht'}).waitFor();
    assert.equal(await page.locator('#save-basis').isVisible(),false);
    await page.locator('#original').setInputFiles(upload(source));
    await page.locator('#source-info').filter({hasText:hash(source)}).waitFor();
    await page.locator('#basis-file').setInputFiles(upload(JSON.stringify(baseline)));
    await page.locator('#retest').waitFor({state:'visible'});
    assert.equal(await page.locator('#demo-current').isVisible(),false);
    await page.locator('#current').setInputFiles(upload(source));
    await page.locator('#current-info').filter({hasText:hash(source)}).waitFor();
    await page.locator('#compare').click();
    await page.locator('#results li').waitFor();
    const unchanged = await exported('save-result');
    assert.equal(unchanged.identical_source_bytes,true);
    assert.deepEqual(unchanged.coverage,{total:1,retested:0,not_retested:1});
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth),true);
    assert.deepEqual(requests,[]);
  } finally {
    await browser.close();
  }
});
