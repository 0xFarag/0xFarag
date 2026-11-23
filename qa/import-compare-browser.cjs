// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { chromium } = require('playwright');
const directory = process.env.AUTHZ_IMPORT_ROOT || path.join(__dirname, '../public/import');
let browser, context, page, fixture;

before(async () => {
  fixture = await fs.mkdtemp(path.join(os.tmpdir(),'authz-compare-'));
  await fs.writeFile(path.join(fixture,'index.html'), '<!doctype html><html lang="de"><title>AuthzLedger QA</title><section id="comparison"></section></html>');
  browser = await chromium.launch({ executablePath: process.env.CHROMIUM_BIN || undefined });
  context = await browser.newContext({ offline: true });
  page = await context.newPage();
  await page.goto(pathToFileURL(path.join(fixture,'index.html')).href);
  for (const file of ['adapters.js','compare.js']) {
    await page.addScriptTag({ content: await fs.readFile(path.join(directory,file), 'utf8') });
  }
  await page.evaluate(() => {
    globalThis.fromFixture = async (source, input, id, example = false) => {
      const file = await AuthzImport.parse(source,new TextEncoder().encode(input));
      return { ...file, id, example };
    };
    globalThis.ffufFile = (results, id='S01') => fromFixture('ffuf',JSON.stringify({results}),id);
    globalThis.record = (p,status=200,host='training.example') => ({ url:'https://'+host+'/'+p, status });
  });
});
after(async () => {
  if (browser) await browser.close();
  if (fixture) await fs.rm(fixture, { force: true, recursive: true });
});
test('Nmap observation transition and independent UDP case retain separate identities',async () => {
  const statuses = await page.evaluate(async () => {
    const sample = AuthzImport.samples.nmap;
    const a = await fromFixture('nmap',sample,'S01');
    const b = await fromFixture('nmap',sample.replace('state="open"','state="closed"').replace('</ports>','<port protocol="udp" portid="443"><state state="open"/></port></ports>'),'S02');
    return AuthzCompare.compare(a,b).entries.map(x=>x.status);
  });
  assert.deepEqual(statuses,['different','later_only']);
});
test('Browser UI compares only after explicit engagement choice and resetting the workspace removes old records', async () => {
  await page.evaluate(async () => {
    const a = await ffufFile([record('private-raw-string')]);
    const b = await ffufFile([],'S02');
    AuthzCompare.render(document.querySelector('#comparison'),[a,b]);
  });
  await page.locator('[data-snapshot=earlier]').selectOption({index:1});
  await page.locator('[data-snapshot=later]').selectOption({index:2});
  assert.equal(await page.locator('tbody tr').count(),0);
  await page.locator('[type=checkbox]').check();
  assert.match(await page.locator('tbody').innerText(), /not_retested/);
  assert.doesNotMatch(await page.locator('#comparison').innerText(), /private-raw-string|fix_verified/);
  await page.locator('[data-snapshot=later]').selectOption({index:1});
  assert.equal(await page.locator('[type=checkbox]').isChecked(),false);
  assert.equal(await page.locator('tbody tr').count(),0);
  await page.evaluate(()=>AuthzCompare.render(document.querySelector('#comparison'),[]));
  assert.equal(await page.locator('select').count(),0);
});
