// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const assert = require('node:assert/strict');
const {test} = require('node:test');
const {createHash} = require('node:crypto');
const {readFile} = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('playwright');
const root = path.join(__dirname,'../public');
const origin = 'https://files.example';
const fixture = Buffer.from('%PDF-1.7\nPrivateFileCanary');
const sha = (bytes,algorithm='sha256') => createHash(algorithm).update(bytes).digest('hex');
const hash = sha(fixture);
const stats = {malicious:1,suspicious:0,harmless:2,undetected:33,timeout:0,'confirmed-timeout':1,failure:1,'type-unsupported':3};
const vt = {data:{id:hash,type:'file',attributes:{sha256:hash,size:fixture.length, private_note:'PrivateReportCanary',
  last_analysis_date:1700000000,last_analysis_stats:stats}}};
const objectFile = (value,name='private-report.json') => ({name,mimeType:'application/json',buffer:Buffer.from(JSON.stringify(value))});

test('Local triage binds all results to one file, rejects stale reports, exports only redacted metadata and never transmits evidence', async () => {
  const browser = await chromium.launch({executablePath:process.env.CHROMIUM_BIN || undefined});
  try {
    const page = await browser.newPage({viewport:{width:390,height:810}});
    const resources = {
      '/dateipruefung/':['dateipruefung/index.html','text/html'],
      '/dateipruefung/app.mjs':['dateipruefung/app.mjs','text/javascript'],
      '/dateipruefung/model.mjs':['dateipruefung/model.mjs','text/javascript'],
      '/dateipruefung/style.css':['dateipruefung/style.css','text/css'],
      '/konto/kundenbereich.css':['konto/kundenbereich.css','text/css'],
      '/assets/authzledger-logo.png':['assets/authzledger-logo.png','image/png'],
      '/assets/authzledger-icon.png':['assets/authzledger-icon.png','image/png']
    };
    await page.route('**/*', async route => {
      const url = new URL(route.request().url());
      const resource = resources[url.pathname];
      if (url.origin !== origin || !resource || route.request().method() !== 'GET') return route.abort();
      await route.fulfill({contentType:resource[1],body:await readFile(path.join(root,resource[0]))});
    });
    await page.goto(origin + '/dateipruefung/', {waitUntil:'load'});
    assert.equal(await page.locator('#choose-file').isEnabled(),true);
    const outgoing = [];
    page.on('request',r => { if (/^https?:/.test(r.url())) outgoing.push(r.url()); });
    await page.locator('#file').setInputFiles({name:'invoice.pdf.exe',mimeType:'application/octet-stream',buffer:fixture});
    await page.locator('#summary').waitFor({state:'visible'});
    assert.equal(await page.locator('#sha256').innerText(),hash);
    assert.equal(await page.locator('#sha512').innerText(),sha(fixture,'sha512'));
    assert.match(await page.locator('#format').innerText(), /PDF/);
    assert.match(await page.locator('#signals').innerText(), /Endung/);
    const hashList = Buffer.from('# PrivateListCanary\n' + hash + '\n');
    await page.locator('#list').setInputFiles({name:'private-list.txt',mimeType:'text/plain',buffer:hashList});
    await page.locator('#list-status').filter({hasText:'ist in der Liste enthalten'}).waitFor();
    await page.locator('#vt').setInputFiles(objectFile(vt));
    await page.locator('#vt-result table').waitFor();
    assert.match(await page.locator('#vt-status').innerText(), /41 gemeldete Engine-Ergebnisse/);
    assert.equal(await page.locator('#vt-result tbody tr').count(),8);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),true);
    async function exported() {
      const pending = page.waitForEvent('download');
      await page.locator('#export').click();
      return JSON.parse(await readFile(await (await pending).path(),'utf8'));
    }
    const evidence = await exported();
    assert.equal(evidence.signed,false);
    assert.equal(evidence.malware_verdict,'not_assessed');
    assert.equal(evidence.local_hash_list.list_sha256,sha(hashList));
    assert.equal(evidence.virustotal_report.report_sha256,sha(objectFile(vt).buffer));
    assert.deepEqual(evidence.virustotal_report.stats,stats);
    assert.doesNotMatch(JSON.stringify(evidence), /Canary|invoice\.pdf|private-report|private-list/);
    await page.locator('#vt').setInputFiles(objectFile({data:{...vt.data,id:'0'.repeat(64)}}));
    await page.locator('#vt-status').filter({hasText:'anderen Datei'}).waitFor();
    assert.equal(await page.locator('#vt-result table').count(),0);
    assert.equal((await exported()).virustotal_report,null);

    // A pending result must not attach to a replacement file.
    await page.evaluate(() => {
      const original = File.prototype.arrayBuffer;
      File.prototype.arrayBuffer = async function() {
        if (this.name === 'late.json') await new Promise(resolve => { window.releaseLateRead = resolve; });
        return original.call(this);
      };
    });
    await page.locator('#vt').setInputFiles(objectFile(vt,'late.json'));
    await page.waitForFunction(() => typeof window.releaseLateRead === 'function');
    const next = Buffer.from('second');
    await page.locator('#file').setInputFiles({name:'second.txt',mimeType:'text/plain',buffer:next});
    await page.locator('#sha256').filter({hasText:sha(next)}).waitFor();
    await page.evaluate(() => window.releaseLateRead());
    const replacement = await exported();
    assert.equal(replacement.file.sha256,sha(next));
    assert.equal(replacement.local_hash_list,null);
    assert.equal(replacement.virustotal_report,null);
    await page.locator('#clear').click();
    assert.equal(await page.locator('#sha256').textContent(),'');
    assert.equal(await page.locator('#sources').isVisible(),false);
    assert.deepEqual(outgoing,[]);
  } finally {
    await browser.close();
  }
});
