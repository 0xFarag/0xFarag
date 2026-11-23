// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';

const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const fs = require('node:fs/promises');

module.exports = async function verifyLocalImport(page, origin) {
  await page.goto(origin + '/import/');
  const requests = [];
  const observe = request => requests.push(request.url());
  page.on('request', observe);
  try {
    const adapters = page.locator('#adapter');
    const sources = ['nikto', 'ffuf', 'gobuster', 'nmap', 'burp', 'nessus', 'cobalt', 'zap', 'har', 'openapi', 'nuclei', 'feroxbuster'];
    const options = await adapters.locator('option').evaluateAll(nodes => nodes.map(node => node.value));
    assert.deepEqual([...options].sort(), ['auto', ...sources].sort());
    assert.equal(await adapters.inputValue(), 'auto');
    await page.locator('#examples').click();
    for (const [index, source] of sources.entries()) {
      await adapters.selectOption(source);
      await page.locator('#add').click();
      await page.waitForFunction(n => document.querySelectorAll('#files code').length === n, index + 1);
    }
    await adapters.selectOption('ffuf');
    await page.locator('#follow').click();
    const followPosition = sources.length + 1;
    await page.waitForFunction(n => document.querySelectorAll('#files code').length === n, followPosition);
    await page.locator('[data-snapshot=earlier]').selectOption({index:2});
    await page.locator('[data-snapshot=later]').selectOption({index:followPosition});
    await page.locator('#authz-compare-scope').check();
    assert.match(await page.locator('#comparison').innerText(), /not_retested/);
    await page.locator('#filter').selectOption('nessus');
    assert.equal(await page.locator('#body tr td:first-child').first().innerText(), 'Nessus');

    await page.locator('#real').click();
    assert.equal(await page.locator('#files code').count(), 0);
    await adapters.selectOption('ffuf');
    const buffer = Buffer.from(JSON.stringify({results:[{url:'https://example.invalid/sample',status:200}]}));
    const digest = createHash('sha256').update(buffer).digest('hex');
    const upload = {name:'sample.json',mimeType:'application/json',buffer};
    await page.locator('#file').setInputFiles(upload);
    await page.waitForFunction(expected => document.querySelector('#files code')?.textContent === expected, digest);
    await page.locator('#file').setInputFiles(upload);
    await page.waitForFunction(() => document.querySelector('#status').textContent.includes('bereits'));
    assert.equal(await page.locator('#files code').count(), 1);
    await adapters.selectOption('nmap');
    await page.locator('#file').setInputFiles({name:'unsupported.xml',mimeType:'application/xml',
      buffer:Buffer.from('<!DOCTYPE nmaprun SYSTEM "https://example.invalid/test.dtd"><nmaprun/>')});
    await page.waitForFunction(() => document.querySelector('#status').textContent.includes('abgelehnt'));
    assert.equal(await page.locator('#files code').count(), 1);
    await page.locator('#clear').click();
    assert.equal(await page.locator('#files code').count(), 0);
    await adapters.selectOption('auto');
    const gobuster = {name:'sensitive-client.txt', mimeType:'text/plain', buffer:Buffer.from('https://example.invalid/other (Status: 403)\n/relative (Status: 200)')};
    const invalid = {name:'other.json', mimeType:'application/json', buffer:Buffer.from('{"results":[],"site":[]}')};
    await page.locator('#file').setInputFiles([upload, invalid, gobuster]);
    await page.waitForFunction(() => document.querySelectorAll('#files code').length === 2);
    assert.match(await page.locator('#status').innerText(), /Datei 2 abgelehnt/);
    const asset = page.locator('#asset-review');
    assert.match(await asset.innerText(), /In mehreren Werkzeugen: 1/);
    assert.match(await asset.innerText(), /Datensätze ohne Hostbezug: 1/);
    const [download] = await Promise.all([page.waitForEvent('download'), asset.getByRole('button',{name:'Belegindex als JSON speichern',exact:true}).click()]);
    const exported = await fs.readFile(await download.path());
    assert.doesNotMatch(exported.toString(), /sensitive-client|example.invalid|\/relative/);
    assert.deepEqual(requests, [], 'Opening local exports must not make network requests');
    page.off('request', observe);
    await page.getByRole('link', {name:'Zur Evidence Workbench'}).click();
    const [fileChooser] = await Promise.all([page.waitForEvent('filechooser'),
      page.getByRole('button',{name:'JSON-Dateien öffnen'}).click()]);
    await fileChooser.setFiles({name:download.suggestedFilename(), mimeType:'application/json', buffer:exported});
    await page.getByRole('heading',{name:'Werkzeugübergreifender Belegindex'}).waitFor();
    assert.equal(await page.locator('#cases li').count(), 3);
    assert.match(await page.locator('#import-sources').textContent(), new RegExp(digest));
    await page.locator('#import-registry summary').click();
    await page.locator('#original-files').setInputFiles([upload,{...upload,name:'changed.json',buffer:Buffer.concat([upload.buffer,Buffer.from(' ')])}]);
    await page.waitForFunction(() => document.querySelector('#original-status').textContent.includes('1 von 2'));
  } finally {
    page.off('request', observe);
  }
};
