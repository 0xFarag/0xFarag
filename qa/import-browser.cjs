// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';

const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');

module.exports = async function verifyLocalImport(page, origin) {
  await page.goto(origin + '/import/');
  const requests = [];
  const observe = request => requests.push(request.url());
  page.on('request', observe);
  try {
    const adapters = page.locator('#adapter');
    const sources = ['nikto', 'ffuf', 'gobuster', 'nmap', 'burp', 'nessus', 'cobalt'];
    const options = await adapters.locator('option').evaluateAll(nodes => nodes.map(node => node.value));
    assert.deepEqual([...options].sort(), [...sources].sort());
    await page.locator('#examples').click();
    for (const [index, source] of sources.entries()) {
      await adapters.selectOption(source);
      await page.locator('#add').click();
      await page.waitForFunction(n => document.querySelectorAll('#files code').length === n, index + 1);
    }
    await adapters.selectOption('ffuf');
    await page.locator('#follow').click();
    await page.waitForFunction(() => document.querySelectorAll('#files code').length === 8);
    await page.locator('[data-snapshot=earlier]').selectOption({index:2});
    await page.locator('[data-snapshot=later]').selectOption({index:8});
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
    assert.deepEqual(requests, [], 'Opening local exports must not make network requests');
  } finally {
    page.off('request', observe);
  }
};
