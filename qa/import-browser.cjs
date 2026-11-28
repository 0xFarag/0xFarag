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
    const sources = ['nikto', 'ffuf', 'gobuster', 'nmap', 'burp', 'nessus', 'cobalt', 'zap', 'har', 'openapi', 'nuclei', 'feroxbuster',
      'dirbuster', 'sqlmap', 'bloodhound', 'neo4j', 'falco'];
    const saveReport = page.locator('#save-report');
    assert.equal(await saveReport.isDisabled(), true);
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

    const [sampleReport] = await Promise.all([page.waitForEvent('download'), saveReport.click()]);
    const sampleHtml = await fs.readFile(await sampleReport.path(), 'utf8');
    assert.match(sampleHtml, /Synthetisches Beispiel/);
    for (const source of ['Nmap', 'DirBuster', 'sqlmap', 'Neo4j', 'BloodHound', 'Falco']) assert.ok(sampleHtml.includes(source));
    await page.locator('#real').click();
    assert.equal(await saveReport.isDisabled(), true);
    assert.equal(await page.locator('#report-status').innerText(), '');
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
    await page.locator('#filter').selectOption('gobuster');
    const [clientReport] = await Promise.all([page.waitForEvent('download'), saveReport.click()]);
    const html = await fs.readFile(await clientReport.path(), 'utf8');
    assert.equal((html.match(/<article>/g) || []).length, 3, 'Report includes every source even when the table is filtered');
    assert.match(html, /Quellenregister/);
    assert.match(html, /ffuf · Importierte Beobachtungen \(1\)/);
    assert.match(html, /Gobuster · Importierte Beobachtungen \(2\)/);
    assert.ok(html.includes(createHash('sha256').update(exported).digest('hex')));
    assert.ok(html.includes(digest));
    assert.doesNotMatch(html, /sensitive-client|example.invalid|\/relative|Synthetisches Beispiel|<script|Fälle im Umfang/);
    await page.locator('#clear').click();
    assert.equal(await saveReport.isDisabled(), true);
    const entries = [
      [{name:'X-Content-Type-Options',value:'nosniff'}, {name:'Strict-Transport-Security',value:'max-age=86400'}],
      [{name:'Content-Type',value:'text/html'}], undefined, []
    ].map((headers, i) => ({
      request:{method: i === 3 ? 'POST' : 'GET', url:'https://private.invalid/private-har'},
      response:{status:200, content:{mimeType:'text/html',text:'PRIVATE-BODY'}, headers}
    }));
    const harBytes = Buffer.from(JSON.stringify({log:{version:'1.2',entries}}));
    const harHash = createHash('sha256').update(harBytes).digest('hex');
    await page.locator('#file').setInputFiles({name:'private-session.har',mimeType:'application/json',buffer:harBytes});
    const headerChecks = page.locator('#har-checks');
    await headerChecks.waitFor();
    assert.deepEqual(await headerChecks.locator('tbody tr').allTextContents(),
      ['Strict-Transport-Security111','X-Content-Type-Options111']);
    await headerChecks.locator('summary').click();
    const trace = await headerChecks.innerText();
    assert.ok(trace.includes(harHash) && trace.includes('Header fehlt im Mitschnitt · Datensätze 2'));
    assert.ok(trace.includes('Headerdaten fehlen oder sind unvollständig · Datensätze 3'));
    assert.doesNotMatch(trace, /private-har|private.invalid|private-session|PRIVATE-BODY|max-age|Datensätze 4/);
    const [checked] = await Promise.all([page.waitForEvent('download'), saveReport.click()]);
    const checkedHtml = await fs.readFile(await checked.path(), 'utf8');
    assert.ok(checkedHtml.includes('Headerprüfung im HAR-Mitschnitt') && checkedHtml.includes(harHash));
    assert.match(checkedHtml, /Header fehlt im Mitschnitt · Datensätze 2/);
    assert.match(checkedHtml, /<details open/);
    assert.doesNotMatch(checkedHtml, /private-har|private.invalid|private-session|PRIVATE-BODY|max-age/);
    await page.locator('#examples').click();
    assert.ok(!(await headerChecks.textContent()).includes(harHash));
    await page.locator('#real').click();
    await page.locator('#clear').click();
    assert.equal(await headerChecks.isVisible(), false);
    assert.deepEqual(requests, [], 'Opening files and exporting their report must not make network requests');
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
