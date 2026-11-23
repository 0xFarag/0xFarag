// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');
const {chromium} = require('playwright');

async function main() {
  const root = path.resolve(__dirname, '../dist');
  const types = {'.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png'};
  const server = http.createServer(async (req, res) => {
    try {
      const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
      const target = path.resolve(root, '.' + pathname + (pathname.endsWith('/') ? 'index.html' : ''));
      assert(target.startsWith(root + path.sep));
      res.setHeader('Content-Type', types[path.extname(target)] || 'application/octet-stream');
      res.end(await fs.readFile(target));
    } catch { res.writeHead(404).end(); }
  });
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  let browser;
  try {
    browser = await chromium.launch({executablePath: process.env.CHROMIUM_BIN || undefined});
    const page = await browser.newPage({viewport: {width: 390, height: 844}});
    await page.goto(base + '/en/workbench/?case=private#work');
    const text = 'Korrektur bestätigt · Private user data العربية';
    const title = page.locator('#new-title');
    await title.evaluate((input, value) => { input.value = value; }, text);
    await page.evaluate(() => { window.testNode = document.getElementById('new-title'); });
    const destination = await page.locator('#az-language [data-az-lang="ar"]').getAttribute('href');
    assert.equal(new URL(destination, base).pathname, '/ar/workbench/');
    await page.locator('#az-language summary').click();
    await page.locator('#az-language [data-az-lang="ar"]').click();
    assert.equal(page.url(), base + '/ar/workbench/?case=private#work');
    assert.equal(await page.locator('html').getAttribute('dir'), 'rtl');
    assert.equal(await title.inputValue(), text);
    assert(await title.evaluate(el => el === window.testNode));
    assert.equal(await page.evaluate(() => window.AuthzI18n.lang), 'ar');
    const localizedHeading = await page.locator('h1').innerText();
    await page.goBack();
    assert.equal(await page.locator('html').getAttribute('lang'), 'en');
    assert.equal(await title.inputValue(), text);
    await page.goto(base + '/workbench/');
    await page.waitForURL(base + '/ar/workbench/');
    assert.equal(await page.locator('h1').innerText(), localizedHeading);
    const noJs = await browser.newContext({javaScriptEnabled: false});
    const plain = await noJs.newPage();
    const rbacHeadings = {
      de: 'Kubernetes-RBAC prüfen', en: 'Review Kubernetes RBAC', fr: 'Examiner le RBAC de Kubernetes',
      it: 'Verifica RBAC di Kubernetes', ar: 'مراجعة RBAC في Kubernetes'
    };
    for (const [lang, heading] of Object.entries(rbacHeadings)) {
      const pageUrl = base + '/' + lang + '/rbac/';
      assert.equal((await plain.goto(pageUrl)).status(), 200);
      assert.equal(await plain.locator('html').getAttribute('lang'), lang === 'de' ? 'de-CH' : lang);
      assert.equal(await plain.locator('#az-language [hreflang]').count(), 5);
      assert.equal(await plain.locator('head link[hreflang]').count(), 6);
      assert.equal(await plain.locator('h1').innerText(), heading);
    }
    await noJs.close();
    console.log('Verified localized direct routes, no-JS navigation, Arabic layout, in-place Workbench language changes and language preference.');
  } finally {
    if (browser) await browser.close();
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
