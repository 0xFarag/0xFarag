'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');

const { chromium } = require('playwright');
const root = path.resolve(__dirname, '../public');
const mime = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css',
  '.js': 'text/javascript', '.json': 'application/json', '.vtt': 'text/vtt',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.webp': 'image/webp',
  '.mp4': 'video/mp4', '.pdf': 'application/pdf', '.txt': 'text/plain',
};

async function serveFile(request, response) {
  try {
    const url = new URL(request.url, 'http://localhost');
    const relative = decodeURIComponent(url.pathname).replace(/^\/+/, '');
    let file = path.resolve(root, relative);
    if (!file.startsWith(root + path.sep) && file !== root) {
      response.writeHead(403).end();
      return;
    }
    if ((await fs.stat(file)).isDirectory()) file = path.join(file, 'index.html');
    const content = await fs.readFile(file);
    response.writeHead(200, {'Content-Type': mime[path.extname(file)] || 'application/octet-stream', 'Content-Length':content.length});
    response.end(content);
  } catch {
    response.writeHead(404).end();
  }
}

async function checkLinks(page, origin) {
  const files = new Map();
  const htmlPages = ['/index.html', '/lab.html', '/installation.html', '/technik/hkdf/'];
  for (const source of htmlPages) {
    const response = await page.goto(origin + source);
    assert.equal(response.status(), 200, source);
    assert.equal(await page.locator('h1').count(), 1, source + ' single main heading');
    const links = await page.locator('[href], [src], [poster]').evaluateAll(nodes =>
      nodes.flatMap(node => ['href', 'src', 'poster'].filter(attr => node.hasAttribute(attr))
        .map(attr => new URL(node.getAttribute(attr), document.baseURI).href)));
    for (const link of links) {
      const dst = new URL(link);
      if (dst.origin !== origin) continue;
      files.set(dst.pathname, (files.get(dst.pathname) || new Set()).add(dst.hash));
    }
  }
  for (const [name, hashes] of files) {
    const response = await page.request.get(origin + name);
    assert.equal(response.status(),200,name);
    if ([...hashes].some(Boolean)) {
      await page.goto(origin + name);
      for (const hash of hashes) {
        if (hash) assert(await page.evaluate(s=>Boolean(document.getElementById(decodeURIComponent(s.slice(1)))),hash), name + hash);
      }
    }
  }
  console.log('All internal references resolve in Chromium, ' + files.size + ' paths.');
}

async function verifyDownload(page, origin) {
  await page.goto(origin + '/installation.html');
  const anchor = page.locator('a[download]').filter({hasText:/Wheel/i}).first();
  // External release assets can be checked via their release inventory instead.
  // Always exercise a local browser download on the Lab, including on mobile.
  if (await anchor.count()) {
    const dst = new URL(await anchor.getAttribute('href'), page.url());
    if (dst.origin === origin) {
      const sha = crypto.createHash('sha256').update((await (await page.request.get(dst.href)).body())).digest('hex');
      const sumsResponse = await page.request.get(origin + '/downloads/empfaengerpruefer/SHA256SUMS.txt');
      assert.equal(sumsResponse.status(),200);
      assert((await sumsResponse.text()).includes(sha), 'website serves the documented wheel');
    }
  }
}

async function exercise(browser, origin, width) {
  const context = await browser.newContext({
    viewport: {width,height:900}, acceptDownloads: true, reducedMotion:'reduce'
  });
  try {
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror',e=>errors.push(String(e)));
    await page.goto(origin);
    const select = page.locator('#finding-select');
    await page.waitForFunction(()=>!document.getElementById('finding-select').disabled);
    assert.equal(await page.locator('#finding-state').innerText(),'fix_verified');
    await select.selectOption({index:1});
    assert.equal(await page.locator('#finding-state').innerText(),'not_retested');
    assert.equal(await page.locator('#finding-id').innerText(),'finding-c05b584f5c488a0155a3397e');
    await page.locator('#verify').click();
    await page.locator('#verification-note[data-result="valid"]').waitFor();
    await page.locator('[name="variant"][value="modified"]').check();
    await page.locator('#verify').click();
    await page.locator('#verification-note[data-result="invalid"]').waitFor();
    const tab = page.locator('#tab-a');
    await tab.focus(); await tab.press('End');
    assert.equal(await page.locator('#tab-c').getAttribute('aria-selected'),'true');
    assert(await page.locator('#case-c').isVisible());
    if (width < 500) {
      await page.locator('.mobile-nav summary').click();
      const lab = page.getByRole('navigation',{name:'Mobile Hauptnavigation'}).getByRole('link',{name:'Lab'});
      assert(await lab.isVisible()); await lab.click();
    } else {
      await page.locator('.wide-nav').getByRole('link',{name:'Lab'}).click();
    }
    assert(new URL(page.url()).pathname.endsWith('/lab.html'));
    const labCases = [
      ['matched','observed'],['telemetry_only','telemetry_only'],
      ['no_data','unavailable'],['foreign','incomparable']
    ];
    for (const [value,expected] of labCases) {
      await page.locator('#signal-case').selectOption(value);
      const waiting=page.waitForEvent('download');
      await page.locator('#signal-download').click();
      const download=await waiting;
      assert.equal(download.suggestedFilename(),'authzledger-lab-ir.json');
      const record=JSON.parse(await fs.readFile(await download.path(),'utf8'));
      assert.equal(record.control_status,expected);
      assert.equal(record.signed,false);
      assert.deepEqual(record.coverage.map(r=>r.status).sort(),['fix_verified','not_retested']);
    }

    for (const target of ['', '/lab.html', '/installation.html']) {
      await page.goto(origin + target);
      assert(await page.evaluate(()=>document.documentElement.scrollWidth <= innerWidth), 'horizontal overflow ' + width + ' ' + target);
    }

    await page.route('**/proof/v1.5.0/report.json', route => route.fulfill({status:200,contentType:'application/json',body:'{}'}));
    await page.goto(origin);
    await page.getByRole('status').filter({hasText:'Prüfung nicht verfügbar'}).waitFor();
    assert(await page.locator('#verify').isDisabled());
    await page.unroute('**/proof/v1.5.0/report.json');
    if (width >= 1000) {
      await checkLinks(page,origin);
      await verifyDownload(page,origin);
      const investor = await page.request.get(origin+'/investor-one-pager.pdf');
      assert.equal(investor.status(),200);
      assert((await investor.body()).subarray(0,5).equals(Buffer.from('%PDF-')));
    }
    assert.deepEqual(errors,[]);
    console.log('Passed stable cockpit, Ed25519 original and tamper, failed-anchor handling, four exported lab cases, keyboard tabs and responsive layout at ' + width + 'px.');
  } finally {
    await context.close();
  }
}

(async()=>{
  const server=http.createServer(serveFile);
  await new Promise((resolve,reject)=>server.once('error',reject).listen(0,'127.0.0.1',resolve));
  const origin='http://127.0.0.1:' + server.address().port;
  let browser;
  try {
    browser = await chromium.launch();
    await exercise(browser,origin,1360);
    await exercise(browser,origin,390);
  } finally {
    if (browser) await browser.close();
    server.closeAllConnections();
    await new Promise(resolve=>server.close(resolve));
  }
})().catch(e=>{console.error(e);process.exitCode=1});
