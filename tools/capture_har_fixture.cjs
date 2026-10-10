/* Produce a genuine Playwright HAR from Chromium traffic to our public lab only.
 * No external site, credentials, cookies, scanner, or proxy is involved.
 */
'use strict';
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');

const playwrightPath = process.env.PLAYWRIGHT_MODULE || 'playwright';
const { chromium } = require(playwrightPath);
const packagePath = require.resolve(path.join(playwrightPath, 'package.json'));
const playwrightVersion = JSON.parse(fs.readFileSync(packagePath, 'utf8')).version;
const directory = path.resolve(process.env.AUTHZ_HAR_FIXTURE_OUTPUT ||
    path.join(__dirname, '..', 'fixtures', 'imports'));
const harPath = path.join(directory, 'chromium-real.har');
const provenancePath = path.join(directory, 'chromium-real.provenance.json');
let server, browser, context;

(async () => {
    fs.mkdirSync(directory, { recursive: true });
    const requests = [];
    server = http.createServer((request, response) => {
        let body = '';
        request.on('data', chunk => {
            body += chunk.toString('utf8');
            if (body.length > 4096) request.destroy();
        });
        request.on('end', () => {
            requests.push({ method: request.method, path: request.url });
            const expectedGet = request.method === 'GET' && request.url === '/public/invoices/invoice-A';
            const expectedPost = request.method === 'POST' && request.url === '/public/preview';
            let value = { error: 'not found' };
            let status = 404;
            if (expectedGet) {
                status = 200;
                value = { id: 'invoice-A', tenant: 'public-lab', amount: 42, classification: 'public-fixture' };
            } else if (expectedPost) {
                assert.deepEqual(JSON.parse(body), { invoice: 'invoice-A', count: 2 });
                status = 200;
                value = { accepted: true, state: 'preview', count: 2 };
            }
            const data = Buffer.from(JSON.stringify(value));
            response.writeHead(status, { 'Content-Type': 'application/json',
                'Content-Length': data.length, 'Cache-Control': 'no-store' });
            response.end(data);
        });
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const origin = `http://127.0.0.1:${server.address().port}`;
    browser = await chromium.launch({ headless: true,
        args: ['--disable-background-networking', '--disable-component-update', '--no-first-run'],
        ...(process.env.CHROME_EXECUTABLE ? { executablePath: process.env.CHROME_EXECUTABLE } : {}) });
    const browserVersion = await browser.version();
    context = await browser.newContext({ serviceWorkers: 'block',
        recordHar: { path: harPath, content: 'embed', mode: 'full' } });
    await context.route('**/*', async route => {
        if (new URL(route.request().url()).origin === origin) await route.continue();
        else await route.abort('blockedbyclient');
    });
    const page = await context.newPage();
    await page.goto(origin + '/public/invoices/invoice-A');
    const preview = await page.evaluate(async () => {
        const response = await fetch('/public/preview', { method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ invoice: 'invoice-A', count: 2 }) });
        return response.json();
    });
    assert.deepEqual(preview, { accepted: true, state: 'preview', count: 2 });
    await context.close(); // Flush the actual exporter artifact; do not rewrite it.
    context = null;
    await browser.close();
    browser = null;
    await new Promise(resolve => server.close(resolve));
    server = null;
    const raw = fs.readFileSync(harPath);
    const har = JSON.parse(raw);
    assert.equal(har.log.version, '1.2');
    assert(har.log.entries.length >= 2);
    assert(har.log.entries.every(entry => new URL(entry.request.url).origin === origin));
    assert(har.log.entries.every(entry => !entry.request.cookies.length));
    assert(har.log.entries.every(entry => !entry.request.headers.some(header =>
        /authorization|cookie/i.test(header.name))));
    const provenance = {
        schema_version: 1,
        kind: 'tool-generated-har-fixture-provenance',
        generated_at: new Date().toISOString(),
        fixture: path.basename(harPath),
        producer: { browser: 'Chromium', browser_version: browserVersion,
            exporter: 'Playwright BrowserContext recordHar', playwright_version: playwrightVersion,
            har_creator: har.log.creator, har_browser: har.log.browser || null },
        authenticity: 'Unmodified HAR written by the installed Playwright exporter from real Chromium loopback HTTP traffic.',
        distinction: 'This is a Playwright HAR capture, not a manually exported Chrome DevTools HAR and not a Burp/ZAP export.',
        source_scope: { origin, external_targets: false, authentication: false,
            response_data: 'Public authored lab objects; no customer or third-party website content.' },
        request_count: har.log.entries.length,
        observed_requests: requests,
        sha256: crypto.createHash('sha256').update(raw).digest('hex'),
        hash_note: 'Only this deliberately public, credential-free test capture is hashed here. Production importer hashes redacted projections only.',
        reproduction: 'PLAYWRIGHT_MODULE=<installed-playwright> CHROME_EXECUTABLE=<chromium> node tools/capture_har_fixture.cjs',
        license: 'Repository license applies to the authored fixture content and capture script; no external website content is bundled.'
    };
    fs.writeFileSync(provenancePath, JSON.stringify(provenance, null, 2) + '\n');
    console.log(JSON.stringify({ fixture: harPath, provenance: provenancePath,
        chromium: browserVersion, playwright: playwrightVersion, requests: har.log.entries.length }));
})().catch(async error => {
    console.error(error.message);
    if (context) await context.close().catch(() => {});
    if (browser) await browser.close().catch(() => {});
    if (server) server.close();
    process.exitCode = 1;
});
