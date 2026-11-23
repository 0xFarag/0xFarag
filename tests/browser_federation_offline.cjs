/* Keyboard-driven Studio projection, with local files only. */
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {once} = require('node:events');
const {createInterface} = require('node:readline');
const {spawn} = require('node:child_process');
const {createHash} = require('node:crypto');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const studio = spawn(process.env.PYTHON || 'python3', ['-u', '-c', [
  'from authzledger.studio import StudioServer',
  'with StudioServer() as studio:',
  '    print(studio.url, flush=True)',
  '    studio.serve_forever()',
].join('\n')], {cwd: process.env.AUTHZ_FEDERATION_STUDIO_CWD || path.resolve(__dirname, '..'), stdio: ['ignore', 'pipe', 'inherit']});

async function run() {
  const lines = createInterface({input: studio.stdout});
  const url = await Promise.race([once(lines, 'line').then(([value]) => value), once(studio, 'exit').then(() => {throw Error('Studio exited');})]);
  const origin = new URL(url).origin;
  const browser = await chromium.launch({headless: true, executablePath: process.env.AUTHZ_CHROMIUM_EXECUTABLE || undefined});
  try {
    const page = await browser.newPage({acceptDownloads: true});
    const errors = [], foreign = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', async route => {
      if (new URL(route.request().url()).origin === origin) return route.continue();
      foreign.push(route.request().url()); await route.abort();
    });
    async function press(selector) {
      await page.locator(selector).focus();
      await page.keyboard.press('Enter');
    }
    await page.goto(url);
    await press('.nav[data-panel="assessment"]');
    await press('#p-open');
    await page.waitForFunction(() => platform.loaded);
    await press('[data-platform-page="surface"]');
    await press('#p-federation summary');
    await page.locator('#p-federation-scope').fill('tcp://192.0.2.10:443');
    const samples = {
      nmap: Buffer.from('<nmaprun scanner="nmap"><host><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="443"><state state="open"/></port></ports></host></nmaprun>'),
      ffuf: Buffer.from('{\r\n"results":[{"url":"https://192.0.2.10/docs","status":200,"length":12}]}\r\n'),
      nuclei: Buffer.from('{"type":"http","template-id":"docs","matched-at":"https://192.0.2.10/docs","matcher-status":false}\n'),
    };
    if (process.env.AUTHZ_FEDERATION_FIXTURES) {
      for (const [profile, filename] of Object.entries({nmap: 'nmap.xml', ffuf: 'ffuf.json', nuclei: 'nuclei.jsonl'})) {
        samples[profile] = await fs.readFile(path.join(process.env.AUTHZ_FEDERATION_FIXTURES, filename));
      }
    }
    for (const [profile, buffer] of Object.entries(samples)) {
      await page.locator('#p-fed-' + profile).setInputFiles({name: 'private-export-' + profile, mimeType: 'application/octet-stream', buffer});
    }
    await press('#p-federation-preview');
    await page.waitForFunction(() => !document.getElementById('p-federation-save').disabled);
    assert.match(await page.locator('#p-federation-status').innerText(), /3 sources · 1 asset · 1 endpoint/);
    await press('#p-federation-observations button:first-child');
    assert.match(await page.locator('#a-inspector-fields').innerText(), /Source SHA-256/i);
    const pending = page.waitForEvent('download');
    await press('#p-federation-save');
    const file = await pending;
    const output = await fs.readFile(await file.path(), 'utf8');
    const projection = JSON.parse(output);
    for (const receipt of projection.receipts) {
      const profile = receipt.source.split('.')[0];
      assert.equal(receipt.sha256, createHash('sha256').update(samples[profile]).digest('hex'));
    }
    assert(projection.graph.findings.every(f => f.evidence_level === 'hint'));
    assert(!JSON.stringify(projection).includes('private-export-'));
    assert(!await page.locator('#p-fed-ffuf').inputValue());
    await page.locator('#p-federation-scope').fill('tcp://192.0.2.11:443');
    assert(await page.locator('#p-federation-save').isDisabled());
    assert.equal(await page.locator('#p-federation-observations button').count(), 0);
    assert.equal(await page.locator('#a-inspector-subtitle').innerText(), 'Select an observation to inspect its source.');
    await press('[data-platform-page="scope"]');
    await page.getByText('Advanced scope policy', {exact: true}).click();
    const service = 'tcp://192.0.2.10:443';
    const scope = {schema_version: 1, kind: 'assessment-scope', id: 'offline-scope', authorization_ref: 'browser-fixture',
      origins: [service], operations: [{origin: service, purpose: 'service', method: 'CONNECT', path: '/'}],
      allowed_networks: ['192.0.2.10/32'], expires_at: '2028-01-01T00:00:00Z', allowed_effects: ['read'],
      limits: {max_requests: 1, concurrency: 1, timeout_seconds: 1, max_response_bytes: 128}};
    await page.locator('#p-title').fill('Federation browser fixture');
    await page.locator('#p-scope-json').fill(JSON.stringify(scope));
    await page.locator('#p-read-attestation').check();
    await press('#p-create');
    await page.locator('#p-surface.active').waitFor();
    await page.locator('#p-federation-scope').fill(service);
    await page.locator('#p-fed-ffuf').setInputFiles({name: 'private-export-ffuf', mimeType: 'application/json', buffer: samples.ffuf});
    await press('#p-federation-preview');
    await page.waitForFunction(() => !document.getElementById('p-federation-consent').disabled);
    assert(await page.locator('#p-federation-retain').isDisabled());
    await page.locator('#p-federation-consent').check();
    await press('#p-federation-retain');
    await page.waitForFunction(() => document.getElementById('p-federation-status').textContent.includes('Retained federation receipt'));
    assert(await page.locator('#p-federation-retain').isDisabled());
    assert.equal(await page.evaluate(() => platform.record.artifacts.filter(a => a.kind === 'federation-receipt').length), 1);
    const profileFiles = {nikto: 'nikto.xml', nessus: 'nessus.nessus', gobuster: 'gobuster.txt', feroxbuster: 'feroxbuster.jsonl'};
    for (const [profile, name] of Object.entries(profileFiles)) {
      await page.locator('#p-fed-' + profile).setInputFiles(path.resolve(__dirname, '../fixtures/offline-tools', name));
    }
    await press('#p-federation-preview');
    await page.waitForFunction(() => !document.getElementById('p-federation-consent').disabled);
    assert.match(await page.locator('#p-federation-status').innerText(), /4 sources · 1 asset · 1 endpoint · 4 observations · 1 excluded record/);
    await page.locator('#p-federation-consent').check();
    await press('#p-federation-retain');
    await page.waitForFunction(() => platform.record.artifacts.filter(a => a.kind === 'federation-receipt').length === 2);
    assert.deepEqual(errors, []); assert.deepEqual(foreign, []);
    if (process.env.AUTHZ_FEDERATION_PROJECTION_OUT) await fs.writeFile(process.env.AUTHZ_FEDERATION_PROJECTION_OUT, output, {flag: 'wx'});
    console.log(JSON.stringify({scenario: 'Studio offline federation', sources: projection.receipts.length,
      observations: projection.graph.observations.length, sourceDigestsVerified: true, stalePreviewCleared: true,
      explicitRetentionVerified: true, externalBrowserRequests: foreign.length, result: 'passed'}));
  } finally { await browser.close(); lines.close(); }
}
run().catch(error => {console.error(error.message); process.exitCode = 1;}).finally(() => studio.kill());
