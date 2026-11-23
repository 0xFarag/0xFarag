/* ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag). */
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const {once} = require('node:events');
const fs = require('node:fs/promises');
const path = require('node:path');
const {createInterface} = require('node:readline');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

async function run() {
  const root = path.resolve(__dirname, '..');
  const server = spawn(process.env.PYTHON || 'python3', ['-u', '-c', [
    'from authzledger.studio import StudioServer',
    'with StudioServer() as server:',
    '    print(server.url, flush=True)',
    '    server.serve_forever()',
  ].join('\n')], {cwd: root, stdio: ['ignore', 'pipe', 'inherit']});
  const lines = createInterface({input: server.stdout});
  let browser;
  try {
    const [url] = await Promise.race([once(lines, 'line'),
      once(server, 'exit').then(() => {throw new Error('Studio exited before readiness');})]);
    browser = await chromium.launch({headless: true, executablePath: process.env.AUTHZ_CHROMIUM_EXECUTABLE || undefined});
    const page = await browser.newPage({acceptDownloads: true});
    page.setDefaultTimeout(8000);
    const foreign = [], errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', route => {
      if (new URL(route.request().url()).origin === new URL(url).origin) return route.continue();
      foreign.push(route.request().url());
      return route.abort();
    });
    await page.goto(url);
    await page.locator('.nav[data-panel="assessment"]').click();
    await page.locator('#p-open').click();
    await page.locator('[data-platform-page="investigate"]').click();
    await page.getByText('Compare saved detection evidence', {exact: true}).press('Enter');
    const fixtures = path.join(root, 'examples', 'blue-evidence');
    await page.locator('#p-blue-anchor').setInputFiles(path.join(fixtures, 'mixed-c-result.json'));
    await page.locator('#p-blue-signals').setInputFiles(path.join(fixtures, 'control-lab.json'));
    const [download] = await Promise.all([page.waitForEvent('download'), page.locator('#p-blue-evaluate').press('Enter')]);
    assert.equal(download.suggestedFilename(), 'blue-evidence.json');
    const result = JSON.parse(await fs.readFile(await download.path(), 'utf8'));
    assert.equal(result.samples.matched.status, 'observed');
    assert.equal(result.samples.foreign.status, 'incomparable');
    assert.equal(result.source_assertions_verified, false);
    assert.match(await page.locator('#p-blue-status').textContent(), /Synthetic/);
    assert.match(await page.locator('#p-blue-retest').textContent(), /1 of 2 findings not retested/);
    const row = name => page.getByRole('row').filter({has: page.getByRole('rowheader', {name, exact: true})});
    assert.match(await row('matched').innerText(), /1 of 1/);
    assert.match(await row('foreign').innerText(), /No eligible events/);

    const signals = JSON.parse(await fs.readFile(path.join(fixtures, 'control-lab.json'), 'utf8'));
    const matched = signals.controls.matched;
    matched.events.push({...matched.events[0], event: 'evt-second'});
    await page.locator('#p-blue-signals').setInputFiles({
      name: 'partial.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify(signals))
    });
    assert.equal(await page.locator('#p-blue-results').isVisible(), false);
    const [partialDownload] = await Promise.all([
      page.waitForEvent('download'), page.locator('#p-blue-evaluate').press('Enter')
    ]);
    const partial = JSON.parse(await fs.readFile(await partialDownload.path(), 'utf8'));
    assert.deepEqual(partial.samples.matched.alert_coverage.unlinked_event_ids, ['evt-second']);
    assert.match(await row('matched').innerText(), /1 of 2/);
    assert.deepEqual(foreign, []);
    assert.deepEqual(errors, []);
    console.log('PASS: keyboard input, offline correlation, JSON download, no foreign requests');
  } finally {
    if (browser) await browser.close();
    lines.close();
    server.kill();
  }
}
run().catch(error => {console.error(error); process.exitCode = 1;});
