/* Read-only, keyboard-driven inspection of an archived capture and two tool exports. */
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const {createHash} = require('node:crypto');
const {once} = require('node:events');
const fs = require('node:fs/promises');
const path = require('node:path');
const {createInterface} = require('node:readline');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const service = 'tcp://192.0.2.10:443';
const url = 'https://192.0.2.10/private-fixture-route';
const target = new URL(url);
const capture = {log: {version: '1.2', entries: [{request: {method: 'GET', url}, response: {status: 200}}]}};
const sources = {
  ffuf: JSON.stringify({results: [{url, status: 200, length: 12}, {url: 'https://192.0.2.11/docs', status: 403}]}),
  nuclei: JSON.stringify({'type': 'http', 'template-id': 'fixture', 'matched-at': url, 'matcher-status': true}),
};
const scope = {
  schema_version: 1, kind: 'assessment-scope', id: 'index-fixture', authorization_ref: 'offline-fixture',
  origins: [service, target.origin], operations: [{origin: service, purpose: 'service', method: 'CONNECT', path: '/'},
    {origin: target.origin, purpose: 'application', method: 'GET', path: target.pathname}],
  allowed_networks: ['192.0.2.10/32'], allowed_effects: ['read'], expires_at: '2028-01-01T00:00:00Z',
  limits: {max_requests: 1, concurrency: 1, timeout_seconds: 1, max_response_bytes: 128},
};
const bootstrap = `
import json, sys
from authzledger.studio import StudioServer
fixture = json.load(sys.stdin)
with StudioServer() as studio:
    scope = fixture['scope']
    case = studio.workbench.create('Source comparison', scope)
    exports = [(family, text.encode()) for family, text in fixture['sources'].items()]
    studio.workbench.retain_federation(case['id'], [fixture['service']], exports, expected_revision=case['revision'])
    studio.workbench.import_source(case['id'], json.dumps(fixture['capture']).encode(), 'har-1.2')
    empty = studio.workbench.create('Empty assessment', scope)
    print(json.dumps({'url': studio.url, 'case': case['id'], 'empty': empty['id']}), flush=True)
    studio.serve_forever()
`;

async function run() {
  const studio = spawn(process.env.PYTHON || 'python3', ['-u', '-c', bootstrap], {
    cwd: process.env.AUTHZ_FEDERATION_STUDIO_CWD || path.resolve(__dirname, '..'), stdio: ['pipe', 'pipe', 'inherit'],
  });
  const lines = createInterface({input: studio.stdout});
  let browser;
  try {
    const ready = Promise.race([once(lines, 'line').then(([line]) => JSON.parse(line)),
      once(studio, 'exit').then(([code]) => {throw Error(`Studio exited with code ${code}`);})]);
    studio.stdin.end(JSON.stringify({scope, service, sources, capture}));
    const fixture = await ready;
    browser = await chromium.launch({headless: true, executablePath: process.env.AUTHZ_CHROMIUM_EXECUTABLE || undefined});
    const page = await browser.newPage({acceptDownloads: true});
    page.setDefaultTimeout(10000);
    const origin = new URL(fixture.url).origin;
    const errors = [], foreign = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', async route => {
      if (new URL(route.request().url()).origin === origin) return route.continue();
      foreign.push(route.request().url());
      await route.abort();
    });
    async function enter(selector) {
      await page.locator(selector).focus();
      await page.keyboard.press('Enter');
    }
    async function loadAssessment(id, title) {
      await page.locator('#p-assessment').selectOption(id);
      await page.locator('#p-context strong').filter({hasText: title}).waitFor();
    }
    async function freeze() {
      await enter('#p-freeze');
      await page.locator('#p-index-open:enabled').waitFor();
    }
    async function requestIndex() {
      const response = page.waitForResponse(r => new URL(r.url()).pathname === '/api/platform/federation-index');
      await enter('#p-index-open');
      return response;
    }
    async function openIndex() {
      const result = await requestIndex();
      assert.equal(result.status(), 200);
      await page.locator('#p-index-results').waitFor();
      return result.json();
    }
    await page.goto(fixture.url);
    await enter('.nav[data-panel="assessment"]');
    await enter('#p-open');
    await loadAssessment(fixture.case, 'Source comparison');
    await enter('[data-platform-page="report"]');
    assert(await page.locator('#p-index-open').isDisabled());
    assert(await page.locator('#p-index-results').isHidden());
    await freeze();
    const index = await openIndex();
    assert.equal(index.kind, 'federated-surface-index');
    assert.equal(index.assessment_id, fixture.case);
    assert.equal(index.services.length, 1);
    assert.equal(index.endpoints.length, 1);
    assert.equal(index.observations.length, 3);
    assert.equal(index.summary.mixed_endpoints, 1);
    assert.equal(index.omissions.length, 1);
    assert.match(await page.locator('#p-report-status').innerText(), new RegExp(index.snapshot_digest));
    assert.match(await page.locator('#p-index-status').innerText(), /observation/i);

    const download = page.waitForEvent('download');
    await enter('#p-index-save');
    const file = await download;
    const text = await fs.readFile(await file.path(), 'utf8');
    assert.deepEqual(JSON.parse(text), index);
    assert(!text.includes('private-fixture-route'));
    const first = '#p-index-rows button:first-child';
    await page.locator('#p-index-kind').selectOption('omissions');
    await enter(first);
    const inspector = page.locator('#a-inspector-fields');
    assert.match(await inspector.innerText(), /out_of_scope/);
    await page.locator('#p-index-kind').selectOption('endpoints');
    await enter(first);
    await enter('#p-index-related');
    assert.equal(await page.locator('#p-index-kind').inputValue(), 'observations');
    assert.equal(await page.locator('#p-index-rows button').count(), 3);
    await page.locator(first).focus();
    const provenance = [];
    for (const row of index.observations) {
      await page.keyboard.press('Enter');
      const details = await inspector.innerText();
      assert(details.includes(row.id) && details.includes(row.artifact_refs[0].pointer));
      provenance.push(details);
      await page.keyboard.press('ArrowDown');
    }
    for (const source of Object.values(sources)) {
      const digest = createHash('sha256').update(source).digest('hex');
      assert(provenance.some(text => text.includes(digest)), 'source digest missing from inspector');
    }

    await loadAssessment(fixture.empty, 'Empty assessment');
    assert(await page.locator('#p-index-open').isDisabled());
    assert(await page.locator('#p-index-results').isHidden());
    assert.equal(await page.locator('#p-index-rows button').count(), 0);
    assert(!provenance.includes(await inspector.innerText()));
    await freeze();
    // Change only the submitted selection once; the real Studio server evaluates it.
    await page.route(origin + '/api/platform/federation-index', route =>
      route.fallback({postData: JSON.stringify({snapshot_id: 'expired-fixture-snapshot'})}), {times: 1});
    const rejected = await requestIndex();
    assert.equal(rejected.status(), 400);
    const {error} = await rejected.json();
    assert.match(error, /frozen assessment snapshot/i);
    await page.locator('#notice.error').filter({hasText: error}).waitFor();
    assert(await page.locator('#p-index-results').isHidden());
    assert(await page.locator('#p-index-save').isHidden());
    assert.equal(await page.locator('#p-index-rows button').count(), 0);
    assert(await page.locator('#p-index-open').isEnabled());
    const emptyIndex = await openIndex();
    assert.equal(emptyIndex.assessment_id, fixture.empty);
    assert.notEqual(emptyIndex.snapshot_digest, index.snapshot_digest);
    assert.equal(emptyIndex.observations.length, 0);
    assert.equal(await page.locator('#p-index-rows button').count(), 0);
    await enter('#p-new');
    assert(await page.locator('#p-index-open').isDisabled());
    assert(await page.locator('#p-index-results').isHidden());
    assert.deepEqual(errors, []);
    assert.deepEqual(foreign, []);
    console.log(JSON.stringify({scenario: 'Studio frozen federation index', observations: index.observations.length,
      sourceDigestsInspected: 2, omissions: 1, mixedEndpoints: 1, exactDownload: true,
      staleIndexCleared: true, rejectedSnapshotStatus: rejected.status(), retrySucceeded: true,
      externalBrowserRequests: 0, result: 'passed'}));
  } finally {
    lines.close();
    studio.kill();
    if (browser) await browser.close();
  }
}
run().catch(error => {console.error(error.message); process.exitCode = 1;});
