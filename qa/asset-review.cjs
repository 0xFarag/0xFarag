// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';

const assert = require('node:assert/strict');
const {readFile} = require('node:fs/promises');
const path = require('node:path');
const vm = require('node:vm');
const {createHash, webcrypto} = require('node:crypto');
const {before, test} = require('node:test');
const {chromium} = require('playwright');
const directory = process.env.AUTHZ_IMPORT_ROOT || path.join(__dirname, '../public/import');
let importer, assets, scripts;

before(async () => {
  scripts = await Promise.all(['adapters.js', 'asset-review.js'].map(file => readFile(path.join(directory, file), 'utf8')));
  const scope = vm.createContext({TextEncoder, TextDecoder, URL, crypto: webcrypto});
  for (const script of scripts) vm.runInContext(script, scope);
  ({AuthzImport: importer, AuthzAssets: assets} = vm.runInContext('({AuthzImport,AuthzAssets})', scope));
});

async function file(source, input, example = false) {
  const parsed = await importer.parse(source, new TextEncoder().encode(input));
  return {...parsed, example};
}
const encode = value => JSON.parse(JSON.stringify(value));
const row = {url: 'https://example.test/private?token=not-in-index', status: 403};

test('Groups exact host across tools with every row reference; hostless rows stay unassigned', async () => {
  const a = await file('ffuf', JSON.stringify({results: [row, row, {...row, url: 'https://elsewhere.test/'}]}));
  const b = await file('gobuster', 'https://EXAMPLE.test/ (Status: 403)\n/local (Status: 200)\n/other (Status: 200)');
  const grouped = assets.groupIndex(assets.createIndex([b, a, a]));
  assert.equal(grouped.hosts.length, 2);
  const common = grouped.hosts[0];
  assert.deepEqual(Object.fromEntries(common.sources), {ffuf: 2, gobuster: 1});
  assert.deepEqual(encode(common.refs.map(ref => ref.record.locator)), ['Datensatz 1', 'Datensatz 2', 'Zeile 1']);
  assert.equal(common.refs[0].record.fingerprint, common.refs[1].record.fingerprint);
  assert.equal(grouped.unassigned.length, 2);
  assert.ok(grouped.unassigned.every(ref => ref.record.asset_id === null));
  assert.deepEqual(encode(grouped.unassigned.map(ref => ref.record.locator)), ['Zeile 2', 'Zeile 3']);
});

test('Exports stable, allowlisted metadata and exact SHA-256 of file bytes, including imports with no matching rows', async () => {
  const contents = JSON.stringify({results: [row]}, null, 2) + '\r\n';
  const a = await file('ffuf', contents);
  const b = await file('ffuf', '{"results":[]}');
  a.name = 'Confidential Client Filename';
  a.rows[0].detail = 'unclassified payload';
  const index = assets.createIndex([a, b]);
  assert.equal(JSON.stringify(index), JSON.stringify(assets.createIndex([b, a])));
  assert.equal(index.workspace, 'real');
  assert.equal(index.signature, 'unsigned');
  assert.deepEqual(encode(index.assessment), {scope:'unverified', controls:'unverified', coverage:'unknown', findings:'not_assessed', retest:'not_assessed'});
  assert.ok(index.files.some(f => !f.observations.length));
  const source = index.files.find(f => f.observations.length);
  assert.deepEqual(Object.keys(source).sort(), ['observations','sha256','source']);
  assert.equal(source.sha256, createHash('sha256').update(contents).digest('hex'));
  assert.deepEqual(Object.keys(source.observations[0]).sort(), ['asset_id','fingerprint','locator']);
  assert.doesNotMatch(JSON.stringify(index), /example\.test|private|token|not-in-index|Confidential|unclassified payload|HTTP 403/);
});

test('Rejects mixed workspaces, invalid source IDs/digests/locators/asset IDs; handles empty workspace', async () => {
  const a = await file('ffuf', JSON.stringify({results: [row]}));
  const example = {...a, example:true};
  assert.equal(assets.createIndex([example]).workspace, 'example');
  assert.equal(assets.createIndex([]).workspace, null);
  assert.throws(() => assets.createIndex([example, a]), /getrennte/);
  for (const change of [{source:'__proto__'}, {digest:'not-a-hash'}, {rows:[{...a.rows[0], locator:row.url}]},
    {rows:[{...a.rows[0], asset:'customer.example'}]}, {rows:[{...a.rows[0],fingerprint:'bad'}]}]) {
    assert.throws(() => assets.createIndex([{...a, ...change}]));
  }
});

test('Browser pages through asset and source rows, downloads a valid index, and clears stale exports', async () => {
  const browser = await chromium.launch({executablePath: process.env.CHROMIUM_BIN || undefined});
  try {
    const page = await browser.newPage({offline:true});
    await page.setContent('<main><section id="assets"></section></main>');
    await page.addScriptTag({content:await readFile(path.join(directory, '../i18n/tool-copy.js'), 'utf8')});
    for (const script of scripts) await page.addScriptTag({content:script});
    const a = await file('ffuf', JSON.stringify({results: [
      ...Array(13).fill(row),
      ...Array.from({length: 12}, (_, n) => ({url:'https://other' + n + '.test/',status:200}))
    ]}), true);
    const b = await file('gobuster', 'https://example.test/ (Status: 403)\n/relative (Status: 200)', true);
    await page.evaluate(files => AuthzAssets.render(document.querySelector('#assets'), files), [a, b]);
    assert.equal(await page.locator('tbody tr').count(), 12);
    await page.getByRole('button',{name:'Assets – nächste Seite'}).click();
    assert.equal(await page.locator('tbody tr').count(), 1);
    await page.getByRole('button',{name:'Assets – vorherige Seite'}).click();
    await page.getByRole('button',{name:'Belege für Asset ' + a.rows[0].asset + ' anzeigen'}).click();
    await page.getByRole('button',{name:'Quellverweise – nächste Seite'}).click();
    const details = page.getByRole('table',{name:'Quellverweise für ' + a.rows[0].asset});
    assert.match(await details.innerText(), /Datensatz 13/);
    assert.match(await details.innerText(), /Zeile 1/);
    assert.ok((await details.innerText()).includes(b.digest));
    await page.getByRole('button',{name:'Belege ohne Hostbezug (1)'}).click();
    assert.match(await page.getByRole('table',{name:'Datensätze ohne zugeordneten Host'}).innerText(), /Zeile 2/);
    const downloadEvent = page.waitForEvent('download');
    await page.getByRole('button',{name:'Beispiel-Belegindex als JSON speichern'}).click();
    const download = await downloadEvent;
    assert.equal(download.suggestedFilename(), 'AuthzLedger-Beispiel-Belegindex.json');
    const exported = JSON.parse(await readFile(await download.path(), 'utf8'));
    assert.deepEqual(exported, encode(assets.createIndex([a, b])));
    await page.evaluate(() => AuthzAssets.render(document.querySelector('#assets'), []));
    assert.equal(await page.locator('#assets button').count(), 0);
    assert.doesNotMatch(await page.locator('#assets').innerText(), new RegExp(b.digest));
  } finally {
    await browser.close();
  }
});
