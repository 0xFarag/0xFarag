// © Nasser Aldin Farag (0xFarag). All rights reserved.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {test} from 'node:test';
import {readFile} from 'node:fs/promises';
import vm from 'node:vm';
import {originalFileChecks, parseProjection, statusLabels} from '../public/workbench/model.mjs';
import {compareProjections} from '../public/workbench/compare.mjs';

const sha = digit => digit.repeat(64);
const profile = {
  schema: 'authzledger.evidence-index.v1',
  rights: '© Nasser Aldin Farag (0xFarag). All rights reserved.',
  workspace: 'real',
  signature: 'unsigned',
  assessment: {scope: 'unverified', controls: 'unverified', coverage: 'unknown', findings: 'not_assessed', retest: 'not_assessed'}
};
const row = (asset_id, locator, fingerprint) => ({asset_id, locator, fingerprint});
const file = (source, digest, observations) => ({source, sha256: sha(digest), observations});
function sample() {
  const host = 'fedcba9876543210';
  return {...structuredClone(profile), files: [
    file('ffuf', 'a', [row(host, 'Datensatz 1', sha('1')), row(host, 'Datensatz 2', sha('1'))]),
    file('gobuster', 'b', [row(null, 'Zeile 7', sha('2'))]),
    file('nikto', 'c', []),
    file('zap', 'd', [row(host, 'Datensatz 1', sha('3'))])
  ]};
}
const encode = data => Buffer.from(JSON.stringify(data));

test('index binds unchecked observations to exact original file and record references', async () => {
  const bytes = encode(sample());
  const model = await parseProjection(bytes);
  assert.equal(model.digest, createHash('sha256').update(bytes).digest('hex'));
  assert.equal(model.kind, 'evidence_index');
  assert.equal(model.rows.length, 4);
  assert.equal(new Set(model.rows.map(r => r.id)).size, 4);
  assert.equal(model.importIndex.sources.length, 4);
  assert.deepEqual(model.importIndex.sources.map(f => f.count), [2,1,0,1]);
  assert.equal(model.importIndex.assets, 1);
  assert.equal(model.importIndex.unassigned, 1);
  assert.ok(model.rows.every(r => r.status === 'import_unassessed' && r.binding === r.reference.file_sha256));
  assert.ok(Object.hasOwn(statusLabels, 'import_unassessed'));
  assert.deepEqual(model.rows[2].reference, {source: 'gobuster', file_sha256: sha('b'), locator: 'Zeile 7', fingerprint: sha('2')});
  assert.equal(model.coverage, null);
  assert.equal(model.scope, null);
  assert.equal(model.assessment, null);
  assert.equal(model.importIndex.workspace, 'real');
  assert.ok(!compareProjections(model, model).comparable);
});

test('feroxbuster preserves the source line, file digest and unchecked observation status', async () => {
  const index = {...profile, files: [file('feroxbuster', 'b', [row('f'.repeat(16), 'Zeile 8', sha('c'))])]};
  const model = await parseProjection(encode(index));
  const [record] = model.rows;
  assert.equal(model.importIndex.sources[0].label, 'feroxbuster');
  assert.equal(record.source, 'feroxbuster');
  assert.equal(record.status, 'import_unassessed');
  assert.equal(model.coverage, null);
  assert.deepEqual(record.reference, {source: 'feroxbuster', file_sha256: sha('b'), locator: 'Zeile 8', fingerprint: sha('c')});
});

test('empty source exports and explicit examples retain their meaning', async () => {
  const data = sample();
  data.workspace = 'example';
  data.files = [file('cobalt', 'd', [])];
  const model = await parseProjection(encode(data));
  assert.equal(model.rows.length, 0);
  assert.equal(model.importIndex.workspace, 'example');
  assert.equal(model.importIndex.sources[0].source, 'cobalt');
  assert.equal(model.importIndex.unassigned, 0);
  data.files = [];
  await assert.rejects(parseProjection(encode(data)));
});

test('rejects unknown properties, trust upgrades, invalid locators, identifiers and ambiguous files', async () => {
  for (const change of [
    x => x.signature = 'signed', x => x.workspace = null, x => x.rights = 'unknown',
    x => x.demo = 'C', x => x.assessment.scope = 'cleared', x => x.assessment.controls = 'valid',
    x => x.assessment.coverage = 1, x => x.assessment.findings = 'confirmed', x => x.assessment.retest = 'fix_verified',
    x => x.files[0].name = 'original', x => x.files[0].source = '__proto__', x => x.files[0].source = ['ffuf'],
    x => x.files[2].sha256 = 'XX', x => x.files[0].observations[0].asset_id = 'private-host',
    x => x.files[0].observations[0].locator = 'Datensatz 0', x => x.files[0].observations[0].locator = 'Zeile 1048577',
    x => x.files[0].observations[0].fingerprint = null, x => x.files[0].observations[0].status = 'confirmed',
    x => x.files[0].observations[0].metadata = {token: 'private'}, x => x.files.push(x.files[0])
  ]) {
    const data = sample();
    change(data);
    await assert.rejects(parseProjection(encode(data)));
  }
});

test('enforces the importer file/row budgets without silently dropping data', async () => {
  const obs = row(null, 'Zeile 1', sha('1'));
  const data = sample();
  data.files = [file('gobuster', 'a', Array(1000).fill(obs)), file('gobuster', 'b', Array(1000).fill(obs)),
    file('gobuster', 'c', Array(500).fill(obs))];
  const model = await parseProjection(encode(data));
  assert.equal(model.rows.length, 2500);
  assert.equal(model.importIndex.unassigned, 2500);
  data.files[2].observations.push(obs);
  await assert.rejects(parseProjection(encode(data)), /2’500/);
  data.files = [file('gobuster', 'a', Array(1001).fill(obs))];
  await assert.rejects(parseProjection(encode(data)), /1000/);
  data.files = Array(21).fill(file('gobuster', 'a', []));
  await assert.rejects(parseProjection(encode(data)), /20/);
});


test('opens the real cross-tool export and keeps originals and private data out of the projection', async () => {
  const runtime = vm.createContext({TextEncoder, TextDecoder, URL, crypto: globalThis.crypto});
  for (const name of ['adapters.js', 'asset-review.js']) {
    vm.runInContext(await readFile(new URL('../public/import/' + name, import.meta.url), 'utf8'), runtime);
  }
  const {AuthzImport, AuthzAssets} = vm.runInContext('({AuthzImport, AuthzAssets})', runtime);
  const inputs = [
    ['ffuf', JSON.stringify({results: [{url: 'https://company.example/private?token=sensitive', status: 403}]})],
    ['gobuster', 'https://company.example/public (Status: 200)\n/private (Status: 403)'],
    ['ffuf', '{"results":[]}']
  ];
  const files = await Promise.all(inputs.map(async ([source, data]) =>
    ({...await AuthzImport.parse(source, new TextEncoder().encode(data)), example: false})));
  const index = AuthzAssets.createIndex(files);
  const bytes = encode(index);
  const model = await parseProjection(bytes);
  assert.equal(model.importIndex.sources.length, 3);
  assert.equal(model.rows.length, 3);
  assert.equal(model.importIndex.assets, 1);
  assert.equal(model.importIndex.unassigned, 1);
  assert.equal(model.importIndex.workspace, 'real');
  assert.ok(!JSON.stringify(model).includes('company.example'));
  assert.ok(!JSON.stringify(model).includes('token=sensitive'));
  for (const [source, data] of inputs) {
    const expected = createHash('sha256').update(data).digest('hex');
    assert.ok(model.importIndex.sources.some(f => f.source === source && f.sha256 === expected));
  }
});


test('original-byte matches, one-byte mismatch, repeats and read errors stay independent of the review', async () => {
  const file = new Blob(['ABC']);
  const hash = createHash('sha256').update('ABC').digest('hex');
  const checks = originalFileChecks([{sha256: hash}]);
  const result = await checks.verify([file, new Blob(['ABD']), file,
    {size: 3, arrayBuffer: async () => { throw Error('disk'); }}, new Blob([''])]);
  assert.deepEqual(result.outcomes.map(x => x.status), ['matched', 'unmatched', 'matched', 'unreadable', 'size']);
  assert.equal(result.outcomes[2].duplicate, true);
  assert.equal(result.outcomes[1].sha256, undefined);
  assert.equal(checks.has(hash), true);
  assert.equal(checks.last, result);
  assert.ok((await checks.verify(Array(21).fill(file))).error);
  const differentSession = originalFileChecks([{sha256: hash}]);
  assert.equal(differentSession.has(hash), false);
});

test('cancelled index or superseded selection cannot commit a pending original-file match', async () => {
  const file = new Blob(['abc']);
  const hash = createHash('sha256').update('abc').digest('hex');
  const checks = originalFileChecks([{sha256: hash}]);
  for (const cancelled of [true, false]) {
    let finish;
    const gate = new Promise(resolve => { finish = resolve; });
    const pending = checks.verify([{size: 3, arrayBuffer: () => gate}]);
    if (cancelled) checks.cancel();
    else await checks.verify([new Blob(['xyz'])]);
    finish(await file.arrayBuffer());
    assert.equal(await pending, null);
    assert.equal(checks.has(hash), false);
  }
});
