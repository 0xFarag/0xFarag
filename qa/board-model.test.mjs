// ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {MAX_BYTES, parseProjection, statusLabels} from '../public/workbench/model.mjs';

const base = new URL('../public/proof/', import.meta.url);
const fixture = async name => readFile(new URL(name, base));
const encode = value => Buffer.from(JSON.stringify(value));

async function altered(name, edit) {
  const value = JSON.parse(await fixture(name));
  edit(value);
  return parseProjection(encode(value));
}

test('native header finding and passive scanner assertion retain separate origins and confidence', async () => {
  const bytes = await fixture('mixed-b-result.json');
  const report = await parseProjection(bytes);
  assert.equal(report.digest, createHash('sha256').update(bytes).digest('hex'));
  assert.equal(report.kind, 'finding');
  assert.equal(report.coverage, null);
  assert.deepEqual(report.rows.map(row => row.status), ['confirmed', 'not_verified']);
  assert.notEqual(report.rows[0].binding, report.rows[1].binding);
  assert.ok(report.rows[0].details.find(({label}) => label === 'Kontrollen').value.includes('reference'));
});

test('retains skipped cases and uses immutable baseline finding digests', async () => {
  const bytes = await fixture('mixed-c-result.json');
  const report = await parseProjection(bytes);
  assert.equal(report.digest, 'e88fa8b182ad1d7b3477516c1432e24a919d1882a4221bf2cb8e25265cff4bd8');
  assert.deepEqual(report.coverage, {total: 2, reviewed: 1, open: 1});
  assert.deepEqual(report.rows.map(r => r.binding), JSON.parse(bytes).transitions.map(r => r.baseline_finding_digest));
  const second = await parseProjection(Buffer.concat([bytes, Buffer.from('\n')]));
  assert.deepEqual(second.rows, report.rows);
  assert.notEqual(second.digest, report.digest);
});

test('tracks mixed sources without counting omissions and negative matches as confirmed issues', async () => {
  const inv = await parseProjection(await fixture('mixed-index.json'));
  assert.equal(inv.rows.length, 6);
  assert.equal(inv.rows.filter(row => row.status === 'hint').length, 3);
  assert.equal(inv.rows.filter(row => row.status === 'observed').length, 2);
  assert.equal(inv.rows.filter(row => row.status === 'excluded').length, 1);
  for (const row of inv.rows) {
    assert.ok(Object.hasOwn(statusLabels, row.status));
    assert.ok(row.details.every(d => typeof d.label === 'string' && typeof d.value === 'string'));
  }
});

test('accepts offsets in typed arrays and isolates bytes before hashing', async () => {
  const bytes = await fixture('mixed-c-result.json');
  const padded = Buffer.concat([Buffer.from('XX'), bytes, Buffer.from('YY')]);
  const view = padded.subarray(2, padded.length - 2);
  const pending = parseProjection(view);
  view.fill(0x20);
  assert.equal((await pending).digest, createHash('sha256').update(bytes).digest('hex'));
});

test('rejects invalid encodings, over-limit, deeply nested and duplicate fields', async () => {
  for (const value of [null, new Uint8Array(), Buffer.alloc(MAX_BYTES + 1), Buffer.from([0xc0, 0x80]), encode('x'),
    Buffer.from('{"x":"unterminated}'), Buffer.from('{"x":0,"\\u0078":1}'),
    Buffer.from('{"a":' + '['.repeat(35) + '1' + ']'.repeat(35) + '}')]) {
    await assert.rejects(parseProjection(value));
  }
});

test('rejects cross-profile payloads, unbound or upgraded evidence', async () => {
  for (const mutate of [p => p.kind = 'federated-surface-index', p => p.finding.control_refs = [], p => p.finding.source_refs = [p.native_execution],
    p => p.external_scanner.assertions[0].verification = 'confirmed',
    p => p.finding.control_refs[0] = p.finding.local_id]) {
    await assert.rejects(altered('mixed-b-result.json', mutate));
  }
});

test('retains inconclusive retests as reviewed and rejects contradictory or duplicate source rows', async () => {
  const report = await altered('mixed-c-result.json', p => p.transitions[0].status = 'inconclusive');
  assert.equal(report.coverage.reviewed, 1);
  assert.equal(report.rows[0].status, 'inconclusive');
  for (const mutate of [p => p.transitions[1].current_finding_digest = p.snapshot_digest,
    p => p.transitions[0].current_finding_digest = null, p => p.transitions[1].finding_id = p.transitions[0].finding_id,
    p => p.transitions[0].status = 'constructor', p => p.transitions[0].baseline_finding_digest = 'invalid',
    p => p.scope_digest = p.scope_digest + '\n']) {
    await assert.rejects(altered('mixed-c-result.json', mutate));
  }
});

test('rejects inventory cardinality, dangling references and negative matcher promoted to a hint', async () => {
  for (const mutate of [p => p.summary.observations++, p => p.services[0].observation_ids.pop(),
    p => p.observations[0].id = p.observations[1].id, p => p.endpoints[0].observation_ids.push(p.index_digest),
    p => p.observations[3].evidence_level = 'hint', p => p.observations[0].evidence_level = 'confirmed']) {
    await assert.rejects(altered('mixed-index.json', mutate));
  }
});

test('recomputes v1 native and federated content digests while preserving domain separation', async () => {
  await assert.rejects(altered('mixed-b-result.json', p => p.finding.check_version = '2.0.0'), /interne Digest/);
  await assert.rejects(altered('mixed-index.json', p => p.observations[0].asserted.length++), /interne Digest/);
});

test('JSON property coercion cannot turn an array into a supported enum', async () => {
  await assert.rejects(altered('mixed-c-result.json', p => p.transitions[0].status = ['fix_verified']));
  await assert.rejects(altered('mixed-index.json', p => p.observations[0].source_kind = ['ffuf']));
});
