// © Nasser Aldin Farag (0xFarag). All rights reserved.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {parseProjection, statusLabels} from '../public/workbench/model.mjs';

const proof = new URL('../public/proof/', import.meta.url);
const bytes = await readFile(new URL('blue-evidence-example.json', proof));
const raw = JSON.parse(bytes);
const sha = b => createHash('sha256').update(b).digest('hex');
const modify = fn => {
  const copy = structuredClone(raw);
  fn(copy);
  return parseProjection(new TextEncoder().encode(JSON.stringify(copy)));
};

test('published SOC example is bound to the shipped original Retest and signal fixture', async () => {
  assert.equal(sha(bytes), 'fee007d0005cab05c797d00cd6c5157d2f4a1611679e22c1ebcc89f731ac12c6');
  assert.equal(sha(await readFile(new URL('mixed-c-result.json', proof))), raw.retest_sha256);
  assert.equal(sha(await readFile(new URL('blue-evidence-signals.json', proof))), raw.signals_sha256);
  const projection = await parseProjection(bytes);
  assert.equal(projection.kind, 'blue');
  assert.equal(projection.digest, sha(bytes));
  assert.equal(projection.assessment, raw.binding.assessment);
  assert.equal(projection.scope, raw.binding.scope);
  assert.equal(projection.coverage, null);
  assert.deepEqual(projection.rows.map(r => r.status), ['soc_observed', 'soc_telemetry_only', 'soc_incomparable', 'soc_unavailable']);
  assert.ok(projection.rows.every(r => Object.hasOwn(statusLabels, r.status)));
  assert.deepEqual(projection.rows[0].signalCoverage, {eligible: 2, linked: 1, excluded: 1, detailed: true});
  assert.deepEqual(projection.signalCoverage, {windows: 4, observedWindows: 1, telemetryOnlyWindows: 1, incomparableWindows: 1,
    unavailableWindows: 1, eventOccurrences: 5, eligibleOccurrences: 3, linkedOccurrences: 1, excludedOccurrences: 2, detailed: true});
  assert.ok(projection.rows[0].details.some(d => d.value === 'evt-lab-002'));
});

test('reader supports original PR-7 output and exposes derivation limits', async () => {
  const model = await modify(d => {
    for (const sample of Object.values(d.samples)) delete sample.alert_coverage;
  });
  assert.equal(model.signalCoverage.detailed, false);
  assert.equal(model.rows[0].signalCoverage.detailed, false);
  assert.equal(model.signalCoverage.linkedOccurrences, 1);
  assert.ok(model.rows[0].details.some(d => d.value.includes('Älteres Format')));
});

test('operator-supplied data retains operator window IDs and distinguishes repeated alerts', async () => {
  const model = await modify(d => {
    d.input_profile = 'authzledger.control-signals.v1'; d.synthetic = false;
    d.samples.matched.alert_count = 2;
  });
  assert.equal(model.rows[0].title, 'Signalfenster matched');
  assert.equal(model.rows[0].signalCoverage.linked, 1);
  assert.ok(model.rows[0].details.some(d => d.value === 'Vom Betreiber bereitgestellte Signaldaten'));
});

test('rejects conflicting scope, profile, trust and source coverage claims', async () => {
  for (const change of [d => d.signed = true, d => d.source_assertions_verified = true,
    d => d.synthetic = false, d => d.input_profile = 'other', d => d.retest_sha256 = 'bad',
    d => d.source_retest_status = 'inconclusive', d => delete d.source_coverage[d.binding.finding],
    d => d.source_coverage['second'] = ['unchanged'], d => d.binding.scope = 3,
    d => d.demo = 'C', d => d.samples = {}, d => d.scope_digest = d.signals_sha256]) {
    await assert.rejects(modify(change));
  }
});

test('rejects inconsistent/forged sums, duplicate or unrelated event IDs, mixed legacy coverage and impossible statuses', async () => {
  const changes = [
    x => x.matching_events.push(x.matching_events[0]), x => x.alerted_events.push('other'),
    x => x.alerted_events.push(x.alerted_events[0]), x => x.alert_coverage.eligible_events++,
    x => x.alert_coverage.linked_events++, x => x.alert_coverage.excluded_events++,
    x => x.alert_coverage.unlinked_event_ids = [], x => x.alert_coverage.unlinked_event_ids[0] = 'different',
    x => x.alert_coverage.unlinked_event_ids.push(x.alert_coverage.unlinked_event_ids[0]),
    x => x.status = 'telemetry_only', x => x.alert_count = 0, x => x.event_count = 1,
    x => x.event_count = 4097, x => x.alert_count = '1', x => x.event_count = -1,
    x => delete x.alert_coverage, x => x.alert_coverage.eligible_events = '2'
  ];
  for (const change of changes) await assert.rejects(modify(d => change(d.samples.matched)));
});

test('timestamps preserve microsecond order and explicit offsets, reject invalid calendar dates', async () => {
  await modify(d => { d.window = {from: '2026-01-01T00:00:00.000001Z', until: '2026-01-01T01:00:00.000002+01:00'}; });
  for (const window of [
    {from: '2026-01-01T00:00:00.000002Z', until: '2026-01-01T01:00:00.000001+01:00'},
    {from: '2026-02-29T01:00:00Z', until: '2026-03-02T00:00:00Z'},
    {from: '2026-05-01T00:00:00', until: '2026-05-02T00:00:00Z'}
  ]) await assert.rejects(modify(d => d.window = window));
});
