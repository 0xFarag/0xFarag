// © Nasser Aldin Farag (0xFarag). All rights reserved.
import test from 'node:test';
import assert from 'node:assert/strict';
import { compareProjections } from '../public/workbench/compare.mjs';

const digest = char => char.repeat(64);
function row(id, fields = {}) {
  return {id,title:'Fall ' + id,source:'Reader',summary:'Datensatz vorhanden',status:'not_retested',
    details:[{label:'Kontrolle',value:'denied'}],binding:digest('c'),...fields};
}
function snapshot(rows, fields = {}) {
  return {kind:'retest',digest:digest('a'),scope:digest('b'),assessment:'mandate-1',baselineExecution:digest('0'),rows,...fields};
}

test('every ID occurs once even when one snapshot omits previously listed cases', () => {
  const left = snapshot([row('x'),row('y'),row('z')]);
  const right = snapshot([row('x'),row('y',{status:'fix_verified'}),row('w')],{digest:digest('e')});
  const result = compareProjections(left,right);
  assert.deepEqual(result.counts,{same:1,changed:1,contextOnly:0,leftOnly:1,rightOnly:1,unbound:0});
  assert.equal(result.leftCount,3);
  assert.equal(result.rightCount,3);
  assert.equal(result.sameFile,false);
  assert.equal(new Set(result.rows.map(entry=>entry.id)).size,4);
  assert.deepEqual(result.rows[1].changes,[{field:'status',label:'Status der Quelle',before:['not_retested'],after:['fix_verified']}]);
  assert.equal(result.rows[2].after,null);
  assert.equal(result.rows[3].before,null);
});

test('incompatible or unbound snapshots report a reason without inferred matches', () => {
  const valid = snapshot([row('a')]);
  const variants = [[null,'missing'], [{kind:'finding'},'kind'],[{scope:digest('e')},'scope'],
    [{scope:''},'scope'],[{baselineExecution:''},'baseline'],[{baselineExecution:digest('1')},'baseline'],[{assessment:'other'},'assessment'],[{assessment:''},'assessment'],[{digest:''},'digest'],
    [{rows:[row('a'),row('a')]},'identity'],[{rows:[row(' ')]},'identity'],[{rows:null},'identity']];
  for (const [override, reason] of variants) {
    const right = override ? {...valid,...override} : null;
    const result = compareProjections(valid, right);
    assert.equal(result.comparable,false);
    assert.equal(result.reason,reason);
    assert.equal(result.rows,undefined);
  }
});

test('missing or divergent stable bindings leave matching IDs visible but incomparable', () => {
  const left = snapshot([row('x'),row('y'),row('z',{binding:''})]);
  const right = snapshot([row('x',{binding:digest('d')}),row('y',{binding:null}),row('z',{binding:''})]);
  const result = compareProjections(left,right);
  assert.equal(result.counts.unbound,3);
  assert.equal(result.rows.every(entry=>entry.state === 'unbound' && !entry.changes.length),true);
});

test('equivalent repeated details do not differ solely on display order', () => {
  const detail = value => ({label:'Kontroll-ID',value});
  const one = snapshot([row('__proto__',{details:[detail('b'),detail('a')]})]);
  const copy = snapshot([row('__proto__',{details:[detail('a'),detail('b')]})], {digest:digest('f')});
  assert.equal(compareProjections(one,copy).counts.same,1);
  assert.equal(compareProjections(one,one).sameFile,true);
  assert.deepEqual(one.rows[0].details, [detail('b'),detail('a')]);
  copy.rows[0].details.push(detail('b'));
  assert.deepEqual(compareProjections(one,copy).rows[0].changes, [{
    field:'detail:Kontroll-ID',label:'Kontroll-ID',before:['a','b'],after:['a','b','b']
  }]);
});

test('empty same-scope projections retain explicit zero totals', () => {
  const result = compareProjections(snapshot([]),snapshot([]));
  assert.equal(result.comparable,true);
  assert.equal(result.rows.length,0);
  assert.equal(result.leftCount,0);
  assert.equal(result.rightCount,0);
});

test('the same display label cannot conceal changes to a top-level field', () => {
  const left = snapshot([row('case',{summary:'one',details:[{label:'Einordnung',value:'x'}]})]);
  const right = snapshot([row('case',{summary:'two',details:[{label:'Einordnung',value:'y'}]})]);
  assert.deepEqual(compareProjections(left,right).rows[0].changes.map(x=>x.field), ['summary','detail:Einordnung']);
});

test('case changes and shared snapshot context changes are counted separately', () => {
  const first = snapshot([row('one',{details:[{label:'Snapshot',value:digest('1')}]})]);
  const later = snapshot([row('one',{details:[{label:'Snapshot',value:digest('2')}]})]);
  const result = compareProjections(first,later);
  assert.equal(result.counts.contextOnly,1);
  assert.equal(result.counts.changed,0);
  assert.equal(result.rows[0].changes[0].label,'Snapshot');
});

test('shipped exercise passes the real reader and retains the skipped case in both snapshots', async () => {
  const {exampleSnapshots} = await import('../public/workbench/compare-example.mjs');
  const [first,second] = await exampleSnapshots();
  const result = compareProjections(first.model,second.model);
  assert.equal(result.sameFile,false);
  assert.equal(first.model.coverage.open,1);
  assert.equal(second.model.coverage.open,1);
  assert.equal(result.counts.changed,1);
  assert.equal(result.counts.contextOnly,1);
  assert.deepEqual(result.rows.map(entry => entry.id), ['uebung-zugriff','uebung-protokoll']);
});

test('unsigned SOC projections cannot assert a shared origin by reusing case IDs, scope or claimed digests', () => {
  const metadata = {kind:'blue',assessment:'assessment-1',scope:digest('f'),retest_sha256:digest('1'),
    signals_sha256:digest('2'),source_snapshot_digest:digest('3')};
  const left = snapshot([row('SOC-case',{binding:digest('1')})],metadata);
  for (const right of [
    {...left,digest:digest('d'),rows:[row('SOC-case',{binding:digest('1'),status:'observed'})]},
    {...left,digest:digest('e'),scope:digest('5')},
    {...left,digest:digest('b'),rows:[row('renamed-case',{binding:digest('1')})]},
    left
  ]) {
    const comparison = compareProjections(left,right);
    assert.equal(comparison.comparable,false);
    assert.equal(comparison.reason,'blue_source_binding');
    assert.equal(comparison.rows,undefined);
    assert.equal(comparison.sameFile,undefined);
  }
});

test('operator SOC reports with copied source hashes and relabelled contexts stay incomparable after import', async () => {
  const {readFile} = await import('node:fs/promises');
  const {parseProjection} = await import('../public/workbench/model.mjs');
  const reference = new URL('../public/proof/blue-evidence-example.json',import.meta.url);
  const first = JSON.parse(await readFile(reference,'utf8'));
  first.synthetic = false;
  first.input_profile = 'authzledger.control-signals.v1';
  const other = structuredClone(first);
  const oldFinding = first.binding.finding;
  other.binding.scope = digest('e');
  other.binding.finding = 'other-finding-id';
  other.source_coverage[other.binding.finding] = other.source_coverage[oldFinding];
  delete other.source_coverage[oldFinding];

  const reader = value => parseProjection(new TextEncoder().encode(JSON.stringify(value)));
  const [left,right] = await Promise.all([reader(first),reader(other)]);
  assert.equal(left.kind,'blue');
  assert.equal(right.kind,'blue');
  assert.notEqual(left.digest,right.digest);
  assert.notEqual(left.scope,right.scope);
  assert.equal(compareProjections(left,right).reason,'blue_source_binding');
});
