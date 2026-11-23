// © Nasser Aldin Farag (0xFarag). All rights reserved.
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {fileURLToPath} from 'node:url';
import {makeBaseline, readPolicy, retestPolicy, sha256} from '../public/rbac/retest.mjs';

const apiGroup = 'rbac.authorization.k8s.io';
const apiVersion = apiGroup + '/v1';
const records = [
  {apiVersion,kind:'Role',metadata:{namespace:'ops', name:'reader'},
    rules:[{apiGroups:[''],resources:['pods'],verbs:['get']}]},
  {apiVersion,kind:'RoleBinding',metadata:{namespace:'ops',name:'readers'},
    roleRef:{apiGroup,kind:'Role',name:'reader'}, subjects:[{kind:'User',name:'alex'}]}
];
const member = {kind:'User',name:'alex',groups:[],namespace:'ops',apiGroup:'',resource:'pods',verb:'get'};
const visitor = {...member, name:'jordan'};
const source = data => new TextEncoder().encode(JSON.stringify(data));
const original = source(records);
const noRules = source([{...records[0],rules:[]}, records[1]]);
const missingRole = source([records[1]]);
const digest = value => createHash('sha256').update(value).digest('hex');
const baseline = (queries = [member, visitor], src = original) => makeBaseline(digest(src), queries, readPolicy(src));

test('retest binds its results to original bytes, current bytes and regenerated query outcomes', async () => {
  const basis = await baseline();
  const result = await retestPolicy(basis, original, noRules);
  assert.equal(result.signature,'unsigned');
  assert.equal(result.original_policy_sha256,digest(original));
  assert.equal(result.current_policy_sha256,digest(noRules));
  assert.equal(result.baseline_sha256,basis.baseline_sha256);
  assert.equal(result.identical_source_bytes,false);
  assert.equal(result.cases[0].id,basis.cases[0].id);
  assert.equal(result.cases[0].before.status,'granted_in_snapshot');
  assert.equal(result.cases[0].after.status,'no_grant_in_snapshot');
  assert.equal(result.cases[0].status,'snapshot_decision_changed');
  assert.equal(result.cases[1].status,'snapshot_result_repeated');
});

test('changed proof location with equivalent permission remains a change of evidence', async () => {
  const result = await retestPolicy(await baseline([member]), original, source([records[1],records[0]]));
  assert.equal(result.cases[0].status,'snapshot_evidence_changed');
  assert.equal(result.cases[0].before.status,result.cases[0].after.status);
  assert.notEqual(result.cases[0].before.proof_sha256,result.cases[0].after.proof_sha256);
});

test('a matching rule narrowed at the same position changes evidence even when access is preserved', async () => {
  const broader = structuredClone(records);
  broader[0].rules[0].verbs = ['*'];
  const before = source(broader);
  const result = await retestPolicy(await baseline([member],before), before, original);
  assert.equal(result.cases[0].before.status, 'granted_in_snapshot');
  assert.equal(result.cases[0].after.status, 'granted_in_snapshot');
  assert.equal(result.cases[0].status, 'snapshot_evidence_changed');
  assert.notEqual(result.cases[0].before.proof_sha256, result.cases[0].after.proof_sha256);
});

test('more than 500 matching rule references cannot establish an identical full proof', async () => {
  const policy = [records[0],...Array.from({length:501},(_,i)=>({...records[1],metadata:{namespace:'ops',name:'b'+i}}))];
  const bytes = source(policy), basis = await baseline([member],bytes);
  assert.equal(basis.cases[0].outcome.match_count,501);
  assert.equal(basis.cases[0].outcome.proof_complete,false);
  const result = await retestPolicy(basis,bytes,bytes);
  assert.equal(result.identical_source_bytes,true);
  assert.equal(result.cases[0].status,'indeterminate');
});

test('incomplete inputs keep an indeterminate result in either direction', async () => {
  const forward = await retestPolicy(await baseline([member]), original, missingRole);
  const backward = await retestPolicy(await baseline([member],missingRole), missingRole, original);
  assert.equal(forward.cases[0].after.status,'indeterminate');
  assert.equal(backward.cases[0].before.status,'indeterminate');
  assert.equal(forward.cases[0].status,'indeterminate');
  assert.equal(backward.cases[0].status,'indeterminate');
});

test('partial and empty selections retain historical observations with no current result', async () => {
  const basis = await baseline();
  for (const [selection, retested] of [[[1],1],[[],0]]) {
    const result = await retestPolicy(basis, original, noRules, selection);
    assert.deepEqual(result.coverage,{total:2,retested,not_retested:2-retested});
    for (const [i,item] of result.cases.entries()) {
      if (!selection.includes(i)) {
        assert.equal(item.status,'not_retested');
        assert.deepEqual(item.before,basis.cases[i].outcome);
        assert.equal(item.after,null);
      }
    }
  }
});

test('byte-identical policy files give an explicit flag and retain the original proof', async () => {
  const basis = await baseline();
  const result = await retestPolicy(basis,original,Buffer.from(original));
  assert.equal(result.identical_source_bytes,true);
  assert.deepEqual(result.coverage,{total:2,retested:2,not_retested:0});
  for (const entry of result.cases) {
    assert.equal(entry.status,'snapshot_result_repeated');
    assert.deepEqual(entry.before,entry.after);
  }
});

test('tampered source, reordered cases, invented grant, changed query and altered baseline digest all fail', async () => {
  const basis = await baseline();
  const prettyBytes = Buffer.from(JSON.stringify(records,null,2));
  await assert.rejects(retestPolicy(basis, prettyBytes, noRules));
  for (const modify of [
    b=>{b.cases.reverse();}, b=>{b.cases[1].outcome.status='granted_in_snapshot';},
    b=>{b.cases[0].query.name='jordan';}, b=>{b.baseline_sha256='0'.repeat(64);},
    b=>{b.cases[0].outcome.match_count=999;}, b=>{b.policy_sha256='f'.repeat(64);}
  ]) {
    const altered = structuredClone(basis); modify(altered);
    await assert.rejects(retestPolicy(altered, original,noRules));
  }
  assert.equal(await sha256(original),digest(original));
});

test('duplicate normalized queries and invalid selections fail atomically', async () => {
  const otherOrder = {...member,groups:['ops','audit','audit']};
  await assert.rejects(baseline([otherOrder, {...member,groups:['audit','ops']}]),/doppelte Frage/);
  const basis = await baseline();
  for (const selection of [[0,0],[-1],[2],[0.5],['1'],null]) {
    await assert.rejects(retestPolicy(basis, original,noRules,selection),/Fallauswahl/);
  }
});

test('normal Node CLI paths support check, baseline and source-bound subset retest including failure exit codes', async t => {
  const dir = await mkdtemp(path.join(os.tmpdir(),'authz-rbac-qa-'));
  t.after(()=>rm(dir,{force:true,recursive:true}));
  const cli = fileURLToPath(new URL('../public/rbac/cli.mjs',import.meta.url));
  await Promise.all([
    writeFile(path.join(dir,'before.json'),original),writeFile(path.join(dir,'after.json'),noRules),
    writeFile(path.join(dir,'case.json'),JSON.stringify(member)),writeFile(path.join(dir,'cases.json'),JSON.stringify([member,visitor]))
  ]);
  const run = (...args) => spawnSync(process.execPath,[cli,...args],{cwd:dir,encoding:'utf8',timeout:12000});
  const ok = (...args) => {
    const proc = run(...args);
    assert.equal(proc.status,0,proc.stderr);
    return JSON.parse(proc.stdout);
  };
  const checked = ok('check','before.json','case.json');
  assert.equal(checked.result.status,'granted_in_snapshot');
  await writeFile(path.join(dir,'unexpected.json'),JSON.stringify({...member,annotation:'private-marker'}));
  const invalidCheck = run('check','before.json','unexpected.json');
  assert.equal(invalidCheck.status,2);
  assert.equal(invalidCheck.stdout,'');
  assert.doesNotMatch(invalidCheck.stderr,/private-marker/);
  const basis = ok('baseline','before.json','cases.json');
  await writeFile(path.join(dir,'baseline.json'),JSON.stringify(basis));
  const args = ['retest','baseline.json','before.json','after.json'];
  assert.deepEqual(ok(...args).coverage,{total:2,retested:2,not_retested:0});
  assert.deepEqual(ok(...args,'none').coverage,{total:2,retested:0,not_retested:2});
  assert.deepEqual(ok(...args,'1').cases.map(c=>c.status),['snapshot_decision_changed','not_retested']);
  for (const invalid of ['0','1,1','3','']) {
    const failed = run(...args,invalid);
    assert.equal(failed.status,2);
    assert.equal(failed.stdout,'');
  }
  const swapped = run('retest','baseline.json','after.json','before.json');
  assert.equal(swapped.status,2);
  assert.equal(swapped.stdout,'');
});
