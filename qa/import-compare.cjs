// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');
const directory = process.env.AUTHZ_IMPORT_ROOT || path.join(__dirname, '../public/import');
const scope = vm.createContext({ TextEncoder, TextDecoder, URL, crypto: webcrypto });
for (const name of ['adapters.js','compare.js']) {
  vm.runInContext(fs.readFileSync(path.join(directory,name),'utf-8'),scope,{filename:name});
}
const { AuthzImport, AuthzCompare } = vm.runInContext('({AuthzImport,AuthzCompare})',scope);
async function fromFixture(source,input,id,example=false) {
  const file = await AuthzImport.parse(source,new TextEncoder().encode(input));
  return { ...file, id, example };
}
const ffufFile = (results, id='S01') => fromFixture('ffuf',JSON.stringify({results}),id);
const record = (p,status=200,host='training.example') => ({url:'https://'+host+'/'+p,status});
const values = value => structuredClone(value);

test('Repeated records retain distinct locators, later-only and missing records are never linked by display metadata', async () => {
  const a = await ffufFile([record('old'),record('kept')]);
  const b = await ffufFile([record('kept'),record('new')],'S02');
  const rows = AuthzCompare.compare(a,b).entries;
  assert.deepEqual(values(rows.map(r=>r.status)),['earlier_only','repeated','later_only']);
  assert.equal(rows[1].earlier[0].position,2);
  assert.equal(rows[1].later[0].position,1);
});
test('Same source/asset/check and different observed HTTP status gives a record difference, not fix verification', async () => {
  const a = await ffufFile([record('a')]);
  const b = await ffufFile([record('a',403)],'S02');
  const status = AuthzCompare.compare(a,b).entries[0].status;
  assert.equal(status,'different');
});
test('Different asset cannot merge even when path, record position and status agree', async () => {
  const a = await ffufFile([record('a')]);
  const b = await ffufFile([record('a',200,'other.example')],'S02');
  const statuses = AuthzCompare.compare(a,b).entries.map(r=>r.status);
  assert.deepEqual(values(statuses),['earlier_only','later_only']);
});
test('Multiple rows under one key are ambiguous even with an identical fingerprint on both sides', async () => {
  const a = await ffufFile([record('a'),record('a')]);
  const b = await ffufFile([record('a')],'S02');
  const forward = AuthzCompare.compare(a,b).entries[0];
  const reverse = AuthzCompare.compare(b,a).entries[0];
  const state = [forward.status,forward.earlier.length,forward.later.length,reverse.status];
  assert.deepEqual(state,['ambiguous',2,1,'ambiguous']);
});
test('Empty later report retains every earlier observation', async () => {
  const a = await ffufFile([record('a'),record('b')]);
  const b = await ffufFile([],'S02');
  const statuses = AuthzCompare.compare(a,b).entries.map(x=>x.status);
  assert.deepEqual(values(statuses),['earlier_only','earlier_only']);
});
test('Hostless relative Gobuster lines stay unlinked across distinct files even if the line itself repeats',async () => {
  const a = await fromFixture('gobuster','/example (Status: 200)','S01');
  const b = await fromFixture('gobuster','/example (Status: 200)\n/other (Status: 200)','S02');
  const s = AuthzCompare.compare(a,b).entries.map(x=>x.status);
  assert.deepEqual(values(s),['unknown','unknown','unknown']);
});
test('Reject identical files, different sources, mixed workspaces and incomplete file metadata', async () => {
  const a = await ffufFile([record('a')]);
  const b = await ffufFile([record('b')],'S02');
  const states = [AuthzCompare.compare(a,{...a,id:'S03'}),AuthzCompare.compare(a,{...b,source:'nmap'}),AuthzCompare.compare(a,{...b,example:true}),AuthzCompare.compare(a,{...b,digest:null})];
  assert.ok(states.every(result=>typeof result.message==='string' && !result.entries));
});
test('Missing check identity or fingerprint retains unverified rows',async () => {
  const a = await ffufFile([record('a')]);
  const b = await ffufFile([record('a'),record('b')],'S02');
  a.rows[0].identity = null;
  b.rows[0].fingerprint = null;
  const statuses = AuthzCompare.compare(a,b).entries.map(x=>x.status);
  assert.deepEqual(values(statuses),['unknown','unknown','later_only']);
});
