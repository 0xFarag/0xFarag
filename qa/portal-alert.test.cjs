// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {webcrypto} = require('node:crypto');
const {readFileSync} = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ctx = vm.createContext({crypto:webcrypto, TextEncoder, TextDecoder, URL});
for (const file of ['alert-profile.js','adapters.js']) {
  vm.runInContext(readFileSync(path.join(__dirname,'../public/import',file),'utf8'), ctx);
}
const api = vm.runInContext('AuthzImport',ctx);
const event = JSON.parse(api.samples.falco);
const bytes = (...events) => new TextEncoder().encode(events.map(x=>JSON.stringify(x)).join('\n'));
test('stored Falco signals retain time, declared priority and pseudonymous host only', async () => {
  const first = {...event, output:'sensitive-output', output_fields:{'user.name':'sensitive-principal'}};
  const second = {...first,time:'2026-01-15T10:00:01Z',hostname:undefined};
  const result = await api.parse('auto', bytes(first, second));
  assert.equal(result.source,'falco');
  assert.equal(result.rows.length,2);
  assert.match(result.rows[0].asset,/^[0-9a-f]{16}$/);
  assert.equal(result.rows[1].asset,'');
  assert.equal(result.rows[0].identity,null);
  assert.equal(result.rows[0].detail,'notice · ' + first.time);
  assert.equal(result.rows[1].locator,'Zeile 2');
  assert.doesNotMatch(JSON.stringify(result), /training\.example|sensitive-/);
});
test('wrong, ambiguous, mixed and invalid Falco records fail closed', async () => {
  for (const changes of [{rule:'Different detector'}, {source:'custom'}, {output_fields:null},
    {time:'2026-02-31T00:00:00Z'}, {priority:'other'}, {hostname:'private/path'}]) {
    await assert.rejects(api.parse('falco',bytes(event,{...event,...changes})), e => e instanceof api.ImportError);
  }
  await assert.rejects(api.parse('auto',bytes({...event,results:[]})), e => e instanceof api.ImportError);
});
