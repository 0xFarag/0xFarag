// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const assert = require('node:assert/strict');
const { webcrypto, createHash } = require('node:crypto');
const { readFileSync } = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const importRoot = process.env.AUTHZ_IMPORT_ROOT || path.join(__dirname, '../public/import');
const sandbox = vm.createContext({ crypto: webcrypto, TextEncoder, TextDecoder, URL });
const source = readFileSync(path.join(importRoot, 'adapters.js'), 'utf8');
const adapter = vm.runInContext(source + '\nAuthzImport;', sandbox);
const bytes = text => new TextEncoder().encode(text);
const parse = (format, data) => adapter.parse(format, bytes(typeof data === 'string' ? data : JSON.stringify(data)));
const sample = format => JSON.parse(adapter.samples[format]);
const secret = 'BANANA_PRIVATE_42';

for (const format of ['zap','har','openapi','nuclei']) {
  test(format + ' example has a source digest, one locatable unconfirmed observation and no raw host', async () => {
    const file = await parse(format, adapter.samples[format]);
    assert.equal(file.digest, createHash('sha256').update(adapter.samples[format]).digest('hex'));
    assert.equal(file.rows.length, 1);
    const [row] = file.rows;
    assert.match(row.asset, /^[a-f0-9]{16}$/);
    assert.match(row.identity, /^[a-f0-9]{64}$/);
    assert.match(row.fingerprint, /^[a-f0-9]{64}$/);
    assert.equal(row.locator, format === 'nuclei' ? 'Zeile 1' : 'Datensatz 1');
    assert.doesNotMatch(JSON.stringify(file), /training\.example|confirmed/);
  });
}

test('ZAP risk changes preserve the case; separate parameters and rules stay distinct', async () => {
  const doc = sample('zap');
  const alert = doc.site[0].alerts[0];
  alert.instances[0].evidence = secret;
  alert.instances[0].param = secret;
  alert.instances[0].uri += '?token=' + secret;
  const first = (await parse('zap',doc)).rows[0];
  alert.riskcode = '2';
  const changed = (await parse('zap',doc)).rows[0];
  assert.doesNotMatch(JSON.stringify(first), new RegExp(secret));
  assert.equal(first.identity, changed.identity);
  assert.notEqual(first.fingerprint, changed.fingerprint);
  alert.instances[0].param = 'group';
  assert.notEqual(first.identity, (await parse('zap',doc)).rows[0].identity);
  alert.instances[0].param = secret;
  alert.alertRef = '10001-2';
  assert.notEqual(first.identity, (await parse('zap',doc)).rows[0].identity);
});

test('HAR bodies, headers, cookies and URL credentials stay private; status zero stays distinct', async () => {
  const doc = sample('har');
  const entry = doc.log.entries[0];
  entry.request.method = 'POST';
  entry.request.url = 'https://user:' + secret + '@training.example/form?q=' + secret;
  entry.request.postData = {text:secret};
  entry.request.headers = [{name:'Authorization', value:secret}];
  entry.response.cookies = [{name:'session',value:secret}];
  entry.response.content = {text:secret};
  entry.response.status = 0;
  const before = (await parse('har',doc)).rows[0];
  assert.equal(before.detail, 'POST · Keine HTTP-Antwort');
  entry.response.status = 403;
  const after = (await parse('har',doc)).rows[0];
  assert.match(after.detail, /HTTP 403/);
  assert.equal(before.identity, after.identity);
  assert.notEqual(before.fingerprint, after.fingerprint);
  entry.request.postData.text = 'different';
  assert.notEqual(before.identity, (await parse('har',doc)).rows[0].identity);
  assert.doesNotMatch(JSON.stringify(before), new RegExp(secret));
});

test('OpenAPI reports declarations only and resolves server precedence locally', async () => {
  const doc = sample('openapi');
  doc.paths['/profile'].get.summary = secret;
  doc.paths['/profile'].get.responses = {'200': {$ref:'https://unused.example/' + secret}};
  doc.paths['/profile'].servers = [{url:'https://path.example/api'}];
  doc.paths['/profile'].get.servers = [{url:'https://op.example/api'}];
  const row = (await parse('openapi',doc)).rows[0];
  assert.equal(row.detail,'Deklarierte Operation · GET');
  assert.equal(row.asset, createHash('sha256').update('op.example').digest('hex').slice(0,16));
  assert.doesNotMatch(JSON.stringify(row), new RegExp(secret));
  delete doc.paths['/profile'].get.servers;
  assert.notEqual(row.identity, (await parse('openapi',doc)).rows[0].identity);
  for (const servers of [[], [{url:'/api'}], [{url:'https://{region}.example'}], [{url:'https://a.example'},{url:'https://b.example'}]]) {
    doc.paths['/profile'].servers = servers;
    const unresolved = (await parse('openapi',doc)).rows[0];
    assert.equal(unresolved.asset,'');
    assert.equal(unresolved.identity,null);
  }
});

test('OpenAPI 3.2 inventories QUERY and additionalOperations without reflecting custom method names', async () => {
  const doc = sample('openapi');
  doc.openapi = '3.2.0';
  doc.paths = {'/private': {query:{},additionalOperations:{[secret]:{}}}};
  const rows = (await parse('openapi',doc)).rows;
  assert.deepEqual(Array.from(rows, r=>r.detail), ['Deklarierte Operation · QUERY', 'Deklarierte Operation · Weitere HTTP-Methode']);
  assert.notEqual(rows[0].identity,rows[1].identity);
  assert.doesNotMatch(JSON.stringify(rows),new RegExp(secret));
});

test('Nuclei reads physical line positions, source severity and distinct matchers without outputting payload', async () => {
  const event = sample('nuclei');
  event['matcher-name'] = secret;
  event['template-id'] = secret;
  event['extracted-results'] = [secret];
  event.request = secret;
  event.response = secret;
  const file = await parse('nuclei','\r\n'+ JSON.stringify(event)+'\r\n'+JSON.stringify({...event,'matcher-name':'another'}));
  assert.deepEqual(Array.from(file.rows,r=>r.locator), ['Zeile 2','Zeile 3']);
  assert.notEqual(file.rows[0].identity,file.rows[1].identity);
  assert.doesNotMatch(JSON.stringify(file),new RegExp(secret));
});

test('structured empty containers are accepted as zero observations', async () => {
  for (const [format, doc] of Object.entries({
    zap:{'@version':'2.17',site:[]},
    har:{log:{version:'1.2',entries:[]}},
    openapi:{openapi:'3.1.1',info:{title:'Empty',version:'1'},paths:{}}
  })) assert.equal((await parse(format,doc)).rows.length, 0);
});

test('malformed or out-of-profile entries reject the entire file', async () => {
  const zap = sample('zap');
  zap.site[0].alerts[0].instances.push({uri:'https://another.example/',method:'GET'});
  const openapi = sample('openapi');
  openapi.paths['/only-ref'] = {$ref:'https://never.example/doc'};
  const har = sample('har');
  har.log.entries.push({request:{method:'GET',url:'file:///private'}, response:{status:200}});
  const event = sample('nuclei');
  for (const [format, doc] of [
    ['zap', zap], ['zap', {}], ['zap', {'@version':'2.0',site:[{'@name':'https://x.example',alerts:{}}]}],
    ['har',har], ['har',{log:{version:'1.1',entries:[]}}],
    ['openapi',openapi], ['openapi',{openapi:'3.2.0',info:{},paths:{'/x':{get:null}}}],
    ['nuclei',JSON.stringify(event)+'\n'+JSON.stringify({...event,'matcher-status':false})],
    ['nuclei','\n'],['nuclei',{...event,type:'dns'}],['nuclei',{...event,'matched-at':'https:///bad'}],
  ]) await assert.rejects(parse(format,doc), error=>error instanceof adapter.ImportError);
});

test('record and byte budgets apply atomically to the new profiles', async () => {
  const doc = sample('har');
  doc.log.entries = Array.from({length:1001},()=>doc.log.entries[0]);
  await assert.rejects(parse('har',doc), error=>error instanceof adapter.ImportError);
  await assert.rejects(parse('openapi',' '.repeat(adapter.limits.bytes+1)), error=>error instanceof adapter.ImportError);
});
