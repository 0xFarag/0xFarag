// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const assert = require('node:assert/strict');
const {test} = require('node:test');
const {webcrypto, createHash} = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const directory = process.env.AUTHZ_IMPORT_ROOT || path.join(__dirname, '../public/import');
const context = vm.createContext({TextEncoder, TextDecoder, URL, crypto:webcrypto});
for (const file of ['adapters.js', 'compare.js', 'asset-review.js']) {
  vm.runInContext(fs.readFileSync(path.join(directory, file), 'utf8'), context);
}
const {AuthzImport, AuthzCompare, AuthzAssets} = vm.runInContext('({AuthzImport,AuthzCompare,AuthzAssets})', context);
const parse = (input) => AuthzImport.parse('feroxbuster', new TextEncoder().encode(input));
const toFile = async (input) => ({...await parse(input), example:false});
const asLines = (...entries) => entries.map(entry => JSON.stringify(entry)).join('\n');
const sha = data => createHash('sha256').update(data).digest('hex');

// Rust FeroxResponse::serialize field set, with synthetic values.
// https://docs.rs/crate/feroxbuster/2.14.0/source/src/response.rs
// Metadata types: src/config/container.rs, src/statistics/container.rs, src/message.rs.
const response = {
  type:'response', url:'https://reports.example/result?key=classified', original_url:'https://portal.example/',
  path:'/result', wildcard:false, status:302, method:'GET', content_length:20, line_count:1, word_count:3,
  headers:{location:'https://secret.example/location', 'set-cookie':'example=sensitive'}, extension:'',
  truncated:false, timestamp:1767225600.125,
};
const configuration = {type:'configuration', target_url:'https://portal.example/', status_codes:[200,302], headers:{authorization:'secret'}};
const statistics = {type:'statistics', requests:165, total_expected:200};
const log = {type:'log', message:'classified', level:'WARN', module:'example'};

test('Native NDJSON tracks only response positions, fingerprints the exact file and never exposes private fields', async () => {
  const input = '\n' + asLines(configuration, response, log, statistics).replaceAll('\n','\r\n') + '\n';
  const file = await toFile(input);
  assert.equal(file.source, 'feroxbuster');
  assert.equal(file.digest, sha(input));
  assert.equal(file.rows.length, 1);
  assert.equal(file.rows[0].locator, 'Zeile 3');
  assert.equal(file.rows[0].asset, sha('reports.example').slice(0, 16));
  assert.equal(file.rows[0].detail, 'GET · HTTP 302');
  assert.match(file.rows[0].identity, /^[0-9a-f]{64}$/);
  assert.equal(AuthzAssets.createIndex([file]).files[0].observations[0].locator, 'Zeile 3');
  assert.doesNotMatch(JSON.stringify(file), /classified|secret|reports\.example|portal\.example|set-cookie|location|authorization/);
  assert.deepEqual(Object.keys(JSON.parse(AuthzImport.samples.feroxbuster)).sort(), Object.keys(response).sort());
});

test('Changed status remains comparable only for matching final URL, original URL and method', async () => {
  const first = await toFile(asLines(response));
  const changed = await toFile(asLines({...response,status:200}));
  assert.equal(AuthzCompare.compare(first, changed).entries[0].status, 'different');
  for (const override of [{method:'HEAD'}, {url:'https://reports.example/new'}, {original_url:'https://other.example/'}]) {
    const other = await toFile(asLines({...response,...override}));
    assert.deepEqual(Array.from(AuthzCompare.compare(first, other).entries, x => x.status), ['earlier_only','later_only']);
  }
  for (const override of [{wildcard:true}, {wildcard:undefined}, {original_url:''}, {original_url:undefined}]) {
    const other = await toFile(asLines({...response,...override}));
    assert.equal(other.rows[0].identity, null);
  }
});

test('Unknown row types, malformed metadata/URL/status/method and empty reports reject the whole file', async () => {
  for (const invalid of [
    {type:'progress'}, {type:'statistics', requests:-1}, {type:'configuration'}, {type:'log',message:13},
    {...response, url:'/relative'}, {...response, url:'file:///temporary'}, {...response, method:'broken method'},
    {...response, status:'302'}, {...response, status:600}, {...response, content_length:-1},
    {...response, original_url:'invalid'}, {...response, wildcard:'false'}
  ]) await assert.rejects(parse(asLines(response, invalid)), AuthzImport.ImportError);
  await assert.rejects(parse(asLines(configuration, statistics, log)), /keine Antwortzeile/);
  await assert.rejects(parse(asLines(response) + '\n{broken'), /Ungültiges JSON/);
});

test('Line and response budgets fail closed before a partially imported file reaches the review', async () => {
  const compact = JSON.stringify({type:'response',url:'https://fixture.invalid/',method:'GET',status:200});
  await assert.rejects(parse(Array.from({length:1001}, () => compact).join('\n')), /1’000/);
  assert.equal((await parse('\n'.repeat(4095) + compact + '\n')).rows[0].locator, 'Zeile 4096');
  await assert.rejects(parse('\n'.repeat(4096) + compact), /4’096/);
});
