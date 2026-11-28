// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const path = require('node:path');
const {createHash} = require('node:crypto');
const vm = require('node:vm');
const root = path.join(__dirname, '..');
const graph = vm.runInNewContext(readFileSync(path.join(root, 'public/import/graph-profiles.js'), 'utf8') + '\nAuthzGraphProfiles;');
const sha = value => createHash('sha256').update(value).digest('hex');
const sourceFile = name => readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');
const bhFile = sourceFile('bloodhound-groups.json');
const neoFile = sourceFile('neo4j-inventory.jsonl');
const lines = text => text.trim().split('\n').map(line => JSON.parse(line));
const jsonl = items => items.map(item => JSON.stringify(item)).join('\n');
class ImportError extends Error {}
const parse = (source, input) => graph.records(source, input, {fileDigest: sha(input), digest: sha, ImportError});

test('native inventories share a domain and keep graph object identities inside their source file', async () => {
  for (const [source, sample] of [['bloodhound', bhFile], ['neo4j', neoFile]]) {
    assert.equal(graph.detect(source === 'bloodhound' ? JSON.parse(sample) : lines(sample)[0]), source);
    const actual = await parse(source, sample);
    assert.equal(actual.length, 3);
    assert.ok(actual.every(row => row.asset === 'corp.example' && row.identity === null));
    const user = actual.find(row => row.detail.startsWith('User '));
    const group = actual.find(row => row.detail.startsWith('Group '));
    const membership = actual.find(row => row.detail.startsWith('MemberOf '));
    const alias = detail => detail.match(/[0-9a-f]{32}$/)[0];
    assert.equal(user.detail.includes('ref'), source === 'bloodhound');
    assert.equal(membership.detail, 'MemberOf · ' + alias(user.detail) + ' → ' + alias(group.detail));
    assert.equal(membership.locator, source === 'bloodhound' ? 'Datensatz 1' : 'Zeile 3');
    assert.doesNotMatch(JSON.stringify(actual), /private-|S-1-5/);
    const other = await parse(source, sample + '\n');
    assert.ok(!JSON.stringify(other).includes(alias(user.detail)));
    assert.equal((await parse(source, graph.samples[source])).length, 3);
  }
});

test('required domains, endpoint declarations, relation types and JSON object keys are validated', async () => {
  for (const change of [
    rows => rows.shift(), rows => rows.push(rows[0]),
    rows => {rows[0].properties.domain = '192.0.2.1';},
    rows => {rows[0].properties.domain = 'other.example';},
    rows => {rows[2].start.properties = {domain:'other.example'};},
    rows => {rows[2].start.labels = ['Group'];},
    rows => {rows[2].label = 'unsupported';},
    rows => {rows[2].label = 'Contains';},
    rows => {rows[2].start = rows[2].end;},
    rows => rows.push(rows[2]),
    rows => {rows[0].labels = ['User', 'User'];}
  ]) {
    const rows = lines(neoFile); change(rows);
    await assert.rejects(parse('neo4j', jsonl(rows)), ImportError);
  }
  const valid = lines(neoFile);
  valid[0].labels = ['OU'];
  valid[2].start = {id: valid[0].id};
  valid[2].label = 'Contains';
  const output = await parse('neo4j', jsonl(valid.reverse()));
  assert.ok(output.some(row => row.detail.startsWith('Contains ') && row.locator === 'Zeile 1'));
  const withDuplicateKey = neoFile.replace('"domain":', '"d\\u006fmain":"other.example","domain":');
  await assert.rejects(parse('neo4j', withDuplicateKey), ImportError);
  const rows = Array.from({length:1001}, (_, i) => ({...valid[2], id:String(i)}));
  await assert.rejects(parse('neo4j', jsonl(rows)), ImportError);
});

test('group headers and SID boundaries are enforced and group references can be resolved later', async () => {
  for (const change of [
    data => {data.meta.count = 0;}, data => {data.meta.version = 7;},
    data => {data.data[0].Properties.domain = 'https://corp.example/';},
    data => {data.data[0].Properties.domainsid = 'S-1-5-21-10-20-31';},
    data => {data.data[0].Members[0].ObjectIdentifier = 'S-1-5-21-10-20-31-1500';},
    data => {data.data[0].Members.push(data.data[0].Members[0]);}
  ]) {
    const data = JSON.parse(bhFile); change(data);
    await assert.rejects(parse('bloodhound', JSON.stringify(data)), ImportError);
  }
  const data = JSON.parse(bhFile), member = data.data[0].Members[0];
  member.ObjectType = 'Group';
  data.data.push({ObjectIdentifier: member.ObjectIdentifier, Properties: data.data[0].Properties, Members: []});
  data.meta.count++;
  const output = await parse('bloodhound', JSON.stringify(data));
  assert.ok(output.every(row => !row.detail.includes('ref')));
  assert.ok(output.some(row => row.detail.startsWith('Group ') && row.locator === 'Datensatz 2'));
});

test('automatic public intake hashes domains and exports no raw directory identifiers', async () => {
  const context = vm.createContext({URL, TextEncoder, TextDecoder, crypto: require('node:crypto').webcrypto});
  for (const script of ['graph-profiles.js', 'adapters.js', 'asset-review.js']) {
    vm.runInContext(readFileSync(path.join(root, 'public/import', script), 'utf8'), context);
  }
  const registry = vm.runInContext('({importer: AuthzImport, assets: AuthzAssets})', context);
  const files = [];
  for (const [source, input] of [['bloodhound', bhFile], ['neo4j', neoFile]]) {
    const file = await registry.importer.parse('auto', Buffer.from(input));
    assert.equal(file.source, source);
    assert.equal(file.digest, sha(input));
    assert.ok(file.rows.every(row => row.asset === sha('corp.example').slice(0, 16)));
    files.push({...file, example:false});
  }
  const index = registry.assets.createIndex(files);
  assert.equal(index.files.length, 2);
  assert.ok(index.files.every(file => file.observations.length === 3));
  assert.doesNotMatch(JSON.stringify([files, index]), /corp\.example|private-|S-1-5/);
});
