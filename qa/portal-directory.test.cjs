// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const {webcrypto} = require('node:crypto');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const directory = path.join(__dirname, '../public/import');
const context = vm.createContext({TextEncoder, TextDecoder, URL, crypto: webcrypto});
for (const script of ['directory-profiles.js', 'adapters.js', 'asset-review.js']) {
  vm.runInContext(fs.readFileSync(path.join(directory, script), 'utf8'), context);
}
const {AuthzImport: api, AuthzAssets: assets} = vm.runInContext('({AuthzImport, AuthzAssets})', context);
const parse = (text, mode = 'auto') => api.parse(mode, new TextEncoder().encode(text));
const sqlHeader = 'Target URL,Place,Parameter,Technique(s),Note(s)';
const dirHeader = '"Found","Response Code","Content Length"';
const textReport = [
  'DirBuster 1.0-RC1 - Report', 'http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project',
  'Report produced on Sat Nov 28 02:05:15 CET 2026', '--------------------------------', '',
  'https://portal.example:443', '--------------------------------', 'Directories found during testing:', '',
  'Dirs found with a 302 response:', '', '/internal/', '', '--------------------------------',
  'Files found during testing:', '', 'Files found with a 200 responce:', '', '/sensitive-file',
  '', '--------------------------------', 'Errors encountered during testing:', '',
  'https://portal.example/private?key=secret : unreleased-message', ''
].join('\r\n');
test('native DirBuster CSV and full text produce distinct provenance and never guess a host for CSV paths', async () => {
  const csv = await parse(dirHeader + '\r\n"/private,doc","200","30"\r\n');
  const text = await parse(textReport);
  assert.deepEqual(csv, await parse(dirHeader+'\r\n"/private,doc","200","30"\r\n', 'dirbuster'));
  assert.equal(csv.source, 'dirbuster'); assert.equal(csv.rows[0].asset, ''); assert.equal(csv.rows[0].identity, null);
  assert.equal(csv.rows[0].detail, 'HTTP 200'); assert.equal(csv.rows[0].locator, 'Zeile 2');
  assert.equal(text.source, 'dirbuster'); assert.equal(text.rows.length, 2);
  assert.deepEqual(Array.from(text.rows, r => [r.locator,r.detail]), [['Zeile 12','Dir · HTTP 302'],['Zeile 19','File · HTTP 200']]);
  assert.match(text.rows[0].asset, /^[a-f0-9]{16}$/);
  assert.equal(text.rows[0].asset, text.rows[1].asset); assert.notEqual(text.rows[0].identity, text.rows[1].identity);
  const index = assets.createIndex([{...csv,example:false},{...text,example:false}]);
  const first = index.files.find(f => f.sha256 === csv.digest);
  assert.equal(first.observations[0].asset_id, null);
  assert.doesNotMatch(JSON.stringify([text,csv,index]), /portal\.example|sensitive-file|private,doc|unreleased-message|internal\/|secret/);
});
test('native sqlmap CSV handles quoted fields and multiline notes without displaying sensitive data or promoting a signal', async () => {
  const input = [sqlHeader, '"https://portal.example/private?query=a,b",GET,internalParam,BE,"note ""one""',
    'line two"', 'https://portal.example/rest,POST,internalParam,T,review; FALSE POSITIVE OR UNEXPLOITABLE',
    'https://portal.example/blank,,,,', ''].join('\r\n');
  const sql = await parse(input);
  assert.deepEqual(sql, await parse(input,'sqlmap'));
  assert.equal(sql.source,'sqlmap');
  assert.deepEqual(Array.from(sql.rows, r => [r.locator, r.detail]), [
    ['Zeile 2','Vom Werkzeug gemeldeter Hinweis'], ['Zeile 4','Vom Werkzeug angezweifelter Hinweis'],
    ['Zeile 5','Keine Technik gemeldet']]);
  assert.equal(sql.rows[0].asset,(await parse(textReport)).rows[0].asset);
  assert.ok(sql.rows.every(r => r.identity === null));
  assert.doesNotMatch(JSON.stringify(sql), /portal\.example|query=|internalParam|line two|false positive or unexploitable|private|GET|POST/);
});
test('malformed headers, credentials, status, notes and ambiguous results reject the entire report', async () => {
  for (const input of [sqlHeader, sqlHeader+'\nhttps://u:p@portal.example/,GET,a,B,', sqlHeader+'\nhttps://portal.example/a,GET,a,Q,,x',
    sqlHeader+'\n"https://portal.example/a,GET,a,B,', sqlHeader+'\nhttps://portal.example/a,GET,a,,',
    sqlHeader+'\nhttps://portal.example/a,GET,a,X,', sqlHeader+'\nftp://portal.example/a,,,,',
    sqlHeader+'\nhttps://portal.example:0/a,,,,', sqlHeader+'\nhttps://portal.example/,,,,\nhttps://@portal.example/,,,,',
    dirHeader+'\n"/secret","602","77"', dirHeader+'\n"http://private.example/a","200","8"',
    textReport.replace('https://portal.example:443','https://user@portal.example'),
    textReport.replace('Dirs found with a 302 response:', 'Files found with a 302 responce:'),
    textReport.replace('Dirs found with a 302 response:', ''), textReport.replace('/sensitive-file','unknown record')]) {
    await assert.rejects(parse(input), api.ImportError);
  }
  assert.equal((await parse(dirHeader+'\n')).rows.length, 0);
  assert.equal((await parse(textReport.split('Directories found')[0]+'--------------------------------\n')).rows.length,0);
});
test('source row budget applies before a partial CSV enters the portal', async () => {
  await assert.rejects(parse(dirHeader+'\n'+'"/one","200","5"\n'.repeat(1001)), /1’000/);
  await assert.rejects(parse(sqlHeader+'\n'+'https://portal.example/,,,,\n'.repeat(1001)), /1’000/);
  const tooManyTextLines = textReport+'\n'.repeat(16384);
  await assert.rejects(parse(tooManyTextLines), api.ImportError);
});
