// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const {test} = require('node:test');
const {chromium} = require('playwright');

const fixture = name => fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');
const json = JSON.stringify;
const jsonl = records => records.map(record => json(record)).join('\n');
const sha = value => createHash('sha256').update(value).digest('hex');
const host = 'review.example';
const site = 'https://' + host;
const privateUrl = site + '/private-path?id=PRIVATE_PAYLOAD';
const falcoRule = 'Redirect STDOUT/STDIN to Network Connection in Container';
const eventTime = '2024-10-20T10:00:42.123456Z';

const reference = {
  // Nine checked-in tool fixtures carry no customer data. The other inputs are
  // independently authored records; none are loaded from the portal example registry.
  nikto: fixture('nikto.xml'), nmap: fixture('nmap.xml'), burp: fixture('burp.xml'),
  nessus: fixture('nessus.nessus'), ffuf: fixture('ffuf.json'), gobuster: fixture('gobuster.txt'),
  cobalt: fixture('cobalt.json'), bloodhound: fixture('bloodhound-groups.json'), neo4j: fixture('neo4j-inventory.jsonl'),
  nuclei: jsonl(['medium','critical'].map(severity => ({type:'http','template-id':'reference-observation','matched-at':privateUrl,
    'matcher-status':true,info:{severity},response:'PRIVATE_PAYLOAD'}))),
  zap: json({'@version':'2.16.0',site:[{'@name':site,alerts:[{pluginid:'332',riskcode:'2',instances:[
    {uri:privateUrl,method:'HEAD',param:'sensitive',evidence:'PRIVATE_PAYLOAD'}]}]}]}),
  har: json({log:{version:'1.2',creator:{name:'Reference',version:'1.0'},entries:[304,0].map(status => ({
    request:{url:privateUrl,method:'GET',headers:[{name:'Cookie',value:'PRIVATE_PAYLOAD'}]},
    response:{status,content:{text:'PRIVATE_PAYLOAD'}}}))}}),
  openapi: json({openapi:'3.1.0',info:{title:'Reference',version:'1.0'},servers:[{url:site}],
    paths:{'/private-path':{head:{responses:{'204':{description:'No Content'}}}}}}),
  feroxbuster: jsonl([{type:'statistics',requests:81},{type:'response',method:'GET',url:privateUrl,status:301,
    wildcard:false,original_url:site+'/',headers:{location:privateUrl}}]),
  dirbuster: '"Found","Response Code","Content Length"\r\n"/private-path","307","0"\r\n"/private-next","401","42"\r\n',
  sqlmap: 'Target URL,Place,Parameter,Technique(s),Note(s)\n'+privateUrl+',GET,private-name,T,\n'+
    privateUrl+',POST,private-name,B,false positive or unexploitable\n'+site+'/private-next,,,,\n',
  falco: json({source:'syscall',rule:falcoRule,priority:'Warning',time:eventTime,hostname:host,
    output:'PRIVATE_PAYLOAD',output_fields:{'proc.name':'private-process'}})
};

// Each expected row explicitly states the normalized tool classification and its
// source host. An empty host denotes an observation that cannot be tied to a host.
const expected = {
  nikto:[['Item 000017','192.0.2.1'],['Item 000017','beta.example']],
  nmap:[['TCP 443 · open','2001:db8::12']],
  burp:[['Gemeldeter Schweregrad · low','app.example']],
  nessus:[['Plugin 123 · Port 443 · Schweregrad 0','app.example']],
  ffuf:[['HTTP 200','app.example'],['HTTP 403','app.example'],['HTTP 200','app.example']],
  gobuster:[['HTTP 200',''],['HTTP 403',''],['HTTP 301','app.example']],
  cobalt:[['detection · 2024-02-29T23:59:59.120Z','app.example']],
  bloodhound:[[/^Group · [0-9a-f]{32}$/,'corp.example'],[/^User · ref · [0-9a-f]{32}$/,'corp.example'],
    [/^MemberOf · [0-9a-f]{32} → [0-9a-f]{32}$/,'corp.example']],
  neo4j:[[/^User · [0-9a-f]{32}$/,'corp.example'],[/^Group · [0-9a-f]{32}$/,'corp.example'],
    [/^MemberOf · [0-9a-f]{32} → [0-9a-f]{32}$/,'corp.example']],
  nuclei:[['HTTP-Match · gemeldeter Schweregrad medium',host],['HTTP-Match · gemeldeter Schweregrad critical',host]],
  zap:[['Plugin 332 · gemeldete Risikostufe 2',host]],
  har:[['GET · HTTP 304',host],['GET · Keine HTTP-Antwort',host]],
  openapi:[['Deklarierte Operation · HEAD',host]],
  feroxbuster:[['GET · HTTP 301',host]],
  dirbuster:[['HTTP 307',''],['HTTP 401','']],
  sqlmap:[['Vom Werkzeug gemeldeter Hinweis',host],['Vom Werkzeug angezweifelter Hinweis',host],['Keine Technik gemeldet',host]],
  falco:[['warning · '+eventTime,host]]
};

// Keep the identifying file envelope while corrupting a field that the profile
// must validate. For multi-row files, an invalid row invalidates the entire file.
const malformed = {
  nikto:['000017','unknown-id'], nmap:['state="open"','state="unspecified"'],
  burp:['<severity>Low</severity>','<severity>ungraded</severity>'],
  nessus:['severity="0"','severity="7"'], ffuf:['"status":403','"status":"403"'],
  gobuster:['(Status: 403)','(Status: 777)'], cobalt:['2024-02-29','2024-02-31'],
  bloodhound:['"count": 1','"count": 99'], neo4j:['"label":"MemberOf"','"label":"Unrecognised"'],
  nuclei:['"matcher-status":true','"matcher-status":false'], zap:[privateUrl,'https://different.example/'],
  har:['"status":304','"status":601'], openapi:['"openapi":"3.1.0"','"openapi":"2.0"'],
  feroxbuster:['"status":301','"status":800'], dirbuster:['"401"','"601"'],
  sqlmap:[',T,',',X,'], falco:['"priority":"Warning"','"priority":"unknown"']
};

test('independent reference files through the public portal parsers in Chromium', async t => {
  const browser = await chromium.launch({executablePath:process.env.CHROMIUM_BIN || undefined});
  t.after(() => browser.close());
  const context = await browser.newContext({serviceWorkers:'block'});
  const requests = [];
  await context.route('**/*', async route => {
    if (route.request().url() === 'https://reference.invalid/' && !requests.length) {
      requests.push(route.request().url());
      return route.fulfill({contentType:'text/html',body:'<!doctype html><title>Reference test</title>'});
    }
    requests.push(route.request().url());
    await route.abort();
  });
  const page = await context.newPage();
  await page.goto('https://reference.invalid/');
  for (const name of ['directory-profiles','graph-profiles','alert-profile','adapters']) {
    await page.addScriptTag({path:path.join(__dirname, '../public/import', name+'.js')});
  }
  async function parse(content, mode = 'auto') {
    return page.evaluate(async ({content,mode}) => {
      try {
        return {file:await AuthzImport.parse(mode,new TextEncoder().encode(content))};
      } catch (error) {
        if (!(error instanceof AuthzImport.ImportError)) throw error;
        return {rejected:true};
      }
    }, {content,mode});
  }
  assert.deepEqual(Object.keys(expected).sort(), await page.evaluate(() => Object.keys(AuthzImport.definitions).sort()));
  assert.deepEqual(Object.keys(malformed).sort(),Object.keys(expected).sort());
  for (const [tool, rows] of Object.entries(expected)) {
    await t.test('recognized source and classifications: '+tool, async () => {
      const {file} = await parse(reference[tool]);
      assert.ok(file, 'valid reference should be accepted');
      assert.equal(file.source,tool);
      assert.equal(file.digest,sha(reference[tool]));
      assert.equal(file.rows.length,rows.length);
      rows.forEach(([detail,asset], index) => {
        const row = file.rows[index];
        if (detail instanceof RegExp) assert.match(row.detail,detail);
        else assert.equal(row.detail,detail);
        assert.equal(row.asset,asset ? sha(asset).slice(0,16) : '');
        assert.match(row.locator,/^(Zeile|Datensatz) [1-9]\d*$/);
        assert.match(row.fingerprint,/^[a-f0-9]{64}$/);
      });
      assert.doesNotMatch(JSON.stringify(file),/PRIVATE_PAYLOAD|private-|S-1-5-|\.example|192\.0\.2\.|2001:db8/);
    });
    await t.test('rejected malformed data: '+tool, async () => {
      const [before, after] = malformed[tool];
      const content = reference[tool].replace(before,after);
      assert.notEqual(content,reference[tool], 'negative fixture must actually be changed');
      assert.deepEqual(await parse(content),{rejected:true});
    });
  }
  for (const [label,mode,content] of [
    ['unknown text','auto','This is a note about an assessment.'],
    ['ambiguous JSON','auto',json({site:[],results:[]})],
    ['wrong XML profile','burp',reference.nmap],
    ['wrong JSON profile','har',reference.zap],
    ['wrong CSV profile','dirbuster',reference.sqlmap]
  ]) {
    await t.test('rejected '+label, async () => assert.deepEqual(await parse(content,mode),{rejected:true}));
  }
  for (const [tool,content] of [
    ['ffuf',json({results:[]})],
    ['nmap','<nmaprun><host><ports><extraports state="closed" count="1000"/></ports></host></nmaprun>'],
    ['zap',json({'@version':'2.16.0',site:[{'@name':site,alerts:[]}]})]
  ]) {
    await t.test('valid zero-observation reference: '+tool, async () => {
      const {file} = await parse(content);
      assert.equal(file.source,tool);
      assert.equal(file.rows.length,0);
    });
  }
  assert.deepEqual(requests,['https://reference.invalid/']);
});
