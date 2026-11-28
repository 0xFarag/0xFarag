// © Nasser Aldin Farag (0xFarag). All rights reserved.
const test=require('node:test');
const assert=require('node:assert/strict');
const {spawn}=require('node:child_process');
const {randomBytes}=require('node:crypto');
const {once}=require('node:events');
const {mkdtemp,readFile,rm}=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const readline=require('node:readline');
const {chromium}=require('playwright');

test('eight offline tool exports share a scoped dossier, with source-bound directory relationships', {timeout:90000},async t=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),'authz-unified-')), pass=randomBytes(24).toString('hex');
  const server=spawn(process.env.PYTHON || 'python3',['-u','-c',[
    'import os,sys','from team.server import bootstrap, make_server',
    'bootstrap(sys.argv[1],"owner@example.test",os.environ["TEST_PASS"],"Workspace","de")',
    's=make_server(sys.argv[1],port=0)','print(s.server_port)','s.serve_forever()'
  ].join('\n'),dir],{cwd:path.resolve(__dirname,'..'),env:{...process.env,TEST_PASS:pass},stdio:['ignore','pipe','inherit']});
  const closed=once(server,'exit');
  t.after(async()=>{server.kill(); await closed; await rm(dir,{recursive:true,force:true});});
  const [port]=await Promise.race([once(readline.createInterface({input:server.stdout}),'line'),closed.then(()=>{throw Error('Team server exited');})]);
  const origin='http://127.0.0.1:'+port, browser=await chromium.launch({executablePath:process.env.CHROMIUM_BIN || undefined});
  t.after(()=>browser.close());
  const page=await browser.newPage(), studio=page.locator('#view-proof'), external=[],errors=[];
  page.setDefaultTimeout(8000);
  page.on('pageerror',err=>errors.push(err.message));
  page.on('request',req=>{if (/^https?:/.test(req.url()) && !req.url().startsWith(origin+'/')) external.push(req.url());});
  await page.goto(origin);
  await page.locator('#username').fill('owner@example.test');
  await page.locator('#password').fill(pass);
  await page.locator('#login-form button').click();
  await studio.getByLabel('Autorisierte Hosts (ein Host pro Zeile)').fill('corp.example');
  await studio.getByLabel('Rules of Engagement').fill('Review recorded inventory.');
  await studio.getByLabel('Requestbudget').fill('32');
  await studio.getByRole('button',{name:'Dossier anlegen',exact:true}).click();
  const fixture=filename=>readFile(path.join(__dirname,'fixtures',filename),'utf8');
  const target='https://corp.example/api', formats=studio.getByRole('combobox',{name:'Format',exact:true});
  const file=studio.getByLabel('Quelldatei',{exact:true});
  const inputs={
    burp:'<items><item><url>'+target+'</url><method>GET</method><status>200</status></item></items>',
    zap:JSON.stringify({site:[{alerts:[{pluginid:'10001',instances:[{uri:target,method:'GET'}]}]}]}),
    nessus:(await fixture('nessus.nessus')).replace('app.example','corp.example'),
    nuclei:JSON.stringify({type:'http','template-id':'offline-fixture','matcher-status':true,'matched-at':target}),
    nikto:(await fixture('nikto.xml')).replace('beta.example','corp.example'),
    sqlmap:'Target URL,Place,Parameter,Technique(s),Note(s)\n'+target+'?user=private-value,GET,user,B,\n',
    bloodhound:await fixture('bloodhound-groups.json'), neo4j:await fixture('neo4j-inventory.jsonl')
  };
  const submit=studio.getByRole('button',{name:'Beobachtungen importieren',exact:true});
  // A filename alone cannot trigger an upload or select an ambiguous format.
  await file.setInputFiles({name:'scanner.nessus',mimeType:'application/octet-stream',buffer:Buffer.from('{}')});
  await studio.getByText(/nicht eindeutig erkannt/).waitFor();
  assert.equal(await formats.inputValue(),'');
  const ids=Object.keys(inputs);
  for (const [n,id] of ids.entries()) {
    const entry={name:'saved.txt',mimeType:'text/plain',buffer:Buffer.from(inputs[id])};
    await file.setInputFiles(entry);
    await studio.getByText(/^Erkanntes Format /).waitFor();
    assert.equal(await formats.inputValue(),id);
    if (id==='burp') {
      await formats.selectOption('nessus');
      await submit.click();
      await studio.locator('.ps-notice').filter({hasText:/Datei passt nicht/}).waitFor();
      await formats.selectOption('burp');
    }
    await submit.click();
    await studio.getByRole('heading',{name:'Beweis',exact:true}).waitFor();
    if (n+1<ids.length) await studio.getByRole('button',{name:'Weitere Quelle importieren',exact:true}).click();
  }
  const summary=studio.getByText('Hosts mit mehreren Werkzeugquellen',{exact:true});
  await summary.click();
  const hostRows=summary.locator('..').getByRole('row');
  const byHost=await hostRows.nth(1).innerText();
  for (const label of ['corp.example','Burp Suite','OWASP ZAP','Nessus','Nuclei','Nikto','sqlmap','BloodHound','Neo4j'])
    assert(byHost.includes(label),label);
  const inventory=studio.getByRole('region',{name:'Verzeichnisinventar'});
  for (const label of ['BloodHound','Neo4j']) {
    const group=inventory.locator('details').filter({has:page.locator(':scope > summary').filter({hasText:new RegExp('^'+label+' · ')})}).first();
    await group.locator(':scope > summary').click();
    const row=group.getByRole('row').filter({hasText:'MemberOf'});
    assert.match(await row.innerText(),/corp\.example/);
    assert.match(await row.innerText(),/User · [a-f0-9]{32}/);
    assert.match(await row.innerText(),/Group · [a-f0-9]{32}/);
  }
  const evidenceText=await studio.innerText();
  assert.doesNotMatch(evidenceText,/private-group|private-user|S-1-5-21|private-value|PRIVATE_PAYLOAD/);
  const pending=page.waitForEvent('download');
  await studio.getByRole('button',{name:'Berichtsdaten (JSON)',exact:true}).click();
  const report=JSON.parse(await readFile(await (await pending).path(),'utf8'));
  assert.deepEqual(Object.keys(report.sources.byFormat).sort(),ids.sort());
  assert.equal(report.baseline.byStatus.confirmed,0);
  assert.equal(report.baseline.byStatus.out_of_scope,1);
  assert.equal(report.coverage.scopedHosts,1);
  assert.deepEqual(external,[]);
  assert.deepEqual(errors,[]);
});
