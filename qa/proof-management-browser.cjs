// © Nasser Aldin Farag (0xFarag). All rights reserved.
const test = require('node:test');
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const {randomBytes} = require('node:crypto');
const {once} = require('node:events');
const {mkdtemp, readFile, rm} = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const {chromium} = require('playwright');

test('scanner imports and versioned management reports in the signed-in Team UI', {timeout:90000}, async t => {
  const data = await mkdtemp(path.join(os.tmpdir(),'authz-management-'));
  const password = randomBytes(24).toString('hex');
  const server = spawn(process.env.PYTHON || 'python3',['-u','-c',[
    'import os,sys','from team.server import bootstrap, make_server',
    'bootstrap(sys.argv[1],"manager@example.test",os.environ["TEST_PASS"],"Workspace","de")',
    'server=make_server(sys.argv[1],port=0)','print(server.server_port)','server.serve_forever()'
  ].join('\n'),data],{cwd:path.resolve(__dirname,'..'),env:{...process.env,TEST_PASS:password},stdio:['ignore','pipe','inherit']});
  const closed=once(server,'exit');
  t.after(async()=>{server.kill(); await closed; await rm(data,{recursive:true,force:true});});
  const [port]=await Promise.race([once(readline.createInterface({input:server.stdout}),'line'),closed.then(()=>{throw Error('Team server exited');})]);
  const browser=await chromium.launch({executablePath:process.env.CHROMIUM_BIN || undefined});
  t.after(()=>browser.close());
  const page=await browser.newPage(), studio=page.locator('#view-proof');
  page.setDefaultTimeout(6000);
  const errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.goto('http://127.0.0.1:'+port);
  async function login(username) {
    await page.locator('#username').fill(username);
    await page.locator('#password').fill(password);
    await page.locator('#login-form button').click();
    await studio.locator('#ps-case').waitFor();
  }
  async function download(name) {
    const pending=page.waitForEvent('download');
    await studio.getByRole('button',{name,exact:true}).click();
    const file=await pending;
    return {name:file.suggestedFilename(),text:await readFile(await file.path(),'utf8')};
  }
  await login('manager@example.test');
  assert.equal(await studio.getByRole('button',{name:'Managementbericht (HTML)'}).count(),0);
  await studio.getByLabel('Autorisierte Hosts (ein Host pro Zeile)').fill('app.example\n192.0.2.1\nbeta.example');
  await studio.getByLabel('Rules of Engagement').fill('Review recorded observations.');
  await studio.getByRole('button',{name:'Dossier anlegen'}).click();
  const initial=JSON.parse((await download('Berichtsdaten (JSON)')).text);
  assert.equal(initial.evidenceStatus,'awaiting_evidence');
  assert.equal(initial.exportStatus,'unsigned');
  const fixtures=[['nessus','nessus.nessus'],['nikto','nikto.xml'],['cobalt','cobalt.json']];
  const formats=studio.getByRole('combobox',{name:'Format',exact:true}), file=studio.getByLabel('Quelldatei');
  assert.match(await file.getAttribute('accept'),/\.nessus/);
  for (const [id,filename] of fixtures) {
    await formats.selectOption(id);
    if (id==='cobalt') await studio.getByText(/authzledger\.defensive-telemetry\.v1/).waitFor();
    await file.setInputFiles(path.join(__dirname,'fixtures',filename));
    await studio.getByRole('button',{name:'Beobachtungen importieren'}).click();
    await studio.getByRole('heading',{name:'Beweis',exact:true}).waitFor();
    await studio.locator('.ps-step').nth(1).click();
  }
  const snapshot=JSON.parse((await download('Berichtsdaten (JSON)')).text);
  assert.equal(snapshot.revision,initial.revision+fixtures.length);
  assert.equal(snapshot.baseline.byStatus.confirmed,0);
  assert.deepEqual(snapshot.sources.byFormat,{nessus:1,nikto:1,cobalt:1});
  await studio.locator('.ps-step').nth(3).click();
  for (const [id] of fixtures) assert.equal(await formats.locator('option[value="'+id+'"]').count(),1);
  await studio.getByText('Dossierverlauf',{exact:true}).click();
  const past=await download('Managementbericht (HTML) · v'+initial.revision);
  assert(past.text.includes('Für diese Revision liegen noch keine Beobachtungen vor.'));
  await page.locator('[data-view=members]').click();
  await page.locator('details:has(> #member-form) > summary').click();
  await page.locator('#member-user').fill('reader@example.test');
  await page.locator('#member-password').fill(password);
  await page.locator('#member-role').selectOption('read_only');
  await page.locator('#member-form button').click();
  await page.locator('#member-list').getByText('reader@example.test',{exact:true}).waitFor();
  await page.locator('#logout').click(); await login('reader@example.test');
  await page.locator('#locale').selectOption('fr');
  const html=await download('Rapport de synthèse (HTML)');
  assert.match(html.name,/\.html$/);
  const doc=await browser.newPage();
  await doc.setContent(html.text);
  await doc.getByRole('heading',{name:'Rapport de synthèse',exact:true}).waitFor();
  await doc.getByText('Synthèse non signée',{exact:false}).waitFor();
  assert.equal(await doc.getByRole('row',{name:'Observations confirmées 0'}).count(),1);
  assert.equal(await doc.getByRole('row',{name:'Nessus 1'}).count(),1);
  assert.equal(await doc.locator('script,iframe,img,link').count(),0);
  assert.doesNotMatch(html.text,/PRIVATE_PAYLOAD|private-path|app\.example/);
  assert.equal((await doc.pdf({format:'A4'})).subarray(0,4).toString(),'%PDF');
  assert.deepEqual(errors,[]);
});
