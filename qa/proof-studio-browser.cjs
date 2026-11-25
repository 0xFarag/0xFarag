// © Nasser Aldin Farag (0xFarag). All rights reserved.
const test=require('node:test');
const assert=require('node:assert/strict');
const {spawn}=require('node:child_process');
const {once}=require('node:events');
const {randomBytes}=require('node:crypto');
const {mkdtemp,rm,readFile}=require('node:fs/promises');
const path=require('node:path');
const os=require('node:os');
const readline=require('node:readline');
const {chromium}=require('playwright');

test('email Studio evaluates a real lab, persists coverage, verifies ZIP bytes and isolates the read-only view', {timeout:100000},async t=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),'authz-proof-browser-'));
  const adminPass=randomBytes(24).toString('hex'), readPass=randomBytes(24).toString('hex');
  const server=spawn(process.env.PYTHON || 'python3',['-u','-c',[
    'import os,sys','from team.server import bootstrap, make_server',
    'bootstrap(sys.argv[1],"admin@example.test",os.environ["TEST_PASS"],"Workspace","de")',
    'httpd=make_server(sys.argv[1],port=0)','print(httpd.server_port)','httpd.serve_forever()'
  ].join('\n'),dir],{cwd:path.resolve(__dirname,'..'),env:{...process.env,TEST_PASS:adminPass},stdio:['ignore','pipe','inherit']});
  const closed=once(server,'exit');
  t.after(async()=>{server.kill();await closed;await rm(dir,{recursive:true,force:true});});
  const [port]=await Promise.race([once(readline.createInterface({input:server.stdout}),'line'),closed.then(()=>{throw Error('server failed to start');})]);
  const origin='http://127.0.0.1:'+port;
  const browser=await chromium.launch({executablePath:process.env.CHROMIUM_BIN || undefined});
  t.after(()=>browser.close());
  const page=await browser.newPage();
  page.setDefaultTimeout(8000);
  const errors=[], external=[];
  page.on('pageerror',err=>errors.push(err.message));
  page.on('request',req=>{ if (/^https?:/.test(req.url()) && !req.url().startsWith(origin+'/')) external.push(req.url());});
  const studio=page.locator('#view-proof');
  async function login(email,pw) {
    await page.locator('#username').fill(email);
    await page.locator('#password').fill(pw);
    await page.locator('#login-form button').click();
    await studio.locator('#ps-case').waitFor();
  }
  const controls=async()=>{ for(const input of await studio.locator('[data-control]').all()) await input.check(); };
  await page.goto(origin);
  await login('admin@example.test',adminPass);
  assert(await page.locator('[data-view=cases]').isHidden());
  // Use actual source bytes for a separate commercial case with a one-observation budget.
  await studio.getByLabel('Autorisierte Hosts (ein Host pro Zeile)',{exact:true}).fill('app.example.test');
  await studio.getByLabel('Rules of Engagement',{exact:true}).fill('Review the supplied evidence offline.');
  await studio.getByLabel('Requestbudget',{exact:true}).fill('1');
  await studio.getByRole('button',{name:'Dossier anlegen',exact:true}).click();
  const file=studio.getByLabel('Quelldatei',{exact:true});
  await file.setInputFiles({name:'broken.har',mimeType:'application/json',buffer:Buffer.from('{')});
  await studio.getByRole('button',{name:'Beobachtungen importieren',exact:true}).click();
  await studio.locator('.ps-notice:not(:empty)').waitFor();
  await studio.getByRole('combobox',{name:'Format',exact:true}).selectOption('burp');
  const observations=['app.example.test','app.example.test','other.example.test'].map((host,i)=>({
    id:'case-'+i,host,method:'GET',path:'/orders/'+(i+1),status:403,marker:true,rule:'protected-marker',source:'Burp'
  }));
  await file.setInputFiles({name:'snapshot.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify({observations}))});
  await studio.getByRole('button',{name:'Beobachtungen importieren',exact:true}).click();
  await studio.getByText('out_of_scope',{exact:true}).first().waitFor();
  await studio.getByText('budget_blocked',{exact:true}).first().waitFor();
  await studio.getByText('inconclusive',{exact:true}).first().waitFor();
  await controls();
  await studio.getByRole('button',{name:'Controls auswerten',exact:true}).click();
  await studio.getByText('confirmed',{exact:true}).first().waitFor();
  await studio.locator('.ps-step').nth(2).click();
  await studio.locator('summary').filter({hasText:'Beweisgraph und minimale Beobachtungsmenge'}).click();
  await studio.getByRole('columnheader',{name:'Geprüfte Beziehung'}).waitFor();
  const graphRow=studio.locator('details[open] table tbody tr').filter({hasText:'case-0'}).first();
  assert.match(await graphRow.innerText(),/GET app.example.test \/orders\/1/);
  assert.match(await graphRow.innerText(),/confirmed/);
  await studio.locator('#ps-case').selectOption('');
  await studio.locator('#ps-mode').selectOption('lab');
  await studio.getByRole('button',{name:'Dossier anlegen',exact:true}).click();
  await studio.getByText('GET lab.authz.local /invoices/1042',{exact:true}).waitFor();
  await studio.getByRole('button',{name:'Weiter zu Beweis',exact:true}).click();
  await controls();
  await studio.getByRole('button',{name:'Controls auswerten',exact:true}).click();
  await studio.getByText('confirmed',{exact:true}).first().waitFor();
  const ids=await studio.locator('.ps-stage tbody input[type=checkbox]:checked').evaluateAll(items=>items.map(x=>x.value));
  assert.deepEqual(ids,['invoice-1042','invoice-1043','invoice-1044']);
  await controls();
  await studio.getByRole('button',{name:'Retest speichern',exact:true}).click();
  await studio.getByRole('button',{name:'Paket signieren',exact:true}).waitFor();
  await studio.locator('summary').filter({hasText:'Gespeicherte Retests'}).click();
  assert.equal(await studio.getByText('resolved_check',{exact:true}).count(),3);
  assert.equal(await studio.getByText('not_retested',{exact:true}).count(),1);
  await studio.getByRole('button',{name:'Paket signieren',exact:true}).click();
  await studio.getByRole('button',{name:'ZIP herunterladen',exact:true}).waitFor();
  const downloaded=page.waitForEvent('download');
  await studio.getByRole('button',{name:'ZIP herunterladen',exact:true}).click();
  const archive=await readFile(await (await downloaded).path());
  await studio.locator('summary').filter({hasText:'ZIP prüfen'}).click();
  async function verify(bytes,expect) {
    await studio.getByLabel('Signiertes ZIP',{exact:true}).setInputFiles({name:'proof.zip',mimeType:'application/zip',buffer:bytes});
    await studio.getByRole('button',{name:'ZIP prüfen',exact:true}).click();
    await studio.getByText(expect).waitFor();
  }
  await verify(archive,/Paket gültig/);
  await verify(Buffer.concat([archive,Buffer.from('!')]),'Paket ungültig');
  const rotate=studio.getByRole('button',{name:'Schlüssel rotieren',exact:true});
  page.once('dialog',d=>d.accept());
  const rotated=page.waitForResponse(r=>r.request().method()==='POST' && r.url().endsWith('/proof/rotate'));
  await rotate.click(); assert.equal((await rotated).status(),200);
  await verify(archive,/Paket gültig/);
  for (const [lang,label] of [['en','Proof workbench'],['fr','Atelier de preuve'],['de','Proof-Workbench']]) {
    await page.locator('#locale').selectOption(lang);
    await studio.getByRole('heading',{name:label,exact:true}).waitFor();
  }
  await page.reload();
  await studio.locator('#ps-case').waitFor();
  assert.notEqual(await studio.locator('#ps-case').inputValue(),'');
  await page.locator('[data-view=members]').click();
  await page.locator('details:has(> #member-form) > summary').click();
  await page.locator('#member-user').fill('reader@example.test'); await page.locator('#member-password').fill(readPass);
  await page.locator('#member-role').selectOption('reviewer');
  await page.locator('#member-form button').click();
  await page.locator('#member-list').getByText('reader@example.test',{exact:true}).waitFor();
  await page.locator('#logout').click(); await login('reader@example.test',readPass);
  await studio.locator('.ps-step').nth(4).click();
  await studio.locator('.ps-keys li').first().waitFor();
  assert.equal(await studio.getByRole('button',{name:/Paket signieren|Schlüssel rotieren|ZIP herunterladen/}).count(),0);
  assert.deepEqual(errors,[]);
  assert.deepEqual(external,[]);
});
