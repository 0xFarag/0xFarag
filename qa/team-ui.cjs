// © Nasser Aldin Farag (0xFarag). All rights reserved.
// Run with node --test qa/team-ui.cjs after installing the Team and Playwright dependencies.
const test = require('node:test');
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const {randomBytes,createHash} = require('node:crypto');
const {mkdtemp,rm,readFile,writeFile,rename} = require('node:fs/promises');
const path = require('node:path');
const os = require('node:os');
const readline = require('node:readline');
const {once} = require('node:events');
const {chromium} = require('playwright');

const root = path.resolve(__dirname,'..');

test('team GUI connects to the real server, reviews records and controls, signs a report, and respects membership', {timeout:90000},async t => {
  const browser = await chromium.launch({executablePath:process.env.CHROMIUM_BIN || undefined});
  t.after(() => browser.close());
  const folder = await mkdtemp(path.join(os.tmpdir(),'authzledger-ui-'));
  t.after(() => rm(folder,{recursive:true,force:true}));
  const adminSecret = randomBytes(32).toString('hex'), readerSecret = randomBytes(32).toString('hex');
  // Only the signing-key clock moves. Sessions, rate limits and evidence timestamps use real time.
  const clock = path.join(folder,'signer-clock'), initialTime = Math.floor(Date.now()/1000);
  await writeFile(clock,String(initialTime));
  const child = spawn(process.env.PYTHON || 'python3',['-u','-c',[
    'import os, sys','from pathlib import Path','from team import keyring','from team.server import bootstrap, make_server',
    'folder, password = sys.argv[1], os.environ["AUTHZ_TEST_PASSWORD"]',
    'keyring.unix_time = lambda: int((Path(folder)/"signer-clock").read_text())',
    'bootstrap(folder,"ui-admin",password,"Verification team","de")',
    'server = make_server(folder,port=0)','print(server.server_port,flush=True)','server.serve_forever()'
  ].join('\n'),folder],{cwd:root,env:{...process.env,AUTHZ_TEST_PASSWORD:adminSecret},stdio:['ignore','pipe','inherit']});
  const exited = once(child,'exit'); t.after(async () => { child.kill(); await exited; });
  const [port] = await Promise.race([once(readline.createInterface({input:child.stdout}),'line'),exited.then(() => {throw Error('Team server did not start');})]);
  const origin = 'http://127.0.0.1:' + port;
  const page = await browser.newPage({viewport:{width:1080,height:830}});
  page.setDefaultTimeout(9000);
  const errors = [], external = [];
  page.on('pageerror',error => errors.push(error.message));
  page.on('request',r => { if (/^https?:/.test(r.url()) && !r.url().startsWith(origin + '/')) external.push(r.url()); });
  const fill = (id,v) => page.locator('#'+id).fill(v);
  const set = (id,v) => page.locator('#'+id).selectOption(v);
  const submit = id => page.locator('#'+id+' button[type=submit]').click();
  async function downloadSelectedKey() {
    const next = page.waitForEvent('download');
    await page.locator('#download-key').click();
    const file = await next, descriptor = JSON.parse(await readFile(await file.path()));
    assert.deepEqual(Object.keys(descriptor).sort(),['algorithm','fingerprint','public_key']);
    assert.equal(descriptor.algorithm,'Ed25519');
    const raw = Buffer.from(descriptor.public_key,'base64');
    assert.equal(raw.length,32);
    assert.equal(createHash('sha256').update(raw).digest('hex'),descriptor.fingerprint);
    assert.equal(file.suggestedFilename(),'authzledger-trust-'+descriptor.fingerprint+'.json');
    return descriptor;
  }
  async function login(user,password) {
    await fill('username',user); await fill('password',password); await submit('login-form');
    await page.locator('#workspace').waitFor();
  }
  await page.goto(origin);
  await login('ui-admin',adminSecret);
  const firstKey = await downloadSelectedKey();
  assert.equal(await page.locator('#trust-select').inputValue(),firstKey.fingerprint);
  await page.locator('#new-case summary').click();
  await fill('case-title','Authorised review'); await fill('case-scope','Review pre-recorded evidence from the approved host.'); await fill('case-assets','example.test');
  await submit('case-form'); await page.locator('#case-detail').waitFor();
  await page.locator('#cr-new > summary').click();
  await fill('cr-hypothesis','The saved access decision matches the agreed rule.');
  await fill('cr-expected','The sample yields the agreed decision.');
  await fill('cr-control','Compare the separate control observation from this case.');
  await page.locator('#cr-new button[type=submit]').click();
  await page.waitForFunction(() => document.querySelectorAll('#control-reviews ol.records > li').length === 1);
  const har = (date,status) => JSON.stringify({log:{version:'1.2',entries:['/object','/control'].map((route,i) => ({
    startedDateTime:date,request:{method:'GET',url:'https://example.test'+route,headers:[{name:'Cookie',value:'PRIVATE-INPUT'}]},
    response:{status:i ? 204 : status}}))}});
  async function upload(name,bytes,count,fmt = 'har') {
    await set('import-format',fmt);
    await page.locator('#import-file').setInputFiles({name,mimeType:'application/json',buffer:Buffer.from(bytes)});
    await submit('import-form'); await page.waitForFunction(n => document.getElementById('import-count').textContent === String(n),count);
  }
  await page.locator('#import-tool summary').click();
  await upload('original.har',har('2025-01-01T00:00:00Z',200),1);
  const originalId = await page.locator('#finding-evidence-file option').last().getAttribute('value');
  const zap = {site:[{alerts:[{pluginid:'10038',riskcode:'2',confidence:'3',
    instances:[{method:'GET',uri:'https://example.test/object',evidence:'PRIVATE ZAP INSTANCE'}]}]}]};
  await upload('api-scan.json',JSON.stringify(zap),2,'zap');
  await page.locator('#finding-tool summary').click();
  assert(await page.locator('#zap-link').isHidden());
  await fill('finding-title','Access boundary'); await fill('expected','denied'); await fill('observed','permitted');
  await set('finding-status','confirmed');
  assert(await page.locator('#zap-link').isVisible());
  assert.equal(await page.locator('#zap-source').inputValue(),'');
  await set('zap-source',await page.locator('#zap-source option').last().getAttribute('value'));
  await set('zap-record','1');
  for (const field of ['finding-evidence-file','finding-control-file']) await set(field,originalId);
  await set('finding-evidence-record','1'); await set('finding-control-record','2');
  await fill('finding-control-expected','204'); await fill('finding-control-observed','204');
  await submit('finding-form'); await page.waitForFunction(() => document.getElementById('finding-count').textContent === '1');
  await page.locator('#cr-add > summary').click();
  await set('cr-review-finding',await page.locator('#cr-review-finding option').last().getAttribute('value'));
  await page.locator('#cr-add button[type=button]').click();
  await fill('cr-observed','The saved observation records an access decision.');
  await fill('cr-control-observed','The separate control is present in the imported file.');
  await set('cr-outcome','supports'); await page.locator('#cr-add button[type=submit]').click();
  await page.waitForFunction(() => document.querySelectorAll('#control-reviews ol.records > li').length === 2);
  const reviewDownload = page.waitForEvent('download'); await page.locator('#cr-export').click();
  const recordBytes = await readFile(await (await reviewDownload).path());
  const review = JSON.parse(recordBytes);
  assert.equal(review.signed,false); assert.equal(review.revisions.length,2);
  assert.equal(review.revisions[1].parent_sha256,review.revisions[0].sha256);
  assert.equal(review.revisions[1].evidence.record,1);
  assert.equal(review.revisions[1].control_evidence.record,2);
  assert(!recordBytes.includes('PRIVATE-INPUT'));
  const findingIndex = page.locator('#findings .evidence-index');
  await findingIndex.locator('summary').click();
  const slimDownload = page.waitForEvent('download'); await findingIndex.getByRole('button').click();
  const slimBytes = await readFile(await (await slimDownload).path()), slim = JSON.parse(slimBytes);
  assert.equal(slim.signed,false);
  assert.equal(slim.schema,'authzledger.evidence-index/v1');
  assert.deepEqual(slim.evidence_index.observations.map(x=>[x.role,x.record]),[['evidence',1],['control',2]]);
  assert.deepEqual(slim.evidence_index.experiments[0].revisions.map(x=>x.sha256),review.revisions.map(x=>x.sha256));
  assert(!slimBytes.includes('The saved observation'));
  await upload('retest.har',har('2025-02-01T00:00:00Z',403),3);
  await page.locator('#retest-tool summary').click();
  await set('retest-status','fix_verified'); await fill('retest-observed','denied');
  const newer = await page.locator('#retest-evidence-file option').last().getAttribute('value');
  for (const [ref,pos] of [['retest-evidence','1'],['retest-control','2']]) { await set(ref+'-file',newer); await set(ref+'-record',pos); }
  await fill('retest-control-expected','204'); await fill('retest-control-observed','204');
  await submit('retest-form'); await page.waitForFunction(() => document.getElementById('retest-count').textContent === '1');
  await set('locale','fr'); await page.waitForFunction(() => document.documentElement.lang === 'fr');
  assert.equal(await page.locator('#detail-title').innerText(),'Authorised review');
  await set('output-language','ar');
  const signed = page.waitForEvent('download'); await submit('handover-form');
  const packageBytes = await readFile(await (await signed).path());
  const pkg = JSON.parse(packageBytes);
  assert.equal(pkg.report.language,'ar'); assert.equal(pkg.report.counts.fix_verified,1); assert(!packageBytes.includes('PRIVATE-INPUT'));
  assert.equal(pkg.report.appendix[0].scanner_lead.format,'zap');
  assert(!packageBytes.includes('PRIVATE ZAP INSTANCE'));
  assert.deepEqual(pkg.report.appendix[0].evidence_index,slim.evidence_index);
  assert(!packageBytes.includes('The saved observation'));
  await page.locator('#verify-file').setInputFiles({name:'signed.json',mimeType:'application/json',buffer:packageBytes});
  await submit('verify-form'); await page.locator('#verified-report').waitFor();
  assert.equal(await page.locator('#verified-report').getAttribute('dir'),'rtl');
  const signedIndex = page.locator('#verified-report .evidence-index');
  await page.locator('#verified-report > details > summary').click();
  await signedIndex.locator('summary').click();
  const attachReview = async bytes => signedIndex.locator('input[type=file]').setInputFiles({
    name:'plan.json',mimeType:'application/json',buffer:bytes
  });
  const matchMessage = 'تطابق جميع المراجعات التسليم الموقّع.';
  await attachReview(recordBytes);
  await signedIndex.getByText(matchMessage,{exact:true}).waitFor();
  const changedReview = structuredClone(review);
  changedReview.revisions[1].observed += ' edited';
  await attachReview(Buffer.from(JSON.stringify(changedReview)));
  await signedIndex.getByText('خطة المراجعة المحددة لا تطابق هذا التسليم.',{exact:true}).waitFor();
  let oldArchive;
  for (const fmt of ['html','pdf']) {
    await set('output-format',fmt);
    const nextDownload = page.waitForEvent('download');
    await submit('handover-form');
    const file = await nextDownload;
    assert(file.suggestedFilename().endsWith('-'+fmt+'.zip'));
    const bytes = await readFile(await file.path());
    oldArchive = bytes;
    await page.locator('#verify-file').setInputFiles({name:file.suggestedFilename(),mimeType:'application/zip',buffer:bytes});
    await submit('verify-form');
    await page.locator('#verified-report').waitFor();
    assert.equal(await page.locator('#verified-report').getAttribute('lang'),'ar');
    assert.match(await page.locator('#verify-result').innerText(),/SHA-256 · [a-f0-9]{64}/);
  }
  // Reading an overdue key cannot rotate it. The next signed handover rotates the signer.
  await writeFile(clock+'.next',String(initialTime+91*86400)); await rename(clock+'.next',clock);
  await Promise.all([page.waitForResponse(r => r.url().endsWith('/trust-keys')),page.locator('#trust-reload').click()]);
  assert.deepEqual(await downloadSelectedKey(),firstKey);
  await set('output-format','json');
  const afterRotation = page.waitForEvent('download'); await submit('handover-form');
  const rotated = JSON.parse(await readFile(await (await afterRotation).path()));
  await page.waitForFunction(() => document.querySelectorAll('#trust-select option').length === 2);
  assert.notEqual(rotated.manifest.fingerprint,firstKey.fingerprint);
  assert.equal(await page.locator('#trust-select').inputValue(),rotated.manifest.fingerprint);
  assert.equal((await downloadSelectedKey()).fingerprint,rotated.manifest.fingerprint);
  await set('trust-select',firstKey.fingerprint);
  for (const lang of ['de','en','fr','it','ar']) {
    await set('locale',lang);
    await page.waitForFunction(l => document.documentElement.lang.startsWith(l),lang);
    assert.equal(await page.locator('#trust-select').inputValue(),firstKey.fingerprint);
    assert(await page.locator('#trust-policy').textContent());
    assert.equal(await page.locator('#trust-dates time').count(),2);
  }
  assert.deepEqual(await downloadSelectedKey(),firstKey);
  // Verification uses the server's pinned history regardless of the key selected for export.
  await set('trust-select',rotated.manifest.fingerprint);
  for (const [name,mimeType,buffer] of [['original.json','application/json',packageBytes],['original.zip','application/zip',oldArchive]]) {
    await page.locator('#verify-file').setInputFiles({name,mimeType,buffer});
    await submit('verify-form'); await page.locator('#verified-report').waitFor();
    assert((await page.locator('#verify-result').innerText()).includes(firstKey.fingerprint));
  }
  pkg.report.counts.fix_verified = 100;
  await page.locator('#verify-file').setInputFiles({name:'modified.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(pkg))});
  await submit('verify-form'); await page.waitForFunction(() => document.getElementById('verify-result').dataset.error === 'true');
  assert(await page.locator('#verified-report').isHidden());
  await page.locator('[data-view=members]').click();
  await page.locator('details:has(> #member-form) > summary').click(); await fill('member-user','ui-reader');
  await fill('member-password',readerSecret); await set('member-role','read_only'); await set('member-locale','en');
  await submit('member-form'); await page.locator('#member-list').getByText('ui-reader',{exact:true}).waitFor();
  await page.locator('[data-view=audit]').click(); await page.locator('#audit-list tr').first().waitFor();
  await page.locator('#logout').click(); await login('ui-reader',readerSecret); await page.locator('#case-detail').waitFor();
  for (const selector of ['[data-view=members]','[data-view=audit]','#new-case','#handover-tool','#finding-tool','#import-tool']) assert(await page.locator(selector).isHidden());
  await set('trust-select',firstKey.fingerprint);
  assert.deepEqual(await downloadSelectedKey(),firstKey);
  assert.equal(await page.locator('#control-reviews ol.records > li').count(),2);
  assert(await page.locator('#cr-new').isHidden()); assert(await page.locator('#cr-add').isHidden());
  assert(await page.locator('#cr-export').isVisible());
  assert.equal(await page.locator('html').getAttribute('lang'),'en'); assert.equal(await page.locator('#finding-count').innerText(),'1');
  assert.deepEqual(errors,[]); assert.deepEqual(external,[]);
});
