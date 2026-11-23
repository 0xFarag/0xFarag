// Run with node --test qa/team-ui.cjs after installing the Team and Playwright dependencies.
const test = require('node:test');
const assert = require('node:assert/strict');
const {spawn} = require('node:child_process');
const {randomBytes} = require('node:crypto');
const {mkdtemp,rm,readFile} = require('node:fs/promises');
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
  const child = spawn(process.env.PYTHON || 'python3',['-u','-c',[
    'import os, sys','from team.server import bootstrap, make_server',
    'folder, password = sys.argv[1], os.environ["AUTHZ_TEST_PASSWORD"]',
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
  async function login(user,password) {
    await fill('username',user); await fill('password',password); await submit('login-form');
    await page.locator('#workspace').waitFor();
  }
  await page.goto(origin);
  await login('ui-admin',adminSecret);
  await page.locator('#new-case summary').click();
  await fill('case-title','Authorised review'); await fill('case-scope','Review pre-recorded evidence from the approved host.'); await fill('case-assets','example.test');
  await submit('case-form'); await page.locator('#case-detail').waitFor();
  const har = (date,status) => JSON.stringify({log:{version:'1.2',entries:['/object','/control'].map((route,i) => ({
    startedDateTime:date,request:{method:'GET',url:'https://example.test'+route,headers:[{name:'Cookie',value:'PRIVATE-INPUT'}]},
    response:{status:i ? 204 : status}}))}});
  async function upload(name,bytes,count) {
    await set('import-format','har');
    await page.locator('#import-file').setInputFiles({name,mimeType:'application/json',buffer:Buffer.from(bytes)});
    await submit('import-form'); await page.waitForFunction(n => document.getElementById('import-count').textContent === String(n),count);
  }
  await page.locator('#import-tool summary').click();
  await upload('original.har',har('2025-01-01T00:00:00Z',200),1);
  await page.locator('#finding-tool summary').click();
  await fill('finding-title','Access boundary'); await fill('expected','denied'); await fill('observed','permitted');
  await set('finding-status','confirmed');
  await set('finding-evidence-record','1'); await set('finding-control-record','2');
  await fill('finding-control-expected','204'); await fill('finding-control-observed','204');
  await submit('finding-form'); await page.waitForFunction(() => document.getElementById('finding-count').textContent === '1');
  await upload('retest.har',har('2025-02-01T00:00:00Z',403),2);
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
  await page.locator('#verify-file').setInputFiles({name:'signed.json',mimeType:'application/json',buffer:packageBytes});
  await submit('verify-form'); await page.locator('#verified-report').waitFor();
  assert.equal(await page.locator('#verified-report').getAttribute('dir'),'rtl');
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
  assert.equal(await page.locator('html').getAttribute('lang'),'en'); assert.equal(await page.locator('#finding-count').innerText(),'1');
  assert.deepEqual(errors,[]); assert.deepEqual(external,[]);
});
