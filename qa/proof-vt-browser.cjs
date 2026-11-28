// © Nasser Aldin Farag (0xFarag). All rights reserved.
const test=require('node:test');
const assert=require('node:assert/strict');
const {spawn}=require('node:child_process');
const {once}=require('node:events');
const {randomBytes,createHash}=require('node:crypto');
const {mkdtemp,rm,readFile}=require('node:fs/promises');
const os=require('node:os');
const path=require('node:path');
const readline=require('node:readline');
const {chromium}=require('playwright');

const categories=['malicious','suspicious','harmless','undetected','timeout','confirmed-timeout','type-unsupported','failure'];
const counts=values=>({...Object.fromEntries(categories.map(k=>[k,0])),...values});
async function workspace(t,configured=true) {
  const dir=await mkdtemp(path.join(os.tmpdir(),'authz-file-ui-')), secret=randomBytes(24).toString('hex');
  const code=[
    'import os,sys','from team import file_reputation as vt','from team.server import bootstrap,make_server',
    'def recorded(digest):',
    '    if digest=="a"*64: raise vt.Error(404,"vt_not_found")',
    '    return {"analysisDate":"2025-01-08T11:00:00+00:00","stats":dict.fromkeys(vt.STATS,0)|{"undetected":65,"malicious":2}}',
    'vt.read_report=recorded',
    'bootstrap(sys.argv[1],"review@example.test",os.environ["TEST_PASS"],"Team","de")',
    'server=make_server(sys.argv[1],port=0)','print(server.server_port)','server.serve_forever()'
  ].join('\n');
  const proc=spawn(process.env.PYTHON || 'python3',['-u','-c',code,dir],{cwd:path.resolve(__dirname,'..'),
    env:{...process.env,TEST_PASS:secret,AUTHZLEDGER_VT_PREMIUM_API_KEY:configured?'fixture':''},stdio:['ignore','pipe','inherit']});
  const closed=once(proc,'exit'); t.after(async()=>{proc.kill();await closed;await rm(dir,{recursive:true,force:true});});
  const [port]=await Promise.race([once(readline.createInterface({input:proc.stdout}),'line'),closed.then(()=>{throw Error('Team server failed');})]);
  const browser=await chromium.launch({executablePath:process.env.CHROMIUM_BIN || undefined}); t.after(()=>browser.close());
  const page=await browser.newPage(), origin='http://127.0.0.1:'+port;
  page.setDefaultTimeout(6000);
  const traffic=[],errors=[];
  page.on('request',r=>{traffic.push({url:r.url(),body:r.postData(),method:r.method()});});
  page.on('pageerror',err=>errors.push(err.message));
  await page.goto(origin);
  await page.locator('#username').fill('review@example.test'); await page.locator('#password').fill(secret);
  await page.locator('#login-form button').click();
  await page.getByRole('button',{name:'Dateiprüfung',exact:true}).click();
  return {page,origin,traffic,errors};
}

test('file hashes and imported reports stay local until explicit hash-only lookup',async t=>{
  const {page,origin,traffic,errors}=await workspace(t);
  await page.getByText('Online-Abfrage verfügbar.',{exact:true}).waitFor();
  const bytes=Buffer.from('%PDF-1.7\nsynthetic local QA content\n');
  const sha=createHash('sha256').update(bytes).digest('hex');
  const lookup=page.locator('#rep-lookup'), hash=page.locator('#rep-hash'), output=page.locator('#rep-result');
  const lookupCalls=()=>traffic.filter(r=>r.url.endsWith('/file-reputation/lookup'));
  await page.locator('#rep-file').setInputFiles({name:'private-name.pdf',mimeType:'application/pdf',buffer:bytes});
  await page.getByText(/Lokaler Dateibefund.*PDF/).waitFor();
  assert.equal(await hash.inputValue(),sha);
  assert.equal(await page.locator('#rep-file').inputValue(),'');
  async function importLocal(values,identify=sha) {
    const data={type:'file',id:identify,attributes:{size:bytes.length,last_analysis_stats:counts(values),last_analysis_date:1700000000}};
    await page.locator('#rep-json').setInputFiles({name:'export.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify({data}))});
  }
  await importLocal({failure:6});
  await output.getByText(/Keine verwertbare Engine-Beurteilung/).waitFor();
  await importLocal({undetected:22});
  await output.getByText(/Kein positiver Treffer/).waitFor();
  await importLocal({malicious:2});
  await output.getByText(/Treffer vorhanden/).waitFor();
  const downloaded=page.waitForEvent('download');
  await page.locator('#rep-export').click();
  const report=JSON.parse(await readFile(await (await downloaded).path(),'utf8'));
  assert.deepEqual([report.input,report.localInspection.format,report.sha256,report.reputation.source],
    ['local_file','pdf',sha,'local_report']);
  assert.doesNotMatch(JSON.stringify(report),/private-name|synthetic local QA/);
  await importLocal({undetected:20},'0'.repeat(64));
  await output.getByText(/JSON-Bericht abgelehnt/).waitFor();
  assert.equal(lookupCalls().length,0);
  await lookup.click();
  await output.getByText('Bericht von VirusTotal',{exact:true}).waitFor();
  assert.deepEqual(JSON.parse(lookupCalls()[0].body),{sha256:sha,consent:true});
  await output.getByText(/Schädlich gemeldet · 2/).waitFor();
  await lookup.click();
  await output.getByText('Gespeicherte VirusTotal-Antwort',{exact:true}).waitFor();
  await hash.fill('a'.repeat(64)); await lookup.click();
  await output.getByText(/VirusTotal kennt diesen Hash nicht/).waitFor();
  await hash.fill('a'.repeat(65)); assert(await lookup.isDisabled());
  assert.equal(await output.innerText(),'');
  await hash.fill(sha);
  await importLocal({suspicious:2});
  await output.getByText(/Treffer vorhanden/).waitFor();
  await page.locator('#locale').selectOption('fr');
  await output.getByText(/Détections signalées/).waitFor();
  await page.locator('#logout').click();
  await page.locator('#login-panel').waitFor({state:'visible'});
  assert.equal(await hash.inputValue(),'');
  assert.equal(await output.textContent(),'');
  assert.deepEqual(traffic.filter(r=>/^https?:/.test(r.url)&&!r.url.startsWith(origin+'/')),[]);
  assert.deepEqual(errors,[]);
});

test('without a provider key the local assessment and evidence export remain available',async t=>{
  const {page}=await workspace(t,false);
  await page.getByText(/Offline-Modus/).waitFor();
  const hash=page.locator('#rep-hash');
  await hash.fill('c'.repeat(64));
  assert(await page.locator('#rep-lookup').isDisabled());
  await page.locator('#rep-result').getByText(/Bisher liegt kein Reputationsbericht/).waitFor();
  assert(await page.locator('#rep-json').isEnabled());
  const downloaded=page.waitForEvent('download');
  await page.locator('#rep-export').click();
  const record=JSON.parse(await readFile(await (await downloaded).path(),'utf8'));
  assert.equal(record.localInspection,null);
  assert.equal(record.reputation.status,'not_assessed');
});
