/* Real Studio platform journey with a scoped loopback target and persistent store. */
const fs=require('fs'),path=require('path'),assert=require('assert'),{spawn,spawnSync}=require('child_process');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const work=path.resolve(__dirname,'..'),out=path.resolve(process.env.AUTHZ_PLATFORM_BROWSER_ARTIFACTS||path.join(work,'artifacts/browser-platform150'));
fs.mkdirSync(out,{recursive:true});fs.rmSync(path.join(out,'acceptance.json'),{force:true});
const temp=fs.mkdtempSync('/tmp/authzledger-platform150-');let server,browser;
const fixture=String.raw`
import json,sys,threading,time
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from authzledger.studio import StudioServer
root=Path(sys.argv[1]); hits=[]
class Target(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  hits.append(self.path);(root/'hits.json').write_text(json.dumps(hits))
  raw=b'{"ok":true}';self.send_response(200)
  if (root/'fixed').exists():
   self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Security-Policy',"default-src 'self'")
  self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
target=ThreadingHTTPServer(('127.0.0.1',0),Target);threading.Thread(target=target.serve_forever,daemon=True).start()
origin='http://127.0.0.1:'+str(target.server_port)
studio=StudioServer(history_path=root/'history.sqlite3');threading.Thread(target=studio.serve_forever,daemon=True).start()
(root/'request.http').write_bytes(('GET / HTTP/1.1\r\nHost: 127.0.0.1:'+str(target.server_port)+'\r\nAuthorization: Bearer browser-secret-not-retained\r\n\r\n').encode())
(root/'response.http').write_bytes(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}')
print(json.dumps({'url':studio.url,'origin':origin}),flush=True)
while True:time.sleep(1)
`;
async function run(){
 server=spawn(process.env.PYTHON||'python3',['-u','-c',fixture,temp],{cwd:work,stdio:['ignore','pipe','pipe']});
 let err='';server.stderr.on('data',data=>err+=data);
 const info=await new Promise((resolve,reject)=>{let output='';server.stdout.on('data',data=>{output+=data;const line=output.split('\n')[0];if(output.includes('\n')){try{resolve(JSON.parse(line));}catch(error){reject(error);}}});server.once('exit',code=>reject(Error('Fixture exited '+code+': '+err)));});
 // Omit executablePath by default so Playwright can use a --only-shell install.
 const executablePath=process.env.AUTHZ_CHROMIUM_EXECUTABLE||process.env.CHROME_EXECUTABLE;
 browser=await chromium.launch({headless:true,...(executablePath?{executablePath}:{})});const page=await browser.newPage({viewport:{width:1500,height:1040},acceptDownloads:true});const errors=[];
 page.on('pageerror',error=>errors.push(error.message));await page.goto(info.url);await page.waitForFunction(()=>document.getElementById('session').textContent.includes('Local'));
 const click=async selector=>{await page.locator(selector).focus();await page.keyboard.press('Enter');};
 const fill=async(selector,value)=>{await page.locator(selector).focus();await page.keyboard.press('ControlOrMeta+A');await page.keyboard.insertText(value);};
 const runPlan=async()=>{const before=await page.evaluate(()=>platform.record.artifacts.filter(a=>a.kind.endsWith('-execution')).length);await page.locator('#p-approved').check();await click('#p-run');await page.waitForFunction(before=>!platform.job&&platform.record.artifacts.filter(a=>a.kind.endsWith('-execution')).length>before,before);};
 await click('.nav[data-panel="assessment"]');await click('#p-open');await page.waitForFunction(()=>platform.loaded);
 assert.match(await page.locator('#p-storage').innerText(),/Persistent local/);
 await fill('#p-title','Platform acceptance <script>unsafe</script>');await fill('#p-authorization-ref','Loopback fixture owner');await fill('#p-origin',info.origin);await fill('#p-networks','127.0.0.1/32');await fill('#p-paths','/');
 await page.locator('#p-read-attestation').check();await click('#p-create');await page.locator('#p-surface.active').waitFor();
 assert.equal(fs.existsSync(path.join(temp,'hits.json')),false);assert.match(await page.locator('#p-context').innerText(),/<script>unsafe<\/script>/);assert.equal(await page.locator('#p-context script').count(),0);
 await page.locator('#p-import-profile').selectOption('burp-http-pair-v1');await page.locator('#p-import-file').setInputFiles(path.join(temp,'request.http'));await page.locator('#p-import-response').setInputFiles(path.join(temp,'response.http'));await fill('#p-source-origin',info.origin);await click('#p-import');
 await page.waitForFunction(()=>document.querySelectorAll('#p-surfaces button').length===1);assert.equal(fs.existsSync(path.join(temp,'hits.json')),false);
 assert.equal((await page.content()).includes('browser-secret-not-retained'),false);
 await page.getByText('Bounded active discovery',{exact:true}).click();await click('#p-discover-plan');await page.locator('#p-review:not([hidden])').waitFor();assert.equal(fs.existsSync(path.join(temp,'hits.json')),false);await runPlan();assert.equal(JSON.parse(fs.readFileSync(path.join(temp,'hits.json'))).length,1);
 await click('[data-platform-page="surface"]');await click('#p-surfaces button');await page.locator('#p-assess.active').waitFor();
 await page.locator('#p-profile').selectOption('web-quick');await page.locator('#p-check').selectOption('misconfig.security_headers');await click('#p-check-build');await click('#p-check-plan');await page.locator('#p-review:not([hidden])').waitFor();
 assert.equal(JSON.parse(fs.readFileSync(path.join(temp,'hits.json'))).length,1);assert.equal(await page.locator('#p-run').isEnabled(),false);
 await runPlan();assert.equal(JSON.parse(fs.readFileSync(path.join(temp,'hits.json'))).length,3);assert.match(await page.locator('#p-evidence').innerText(),/confirmed/);
 await click('#p-evidence button:last-child');await click('#p-inspector-focus');assert.equal(await page.evaluate(()=>document.activeElement.id),'a-inspector-fields');assert.match(await page.locator('#a-inspector-fields').innerText(),/baseline/);
 fs.writeFileSync(path.join(temp,'fixed'),'fixed');await click('#p-retest');await page.locator('#p-review:not([hidden])').waitFor();await runPlan();assert.equal(JSON.parse(fs.readFileSync(path.join(temp,'hits.json'))).length,5);
 await click('[data-platform-page="report"]');await click('#p-freeze');await page.locator('[data-platform-export="json"]:enabled').waitFor();
 await page.getByText('Finding review and report inclusion',{exact:true}).click();await page.locator('#p-annotation-review').selectOption('reviewed');await fill('#p-annotation-rationale','Controlled response comparison demonstrates this configuration observation.');await fill('#p-annotation-impact','Explicitly required headers were absent from the tested endpoint.');await fill('#p-annotation-remediation','Set the required headers and repeat the same baseline and probe.');await click('#p-annotation-save');await page.waitForFunction(()=>platform.snapshot===null&&platform.record.assessment.finding_annotations);assert.equal(await page.locator('[data-platform-export="json"]').isEnabled(),false);await click('#p-freeze');await page.locator('[data-platform-export="json"]:enabled').waitFor();
 for(const format of ['json','html','pdf']){const pending=page.waitForEvent('download');await click('[data-platform-export="'+format+'"]');const download=await pending;await download.saveAs(path.join(out,'assessment.'+format));}
 let pending=page.waitForEvent('download');await click('#p-signing');let downloaded=await pending;await downloaded.saveAs(path.join(out,'public.pem'));
 pending=page.waitForEvent('download');await click('#p-proof');downloaded=await pending;await downloaded.saveAs(path.join(out,'proof.zip'));
 const verified=spawnSync(process.env.PYTHON||'python3',['-c',`import sys,zipfile,subprocess\nfrom pathlib import Path\np=Path(sys.argv[1]);zipfile.ZipFile(p/'proof.zip').extractall(p/'proof')\nr=subprocess.run([sys.executable,'-I','tools/verify_bundle.py',str(p/'proof'),'--public-key',str(p/'public.pem')],capture_output=True,text=True)\nprint(r.stdout,r.stderr);raise SystemExit(r.returncode)`,out],{cwd:work,encoding:'utf8'});
 assert.equal(verified.status,0,verified.stdout+verified.stderr);const snapshot=JSON.parse(fs.readFileSync(path.join(out,'assessment.json')));assert.equal(snapshot.kind,'platform-snapshot');assert(snapshot.findings.some(f=>f.review==='reviewed'&&f.impact&&f.remediation));
 assert.equal(await page.evaluate(()=>JSON.stringify(localStorage)+JSON.stringify(sessionStorage)),'{}{}');
 await page.evaluate(()=>window.scrollTo(0,0));await page.screenshot({path:path.join(out,'platform-proof.png'),fullPage:true});await page.setViewportSize({width:390,height:844});assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1),false);
 const aid=await page.evaluate(()=>platform.id),hits=JSON.parse(fs.readFileSync(path.join(temp,'hits.json'))).length;
 await page.goto(info.url);await click('.nav[data-panel="assessment"]');await click('#p-open');await page.waitForFunction(()=>platform.loaded);await page.locator('#p-assessment').selectOption(aid);await page.waitForFunction(()=>platform.record?.artifacts.some(a=>a.kind==='retest-execution'));
 assert.equal(JSON.parse(fs.readFileSync(path.join(temp,'hits.json'))).length,hits);assert.deepEqual(errors,[]);
 fs.writeFileSync(path.join(out,'acceptance.json'),JSON.stringify({passed:true,browser_version:browser.version(),playwright_version:require('playwright/package.json').version,keyboard_primary_actions:true,scope_before_dispatch:true,offline_raw_import:true,bounded_discovery:true,persistent_assessment:true,header_controls:true,source_bound_retest:true,verified_proof:true,no_browser_secret_storage:true,viewport_390:true,page_errors:errors},null,2));console.log('Platform150 browser acceptance passed.');
}
run().catch(error=>{console.error(error);process.exitCode=1;}).finally(async()=>{if(browser)await browser.close();if(server)server.kill('SIGTERM');});
