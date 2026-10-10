/* Real retained-source retest, failed polling recovery and signed comparison. */
const fs=require('fs'),path=require('path'),assert=require('assert'),{spawn,spawnSync}=require('child_process');
const work=path.resolve(__dirname,'..'),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const out=path.resolve(process.env.AUTHZ_BROWSER_COMPARISON_ARTIFACTS||path.join(work,'artifacts/browser-comparison'));
fs.mkdirSync(out,{recursive:true});
const temporary=fs.mkdtempSync('/tmp/authzledger-browser-comparison-');
let server,browser;
const fixture=String.raw`
import json,sys,threading
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from authzledger.engine import run
from authzledger.model import load_contract
from authzledger.intelligence import build_graph
from authzledger.signing import generate_keypair
from authzledger.studio import StudioServer
fixed=False
class Fixture(BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def do_GET(self):
  status=200 if self.path=='/control' or self.path=='/private' and not fixed else 403
  raw=json.dumps({'id':'protected-object'} if status==200 else {'error':'forbidden'}).encode()
  self.send_response(status); self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
f=ThreadingHTTPServer(('127.0.0.1',0),Fixture);threading.Thread(target=f.serve_forever,daemon=True).start()
contract=load_contract({'version':1,'name':'Source-bound comparison fixture','target':f'http://127.0.0.1:{f.server_port}','identities':{'owner':{'headers':{}}},'cases':[
 {'id':'positive','identity':'owner','method':'GET','path':'/control','expect':{'status':[200],'json':{'/id':'protected-object'}}},
 {'id':'negative','identity':'owner','method':'GET','path':'/private','requires':['positive'],'expect':{'status':[403],'json_absent':['/id']}},
 {'id':'unselected','identity':'owner','method':'GET','path':'/other','requires':['positive'],'expect':{'status':[403],'json_absent':['/id']}}]})
folder=Path(sys.argv[1]);private=folder/'private.pem';public=folder/'public.pem';generate_keypair(private,public)
s=StudioServer(signing_key=private,public_key=public)
baseline=run(contract);s.record_run(contract,baseline,build_graph(contract,baseline));fixed=True
print(s.url,flush=True)
try: s.serve_forever()
finally: s.server_close();f.shutdown();f.server_close()
`;
(async()=>{
 server=spawn(process.env.PYTHON||'python3',['-u','-c',fixture,temporary],{cwd:work});
 let stderr='';server.stderr.on('data',chunk=>stderr+=chunk);
 const url=await new Promise((resolve,reject)=>{let text='';server.stdout.on('data',chunk=>{text+=chunk;const match=text.match(/http:\/\/127\.0\.0\.1:\d+\/#[A-Za-z0-9_-]+/);if(match)resolve(match[0]);});server.on('error',reject);server.on('exit',code=>reject(Error('Studio exited '+code+': '+stderr)));setTimeout(()=>reject(Error('Studio startup timeout: '+stderr)),10000).unref();});
 browser=await chromium.launch({headless:true,...(process.env.CHROME_EXECUTABLE?{executablePath:process.env.CHROME_EXECUTABLE}:{})});
 const context=await browser.newContext({viewport:{width:1500,height:1050},acceptDownloads:true});
 const page=await context.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));
 await page.goto(url);await page.locator('#access-matrix .matrix-cell').nth(23).waitFor();
 await page.locator('.nav[data-panel="history"]').click();await page.locator('.timeline-run').first().click();
 await page.locator('#retest-cases input').nth(2).waitFor();
 await page.locator('#retest-cases input[value="positive"]').uncheck();await page.locator('#retest-cases input[value="unselected"]').uncheck();
 await page.locator('#history-retest').click();await page.waitForFunction(()=>document.getElementById('plan').textContent.includes('2 explicit requests'));
 assert.match(await page.locator('#plan').innerText(),/Required controls: positive/);
 assert.match(await page.locator('#plan').innerText(),/Not retested: unselected/);
 assert.equal(await page.locator('#run').isEnabled(),false);
 await page.locator('#authorized').check();
 let interrupted=false,seenJob;
 await page.route('**/api/jobs/*',async route=>{if(!interrupted){interrupted=true;seenJob=route.request().url();await route.abort('failed');}else{assert.equal(route.request().url(),seenJob);await route.continue();}});
 await page.locator('#run').click();await page.locator('#resume-job').waitFor({state:'visible'});
 assert.match(await page.locator('#run-state').innerText(),/may still be running/);
 assert.equal(await page.locator('#run').isEnabled(),false);assert.equal(await page.locator('#demo').isEnabled(),false);
 await page.locator('#resume-job').click();
 await page.waitForFunction(()=>document.getElementById('run-state').textContent.startsWith('Execution complete'),{},{timeout:10000});
 assert.match(await page.locator('#comparison').innerText(),/1\s+Resolved checks/);
 assert.match(await page.locator('#comparison').innerText(),/unselected\s+pass → not_retested\s+not_retested/);
 assert.match(await page.locator('#comparison').innerText(),/Only the dependency-closed selection/);
 assert.equal(await page.locator('#results tr').count(),2);
 await page.locator('#notice').evaluate(el=>el.hidden=true);await page.locator('.retest').screenshot({path:path.join(out,'comparison.png')});
 async function download(id,name){const pending=page.waitForEvent('download');await page.locator(id).click();const file=await pending;await file.saveAs(path.join(out,name));return fs.readFileSync(path.join(out,name));}
 const envelope=JSON.parse(await download('#export-envelope','comparison.json'));assert.equal(envelope.summary.not_retested,1);assert.equal(envelope.summary.resolved_check,1);
 const html=await download('#export-diff','comparison.html');assert(html.includes(Buffer.from(envelope.comparison_sha256)));
 await page.locator('.nav[data-panel="intelligence"]').click();const proof=await download('#proof-export','proof.zip');assert.equal(proof.readUInt16LE(0),0x4b50);
 const verified=spawnSync(process.env.PYTHON||'python3',['-c',"import sys,zipfile; from pathlib import Path; from authzledger.signing import verify_bundle; p=Path(sys.argv[3]); zipfile.ZipFile(sys.argv[1]).extractall(p); errors=verify_bundle(p,sys.argv[2]); print(errors);sys.exit(bool(errors))",path.join(out,'proof.zip'),path.join(temporary,'public.pem'),path.join(temporary,'proof')],{cwd:work,encoding:'utf8'});assert.equal(verified.status,0,verified.stderr+verified.stdout);
 const isolated=spawnSync(process.env.PYTHON||'python3',['-I',path.join(work,'tools/verify_bundle.py'),path.join(temporary,'proof'),'--public-key',path.join(temporary,'public.pem')],{cwd:temporary,encoding:'utf8'});assert.equal(isolated.status,0,isolated.stderr+isolated.stdout);assert.match(isolated.stdout,/semantics.*not established/);
 // A graph rebuilt from a different contract must not inherit a same-ID retest claim.
 await page.locator('.graph-boundary').filter({hasText:/\/private$/}).click();assert.match(await page.locator('#graph-explanation').innerText(),/Retest · resolved_check/);
 await page.locator('.nav[data-panel="workspace"]').click();await page.locator('details.editor summary').click();
 const unrelated=JSON.parse(await page.locator('#contract').inputValue());unrelated.target='http://127.0.0.1:9';
 await page.locator('#contract').fill(JSON.stringify(unrelated));await page.locator('.nav[data-panel="intelligence"]').click();
 await page.locator('#graph-source').selectOption('contract');await page.locator('#map-build').click();
 await page.waitForFunction(()=>document.getElementById('graph-meta').textContent.startsWith('http://127.0.0.1:9'));
 await page.locator('.graph-boundary').filter({hasText:/\/private$/}).click();assert(!/Retest ·/.test(await page.locator('#graph-explanation').innerText()));
 await page.locator('.nav[data-panel="evidence"]').click();await page.setViewportSize({width:390,height:844});assert(!await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1),'Selective comparison must not overflow mobile viewport');
 assert.deepEqual(errors,[]);const result={passed:true,browser:await browser.version(),page_errors:errors,workflows:['retained full baseline case selection','dependency closure preview without execution','polling transport failure preserves job identifier and blocks restart','same-job reconnection','resolved check and explicit not_retested coverage','comparison JSON and HTML export','unrelated same-case-ID graph cannot inherit retest status','signed graph/report/comparison ZIP verified independently','390px viewport without document overflow']};fs.writeFileSync(path.join(out,'acceptance.json'),JSON.stringify(result,null,2));console.log(JSON.stringify(result));
 await context.close();await browser.close();server.kill();fs.rmSync(temporary,{recursive:true,force:true});
})().catch(async error=>{console.error(error);if(browser)await browser.close();if(server)server.kill();fs.rmSync(temporary,{recursive:true,force:true});process.exit(1)});
