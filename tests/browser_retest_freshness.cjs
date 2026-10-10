/* Actual 100-case baseline → 10-case dependency-closed retest, historical UI timestamps. */
const fs=require('fs'),path=require('path'),assert=require('assert'),{spawn}=require('child_process');
const work=path.resolve(__dirname,'..'),{chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');
const out=path.resolve(process.env.AUTHZ_BROWSER_FRESHNESS_ARTIFACTS||path.join(work,'artifacts/browser-retest-freshness'));fs.mkdirSync(out,{recursive:true});let server,browser;
const fixture=String.raw`
import json,sys,threading,time,os
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
sys.path.insert(0,'tests')
from test_experiments import fixture_spec
from authzledger.experiments import compile_experiment
from authzledger.studio import StudioServer
state={'fixed':False,'hits':0}
class Fixture(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  state['hits']+=1
  if self.path=='/me':status,body=200,{'principal':'peer','tenant':'B'}
  elif self.path=='/known-denial':status,body=403,{'error':'denied'}
  elif self.headers.get('Authorization')=='Bearer owner':status,body=200,{'marker':'synthetic-A'}
  else:status,body=403,({'error':'denied'} if state['fixed'] else {'marker':'synthetic-A'})
  raw=json.dumps(body).encode();self.send_response(status);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
f=ThreadingHTTPServer(('127.0.0.1',0),Fixture);threading.Thread(target=f.serve_forever,daemon=True).start()
os.environ.update(CONTRAST_OWNER='Bearer owner',CONTRAST_PEER='Bearer peer')
spec=fixture_spec('http://127.0.0.1:'+str(f.server_port));spec['contract']['limits']={'max_requests':100,'concurrency':4}
for index in range(6):
 cid='extra-control-'+str(index);spec['contract']['cases'].append({'id':cid,'identity':'owner','method':'GET','path':'/invoice/A','expect':{'status':[200],'json':{'/marker':'synthetic-A'}}});spec['contract']['cases'][3]['requires'].append(cid)
for index in range(90):spec['contract']['cases'].append({'id':'outside-'+str(index),'identity':'owner','method':'GET','path':'/invoice/A','expect':{'status':[200],'json':{'/marker':'synthetic-A'}}})
s=StudioServer();job=s.start_assessment_job(s.assessment_review('experiment',compile_experiment(spec)))
while s.jobs[job['id']]['state']=='running':time.sleep(.01)
assert s.jobs[job['id']]['state']=='complete',s.jobs[job['id']]
assert state['hits']==100,state['hits']
state['fixed']=True
print(json.dumps({'url':s.url,'baseline_job':job['id'],'baseline_requests':state['hits']}),flush=True)
try:s.serve_forever()
finally:s.server_close();f.shutdown();f.server_close()
`;
(async()=>{server=spawn(process.env.PYTHON||'python3',['-u','-c',fixture],{cwd:work});let stderr='';server.stderr.on('data',data=>stderr+=data);const info=await new Promise((resolve,reject)=>{let text='';server.stdout.on('data',data=>{text+=data;try{resolve(JSON.parse(text.trim()));}catch{}});server.on('exit',code=>reject(Error('Fixture exited '+code+stderr)));setTimeout(()=>reject(Error('Fixture timeout '+stderr)),15000).unref();});browser=await chromium.launch({headless:true,...(process.env.CHROME_EXECUTABLE?{executablePath:process.env.CHROME_EXECUTABLE}:{})});const page=await browser.newPage({viewport:{width:1480,height:1000}}),errors=[];page.on('pageerror',error=>errors.push(error.message));await page.goto(info.url);await page.locator('#a-recovery button').first().waitFor({state:'attached'});await page.locator('.nav[data-panel="assessment"]').click();await page.locator('#a-recovery button[data-job-id="'+info.baseline_job+'"]').click();await page.waitForFunction(()=>assessment.current?.value.report.results.length===100);await page.locator('#a-findings button').first().click();await page.locator('#a-retest').click();await page.locator('#a-plan-card:not([hidden])').waitFor();assert.match(await page.locator('#a-plan-budget').innerText(),/10 request/);await page.locator('#a-authorized').check();await page.locator('#a-run').click();await page.waitForFunction(()=>assessment.comparison?.coverage.retested_cases===10&&!assessment.job);
 const actual=await page.evaluate(()=>({baseline:assessment.comparison.baseline_report.finished_at,current:assessment.comparison.current_report.finished_at,coverage:assessment.comparison.coverage,original_baseline_root:assessment.executions[0].value.report.evidence.root_sha256,compared_baseline_root:assessment.comparison.baseline_report.evidence.root_sha256,comparison_digest:assessment.comparison.comparison_sha256,current_count:assessment.current.value.report.results.length}));assert.equal(actual.current_count,10);assert.equal(actual.coverage.not_retested_cases,90);assert.equal(actual.original_baseline_root,actual.compared_baseline_root);const historical=await page.locator('#a-retest-result .assessment-row').filter({hasText:'outside-0 ·'}).innerText();assert(historical.includes('not_retested · historical evidence: '+actual.baseline),historical);if(actual.baseline!==actual.current)assert(!historical.includes(actual.current),historical);const fresh=await page.locator('#a-retest-result .assessment-row').filter({hasText:'target ·'}).innerText();assert(fresh.includes('baseline: '+actual.baseline+' → retest: '+actual.current),fresh);await page.locator('#a-findings button').first().click();await page.waitForFunction(timestamp=>document.getElementById('a-inspector-fields').textContent.includes('retest: '+timestamp),actual.current);assert.deepEqual(errors,[]);await page.screenshot({path:path.join(out,'retest-freshness.png'),fullPage:false});fs.writeFileSync(path.join(out,'acceptance.json'),JSON.stringify({passed:true,gate:'F08-05',...actual,page_errors:errors},null,2));console.log('100 → 10 retest freshness browser acceptance passed.');})().catch(error=>{console.error(error);process.exitCode=1;}).finally(async()=>{if(browser)await browser.close();if(server)server.kill('SIGTERM');});
