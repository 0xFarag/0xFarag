// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const {test}=require('node:test'), assert=require('node:assert/strict'), fs=require('node:fs/promises');
const http=require('node:http'),path=require('node:path');
const {chromium}=require('playwright');
test('Real homepage, mobile header, release inventory and localised private pilot letters',async t=>{
  const root=process.env.AUTHZ_TEST_DIST || path.resolve(__dirname,'../dist');
  const types={'.html':'text/html; charset=utf-8','.js':'application/javascript','.mjs':'application/javascript','.css':'text/css','.png':'image/png','.ttf':'font/ttf'};
  const server=http.createServer(async(req,res)=>{
    const pathname=new URL(req.url,'http://localhost').pathname;
    if(!['GET','HEAD'].includes(req.method)){res.writeHead(405).end();return;}
    const file=path.resolve(root,'.'+pathname+(pathname.endsWith('/')?'index.html':''));
    if(!file.startsWith(root+path.sep)){res.writeHead(404).end();return;}
    try{res.setHeader('Content-Type',types[path.extname(file)]||'application/octet-stream');res.end(await fs.readFile(file));}
    catch{res.writeHead(404).end();}
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>server.close(resolve)));
  const browser=await chromium.launch();t.after(()=>browser.close());
  async function changeLanguage(page,lang) {
    await page.locator('#az-language > summary').click();
    await page.locator('[data-az-lang="'+lang+'"]').click();
    await page.waitForFunction(expected=>document.documentElement.lang.startsWith(expected),lang);
  }
  for(const lang of ['de','en','fr','it','ar']){
    const page=await browser.newPage({viewport:{width:390,height:844}}),base='http://127.0.0.1:'+server.address().port;
    const writes=[];page.on('request',r=>{if(r.method()!=='GET')writes.push(r.url());});
    await page.goto(base+'/'+lang+'/');await page.locator('[data-desk-open]').click();
    assert(await page.locator('#authz-desk').isVisible());
    const form=page.locator('[data-pilot-form]');await form.locator('[name=organisation]').fill('Organisation test');await form.locator('[name=contact]').fill('A. Muster');await form.locator('[name=email]').fill('review@example.org');
    await form.locator('[name=guided]').check();await form.locator('[type=submit]').click();
    const pending=page.waitForEvent('download');await form.locator('a[download]').click();const dl=await pending;
    const content=await fs.readFile(await dl.path(),'utf8');assert.match(content,/CHF 4’800/);assert.match(content,/review@example.org/);assert.match(content,/not_retested/);assert.equal(writes.length,0);
    await page.reload();assert.equal(await form.locator('[name=organisation]').inputValue(),'Organisation test');
    await form.locator('button[type=button]').click();await page.reload();assert.equal(await form.locator('[name=organisation]').inputValue(),'');
    await page.goto(base+'/'+lang+'/downloads/stable/');assert.equal(await page.locator('a[href*="/releases/download/v1.5.0/"]').count(),6);
    await page.close();
  }
  // Exercise the actual same-document language picker with unsaved inputs and a previously generated letter.
  const base='http://127.0.0.1:'+server.address().port, page=await browser.newPage({viewport:{width:390,height:844}});
  const writes=[];page.on('request',req=>{if(req.method()!=='GET')writes.push(req.url());});
  await page.goto(base+'/de/'); await page.locator('[data-desk-open]').click();
  const form=page.locator('[data-pilot-form]'),question=page.locator('#authz-desk-question');
  await question.fill('Meine Frage bleibt unverändert.');
  await form.locator('[name=organisation]').fill('Organisation Test');
  await form.locator('[name=contact]').fill('C. Muster');
  await form.locator('[name=email]').fill('review@example.org');
  await form.locator('[name=guided]').check();
  await changeLanguage(page,'fr');
  assert.equal(await question.inputValue(),'Meine Frage bleibt unverändert.');
  await page.getByLabel('Votre question sur le produit').waitFor();
  await page.getByRole('button',{name:'Est-ce que cela remplace Nessus ?'}).waitFor();
  assert.equal(await form.getByLabel('Personne de contact').inputValue(),'C. Muster');
  assert(await form.locator('[name=guided]').isChecked());
  await form.getByRole('button',{name:'Enregistrer localement et préparer la lettre d’offre'}).click();
  await changeLanguage(page,'en');
  const pending=page.waitForEvent('download');
  await form.getByRole('link',{name:'Download offer letter'}).click();
  const blob=await pending;
  assert.match(await fs.readFile(await blob.path(),'utf8'),/AuthzLedger · Draft offer[\s\S]+Organisation Test/);
  assert.equal(await question.inputValue(),'Meine Frage bleibt unverändert.');
  assert.deepEqual(writes,[]);
  await page.route('**/api/workspace',r=>r.fulfill({json:{available:true,origin:'https://team.example.test'}}));
  await page.goto(base+'/de/studio/');
  await page.getByRole('link',{name:'Workbench öffnen',exact:true}).waitFor();
  await changeLanguage(page,'fr');
  assert.equal(await page.getByRole('link',{name:'Ouvrir la Workbench',exact:true}).getAttribute('href'),'https://team.example.test/');
  const guide=page.getByRole('link',{name:'Guide d’utilisation et d’exploitation de Proof Studio (allemand, Markdown)'});
  const guideUrl=new URL(await guide.getAttribute('href'),page.url());
  const guideFile=await page.request.get(guideUrl.href);
  assert(guideFile.ok());assert.match(await guideFile.text(),/Erstes Konto und Teamdienst/);
  await page.close();
});
