// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('playwright');
const root = path.join(__dirname,'../public');
const origin = 'https://matrix.example';
const asFile = (text,name='snapshot.json')=>({name,mimeType:'application/json',buffer:Buffer.from(text)});

test('offline matrix browser uses real uploads, displays sparse cells and evidence, edits, compares, restores and switches locale',async()=>{
  const browser = await chromium.launch({executablePath:process.env.CHROMIUM_BIN || undefined});
  try {
    const page = await browser.newPage({viewport:{width:390,height:844}});
    const errors = [], requests = [];
    page.on('pageerror',e=>errors.push(e.message));
    await page.route('**/*',async route=>{
      const url = new URL(route.request().url());
      if (url.origin !== origin || route.request().method() !== 'GET') return route.abort();
      const name = url.pathname === '/rbac/' ? '/rbac/index.html' : url.pathname;
      const type = {'.html':'text/html','.mjs':'text/javascript','.js':'text/javascript','.css':'text/css','.png':'image/png'}[path.extname(name)];
      if (!type) return route.abort();
      return route.fulfill({contentType:type,body:await fs.readFile(path.join(root,name))});
    });
    await page.goto(origin+'/rbac/#matrix');
    await page.getByText('Öffnen Sie Ihren ursprünglichen Snapshot',{exact:false}).waitFor();
    assert.equal(await page.locator('#matrix-tools').isVisible(),false);
    const api='rbac.authorization.k8s.io';
    const metadata={name:'view',namespace:'ops'};
    const policy=JSON.stringify({apiVersion:'v1',kind:'List',items:[
      {apiVersion:api+'/v1',kind:'Role',metadata,rules:[{verbs:['get'],resources:['pods'],apiGroups:['']}]},
      {apiVersion:api+'/v1',kind:'RoleBinding',metadata,subjects:[{kind:'User',name:'Alice'}],roleRef:{apiGroup:api,kind:'Role',name:'view'}}
    ]});
    const empty=JSON.stringify({apiVersion:'v1',kind:'List',items:[]});
    page.on('request',r=>{if(r.url().startsWith('https://'))requests.push(r.url());});
    await page.locator('#original').setInputFiles(asFile(policy));
    const form = page.locator('#query-form');
    for (const [name,verb,expected] of [['Alice','get','no_grant'],['Bob','list','grant']]) {
      await form.locator('[name=name]').fill(name);
      await form.locator('[name=namespace]').fill('ops');
      await form.locator('[name=resource]').fill('pods');
      await form.locator('[name=verb]').fill(verb);
      await page.locator('#run').click();
      await page.locator('#matrix-target').selectOption(expected);
      await page.locator('#matrix-add').click();
    }
    const cells = page.locator('.matrix-cell');
    assert.equal(await cells.count(),2);
    assert.equal(await page.locator('#matrix-table .matrix-sr').count(),2);
    await cells.first().click();
    assert.match(await page.locator('#matrix-detail').innerText(),/RoleBinding ops\/view.*Role view.*Regel 1/s);
    await page.locator('#matrix-after').setInputFiles(asFile(empty));
    await page.locator('#matrix-hashes code').nth(1).waitFor();
    assert.match(await cells.first().innerText(),/Vergleich · Keine Erlaubnis im Export/);
    await page.locator('#matrix-edit').selectOption('grant');
    assert.equal(await cells.first().getAttribute('data-assessment'),'differs');
    for (const [lang,title] of [['en','Permissions matrix'],['fr','Matrice des autorisations'],['it','Matrice delle autorizzazioni'],['ar','مصفوفة الأذونات']]) {
      await page.evaluate(lang=>{document.documentElement.lang=lang; window.dispatchEvent(new CustomEvent('authzlanguage',{detail:{lang}}));},lang);
      assert.equal(await page.locator('#matrix-title').innerText(),title);
      assert.equal(await page.locator('#matrix-edit').inputValue(),'grant');
    }
    await page.locator('#matrix-after').setInputFiles(asFile('invalid'));
    await page.locator('#matrix-status').filter({hasText:'غير صالح'}).waitFor();
    assert.equal(await page.locator('#matrix-hashes code').count(),2);
    const downloading = page.waitForEvent('download'); await page.locator('#matrix-save').click();
    const report = JSON.parse(await fs.readFile(await (await downloading).path(),'utf8'));
    assert.equal(report.cases[0].after.assessment,'differs');
    report.cases[0].before.status='forged';
    await page.locator('#clear').click();
    assert.equal(await cells.count(),0);
    await page.locator('#original').setInputFiles(asFile(policy));
    await page.locator('#matrix-file').setInputFiles(asFile(JSON.stringify(report)));
    await page.locator('#matrix-detail h3').waitFor();
    assert.equal(await cells.count(),2);
    assert.equal(await cells.first().getAttribute('data-assessment'),'matches');
    assert.equal(await page.locator('#matrix-hashes code').count(),0);
    await page.locator('#matrix-detail .matrix-entry button').click();
    assert.equal(await cells.count(),1);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
    assert.deepEqual(errors,[]);
    assert.deepEqual(requests,[]);
  } finally { await browser.close(); }
});
