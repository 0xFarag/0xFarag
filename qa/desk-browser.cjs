// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const {chromium} = require('playwright');
const {makeDesk,UNAVAILABLE} = require('../lib/desk');
const assets = path.resolve(__dirname, '../public');

test('Desk loads quietly, asks only on submit, keeps mobile content readable and reports failure', async t => {
  const env = {XAI_API_KEY:'test-only-key'};
  let requests = 0, classify = 'confirmed';
  const desk = makeDesk({env,fetchImpl:async()=>({ok:true,json:async()=>({choices:[{message:{content:classify}}]})})});
  const server = http.createServer(async (req,res) => {
    if (req.url === '/api/desk') {
      requests++;
      let raw=''; for await (const chunk of req) raw+=chunk;
      req.body=JSON.parse(raw);
      res.status=code=>{res.statusCode=code;return res;};
      res.json=body=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify(body));};
      return desk(req,res);
    }
    if (req.url === '/desk.js' || req.url === '/desk.css') {
      res.setHeader('Content-Type',req.url.endsWith('.js')?'text/javascript':'text/css');
      return res.end(fs.readFileSync(path.join(assets,req.url.slice(1))));
    }
    if (req.url === '/') {
      res.setHeader('Content-Type','text/html; charset=utf-8');
      return res.end('<!doctype html><html lang="de"><head><link rel="stylesheet" href="/desk.css"><script defer src="/desk.js"></script></head>' +
        '<body><header><button data-desk-open>Desk fragen</button></header><main style="height:110vh">Produkt</main><footer>Rechte</footer></body></html>');
    }
    res.writeHead(404);res.end();
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>new Promise(resolve=>server.close(resolve)));
  env.AUTHZ_DESK_ORIGIN='http://127.0.0.1:'+server.address().port;
  const browser = await chromium.launch({headless:true, ...(process.env.CHROMIUM_PATH ? {executablePath:process.env.CHROMIUM_PATH} : {})});
  t.after(()=>browser.close());
  const page=await browser.newPage({viewport:{width:360,height:740}});
  await page.goto(env.AUTHZ_DESK_ORIGIN);
  assert.equal(await page.locator('#authz-desk').isVisible(),false);
  assert.equal(requests,0);
  await page.getByRole('button',{name:'Desk fragen'}).click();
  await page.getByRole('button',{name:'Ersetzt das Nessus?'}).click();
  assert.equal(requests,0);
  assert.equal(await page.locator('#authz-desk-question').inputValue(),'Ersetzt das Nessus?');
  assert.ok(await page.evaluate(()=>{
    const panel=document.querySelector('#authz-desk').getBoundingClientRect();
    return panel.top >= document.querySelector('main').getBoundingClientRect().bottom &&
      panel.bottom <= document.querySelector('footer').getBoundingClientRect().top && panel.right<=innerWidth;
  }));
  await page.getByRole('button',{name:'Senden'}).click();
  await page.waitForSelector('#authz-desk[data-state=answer]');
  assert.equal(requests,1);
  assert.match(await page.locator('.desk-history').innerText(),/Nein\./);
  classify='not an approved fact';
  await page.locator('textarea').fill('Weitere Produktfrage?');
  await page.getByRole('button',{name:'Senden'}).click();
  await page.waitForSelector('#authz-desk[data-state=error]');
  assert.equal(await page.locator('.desk-status').innerText(),UNAVAILABLE);
  await page.getByRole('button',{name:'Schliessen'}).click();
  assert.equal(await page.locator('#authz-desk').isVisible(),false);
  assert.equal(await page.locator('[data-desk-open]').evaluate(el=>document.activeElement===el),true);
});
