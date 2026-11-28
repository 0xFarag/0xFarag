// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';

const {test} = require('node:test');
const assert = require('node:assert/strict');
const {randomBytes} = require('node:crypto');
const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('playwright');

const root = path.join(__dirname, '../public');
const accountPath = '/api/account';
const loginPath = '/anmeldung/';
const live = process.env.AUTHZ_ACCOUNT_QA_LIVE_ORIGIN;
const mime = {'.html':'text/html', '.css':'text/css', '.mjs':'text/javascript', '.js':'text/javascript',
  '.png':'image/png', '.svg':'image/svg+xml', '.woff2':'font/woff2'};

// Atomic in-memory substitute for private storage. The actual WebAuthn verifier and
// HTTP handler run unchanged in the loopback fixture.
function isolatedStore() {
  const rows = new Map();
  let revision = 0;
  function persist(key, value) { rows.set(key, {value:structuredClone(value), etag:String(++revision)}); }
  return {
    async read(key) { return structuredClone(rows.get(key) || null); },
    async create(key, value) {
      if (rows.has(key)) return false;
      persist(key, value); return true;
    },
    async replace(key, value, etag) {
      if (!rows.has(key) || rows.get(key).etag !== etag) return false;
      persist(key, value); return true;
    },
    async remove(key, etag) {
      if (!rows.has(key) || rows.get(key).etag !== etag) return false;
      return rows.delete(key);
    }
  };
}

async function loopbackApp(t) {
  const {makeHandler} = require('../lib/passkeys.js');
  let handler;
  const server = http.createServer(async (req, res) => {
    try {
      const route = new URL(req.url, 'http://localhost').pathname;
      if (route === accountPath) {
        if (req.method === 'POST') {
          const chunks = [];
          for await (const part of req) chunks.push(part);
          req.body = Buffer.concat(chunks).toString('utf8');
        }
        res.status = code => { res.statusCode = code; return res; };
        res.json = data => { res.setHeader('Content-Type','application/json'); res.end(JSON.stringify(data)); };
        await handler(req, res);
        return;
      }
      const target = path.resolve(root, '.' + route + (route.endsWith('/') ? 'index.html' : ''));
      if (!target.startsWith(root + path.sep)) { res.writeHead(404).end(); return; }
      const bytes = await fs.readFile(target);
      res.writeHead(200, {'Content-Type':mime[path.extname(target)] || 'application/octet-stream'});
      res.end(bytes);
    } catch (error) {
      res.writeHead(error.code === 'ENOENT' ? 404 : 500).end();
    }
  });
  await new Promise((resolve,reject) => server.once('error',reject).listen(0,'127.0.0.1',resolve));
  t.after(async () => {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  });
  const origin = 'http://localhost:' + server.address().port;
  handler = makeHandler({store:isolatedStore(), secret:randomBytes(32), origin});
  return origin;
}

function launchOptions() {
  const options = {executablePath:process.env.CHROMIUM_BIN || undefined};
  if (live && process.env.AUTHZ_ACCOUNT_QA_USE_PROXY === '1') {
    const proxy = new URL(process.env.HTTPS_PROXY);
    options.proxy = {server:proxy.origin, username:decodeURIComponent(proxy.username) || undefined,
      password:decodeURIComponent(proxy.password) || undefined};
    // Optional pinned transport certificate for a locally trusted testing proxy.
    const pin = process.env.AUTHZ_ACCOUNT_QA_SPKI;
    if (pin) {
      assert.match(pin, /^[A-Za-z0-9+/]{43}=$/);
      options.args = ['--ignore-certificate-errors-spki-list=' + pin];
    }
  }
  return options;
}

async function newVisitor(browser, origin) {
  const context = await browser.newContext({locale:'de-CH'});
  const crossOriginRequests = [];
  await context.route('**/*', async route => {
    if (new URL(route.request().url()).origin === origin) return route.continue();
    crossOriginRequests.push(new URL(route.request().url()).origin);
    return route.abort();
  });
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const {authenticatorId} = await cdp.send('WebAuthn.addVirtualAuthenticator', {options:{
    protocol:'ctap2', ctap2Version:'ctap2_1', transport:'internal',
    hasResidentKey:true, hasUserVerification:true, isUserVerified:true, automaticPresenceSimulation:true
  }});
  await page.goto(origin + loginPath);
  await page.locator('#anonymous').waitFor({state:'visible'});
  return {context,page,cdp,authenticatorId,crossOriginRequests,createdId:null};
}

async function accountState(visitor) {
  return visitor.page.evaluate(async () => {
    const response = await fetch('/api/account', {cache:'no-store'});
    return {status:response.status, body:await response.json(), cache:response.headers.get('cache-control')};
  });
}

async function signedOut(visitor) {
  await visitor.page.locator('#anonymous').waitFor({state:'visible'});
  assert.equal(await visitor.page.locator('#account').isVisible(), false);
  const state = await accountState(visitor);
  assert.equal(state.status, 401);
  assert.equal(state.body.authenticated, false);
  assert.equal(state.body.account, undefined);
}

async function ceremony(visitor, action) {
  const {page} = visitor;
  const done = page.waitForResponse(response => new URL(response.url()).pathname === accountPath &&
    response.request().method() === 'POST' && response.request().postDataJSON()?.action === action + '-finish');
  const [response] = await Promise.all([done,page.locator(action === 'register' ? '#register' : '#login').click()]);
  assert.equal(response.status(), 200, action + ' finish');
  const result = await response.json();
  assert.equal(result.authenticated, true);
  if (action === 'register') visitor.createdId = result.account.id;
  await page.locator('#account').waitFor({state:'visible'});
  assert.equal(await page.locator('#account-id').innerText(), result.account.id);
  return result.account;
}

async function createAccount(visitor) {
  await signedOut(visitor);
  const account = await ceremony(visitor, 'register');
  assert.ok(account.id && Number.isFinite(Date.parse(account.createdAt)));
  const {credentials} = await visitor.cdp.send('WebAuthn.getCredentials', {authenticatorId:visitor.authenticatorId});
  assert.equal(credentials.length,1);
  assert.ok(credentials[0].isResidentCredential);
  const state = await accountState(visitor);
  assert.equal(state.status,200);
  assert.deepEqual(state.body.account,account);
  assert.match(state.cache,/no-store/);
  const cookies = await visitor.context.cookies();
  assert.ok(cookies.some(cookie => cookie.name.startsWith('__Host-') && cookie.secure && cookie.httpOnly &&
    cookie.path === '/' && cookie.sameSite === 'Strict'));
  await visitor.page.reload();
  await visitor.page.locator('#account').waitFor({state:'visible'});
  assert.equal(await visitor.page.locator('#account-id').innerText(),account.id);
  return account.id;
}

// Only delete an account created by this exact, isolated test visitor.
async function removeOwnAccount(visitor) {
  if (!visitor.createdId) return;
  let state = await accountState(visitor);
  if (state.status === 401) {
    await visitor.page.reload();
    await visitor.page.locator('#anonymous').waitFor({state:'visible'});
    await ceremony(visitor, 'login');
    state = await accountState(visitor);
  }
  assert.equal(state.body.account?.id,visitor.createdId,'cleanup must target our own synthetic account');
  await visitor.page.locator('#delete-open').click();
  await visitor.page.locator('#delete-confirm').click();
  await signedOut(visitor);
  visitor.createdId = null;
}

test('register a resident passkey, restore a protected session, log in again and delete only its owner', {timeout:150000}, async t => {
  if (live) assert.equal(live, 'https://authzledger.com', 'live mode requires the production origin explicitly');
  const origin = live || await loopbackApp(t);
  const browser = await chromium.launch(launchOptions());
  const visitors = [];
  t.after(async () => {
    try { for (const visitor of visitors) await removeOwnAccount(visitor); }
    finally { await browser.close(); }
  });
  const main = await newVisitor(browser,origin); visitors.push(main);
  const id = await createAccount(main);
  const beforeLogout = !live && await main.context.storageState();
  if (!live) {
    const wrongOrigin = await main.context.request.post(origin + accountPath, {
      headers:{Origin:'https://other.example'}, data:{action:'logout'}
    });
    assert.equal(wrongOrigin.status(),403);
    assert.equal((await accountState(main)).body.account.id,id);
  }
  await main.page.locator('#logout').click();
  await signedOut(main);
  if (beforeLogout) {
    const stale = await browser.newContext({storageState:beforeLogout});
    try {
      assert.equal((await stale.request.get(origin + accountPath)).status(),401,
        'logout revokes the previous session on the server');
    } finally { await stale.close(); }
  }
  assert.equal((await ceremony(main,'login')).id,id);
  await main.page.locator('#delete-open').click();
  await main.page.locator('#delete-cancel').click();
  assert.equal((await accountState(main)).body.account.id,id);

  if (!live) {
    const other = await newVisitor(browser,origin); visitors.push(other);
    const otherId = await createAccount(other);
    assert.notEqual(otherId,id);
    // Emulate a password manager providing the same virtual passkey to another browser.
    const secondBrowser = await newVisitor(browser,origin); visitors.push(secondBrowser);
    const {credentials} = await other.cdp.send('WebAuthn.getCredentials', {authenticatorId:other.authenticatorId});
    await secondBrowser.cdp.send('WebAuthn.addCredential', {
      authenticatorId:secondBrowser.authenticatorId, credential:credentials[0]
    });
    assert.equal((await ceremony(secondBrowser,'login')).id,otherId);
    secondBrowser.createdId = other.createdId;
    other.createdId = null;
    await other.page.reload();
    await signedOut(other);
    await removeOwnAccount(secondBrowser);
    assert.equal((await accountState(main)).body.account.id,id);
  }
  await removeOwnAccount(main);
  const [rejected] = await Promise.all([
    main.page.waitForResponse(r => new URL(r.url()).pathname === accountPath &&
      r.request().method() === 'POST' && r.request().postDataJSON()?.action === 'login-finish'),
    main.page.locator('#login').click()
  ]);
  assert.ok([400,401,403].includes(rejected.status()), 'a removed credential cannot sign in');
  await signedOut(main);
  for (const visitor of visitors) assert.deepEqual(visitor.crossOriginRequests,[]);
});
