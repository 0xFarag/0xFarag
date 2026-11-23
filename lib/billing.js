// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';

const { isIP } = require('node:net');
const { createHash, randomBytes } = require('node:crypto');

const API_VERSION = '2026-11-18.endive';
const AMOUNTS = Object.freeze({solo: 120000, team: 480000});
const LIVE_ORIGINS = ['https://authzledger.com', 'https://www.authzledger.com'];
const OFFLINE = Object.freeze({state:'offline', checkout:{solo:false, team:false}, portal:false, publishableKey:null});

class BillingError extends Error {
  constructor(status = 503, code = 'unavailable') {
    super(code);
    this.status = status;
  }
}

function exactHttpsOrigin(input) {
  try {
    const url = new URL(input);
    return url.protocol === 'https:' && url.origin === input && !url.username && !url.password;
  } catch { return false; }
}

function readConfig(env, req) {
  const mode = env.AUTHZ_BILLING_MODE;
  const host = req.headers.host;
  if (mode !== 'live' && mode !== 'test') return null;
  // Vercel owns the routing host. Never construct a Stripe return URL from a forwarded header.
  let origin;
  if (mode === 'live') {
    if (env.VERCEL_ENV !== 'production') return null;
    origin = LIVE_ORIGINS.find(value => new URL(value).host === host);
  } else {
    const testOrigin = env.AUTHZ_BILLING_TEST_ORIGIN;
    if (env.VERCEL_ENV === 'production' || !exactHttpsOrigin(testOrigin) ||
        LIVE_ORIGINS.includes(testOrigin) || new URL(testOrigin).host !== host) return null;
    origin = testOrigin;
  }
  if (!origin || !/^acct_[a-zA-Z0-9]+$/.test(env.STRIPE_MERCHANT_ACCOUNT_ID || '')) return null;
  if (!(new RegExp('^(sk|rk)_' + mode + '_[a-zA-Z0-9]+$')).test(env.STRIPE_SECRET_KEY || '')) return null;
  const pk = (new RegExp('^pk_' + mode + '_[a-zA-Z0-9]+$')).test(env.STRIPE_PUBLISHABLE_KEY || '')
    ? env.STRIPE_PUBLISHABLE_KEY : null;
  return {
    mode, live:mode === 'live', origin, returnOrigin:mode === 'live' ? LIVE_ORIGINS[0] : origin,
    accountId:env.STRIPE_MERCHANT_ACCOUNT_ID, secret:env.STRIPE_SECRET_KEY, pk,
    prices:{solo:env.STRIPE_PRICE_SOLO,team:env.STRIPE_PRICE_TEAM}, portalId:env.STRIPE_PORTAL_CONFIGURATION,
    automaticTax:env.STRIPE_AUTOMATIC_TAX === 'true',
  };
}

async function stripe(config, fetcher, path, form, key) {
  const headers = {Authorization:'Bearer ' + config.secret, 'Stripe-Version':API_VERSION};
  const options = {method:form ? 'POST' : 'GET', headers, signal:AbortSignal.timeout(6000), redirect:'error'};
  if (form) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded';
    headers['Idempotency-Key'] = key;
    options.body = new URLSearchParams(form);
  }
  const response = await fetcher('https://api.stripe.com/v1/' + path, options);
  if (response.status === 429) throw new BillingError(429,'rate_limited');
  if (!response.ok) throw new BillingError();
  return response.json();
}

async function account(config, fetcher) {
  // /account identifies the account that owns the API key; never query a caller-supplied Connect account.
  const data = await stripe(config, fetcher, 'account');
  if (data.object !== 'account' || data.id !== config.accountId || data.country !== 'CH') throw new BillingError();
  return data;
}

function canCharge(config, merchant) {
  return Boolean(config.pk && (!config.live || (merchant.charges_enabled === true && merchant.payouts_enabled === true)));
}

async function verifiedPrice(config, fetcher, plan) {
  const id = config.prices[plan];
  if (!/^price_[a-zA-Z0-9]+$/.test(id || '') || config.prices.solo === config.prices.team) return false;
  const p = await stripe(config, fetcher, 'prices/' + id + '?expand[]=product');
  return p.object === 'price' && p.id === id && p.livemode === config.live && p.active === true &&
    p.product?.object === 'product' && p.product.active === true && p.product.livemode === config.live &&
    p.type === 'recurring' && p.billing_scheme === 'per_unit' && p.currency === 'chf' &&
    p.unit_amount === AMOUNTS[plan] && Number(p.unit_amount_decimal) === AMOUNTS[plan] &&
    !p.transform_quantity && !p.custom_unit_amount && p.recurring?.usage_type === 'licensed' &&
    p.recurring.interval === 'year' && p.recurring.interval_count === 1;
}

async function portalLogin(config, fetcher) {
  if (!/^bpc_[a-zA-Z0-9]+$/.test(config.portalId || '')) return null;
  const portal = await stripe(config, fetcher, 'billing_portal/configurations/' + config.portalId);
  if (portal.object !== 'billing_portal.configuration' || portal.id !== config.portalId ||
      portal.livemode !== config.live || !portal.active || !portal.login_page?.enabled) return null;
  const address = portal.login_page.url;
  if (typeof address !== 'string' || !/^https:\/\/billing\.stripe\.com\/p\/login\/(?:test_)?[a-zA-Z0-9]+$/.test(address)) return null;
  const sample = new URL(address).pathname.startsWith('/p/login/test_');
  return sample !== config.live ? address : null;
}

function send(res,status,body) {
  return res.status(status).json(body);
}

function responseHeaders(res) {
  res.setHeader('Cache-Control','private, no-store, max-age=0');
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('Referrer-Policy','no-referrer');
}

function parsePurchase(req) {
  if (!/^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || ''))
    throw new BillingError(415,'invalid_request');
  if (Number(req.headers['content-length'] || 0) > 1024) throw new BillingError(413,'invalid_request');
  let b = req.body;
  if (typeof b === 'string' || Buffer.isBuffer(b)) {
    if (Buffer.byteLength(b) > 1024) throw new BillingError(413,'invalid_request');
    try { b = JSON.parse(b.toString()); } catch { throw new BillingError(400,'invalid_request'); }
  }
  if (!b || typeof b !== 'object' || Array.isArray(b) || Object.keys(b).length !== 2 ||
      !Object.hasOwn(b,'plan') || !Object.hasOwn(b,'requestId') || typeof b.plan !== 'string' ||
      !Object.hasOwn(AMOUNTS,b.plan) || typeof b.requestId !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(b.requestId))
    throw new BillingError(400,'invalid_request');
  return b;
}

// Supplemental per-instance burst limit. The Vercel WAF owns the distributed limit.
function burstLimiter(now) {
  let until = 0;
  const slots = new Map();
  const salt = randomBytes(24);
  return req => {
    const time = now();
    if (time >= until) { slots.clear(); until = time + 60000; }
    // Vercel sets this header at its trusted edge. Ignore arbitrary fallback forwarding headers.
    const value = req.headers['x-vercel-forwarded-for'];
    const address = typeof value === 'string' && isIP(value) ? value : (req.socket?.remoteAddress || 'unknown');
    const ip = createHash('sha256').update(salt).update(address).digest('hex');
    const hits = slots.get(ip) || 0;
    if (hits >= 10 || (!hits && slots.size >= 4096)) throw new BillingError(429,'rate_limited');
    slots.set(ip,hits+1);
  };
}

function makeBilling({env=process.env, fetcher=globalThis.fetch, now=Date.now}={}) {
  const limit = burstLimiter(now);
  let statusCache;

  async function status(config) {
    if (!config) return OFFLINE;
    // The public GET can be coalesced briefly per warm instance. Mutating calls always recheck Stripe.
    if (statusCache && statusCache.origin === config.origin && statusCache.until > now()) return statusCache.pending;
    const pending = (async () => {
      try {
        const merchant = await account(config, fetcher);
        const check = plan => canCharge(config, merchant) ? verifiedPrice(config, fetcher, plan).catch(() => false) : false;
        const [solo,team,portal] = await Promise.all([
          check('solo'),check('team'),portalLogin(config, fetcher).catch(() => null)
        ]);
        if (!solo && !team && !portal) return OFFLINE;
        return {state:config.mode, checkout:{solo,team}, portal:Boolean(portal), publishableKey:solo || team ? config.pk : null};
      } catch { return OFFLINE; }
    })();
    statusCache = {origin:config.origin,until:now()+15000,pending};
    return pending;
  }

  async function checkout(config,req,res) {
    const requestOrigin = req.headers.origin;
    if (!requestOrigin || (req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'same-origin') ||
      !exactHttpsOrigin(requestOrigin) || new URL(requestOrigin).host !== req.headers.host)
      throw new BillingError(403,'forbidden');
    const {plan,requestId} = parsePurchase(req);
    if (!config || requestOrigin !== config.origin) throw new BillingError();
    limit(req);
    const merchant = await account(config, fetcher);
    if (!canCharge(config,merchant) || !await verifiedPrice(config,fetcher,plan)) throw new BillingError();
    const session = await stripe(config,fetcher,'checkout/sessions',{
      mode:'subscription',ui_mode:'embedded_page',currency:'chf',
      'adaptive_pricing[enabled]':'false', 'automatic_tax[enabled]':String(config.automaticTax),
      'line_items[0][price]':config.prices[plan], 'line_items[0][quantity]':'1',
      'metadata[authzledger_plan]':plan, 'subscription_data[metadata][authzledger_plan]':plan,
      billing_address_collection:'required','consent_collection[terms_of_service]':'required',
      return_url:config.returnOrigin+'/kasse/abschluss/',
    },'authzledger-'+plan+'-'+requestId.toLowerCase());
    const prefix = 'cs_'+config.mode+'_';
    if (session.object !== 'checkout.session' || !session.id?.startsWith(prefix) || session.mode !== 'subscription' ||
        session.livemode !== config.live || session.currency !== 'chf' || session.ui_mode !== 'embedded_page' ||
        session.amount_subtotal !== AMOUNTS[plan] || session.status !== 'open' ||
        typeof session.client_secret !== 'string' || !session.client_secret.length) throw new BillingError();
    return send(res,200,{clientSecret:session.client_secret});
  }

  return operation => async (req,res) => {
    responseHeaders(res);
    const method = operation === 'checkout' ? 'POST' : 'GET';
    if (req.method !== method) {
      res.setHeader('Allow',method);
      return send(res,405,{error:'method_not_allowed'});
    }
    try {
      const config = readConfig(env,req);
      if (operation === 'status') return send(res,200,await status(config));
      if (operation === 'checkout') return await checkout(config,req,res);
      if (!config) throw new BillingError();
      await account(config,fetcher);
      const url = await portalLogin(config,fetcher);
      if (!url) throw new BillingError();
      return res.redirect(303,url);
    } catch (err) {
      const status = err instanceof BillingError ? err.status : 503;
      if (operation === 'portal' && /\btext\/html\b/.test(req.headers.accept || '')) return res.redirect(303,'/konto/?status=unavailable');
      if (status === 429) res.setHeader('Retry-After','60');
      return send(res,status,{error:err instanceof BillingError ? err.message : 'unavailable'});
    }
  };
}

module.exports = {makeBilling};
