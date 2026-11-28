// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';
const {makeHandler} = require('../lib/passkeys');
const {createAccountStore} = require('../lib/account-store');

const portalOrigin = 'https://authzledger.com';
let account;

module.exports = function(req, res) {
  // Preview deployments and Vercel aliases never accept credentials for the production RP.
  if (req.headers.host !== 'authzledger.com' ||
      process.env.VERCEL_ENV !== 'production' ||
      !process.env.AUTHZLEDGER_ACCOUNT_SECRET ||
      !process.env.BLOB_READ_WRITE_TOKEN) {
    res.setHeader('Cache-Control','private, no-store');
    return res.status(503).json({error:'unavailable'});
  }
  if (!account) {
    const store = createAccountStore({token:process.env.BLOB_READ_WRITE_TOKEN});
    account = makeHandler({store, secret:process.env.AUTHZLEDGER_ACCOUNT_SECRET, origin:portalOrigin});
  }
  return account(req, res);
};
