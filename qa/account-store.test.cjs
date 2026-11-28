// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';

const assert = require('node:assert/strict');
const {test} = require('node:test');
const {createAccountStore} = require('../lib/account-store');
const key = 'credentials/' + 'a'.repeat(43);
const persistedPath = 'authzledger/accounts/v1/' + key + '.json';

class BlobError extends Error {}
class BlobPreconditionFailedError extends BlobError {}
class BlobNotFoundError extends BlobError {}

function stream(text) {
  return new Response(text).body;
}

function memorySdk() {
  const records = new Map();
  let revision = 0;
  return {
    BlobError, BlobNotFoundError, BlobPreconditionFailedError,
    async get(path, options) {
      assert.equal(options.access, 'private');
      assert.equal(options.useCache, false);
      const row = records.get(path);
      if (!row) return null;
      return {statusCode:200, stream:stream(row.body), blob:{pathname:path, size:Buffer.byteLength(row.body), etag:row.tag}};
    },
    async put(path, body, options) {
      assert.equal(options.access, 'private');
      assert.equal(options.addRandomSuffix, false);
      assert.equal(typeof options.allowOverwrite, 'boolean');
      if (options.allowOverwrite) {
        assert.ok(options.ifMatch);
        if (records.get(path)?.tag !== options.ifMatch) throw new BlobPreconditionFailedError();
      } else if (records.has(path)) {
        throw new BlobError('Vercel Blob: This blob already exists, use allowOverwrite to update it.');
      }
      records.set(path,{body,tag:'"version-' + (++revision) + '"'});
    },
    async del(path, options) {
      assert.ok(options.ifMatch);
      if (records.get(path)?.tag !== options.ifMatch) throw new BlobPreconditionFailedError();
      records.delete(path);
    }
  };
}

test('parallel create, replace and remove respect private conditional object versions', async () => {
  const sdk = memorySdk();
  const store = createAccountStore({sdk});
  assert.equal(await store.read(key), null);
  assert.deepEqual(await Promise.all([store.create(key, {id:1}),store.create(key, {id:2})]),[true,false]);
  const first = await store.read(key);
  assert.deepEqual(first.value,{id:1});
  assert.deepEqual(await Promise.all([store.replace(key,{id:3},first.etag),store.replace(key,{id:4},first.etag)]),[true,false]);
  const latest = await store.read(key);
  assert.deepEqual(latest.value,{id:3});
  assert.notEqual(latest.etag,first.etag);
  assert.equal(await store.remove(key,first.etag),false);
  assert.equal(await store.remove(key,latest.etag),true);
  assert.equal(await store.read(key),null);
  assert.equal(await store.replace(key,{id:5},latest.etag),false);
  for (const slot of [0,1]) assert.equal(await store.create('limits/registration-' + slot,{day:20000,count:1}), true);
});

test('untrusted paths, wildcard/multiple versions and oversized writes never reach the provider', async () => {
  const sdk=memorySdk();
  const store=createAccountStore({sdk});
  for (const name of ['../credentials/a','credentials/../limits/registration-0','/limits/registration-0','limits/registration-2','limits/registration-0?cache=1','https://example.test','credentials/'+ 'a'.repeat(42)]) {
    await assert.rejects(store.read(name), /Invalid account storage key/);
  }
  for (const tag of ['', '*', '"one","two"', '"version"\r\n', undefined]) {
    assert.throws(() => store.replace(key, {}, tag), /Invalid account storage version/);
    await assert.rejects(store.remove(key, tag), /Invalid account storage version/);
  }
  await assert.rejects(store.create(key,{s:'x'.repeat(65536)}), /Invalid account record/);
  assert.equal(await store.read(key),null);
});

test('corrupt or unbounded reads and provider errors fail closed without disclosing provider details', async () => {
  const sdk=memorySdk();
  const store=createAccountStore({sdk});
  const body = Buffer.from('{"a":2}');
  for (const [payload, path, size, etag] of [
    [Buffer.from('x'.repeat(65537)),persistedPath,0,'tag'],
    [body,persistedPath,65537,'tag'],
    [body,'another/account',0,'tag'],
    [body,persistedPath,0,'*'],
    [Buffer.from([255]),persistedPath,0,'tag'],
    [Buffer.from('unexpected content'),persistedPath,0,'tag'],
    [Buffer.from('null'),persistedPath,0,'tag']
  ]) {
    sdk.get = async () => ({statusCode:200,stream:stream(payload),blob:{pathname:path,size,etag}});
    await assert.rejects(store.read(key), /^Error: Account storage unavailable$/);
  }
  const fail = async () => {throw new BlobError('private provider diagnostics');};
  sdk.get = sdk.put = sdk.del = fail;
  for (const operation of [store.read(key), store.create(key,{}), store.replace(key,{},'tag'), store.remove(key,'tag')]) {
    await assert.rejects(operation,/^Error: Account storage unavailable$/);
  }
  sdk.get = sdk.del = async () => {throw new BlobNotFoundError();};
  assert.equal(await store.read(key),null);
  assert.equal(await store.remove(key,'tag'),false);
});
