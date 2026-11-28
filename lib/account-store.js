// © Nasser Aldin Farag (0xFarag). All rights reserved.
'use strict';

const ROOT = 'authzledger/accounts/v1/';
const MAX_BYTES = 64 * 1024;
const contentType = 'application/json; charset=utf-8';

function pathname(key) {
  if (typeof key !== 'string' || !/^(?:credentials\/[A-Za-z0-9_-]{43}|limits\/registration-[01])$/.test(key)) {
    throw new Error('Invalid account storage key');
  }
  return ROOT + key + '.json';
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function encode(value) {
  if (!isRecord(value)) throw new Error('Invalid account record');
  const json = JSON.stringify(value);
  if (!json || Buffer.byteLength(json) > MAX_BYTES) throw new Error('Invalid account record');
  return json;
}

function checkEtag(tag) {
  // Accept opaque version tags, with or without HTTP quotes. Never accept a
  // wildcard or multiple ETags: every mutation must match exactly one version.
  if (typeof tag !== 'string' || !/^(?:"[A-Za-z0-9_.:+/=-]{1,256}"|[A-Za-z0-9_.:+/=-]{1,256})$/.test(tag)) {
    throw new Error('Invalid account storage version');
  }
  return tag;
}

async function decode(result, expectedPath) {
  const {blob, stream} = result;
  if (result.statusCode !== 200 || !stream || blob?.pathname !== expectedPath ||
      !Number.isSafeInteger(blob.size) || blob.size < 0 || blob.size > MAX_BYTES) {
    if (stream) await stream.cancel();
    throw new Error('Invalid account record');
  }
  let etag;
  try { etag = checkEtag(blob.etag); } catch (error) {
    await stream.cancel();
    throw error;
  }
  const reader = stream.getReader();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BYTES) {
        await reader.cancel();
        throw new Error('Invalid account record');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const value = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(Buffer.concat(chunks, size)));
  if (!isRecord(value)) throw new Error('Invalid account record');
  return {value, etag};
}

function createAccountStore({token, storeId, sdk = require('@vercel/blob')} = {}) {
  const auth = token ? {token} : storeId ? {storeId} : {};
  const options = () => ({...auth, abortSignal:AbortSignal.timeout(8000)});
  const unavailable = () => new Error('Account storage unavailable');

  async function write(path, value, ifMatch) {
    const json = encode(value);
    try {
      await sdk.put(path, json, {
        ...options(), access:'private', contentType, addRandomSuffix:false,
        allowOverwrite:ifMatch !== undefined, ...(ifMatch === undefined ? {} : {ifMatch})
      });
      return true;
    } catch (error) {
      if (error instanceof sdk.BlobPreconditionFailedError) return false;
      if (ifMatch !== undefined && error instanceof sdk.BlobNotFoundError) return false;
      // The SDK represents the no-overwrite collision as a generic BlobError.
      if (ifMatch === undefined && error instanceof sdk.BlobError &&
          /^(?:Vercel Blob: )?This blob already exists(?:[.,]|$)/i.test(error.message)) return false;
      throw unavailable();
    }
  }

  return {
    async read(key) {
      const path = pathname(key);
      try {
        // Bypass the private edge cache so deleted sessions and CAS versions
        // are observed immediately. In SDK v2.9 get returns null for HTTP 404.
        const result = await sdk.get(path, {...options(), access:'private', useCache:false});
        return result === null ? null : await decode(result, path);
      } catch (error) {
        if (error instanceof sdk.BlobNotFoundError) return null;
        throw unavailable();
      }
    },
    create(key, value) {
      return write(pathname(key), value);
    },
    replace(key, value, etag) {
      return write(pathname(key), value, checkEtag(etag));
    },
    async remove(key, etag) {
      const path = pathname(key);
      const ifMatch = checkEtag(etag);
      try {
        await sdk.del(path, {...options(), ifMatch});
        return true;
      } catch (error) {
        if (error instanceof sdk.BlobPreconditionFailedError || error instanceof sdk.BlobNotFoundError) return false;
        throw unavailable();
      }
    }
  };
}
module.exports = {createAccountStore};
