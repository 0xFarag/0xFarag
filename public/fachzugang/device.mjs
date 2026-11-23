// © Nasser Aldin Farag (0xFarag). All rights reserved.
const database = 'authzledger-fachzugang-v1';
const store = 'device';
const slot = 'review-signer';
export const endpoint = '/api/pro-review';

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(database, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(store);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error('Die Schlüsselablage ist in einem anderen Fenster belegt.'));
  });
}

async function storedPair(pair) {
  const db = await openDatabase();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(store, pair ? 'readwrite' : 'readonly');
      const entries = tx.objectStore(store);
      const request = pair ? entries.add(pair, slot) : entries.get(slot);
      tx.oncomplete = () => resolve(pair || request.result);
      tx.onabort = () => reject(tx.error || request.error || new Error('Schlüsselablage abgebrochen.'));
    });
  } finally {
    db.close();
  }
}

export async function deviceKey(create = false) {
  const existing = await storedPair();
  if (existing || !create) return existing;
  const pair = await crypto.subtle.generateKey('Ed25519', false, ['sign','verify']);
  try {
    return await storedPair(pair);
  } catch (error) {
    // A second tab may already have created the key. Never replace its key.
    if (error.name !== 'ConstraintError') throw error;
    return storedPair();
  }
}

function base64url(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

export async function publicApplication(pair) {
  const raw = await crypto.subtle.exportKey('raw', pair.publicKey);
  return {
    kid: base64url(await crypto.subtle.digest('SHA-256', raw)),
    jwk: {kty:'OKP', crv:'Ed25519', x:base64url(raw)}
  };
}

export async function signedRequest(pair, kid, cases, origin, issuedAt = Math.floor(Date.now() / 1000)) {
  const values = cases.map(c => [c.scope, c.controls, c.binding, c.retest]);
  const canonical = ['authzledger.pro-review.v1', 'POST', endpoint, origin, kid, issuedAt, values];
  const bytes = new TextEncoder().encode(JSON.stringify(canonical));
  const signature = base64url(await crypto.subtle.sign('Ed25519', pair.privateKey, bytes));
  return {kid, issuedAt, cases, signature};
}
