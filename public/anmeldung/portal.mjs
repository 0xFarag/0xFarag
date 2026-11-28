// © Nasser Aldin Farag (0xFarag). All rights reserved.
const el = id => document.getElementById(id);
const t = key => window.AuthzI18n?.t(key) ?? key;
const messages = {
  unavailable: 'Der Kontodienst ist gerade nicht erreichbar. Versuchen Sie es erneut.',
  unsupported: 'Dieser Browser unterstützt hier keine Passkeys. Öffnen Sie die Seite in einem aktuellen Browser über HTTPS.',
  cancelled: 'Die Passkey-Abfrage wurde abgebrochen oder ist abgelaufen. Sie können es erneut versuchen.',
  challenge_expired: 'Die Anfrage ist abgelaufen. Starten Sie die Anmeldung oder Einrichtung erneut.',
  verification_failed: 'Der Passkey konnte nicht bestätigt werden. Wählen Sie den zu diesem Konto gehörenden Passkey.',
  conflict: 'Die Anfrage konnte nicht abgeschlossen werden. Prüfen Sie Ihren Kontostatus erneut.',
  rate_limited: 'Zu viele Anfragen. Versuchen Sie es später erneut.',
  invalid_origin: 'Öffnen Sie die Anmeldung direkt auf authzledger.com.',
  reauthenticate: 'Bestätigen Sie Ihren Passkey erneut und wählen Sie dann nochmals «Konto löschen».',
  unauthenticated: 'Ihre Sitzung ist abgelaufen. Melden Sie sich erneut an.'
};
const actions = ['register','login','logout','delete-open','delete-confirm','delete-cancel','reauth','retry'];
let account = null;
let notice = '';
let isError = false;
let active = null;
let channel;
try { channel = new BroadcastChannel('authzledger-website-session'); } catch { /* Revalidate when returning to the tab. */ }
const supported = () => window.isSecureContext && typeof window.PublicKeyCredential === 'function'
  && typeof navigator.credentials?.create === 'function' && typeof navigator.credentials?.get === 'function';

function message(key = '', error = false) {
  notice = key;
  isError = error;
  el('status').textContent = t(key);
  el('status').toggleAttribute('data-error', error);
}
function drawAccount() {
  el('heading').textContent = t(account ? 'Mein Website-Konto' : 'Anmeldung');
  el('account-id').textContent = account?.id ?? '';
  el('account-created').textContent = account ? new Intl.DateTimeFormat(
    document.documentElement.lang, {dateStyle:'long'}
  ).format(new Date(account.createdAt)) : '';
}
function show(next) {
  account = next;
  el('account').hidden = !account;
  el('anonymous').hidden = Boolean(account);
  el('confirm-delete').hidden = true;
  el('retry').hidden = el('reauth').hidden = true;
  drawAccount();
}
function mask() {
  show(null);
  el('anonymous').hidden = true;
}
function setEnabled() {
  for (const id of actions) el(id).disabled = Boolean(active) || (['login','register'].includes(id) && !supported());
}
function checked(data) {
  if (data?.authenticated !== true || typeof data.account?.id !== 'string' || !data.account.id
      || typeof data.account.createdAt !== 'string' || !Number.isFinite(Date.parse(data.account.createdAt))) {
    throw new Error('unavailable');
  }
  return data.account;
}
async function request(body, signal) {
  const res = await fetch('/api/account', {
    method: body ? 'POST' : 'GET',
    credentials:'same-origin', cache:'no-store', redirect:'error', signal,
    headers: body ? {'Content-Type':'application/json','Accept':'application/json'} : {Accept:'application/json'},
    ...(body ? {body:JSON.stringify(body)} : {})
  });
  const data = await res.json();
  if (!body && res.status === 401 && data?.authenticated === false) return data;
  if (!res.ok) throw new Error(Object.hasOwn(messages, data?.error) ? data.error : 'unavailable');
  return data;
}
async function refresh() {
  if (active) return;
  const operation = new AbortController();
  active = operation;
  mask(); message('Zugang wird geprüft …'); setEnabled();
  try {
    const data = await request(null, operation.signal);
    if (operation.signal.aborted) return;
    show(data.authenticated === false ? null : checked(data));
    if (!account && !supported()) message(messages.unsupported, true);
    else message();
  } catch {
    if (operation.signal.aborted) return;
    mask(); el('retry').hidden = false; message(messages.unavailable, true);
  } finally {
    if (active === operation) { active = null; setEnabled(); }
  }
}

function decode(s) {
  const raw = atob(s.replaceAll('-','+').replaceAll('_','/'));
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}
function encode(buffer) {
  return btoa(Array.from(new Uint8Array(buffer), b => String.fromCharCode(b)).join(''))
    .replaceAll('+','-').replaceAll('/','_').replace(/=+$/, '');
}
function browserOptions(value, register) {
  const native = register ? 'parseCreationOptionsFromJSON' : 'parseRequestOptionsFromJSON';
  if (typeof PublicKeyCredential[native] === 'function') return PublicKeyCredential[native](value);
  const options = {...value, challenge:decode(value.challenge)};
  if (register) options.user = {...value.user, id:decode(value.user.id)};
  for (const field of ['excludeCredentials','allowCredentials']) {
    if (options[field]) options[field] = options[field].map(item => ({...item,id:decode(item.id)}));
  }
  return options;
}
function asJson(credential, register) {
  if (typeof credential?.toJSON === 'function') return credential.toJSON();
  const auth = credential.response;
  const response = {clientDataJSON:encode(auth.clientDataJSON)};
  if (register) {
    response.attestationObject = encode(auth.attestationObject);
    if (auth.getTransports) response.transports = auth.getTransports();
  } else {
    response.authenticatorData = encode(auth.authenticatorData);
    response.signature = encode(auth.signature);
    if (auth.userHandle) response.userHandle = encode(auth.userHandle);
  }
  return {id:credential.id, rawId:encode(credential.rawId), type:credential.type,
    authenticatorAttachment:credential.authenticatorAttachment || undefined,
    clientExtensionResults:credential.getClientExtensionResults(), response};
}

async function run(action) {
  if (active) return;
  const register = action === 'register';
  if ((register || action === 'login') && !supported()) { message(messages.unsupported, true); return; }
  const operation = new AbortController();
  active = operation; setEnabled(); el('retry').hidden = true;
  try {
    if (register || action === 'login') {
      message('Bestätigen Sie die Anfrage auf Ihrem Gerät.');
      const {options} = await request({action:action + '-options'}, operation.signal);
      const input = {publicKey:browserOptions(options, register), signal:operation.signal};
      const credential = register ? await navigator.credentials.create(input) : await navigator.credentials.get(input);
      if (!credential) throw new Error('cancelled');
      const data = await request({action:action + '-finish',response:asJson(credential, register)}, operation.signal);
      if (operation.signal.aborted) return;
      show(checked(data));
      message(register ? 'Ihr Konto ist eingerichtet.' : 'Sie sind angemeldet.');
    } else {
      const data = await request({action}, operation.signal);
      if (operation.signal.aborted) return;
      if (data?.authenticated !== false) throw new Error('unavailable');
      show(null);
      message(action === 'logout' ? 'Sie sind abgemeldet.' : 'Ihr Website-Konto wurde gelöscht.');
    }
    channel?.postMessage('changed'); el('heading').focus();
  } catch (error) {
    if (operation.signal.aborted) return;
    let code = error?.message;
    if (['NotAllowedError','AbortError'].includes(error?.name)) code = 'cancelled';
    if (error?.name === 'NotSupportedError') code = 'unsupported';
    if (code === 'reauthenticate') {
      el('confirm-delete').hidden = true;
      el('reauth').hidden = false;
    }
    if (code === 'unauthenticated') show(null);
    if (code === 'unavailable' || code === 'conflict' || !Object.hasOwn(messages, code)) {
      if (account) mask();
      el('retry').hidden = false;
    }
    message(messages[code] || messages.unavailable, true);
  } finally {
    if (active === operation) { active = null; setEnabled(); }
  }
}
el('login').onclick = () => run('login');
el('register').onclick = () => run('register');
el('logout').onclick = () => run('logout');
el('delete-open').onclick = () => { el('confirm-delete').hidden = false; el('delete-cancel').focus(); };
el('delete-cancel').onclick = () => { el('confirm-delete').hidden = true; el('delete-open').focus(); };
el('delete-confirm').onclick = () => run('delete-account');
el('reauth').onclick = () => run('login');
el('retry').onclick = refresh;
window.addEventListener('authzlanguage', () => { drawAccount(); message(notice, isError); });
window.addEventListener('pagehide', () => { active?.abort(); active = null; mask(); message(); setEnabled(); });
window.addEventListener('pageshow', event => { if (event.persisted) refresh(); });
document.addEventListener('visibilitychange', () => { if (!document.hidden && !active) refresh(); });
if (channel) channel.onmessage = event => { if (event.data === 'changed' && !active) refresh(); };
refresh();
