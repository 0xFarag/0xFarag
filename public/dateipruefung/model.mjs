// © Nasser Aldin Farag (0xFarag). All rights reserved.
export const MAX_FILE_BYTES = 16 * 1024 * 1024;
export const MAX_HASH_LIST_BYTES = 1024 * 1024;
export const MAX_REPORT_BYTES = 2 * 1024 * 1024;
const sha256Pattern = /^[a-f0-9]{64}$/i;

const formats = {
  unknown: ['Keine unterstützte Kennung', []],
  pe: ['Windows-PE-Kennung', ['exe','dll','sys','scr','cpl','ocx','efi','com','pyd','node','drv','msstyles','mui']],
  elf: ['ELF-Kennung', ['elf','so','o','ko','bin','axf','appimage']],
  pdf: ['PDF-Kennung', ['pdf']],
  zip: ['ZIP-Container-Kennung', ['zip','zipx','jar','war','ear','apk','aab','ipa','docx','docm','dotx','dotm',
    'xlsx','xlsm','xltx','xltm','pptx','pptm','ppsx','ppsm','epub','odt','ods','odp','vsix','xpi','nupkg','whl']],
  gzip: ['Gzip-Kennung', ['gz','gzip','tgz','svgz']],
  png: ['PNG-Kennung', ['png','apng']], jpeg: ['JPEG-Kennung', ['jpg','jpeg','jpe','jfif']],
  gif: ['GIF-Kennung', ['gif']], wasm: ['WebAssembly-Kennung', ['wasm']]
};
const commonDocument = new Set(['txt','pdf','png','jpg','jpeg','gif','doc','docx','xls','xlsx','ppt','pptx','rtf','csv','zip']);
const executable = new Set(['exe','scr','com','pif','bat','cmd','msi','msp','js','jse','vbs','vbe','wsf','hta','ps1','lnk','cpl','dll']);
const recognisedExtensions = new Set([...Object.values(formats).flatMap(([, exts]) => exts), ...commonDocument, ...executable]);

function ensure(condition, message) {
  if (!condition) throw new Error(message);
}
function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function prefix(bytes, sequence, offset = 0) {
  return bytes.length >= offset + sequence.length && sequence.every((byte, index) => bytes[offset + index] === byte);
}
function fileType(bytes) {
  if (prefix(bytes, [0x4d,0x5a]) && bytes.length >= 64) {
    const offset = new DataView(bytes.buffer,bytes.byteOffset,bytes.byteLength).getUint32(0x3c,true);
    if (offset >= 64 && offset <= bytes.length - 24 && prefix(bytes,[0x50,0x45,0,0],offset)) return 'pe';
  }
  if (prefix(bytes,[0x7f,0x45,0x4c,0x46]) && [1,2].includes(bytes[4]) && [1,2].includes(bytes[5]) &&
      bytes[6] === 1 && bytes.length >= (bytes[4] === 1 ? 52 : 64)) return 'elf';
  if (/^%PDF-[12]\.[0-9](?:\s|$)/.test(String.fromCharCode(...bytes.subarray(0,9)))) return 'pdf';
  if ((bytes.length >= 30 && prefix(bytes,[0x50,0x4b,3,4])) ||
      (bytes.length >= 22 && prefix(bytes,[0x50,0x4b,5,6]))) return 'zip';
  if (bytes.length >= 10 && prefix(bytes,[0x1f,0x8b,8]) && !(bytes[3] & 0xe0)) return 'gzip';
  if (prefix(bytes,[0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a])) return 'png';
  if (bytes.length >= 4 && prefix(bytes,[0xff,0xd8,0xff])) return 'jpeg';
  if (bytes.length >= 13 && /^GIF(?:87a|89a)$/.test(String.fromCharCode(...bytes.subarray(0,6)))) return 'gif';
  if (prefix(bytes,[0,0x61,0x73,0x6d,1,0,0,0])) return 'wasm';
  return 'unknown';
}

function nameSignals(name, id, bytes) {
  const signals = [];
  const basename = name.split(/[\\/]/).at(-1);
  const parts = basename.toLowerCase().split('.');
  const extension = parts.length > 1 ? parts.at(-1) : '';
  if (/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(basename))
    signals.push({id:'bidi', label:'Der Name enthält ein Unicode-Zeichen zur Steuerung der Leserichtung.'});
  if (parts.length >= 3 && commonDocument.has(parts.at(-2)) && executable.has(extension))
    signals.push({id:'double_extension',label:'Auf eine Dokument- oder Archivendung folgt eine ausführbare oder aktivierbare Endung.'});
  if (id !== 'unknown' && recognisedExtensions.has(extension) && !formats[id][1].includes(extension))
    signals.push({id:'extension_mismatch',label:'Die bekannte Dateiendung passt nicht zur erkannten Formatkennung.'});
  if (id !== 'pe' && prefix(bytes,[0x4d,0x5a]))
    signals.push({id:'mz_unconfirmed',label:'MZ-Präfix vorhanden. Der Verweis auf einen vollständigen PE-Signatur- und COFF-Header ist nicht bestätigt.'});
  return signals;
}

function entropy(bytes) {
  const counts = new Uint32Array(256);
  for (const byte of bytes) counts[byte]++;
  let bits = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const fraction = count / bytes.length;
    bits -= fraction * Math.log2(fraction);
  }
  return bits;
}
async function hashBytes(algorithm, bytes) {
  const digest = await crypto.subtle.digest(algorithm, bytes);
  return Array.from(new Uint8Array(digest), value => value.toString(16).padStart(2,'0')).join('');
}

export async function inspectFile(input, name = '') {
  ensure(input instanceof ArrayBuffer || input instanceof Uint8Array, 'Die Datei muss als unveränderte Bytes vorliegen.');
  ensure(input.byteLength <= MAX_FILE_BYTES, 'Eine Datei darf höchstens 16 MiB gross sein.');
  ensure(typeof name === 'string' && name.length <= 2048, 'Der Dateiname ist zu lang oder ungültig.');
  ensure(globalThis.crypto?.subtle, 'Für kryptografische Hashes ist ein sicherer Browserkontext erforderlich.');
  const bytes = Uint8Array.from(input instanceof Uint8Array ? input : new Uint8Array(input));
  const id = fileType(bytes);
  const [sha256, sha512] = await Promise.all([hashBytes('SHA-256',bytes), hashBytes('SHA-512',bytes)]);
  return {size: bytes.length, sha256, sha512, format:{id, label:formats[id][0], extensions:[...formats[id][1]]},
    entropy: entropy(bytes), signals: nameSignals(name,id,bytes), signed:false};
}

export function parseHashList(text) {
  ensure(typeof text === 'string' && text.length <= MAX_HASH_LIST_BYTES &&
    new TextEncoder().encode(text).byteLength <= MAX_HASH_LIST_BYTES, 'Die Hashliste darf höchstens 1 MiB gross sein.');
  const lines = text.split(/\r?\n/);
  // A conventional trailing line terminator does not add another data line.
  if (lines.at(-1) === '') lines.pop();
  ensure(lines.length <= 10000, 'Die Hashliste darf höchstens 10’000 Zeilen enthalten.');
  const hashes = new Set();
  for (const [i,line] of lines.entries()) {
    const clean = line.trim();
    if (!clean || clean.startsWith('#')) continue;
    ensure(sha256Pattern.test(clean), 'Zeile ' + (i+1) + ' benötigt genau einen SHA-256-Wert.');
    hashes.add(clean.toLowerCase());
  }
  return hashes;
}

export function matchKnownHash(model, hashes) {
  ensure(typeof model?.sha256 === 'string' && sha256Pattern.test(model.sha256) && hashes instanceof Set, 'Datei oder Hashliste fehlt.');
  return hashes.has(model.sha256.toLowerCase());
}

const statNames = ['malicious','suspicious','harmless','undetected','timeout','confirmed-timeout','failure','type-unsupported'];
export function checkVirusTotalReport(model, input) {
  ensure(object(model) && typeof model.sha256 === 'string' && sha256Pattern.test(model.sha256), 'Wählen Sie zuerst eine Datei.');
  ensure(object(input) && object(input.data) && input.data.type === 'file' && object(input.data.attributes),
    'Erwartet wird ein VirusTotal-v3-Dateibericht mit data.type=file und data.attributes.');
  const data = input.data, attributes = data.attributes, expected = model.sha256.toLowerCase();
  ensure(typeof data.id === 'string' && sha256Pattern.test(data.id) && data.id.toLowerCase() === expected,
    'Die SHA-256-Objekt-ID passt nicht zur gewählten Datei.');
  if (Object.hasOwn(attributes,'sha256'))
    ensure(typeof attributes.sha256 === 'string' && sha256Pattern.test(attributes.sha256) && attributes.sha256.toLowerCase() === expected,
      'Der SHA-256 im Attribut widerspricht der gewählten Datei.');
  if (Object.hasOwn(attributes,'size')) ensure(attributes.size === model.size, 'Die gemeldete Dateigrösse widerspricht der gewählten Datei.');
  const incoming = attributes.last_analysis_stats;
  ensure(object(incoming) && Object.keys(incoming).length === statNames.length &&
    statNames.every(key => Object.hasOwn(incoming,key)), 'Die acht dokumentierten Analysezähler fehlen oder enthalten zusätzliche Kategorien.');
  const stats = {};
  let total = 0;
  for (const key of statNames) {
    const count = incoming[key];
    ensure(Number.isInteger(count) && count >= 0 && count <= 100000, 'Ein Analysezähler ist ungültig.');
    stats[key] = count;
    total += count;
  }
  let analyzedAt = null;
  if (Object.hasOwn(attributes,'last_analysis_date')) {
    const time = attributes.last_analysis_date;
    ensure(Number.isInteger(time) && time >= 0 && time <= 253402300799, 'Der Analysezeitpunkt ist kein gültiger Unix-Zeitstempel in Sekunden.');
    analyzedAt = new Date(time * 1000).toISOString();
  }
  return {sha256:expected, stats, total, analyzedAt};
}
