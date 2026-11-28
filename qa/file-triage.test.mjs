// © Nasser Aldin Farag (0xFarag). All rights reserved.
import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {inspectFile, reviewFile, matchKnownHash, parseHashList, checkVirusTotalReport, MAX_FILE_BYTES, MAX_HASH_LIST_BYTES} from '../public/dateipruefung/model.mjs';

const ac = new TextEncoder();
const h = (alg,data) => createHash(alg).update(data).digest('hex');
const signals = data => data.signals.map(s=>s.id);
function magic(length, prefix) {
  const b = new Uint8Array(length); b.set(prefix); return b;
}
function pe(offset = 96) {
  const b = magic(160,[0x4d,0x5a]);
  new DataView(b.buffer).setUint32(0x3c,offset,true);
  if (offset === 96) b.set([0x50,0x45,0,0],96);
  return b;
}
const categories = {'malicious':2,'suspicious':1,'harmless':0,'undetected':5,'timeout':1,'confirmed-timeout':3,'failure':4,'type-unsupported':2};
const vtReport = model => ({data:{type:'file',id:model.sha256,attributes:{sha256:model.sha256, size:model.size,
  last_analysis_date:1704067200,last_analysis_stats:{...categories}, meaningful_name:'private',last_analysis_results:{}}}});

test('hashes exact local bytes incl empty, offsets, mutation during digest, and upper limit', async () => {
  const b = Uint8Array.of(3,5,1,0,9);
  const selected = b.subarray(1,4);
  const orig = Uint8Array.from(selected);
  const task = inspectFile(selected,'private-identity-name.pdf');
  selected.fill(42);
  const result = await task;
  assert.equal(result.sha256,h('sha256',orig)); assert.equal(result.sha512,h('sha512',orig));
  assert.equal(result.size,3); assert.equal(result.signed,false);
  assert.ok(!JSON.stringify(result).includes('private-identity'));
  const empty = await inspectFile(new ArrayBuffer(0));
  assert.equal(empty.sha256,h('sha256','')); assert.equal(empty.entropy,0);
  await assert.rejects(inspectFile(new Uint8Array(MAX_FILE_BYTES + 1)));
  await assert.rejects(inspectFile('file'));
});

test('recognizes file signatures, rejecting invalid offsets, truncated images, ELF class and PDF false starts', async () => {
  const localZip = magic(30,[0x50,0x4b,3,4]);
  const elf = magic(64,[0x7f,0x45,0x4c,0x46,2,1,1]);
  for (const [file,id] of [[pe(),'pe'],[elf,'elf'],[ac.encode('%PDF-1.7\nexample'),'pdf'],[localZip,'zip'],
    [magic(22,[0x50,0x4b,5,6]),'zip'],[magic(10,[0x1f,0x8b,8,0]),'gzip'],
    [Uint8Array.of(0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a),'png'],[Uint8Array.of(255,216,255,224),'jpeg'],
    [magic(13,ac.encode('GIF87a')),'gif'],[Uint8Array.of(0,0x61,0x73,0x6d,1,0,0,0),'wasm'],
    [pe(0xfffffff0),'unknown'],[pe(6),'unknown'],[pe().slice(0,104),'unknown'],[elf.slice(0,15),'unknown'],
    [ac.encode('dummy %PDF-2.0'),'unknown'],[ac.encode('%PDF-1.A'),'unknown']]) {
    assert.equal((await inspectFile(file)).format.id,id);
  }
  assert.deepEqual(signals(await inspectFile(pe(0xfffffff0))),['mz_unconfirmed']);
});

test('filename anomalies and whole-file byte entropy stay descriptive and omit private filenames', async () => {
  const detected = await inspectFile(pe(),'report\u202e.pdf.exe');
  assert.deepEqual(signals(detected),['bidi','double_extension']);
  assert.deepEqual(signals(await inspectFile(pe(),'report.pdf')),['extension_mismatch']);
  assert.deepEqual(signals(await inspectFile(magic(30,[0x50,0x4b,3,4]),'report.docx')),[]);
  assert.deepEqual(signals(await inspectFile(magic(10,[0x1f,0x8b,8,0]),'file.tar.gz')),[]);
  assert.equal((await inspectFile(Uint8Array.from({length:256},(_,i)=>i))).entropy,8);
  assert.equal((await inspectFile(Uint8Array.of(1,1,1))).entropy,0);
});

test('local triage gives actions based on the observed format and naming indicators', async () => {
  for (const [bytes,name,action,reason] of [
    [pe(),'invoice.pdf','review','name_signals'], [pe(),'program.exe','review','executable_format'],
    [magic(30,[0x50,0x4b,3,4]),'data.zip','review','container_format'],
    [ac.encode('unknown'),'','identify','unrecognized_format'], [ac.encode('%PDF-1.7\n'),'','compare','recognized_format']
  ]) {
    assert.deepEqual(reviewFile(await inspectFile(bytes,name)),{action,reason});
  }
});

test('bounded hash list matches SHA-256 exactly; comments and case normalization are supported', async () => {
  const original = await inspectFile(ac.encode('analyst fixture'));
  const list = parseHashList('# tested locally\n' + original.sha256.toUpperCase() + '\r\n' + original.sha256 + '\n');
  assert.equal(list.size,1);
  assert.equal(matchKnownHash(original,list),true);
  assert.equal(matchKnownHash(await inspectFile(ac.encode('analyst fixturE')),list),false);
  assert.equal(parseHashList('').size,0);
  assert.throws(()=>parseHashList(original.sha256 + ' original.exe'));
  assert.throws(()=>parseHashList('z'.repeat(64)));
  assert.throws(()=>parseHashList('# text\n'.repeat(10001)));
  assert.throws(()=>parseHashList('é'.repeat(MAX_HASH_LIST_BYTES/2+1)));
});

test('binds local VirusTotal v3 file metadata and preserves every documented result bucket', async () => {
  const original = await inspectFile(ac.encode('test'));
  const vt = vtReport(original);
  const checked = checkVirusTotalReport(original,vt);
  assert.deepEqual(checked.stats,categories);
  assert.equal(checked.total,18);
  assert.equal(checked.analyzedAt,'2024-01-01T00:00:00.000Z');
  assert.ok(!JSON.stringify(checked).includes('private'));
  vt.data.id = original.sha256.toUpperCase();
  delete vt.data.attributes.sha256;
  delete vt.data.attributes.last_analysis_date;
  assert.equal(checkVirusTotalReport(original,vt).analyzedAt,null);
  vt.data.attributes.last_analysis_stats = Object.fromEntries(Object.keys(categories).map(k=>[k,0]));
  assert.equal(checkVirusTotalReport(original,vt).total,0);
});

test('rejects mismatched object hashes, wrong size or type, inconsistent counts and invalid timestamps', async () => {
  const target=await inspectFile(ac.encode('pinned'));
  for (const mutate of [r=>r.data.id='a'.repeat(64), r=>r.data.type='analysis', r=>r.data.attributes.sha256='b'.repeat(64),
    r=>r.data.attributes.size++, r=>r.data.attributes.last_analysis_stats.timeout=-1,
    r=>delete r.data.attributes.last_analysis_stats.failure, r=>r.data.attributes.last_analysis_stats.unknown=7,
    r=>r.data.attributes.last_analysis_stats['type-unsupported']='0', r=>r.data.attributes.last_analysis_date=1704067200000]) {
    const report=vtReport(target); mutate(report);
    assert.throws(()=>checkVirusTotalReport(target,report));
  }
});

test('hash-only comparisons accept an optional valid source size without a fictitious local measurement',async () => {
  const pinned=await inspectFile(ac.encode('pinned'));
  const input=vtReport(pinned);
  assert.equal(checkVirusTotalReport({sha256:pinned.sha256},input).total,18);
  for (const invalid of [-1,1.5,'6',Number.MAX_SAFE_INTEGER+1]) {
    input.data.attributes.size=invalid;
    assert.throws(()=>checkVirusTotalReport({sha256:pinned.sha256},input));
  }
});
