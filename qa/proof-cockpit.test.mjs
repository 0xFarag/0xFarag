// © Nasser Aldin Farag (0xFarag). All rights reserved.
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import test from 'node:test';
import {readJson,sha256,verifyDelivery} from '../public/proof-cockpit/verify.mjs';

const {proof,trustedKey,original,document:html} = JSON.parse(await readFile(new URL('./fixtures/team-proof-cockpit.json',import.meta.url),'utf8'));
const bytes = t => new TextEncoder().encode(t);
test('reads native v1 signatures, links source records and preserves unretested findings',async()=>{
  const data = await verifyDelivery(proof.handover,trustedKey);
  assert.equal(data.counts.not_retested,1);
  assert.equal(data.counts.fix_verified,1);
  assert.equal(data.rows.filter(f=>f.control).length,2);
  assert(data.sources.some(s=>s.sha256));
  assert(data.sources.map(s=>s.sha256).includes(await sha256(bytes(original))));
});
test('verifies native signed HTML and rejects substituted bytes, wrong proof or mismatched keys',async()=>{
  assert.equal((await verifyDelivery(proof,trustedKey,bytes(html))).format,'html');
  await assert.rejects(()=>verifyDelivery(proof,trustedKey),/documentNeeded/);
  await assert.rejects(()=>verifyDelivery(proof,trustedKey,bytes(html+' ')),/documentMismatch/);
  const wrong = structuredClone(proof);
  wrong.document.format='pdf';
  await assert.rejects(()=>verifyDelivery(wrong,trustedKey,bytes(html)),/invalid/);
  await assert.rejects(()=>verifyDelivery(proof.handover,{...trustedKey,fingerprint:'0'.repeat(64)}),/key/);
  const tampered = structuredClone(proof.handover);
  tampered.report.counts.confirmed++;
  await assert.rejects(()=>verifyDelivery(tampered,trustedKey),/invalid/);
});
test('bounds UTF-8 JSON and rejects ambiguous duplicate keys',()=>{
  assert.throws(()=>readJson(bytes('{"signature":1,"signature":2}'),4096),/json/);
  assert.throws(()=>readJson(new Uint8Array([0xc0]),4096),/json/);
  assert.throws(()=>readJson(bytes('{}'),1),/size/);
});
