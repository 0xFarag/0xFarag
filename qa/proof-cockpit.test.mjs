// © Nasser Aldin Farag (0xFarag). All rights reserved.
import assert from 'node:assert/strict';
import {generateKeyPairSync,sign} from 'node:crypto';
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


const indexed = JSON.parse(await readFile(new URL('./fixtures/team-index-cockpit.json',import.meta.url),'utf8'));

test('verifies a native evidence index and links every revision to its signed predecessor',async()=>{
  const data = await verifyDelivery(indexed.package,indexed.trustedKey);
  const observed = data.rows.find(row => row.evidence_index.experiments.length);
  assert.equal(observed.evidence_index.observations.length,2);
  assert.equal(observed.evidence_index.observations[1].fingerprint,observed.control.fingerprint);
  const [plan,review] = observed.evidence_index.experiments[0].revisions;
  assert.equal(plan.parent_sha256,null);
  assert.equal(review.parent_sha256,plan.sha256);
  const hint = data.rows.find(row => row.status === 'hint');
  assert.equal(hint.evidence_index.observations.length,1);
  assert.deepEqual(hint.evidence_index.experiments,[]);
});

function serialized(value) {
  return JSON.stringify(value,(key,item) => {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return item;
    return Object.fromEntries(Object.entries(item).sort(([a],[b]) => a < b ? -1 : a > b ? 1 : 0));
  });
}

test('rejects inconsistent indexed statements even if the signing key is trusted',async()=>{
  const {privateKey,publicKey} = generateKeyPairSync('ed25519');
  const key = Buffer.from(publicKey.export({format:'jwk'}).x,'base64url');
  const trust = {algorithm:'Ed25519',fingerprint:await sha256(key),public_key:key.toString('base64')};
  async function signed(edit) {
    const envelope = structuredClone(indexed.package);
    const report = envelope.report;
    const row = report.appendix.find(value => value.evidence_index.experiments.length);
    const index = row.evidence_index;
    const chain = index.experiments[0].revisions;
    edit(report,row,index,chain);
    envelope.manifest.fingerprint = trust.fingerprint;
    envelope.manifest.report_sha256 = await sha256(bytes(serialized(report)));
    envelope.signature = sign(null,bytes(envelope.manifest.schema+'\n'+serialized(envelope.manifest)),privateKey).toString('base64');
    return verifyDelivery(envelope,trust);
  }
  assert.equal((await signed(()=>{})).counts.findings,2);
  const invalid = [
    report => { delete report.evidence_index_schema; },
    report => { report.evidence_index_schema = null; },
    report => { report.evidence_index_schema = 'authzledger.evidence-index/v2'; },
    (_,row) => { delete row.evidence_index; },
    (_,row,index) => { index.observations.reverse(); },
    (_,row,index) => { index.observations.pop(); },
    (report,row) => { report.appendix.find(other => other.status === 'hint').control = row.control; },
    (_,row,index) => { index.observations[0].record++; },
    (_,row,index) => { index.observations[0].description = 'Unexpected free text'; },
    (_,row,index) => { index.experiments[0].plan_id = 'f'.repeat(32); },
    (_,row,index,chain) => { chain[1].parent_sha256 = null; },
    (_,row,index,chain) => { chain[1].id = chain[0].id; },
    (_,row,index,chain) => { chain[1].sha256 = chain[0].sha256; },
    (report,row,index) => { report.appendix.find(other => other !== row).evidence_index.experiments = index.experiments; }
  ];
  for (const edit of invalid) await assert.rejects(()=>signed(edit),/structure/);
});
