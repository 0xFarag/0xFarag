// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {checkKeys} from '../workbench/model.mjs';

const schema = 'authzledger.team-handover.v1';
const formats = new Set(['burp','zap','har','openapi','nmap','nuclei']);
export const retestStates = ['fix_verified','persists','inconclusive','not_retested'];
const digest = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
const encoder = new TextEncoder();

function requireValue(condition, message = 'structure') {
  if (!condition) throw new Error(message);
}
export function readJson(bytes, limit) {
  requireValue(bytes.byteLength > 0 && bytes.byteLength <= limit, 'size');
  try {
    const text = new TextDecoder('utf-8',{fatal:true}).decode(bytes);
    const value = JSON.parse(text);
    checkKeys(text);
    return value;
  } catch { throw new Error('json'); }
}
// Matches the Team v1 producer's sorted UTF-8 JSON. Its field names are ASCII and numbers are integers.
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(key => {
      requireValue(/^[\x20-\x7e]+$/.test(key));
      return JSON.stringify(key) + ':' + canonical(value[key]);
    }).join(',') + '}';
  }
  if (typeof value === 'number') requireValue(Number.isSafeInteger(value));
  return JSON.stringify(value);
}
function raw(text, size, error) {
  requireValue(typeof text === 'string' && text.length === 4 * Math.ceil(size / 3),error);
  let data;
  try { data = atob(text); } catch { throw new Error(error); }
  requireValue(btoa(data) === text && data.length === size,error);
  return Uint8Array.from(data, x => x.charCodeAt(0));
}
export async function sha256(bytes) {
  requireValue(globalThis.crypto?.subtle,'unsupported');
  const value = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(value), n => n.toString(16).padStart(2,'0')).join('');
}
const evidenceIndexSchema = 'authzledger.evidence-index/v1';
const identifier = value => typeof value === 'string' && /^[0-9a-f]{32}$/.test(value);
const observationFields = ['format','sha256','record','fingerprint'];

function hasFields(value, fields) {
  return value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value,field));
}

function checkEvidenceIndex(row, seenRevisions, seenDigests) {
  const index = row.evidence_index;
  requireValue(hasFields(index,['observations','experiments']) && Array.isArray(index.observations));
  requireValue((row.status === 'confirmed') === (row.control !== null));
  const roles = row.status === 'confirmed' ? ['evidence','control'] : ['evidence'];
  requireValue(index.observations.length === roles.length);
  for (const [position,role] of roles.entries()) {
    const item = index.observations[position];
    const source = row[role];
    requireValue(hasFields(item,['role',...observationFields]) && item.role === role &&
      observationFields.every(field => item[field] === source[field]));
  }
  requireValue(Array.isArray(index.experiments) && index.experiments.length <= 256);
  for (const experiment of index.experiments) {
    requireValue(hasFields(experiment,['plan_id','revisions']) && identifier(experiment.plan_id));
    const revisions = experiment.revisions;
    requireValue(Array.isArray(revisions) && integer(revisions.length,1,256) &&
      revisions[0].id === experiment.plan_id && seenRevisions.size + revisions.length <= 256);
    let previous = null;
    for (const revision of revisions) {
      requireValue(hasFields(revision,['id','sha256','parent_sha256']) && identifier(revision.id) &&
        digest(revision.sha256) && revision.parent_sha256 === previous &&
        !seenRevisions.has(revision.id) && !seenDigests.has(revision.sha256));
      seenRevisions.add(revision.id);
      seenDigests.add(revision.sha256);
      previous = revision.sha256;
    }
  }
}

function checkReport(manifest, report) {
  const hasIndex = Object.hasOwn(report,'evidence_index_schema');
  requireValue(!hasIndex || report.evidence_index_schema === evidenceIndexSchema);
  const seenRevisions = new Set(), seenDigests = new Set();
  requireValue(Array.isArray(manifest.sources) && manifest.sources.length <= 32);
  requireValue(Array.isArray(manifest.retests) && manifest.retests.length <= 384);
  requireValue(Array.isArray(report.appendix) && report.appendix.length <= 128 && digest(report.scope_sha256));
  const sources = new Map();
  for (const item of manifest.sources) {
    requireValue(formats.has(item.format) && digest(item.sha256) && integer(item.bytes,1,1048576) && integer(item.records,0,1000));
    const key = item.format + ':' + item.sha256;
    requireValue(!sources.has(key));
    sources.set(key,item);
  }
  const latest = new Map();
  const ids = new Set();
  const counts = {findings:report.appendix.length,hint:0,confirmed:0,not_retested:0,fix_verified:0,persists:0,inconclusive:0};
  for (const test of manifest.retests) {
    requireValue(retestStates.includes(test.status) && digest(test.baseline_sha256) && digest(test.sha256));
    latest.set(test.finding_id,test);
  }
  function checkRef(ref) {
    if (ref === null) return;
    const src = sources.get(ref.format + ':' + ref.sha256);
    requireValue(src && integer(ref.record,1,src.records) && digest(ref.fingerprint) && (ref.asset_id === null || digest(ref.asset_id)));
  }
  function controls(e,c) {
    return e && c && e.asset_id && e.asset_id === c.asset_id && e.fingerprint !== c.fingerprint;
  }
  for (const row of report.appendix) {
    requireValue(/^[0-9a-f]{32}$/.test(row.id) && !ids.has(row.id) && digest(row.finding_sha256));
    ids.add(row.id);
    requireValue(['hint','confirmed'].includes(row.status) && retestStates.includes(row.retest));
    for (const ref of [row.evidence,row.control,row.retest_evidence,row.retest_control]) checkRef(ref);
    requireValue(row.evidence && (row.status === 'hint' || controls(row.evidence,row.control)));
    if (Object.hasOwn(row,'scanner_lead')) {
      const lead = row.scanner_lead;
      requireValue(hasIndex && lead && Object.keys(lead).sort().join(',') === 'asset_id,fingerprint,format,record,sha256');
      checkRef(lead);
      requireValue(row.status === 'confirmed' && lead.format === 'zap' && lead.asset_id === row.evidence.asset_id &&
        ['burp','har'].includes(row.evidence.format) && ['burp','har'].includes(row.control?.format));
    }
    requireValue(Object.hasOwn(row,'evidence_index') === hasIndex);
    if (hasIndex) checkEvidenceIndex(row,seenRevisions,seenDigests);
    const test = latest.get(row.id);
    requireValue(row.retest === (test?.status ?? 'not_retested'));
    if (row.retest === 'not_retested') requireValue(row.retest_evidence === null && row.retest_control === null);
    else requireValue(row.retest_evidence);
    if (['fix_verified','persists'].includes(row.retest)) {
      requireValue(row.status === 'confirmed' && controls(row.retest_evidence,row.retest_control));
      requireValue(row.retest_evidence.asset_id === row.evidence.asset_id);
      for (const next of [row.retest_evidence,row.retest_control]) {
        requireValue([row.evidence,row.control].every(prev => next.sha256 !== prev.sha256 && next.fingerprint !== prev.fingerprint));
      }
    }
    counts[row.status]++; counts[row.retest]++;
  }
  const findings = new Map(report.appendix.map(f => [f.id,f.finding_sha256]));
  for (const test of manifest.retests) requireValue(findings.get(test.finding_id) === test.baseline_sha256);
  requireValue(Object.entries(counts).every(([key,n]) => report.counts[key] === n));
  return {counts,rows:report.appendix,sources:[...sources.values()],scope:report.scope_sha256};
}

export async function verifyHandover(envelope, trust) {
  requireValue(envelope && Object.keys(envelope).sort().join(',') === 'manifest,report,signature' && envelope.manifest?.schema === schema,'profile');
  requireValue(globalThis.crypto?.subtle,'unsupported');
  const {manifest, report, signature} = envelope;
  requireValue(trust?.algorithm === 'Ed25519' && digest(trust.fingerprint),'key');
  const keyBytes = raw(trust.public_key,32,'key');
  requireValue(await sha256(keyBytes) === trust.fingerprint && trust.fingerprint === manifest.fingerprint && manifest.algorithm === 'Ed25519','key');
  let key;
  try { key = await crypto.subtle.importKey('raw',keyBytes,{name:'Ed25519'},false,['verify']); }
  catch (error) { throw new Error(error.name === 'NotSupportedError' ? 'unsupported' : 'key'); }
  requireValue(await crypto.subtle.verify('Ed25519',key,raw(signature,64,'invalid'),encoder.encode(schema+'\n'+canonical(manifest))), 'invalid');
  requireValue(await sha256(encoder.encode(canonical(report))) === manifest.report_sha256,'invalid');
  try { return {...checkReport(manifest,report),fingerprint:trust.fingerprint}; }
  catch { throw new Error('structure'); }
}

export async function verifyDelivery(proof, trust, documentBytes) {
  if (proof?.manifest) {
    requireValue(!documentBytes,'documentMismatch');
    return verifyHandover(proof,trust);
  }
  requireValue(proof && Object.keys(proof).sort().join(',') === 'document,handover,signature' &&
    proof.document?.schema === 'authzledger.team-document.v1','profile');
  requireValue(documentBytes?.byteLength,'documentNeeded');
  const result = await verifyHandover(proof.handover,trust);
  const statement = proof.document;
  const fields = ['algorithm','bytes','case_id','fingerprint','format','handover_sha256','rights','schema','scope_sha256','sha256','team_id'];
  requireValue(Object.keys(statement).sort().join(',') === fields.join(',') &&
    statement.rights === '© Nasser Aldin Farag (0xFarag). All rights reserved.' &&
    ['pdf','html'].includes(statement.format) && statement.algorithm === 'Ed25519' &&
    statement.fingerprint === result.fingerprint && statement.team_id === proof.handover.manifest.team_id &&
    statement.case_id === proof.handover.manifest.case_id && statement.scope_sha256 === result.scope,'documentMismatch');
  requireValue(statement.bytes === documentBytes.byteLength && statement.sha256 === await sha256(documentBytes) &&
    statement.handover_sha256 === await sha256(encoder.encode(canonical(proof.handover))),'documentMismatch');
  const key = await crypto.subtle.importKey('raw',raw(trust.public_key,32,'key'),'Ed25519',false,['verify']);
  requireValue(await crypto.subtle.verify('Ed25519',key,raw(proof.signature,64,'invalid'),
    encoder.encode(statement.schema+'\n'+canonical(statement))),'invalid');
  return {...result,format:statement.format};
}
