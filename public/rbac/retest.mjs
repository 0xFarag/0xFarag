// © Nasser Aldin Farag (0xFarag). All rights reserved.
import {evaluateAccess, inspectPolicy} from './model.mjs';

export const POLICY_BYTES = 2 * 1024 * 1024;
export const CASE_LIMIT = 32;
const encoder = new TextEncoder();
const hex = /^[0-9a-f]{64}$/;
const rights = '© Nasser Aldin Farag (0xFarag). All rights reserved.';
const fields = ['kind','name','subjectNamespace','namespace','verb','apiGroup','resource','subresource','resourceName','fieldSelectorName'];
const required = ['kind','name','namespace','verb','apiGroup','resource'];

function demand(condition, message) {
  if (!condition) throw Error(message);
}
function canonical(value) {
  return JSON.stringify(value, (key, data) => {
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      return Object.fromEntries(Object.keys(data).sort().map(k => [k,data[k]]));
    }
    return data;
  });
}
export async function sha256(bytes) {
  const hash = await crypto.subtle.digest('SHA-256',bytes);
  return [...new Uint8Array(hash)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
export function readPolicy(bytes) {
  demand(bytes instanceof Uint8Array && bytes.byteLength > 0 && bytes.byteLength <= POLICY_BYTES, 'Richtliniendateien müssen zwischen 1 Byte und 2 MiB gross sein.');
  let input;
  try { input = JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)); }
  catch { throw Error('Die Richtliniendatei enthält kein gültiges UTF-8-JSON.'); }
  return inspectPolicy(input);
}
export function normalizeQuery(query) {
  demand(query && typeof query === 'object' && !Array.isArray(query), 'Ungültige Prüfanfrage.');
  demand(Object.keys(query).every(k => [...fields,'groups'].includes(k)) && required.every(k=>Object.hasOwn(query,k)),
    'Die Prüfanfrage enthält fehlende oder unbekannte Felder.');
  const result = {};
  for (const field of fields) {
    if (!Object.hasOwn(query,field)) continue;
    demand(typeof query[field] === 'string' && query[field].length <= 253,'Ungültiger Wert in der Prüfanfrage.');
    if (required.includes(field) || query[field] !== '') result[field] = query[field];
  }
  const groups = query.groups ?? [];
  demand(Array.isArray(groups) && groups.length <= 64 && groups.every(g=>typeof g === 'string' && g.length > 0 && g.length <= 253), 'Ungültige Gruppenliste.');
  result.groups = [...new Set(groups)].sort();
  return result;
}
async function summarize(model, query) {
  const result = evaluateAccess(model,query);
  const roles = new Map(model.roles.map(r => [r.objectIndex,r]));
  const bindings = new Map(model.bindings.map(b => [b.objectIndex,b]));
  const sourceBindings = new Map(), sourceRules = new Map();
  for (const ref of result.matches) {
    sourceBindings.set(ref.bindingIndex,bindings.get(ref.bindingIndex));
    const ruleKey = ref.roleIndex + '/' + ref.ruleIndex;
    sourceRules.set(ruleKey,roles.get(ref.roleIndex).rules[ref.ruleIndex-1]);
  }
  const evidence = {result, bindings:[...sourceBindings.entries()], rules:[...sourceRules.entries()]};
  return {status:result.status, match_count:result.matchCount, proof_complete:result.matches.length === result.matchCount,
    proof_sha256:await sha256(encoder.encode(canonical(evidence)))};
}
export async function makeBaseline(policySha256, queries, model) {
  demand(typeof policySha256 === 'string' && hex.test(policySha256), 'Der ursprüngliche Datei-Hash fehlt.');
  demand(Array.isArray(queries) && queries.length > 0 && queries.length <= CASE_LIMIT, 'Eine Prüfbasis benötigt 1 bis 32 Fragen.');
  const seen = new Set(), cases = [];
  for (const raw of queries) {
    const query = normalizeQuery(raw);
    const id = await sha256(encoder.encode(canonical(query)));
    demand(!seen.has(id), 'Die Prüfbasis enthält eine doppelte Frage.');
    seen.add(id);
    cases.push({id,query,outcome:await summarize(model,query)});
  }
  const body = {schema:'authzledger.rbac-baseline.v1', rights, signature:'unsigned', policy_sha256:policySha256, cases};
  return {...body, baseline_sha256:await sha256(encoder.encode(canonical(body)))};
}
export async function retestPolicy(baseline, baselinePolicyBytes, currentPolicyBytes, selectedIndices) {
  demand(baseline?.schema === 'authzledger.rbac-baseline.v1' && Array.isArray(baseline.cases)
    && baseline.cases.length > 0 && baseline.cases.length <= CASE_LIMIT, 'Ungültige Prüfbasis.');
  const oldModel = readPolicy(baselinePolicyBytes);
  const newModel = readPolicy(currentPolicyBytes);
  const oldDigest = await sha256(baselinePolicyBytes);
  demand(oldDigest === baseline.policy_sha256, 'Die ursprüngliche Datei passt nicht zur Prüfbasis (SHA-256).');
  const expected = await makeBaseline(oldDigest,baseline.cases.map(c => c?.query),oldModel);
  demand(canonical(expected) === canonical(baseline), 'Die Prüfbasis stimmt nicht mit der erneuten Auswertung des Originals überein.');
  const chosen = selectedIndices === undefined ? expected.cases.map((_,i)=>i) : selectedIndices;
  demand(Array.isArray(chosen) && chosen.length <= expected.cases.length &&
    chosen.every(i=>Number.isInteger(i) && i >= 0 && i < expected.cases.length) && new Set(chosen).size === chosen.length,
    'Die Fallauswahl ist ungültig.');
  const selection = new Set(chosen), cases = [];
  for (const [i, c] of expected.cases.entries()) {
    const after = selection.has(i) ? await summarize(newModel,c.query) : null;
    let status = 'not_retested';
    if (after) {
      if ([c.outcome.status,after.status].includes('indeterminate')) status = 'indeterminate';
      else if (c.outcome.status !== after.status) status = 'snapshot_decision_changed';
      else if (!c.outcome.proof_complete || !after.proof_complete) status = 'indeterminate';
      else if (c.outcome.proof_sha256 !== after.proof_sha256) status = 'snapshot_evidence_changed';
      else status = 'snapshot_result_repeated';
    }
    cases.push({id:c.id, before:c.outcome, after, status});
  }
  const currentHash = await sha256(currentPolicyBytes);
  return {schema:'authzledger.rbac-retest.v1',rights,signature:'unsigned',basis:'offline_rbac_snapshots',
    baseline_sha256:expected.baseline_sha256, original_policy_sha256:oldDigest, current_policy_sha256:currentHash,
    identical_source_bytes:oldDigest === currentHash, coverage:{total:cases.length,retested:selection.size,not_retested:cases.length-selection.size},cases};
}
