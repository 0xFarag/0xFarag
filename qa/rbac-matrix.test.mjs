// © Nasser Aldin Farag (0xFarag). All rights reserved.
import assert from 'node:assert/strict';
import {test} from 'node:test';
import {createMatrix, assessment, axes} from '../public/rbac/matrix.mjs';
import {normalizeQuery, readPolicy, sha256} from '../public/rbac/retest.mjs';
import {matrixText} from '../public/rbac/matrix-languages.mjs';

const api = 'rbac.authorization.k8s.io';
const group = {kind:'Group',name:'reader'};
const query = {kind:'User',name:'Ada',groups:['reader'],namespace:'ops',verb:'get',apiGroup:'',resource:'pods'};
async function snapshot({verbs=['get'],partial=false}={}) {
  const metadata = {name:'reading',namespace:'ops'};
  const data = {kind:'List',apiVersion:'v1',metadata:partial ? {continue:'next'} : {},items:[
    {kind:'Role',apiVersion:api+'/v1',metadata,rules:[{verbs,apiGroups:[''],resources:['pods']}]},
    {kind:'RoleBinding',apiVersion:api+'/v1',metadata,subjects:[group],roleRef:{apiGroup:api,kind:'Role',name:'reading'}}
  ]};
  const bytes = new TextEncoder().encode(JSON.stringify(data));
  return {digest:await sha256(bytes),model:readPolicy(bytes)};
}
test('expectation, grants, absent grants, incomplete snapshots and before/after retain distinct results',async()=>{
  const original = await snapshot(), later = await snapshot({verbs:['list']});
  const m = createMatrix(original);
  const id = m.add(query,'no_grant');
  assert.equal(assessment(m.rows[0].before,m.rows[0].expected),'differs');
  assert.equal(m.rows[0].before.matches[0].bindingIndex,2);
  assert.equal(m.rows[0].before.matches[0].ruleIndex,1);
  assert.equal(m.export().cases[0].after,null);
  m.compare(later);
  assert.equal(m.export().cases[0].after.assessment,'matches');
  m.setExpected(id,'grant');
  assert.equal(m.export().cases[0].before.assessment,'matches');
  assert.equal(m.export().cases[0].after.assessment,'differs');
  m.compare(await snapshot({verbs:['list'],partial:true}));
  assert.equal(m.export().cases[0].after.assessment,'uncertain');
  assert.equal(m.export().cases[0].after.status,'indeterminate');
  m.compare(null);
  assert.equal(m.export().comparison_sha256,null);
  m.remove(id);
  assert.equal(m.rows.length,0);
});
test('matrix axes preserve groups, subject namespace and exact request restrictions',()=>{
  const base = axes(normalizeQuery(query));
  for (const attrs of [{groups:[]},{kind:'Group'},{kind:'ServiceAccount',subjectNamespace:'ops'}]) {
    const next = axes(normalizeQuery({...query,...attrs}));
    assert.notEqual(next[0],base[0]); assert.equal(next[1],base[1]);
  }
  for (const attrs of [{namespace:''},{apiGroup:'test.io'},{subresource:'log'},{resourceName:'x'},{fieldSelectorName:'x'},{verb:'list'}]) {
    const next = axes(normalizeQuery({...query,...attrs}));
    assert.equal(next[0],base[0]); assert.notEqual(next[1],base[1]);
  }
});
test('import checks original hash, validates every input, recomputes claims and updates atomically',async()=>{
  const original = await snapshot(), m = createMatrix(original);
  m.add(query,'grant');
  const saved = m.export();
  saved.cases[0].before.status = 'forged';
  saved.cases[0].after = {status:'forged'};
  m.restore(saved);
  assert.equal(m.export().cases[0].before.status,'granted_in_snapshot');
  assert.equal(m.export().cases[0].after,null);
  assert.throws(()=>m.restore({...saved,original_sha256:'other'}),/wrongSource/);
  assert.throws(()=>m.restore({...saved,cases:[...saved.cases,...saved.cases]}),/duplicate/);
  assert.throws(()=>m.restore({...saved,cases:[{...saved.cases[0],expected:'unsafe'}]}),/badFile/);
  assert.throws(()=>m.restore({...saved,cases:[...saved.cases,{expected:'grant',query:{...query,verb:'*'}}]}));
  assert.equal(m.rows.length,1);
  assert.throws(()=>m.add(query,'grant'),/duplicate/);
  for (let i=1;i<32;i++) m.add({...query,name:'user'+i},'grant');
  assert.throws(()=>m.add({...query,name:'last'},'grant'),/limit/);
  assert.equal(m.rows.length,32);
});
test('all five locales distinguish grant absence, uncertainty, mismatch, and expected grant',()=>{
  for (const lang of ['de-CH','en','fr','it','ar']) {
    const keys = ['no_grant_in_snapshot','indeterminate','differs','expectGrant'];
    assert.equal(new Set(keys.map(k=>matrixText(lang,k))).size,4);
    for (const key of keys) assert.notEqual(matrixText(lang,key),key);
  }
});
