// © Nasser Aldin Farag (0xFarag). All rights reserved.
import test from 'node:test';
import assert from 'node:assert/strict';
import {inspectPolicy, evaluateAccess} from '../public/rbac/model.mjs';

const group = 'rbac.authorization.k8s.io';
const apiVersion = group + '/v1';
const rule = (change = {}) => ({apiGroups:[''], resources:['pods'], verbs:['get'], ...change});
const role = (name, rules = [rule()], namespace = 'ops') => ({
  apiVersion, kind: namespace ? 'Role' : 'ClusterRole', metadata: {name, ...(namespace ? {namespace} : {})}, rules
});
const bind = ({name = 'readers', namespace = 'ops', subject = {kind:'User',name:'alice'}, roleName = 'reader', roleKind = 'Role'} = {}) => ({
  apiVersion, kind: namespace ? 'RoleBinding' : 'ClusterRoleBinding',
  metadata:{name, ...(namespace ? {namespace} : {})}, roleRef:{apiGroup:group,kind:roleKind,name:roleName}, subjects:[subject]
});
const query = (change = {}) => ({kind:'User', name:'alice', groups:[], namespace:'ops', verb:'get', apiGroup:'', resource:'pods', ...change});
const evaluate = (objects, change = {}) => evaluateAccess(inspectPolicy(objects), query(change));
const granted = 'granted_in_snapshot', absent = 'no_grant_in_snapshot', unknown = 'indeterminate';

test('native snapshot binds grants to exact source object positions and one-based rule numbers', () => {
  const snapshot = {apiVersion:'v1',kind:'List',items:[bind(), role('reader',[rule({verbs:['list']}),rule()])]};
  const model = inspectPolicy(snapshot);
  assert.deepEqual(model.counts,{roles:1,bindings:1});
  const result = evaluateAccess(model,query());
  assert.equal(result.status,granted);
  assert.deepEqual(result.matches,[{bindingKind:'RoleBinding',bindingName:'readers',bindingIndex:1, namespace:'ops',
    roleKind:'Role',roleName:'reader',roleIndex:2,ruleIndex:2}]);
  assert.equal(evaluateAccess(model,query({name:'bob'})).status,absent);
  assert.equal(evaluateAccess(model,query({verb:'delete'})).status,absent);
  assert.equal(evaluateAccess(model,query({apiGroup:'apps'})).status,absent);
});

test('separates role namespaces, namespace-limited ClusterRole bindings and cluster-wide binding scope', () => {
  const resources = ['*'];
  const cr = role('reader',[rule({resources})],'');
  const rb = bind({roleKind:'ClusterRole'});
  assert.equal(evaluate([rb,cr],{namespace:'default'}).status,absent);
  assert.equal(evaluate([rb,cr],{namespace:'',resource:'nodes'}).status,absent);
  assert.equal(evaluate([rb,cr],{namespace:''}).status,absent);
  const crb = bind({roleKind:'ClusterRole',namespace:''});
  assert.equal(evaluate([crb,cr],{namespace:'',resource:'nodes'}).status,granted);
  assert.equal(evaluate([crb,cr],{namespace:'default'}).status,granted);
  assert.throws(()=>evaluate([rb,cr],{namespace:'ops',resource:'nodes'}));
  assert.equal(evaluate([bind(),role('reader',[],'ops'),role('reader',[rule()],'other')]).status,absent);
});

test('separates bare resources, exact subresources, */subresource and whole resource wildcards', () => {
  const verify = (resources,subresource, verb = 'get',apiGroup = '',resource = 'pods') =>
    evaluate([bind(),role('reader',[rule({verbs:['*'],apiGroups:['*'],resources})])],{subresource,verb,apiGroup,resource}).status;
  assert.equal(verify(['pods'],'log'),absent);
  assert.equal(verify(['pods/log'],'log'),granted);
  assert.equal(verify(['*/log'],'log'),granted);
  assert.equal(verify(['*/log'],''),absent);
  assert.equal(verify(['pods/*'],'log'),absent);
  assert.equal(verify(['*'],'status','update','apps','deployments'),granted);
});

test('resourceNames matches exact names; respects unnameable verbs and list field selectors', () => {
  const objects = [bind(),role('reader',[rule({verbs:['*'],resources:['*'],resourceNames:['allow','*']})])];
  const status = q => evaluate(objects,q).status;
  assert.equal(status({resourceName:'allow'}),granted);
  assert.equal(status({resourceName:'other'}),absent);
  assert.equal(status({resourceName:''}),absent);
  for (const verb of ['list','watch']) {
    assert.equal(status({verb,resourceName:'allow'}),absent);
    assert.equal(status({verb,fieldSelectorName:'allow'}),granted);
    assert.equal(status({verb,fieldSelectorName:'other'}),absent);
  }
  assert.equal(status({verb:'deletecollection',resourceName:'allow'}),absent);
  assert.equal(status({verb:'create',resourceName:'allow'}),absent);
  assert.equal(status({verb:'create',resourceName:'allow',subresource:'status'}),granted);
});

test('supports explicit group membership, User aliases and namespace-qualified ServiceAccounts', () => {
  const own = [bind({subject:{kind:'ServiceAccount',name:'build'}}),role('reader')];
  assert.equal(evaluate(own,{kind:'ServiceAccount',name:'build',subjectNamespace:'ops'}).status,granted);
  assert.equal(evaluate(own,{kind:'ServiceAccount',name:'build',subjectNamespace:'other'}).status,absent);
  assert.equal(evaluate(own,{name:'system:serviceaccount:ops:build'}).status,granted);
  const team = [bind({subject:{kind:'Group',name:'audit'}}),role('reader')];
  assert.equal(evaluate(team,{groups:['audit']}).status,granted);
  assert.equal(evaluate(team,{groups:[]}).status,absent);
  assert.equal(evaluate(team,{kind:'Group',name:'audit'}).status,granted);
  assert.equal(evaluate(team,{kind:'ServiceAccount',subjectNamespace:'ops',groups:['audit']}).status,granted);
  assert.equal(evaluate(own,{kind:'Group',name:'system:serviceaccount:ops:build'}).status,absent);
});

test('relevant unresolved, aggregated and paginated lists are indeterminate unless a separate rule establishes a grant', () => {
  const aggregated = {...role('reader',[rule()],''),aggregationRule:{clusterRoleSelectors:[{matchLabels:{tier:'frontend'}}]}};
  assert.equal(evaluate([bind()]).status,unknown);
  assert.equal(evaluate([bind()],{name:'bob'}).status,absent);
  assert.equal(evaluate([bind({roleKind:'ClusterRole'}),aggregated]).status,unknown);
  const page = {apiVersion:'v1',kind:'List',metadata:{continue:'opaque'},items:[]};
  assert.equal(evaluate(page).status,unknown);
  const explicit = [page,bind(),role('reader'),bind({name:'additional',roleKind:'ClusterRole'}),aggregated];
  const result = evaluate(explicit);
  assert.equal(result.status,granted);
  assert.ok(result.reasons.length >= 2);
  assert.equal(evaluate({apiVersion:'v1',kind:'List',items:[]}).status,absent);
});

test('typed lists accept implicit item types; skips valid non-resource rules; invalid inputs fail closed',() => {
  const obj = role('reader'), binding = bind();
  const {kind, apiVersion:_, ...inner} = obj;
  const typed = {apiVersion, kind:'RoleList', items:[inner]};
  assert.equal(evaluate([typed,binding]).status,granted);
  const cr = role('reader',[{verbs:['get'],nonResourceURLs:['/healthz']}],'');
  assert.equal(evaluate([cr,bind({namespace:'',roleKind:'ClusterRole'})]).status,absent);
  for (const bad of [null,{...obj,apiVersion:'v1'},{...obj,metadata:{name:'reader'}},
    {...binding,roleRef:{...binding.roleRef,apiGroup:'other'}}, [obj,obj],
    {...obj,rules:[{verbs:['get'],resources:['pods']}]}, role('reader',[{verbs:['get'],nonResourceURLs:['/*']}]),
    bind({roleKind:'Role',namespace:''}), bind({namespace:'',roleKind:'ClusterRole',subject:{kind:'ServiceAccount',name:'svc'}}),
    {...typed,items:[binding]}, {...typed,items:Array(1001).fill(inner)}]) assert.throws(()=>inspectPolicy(bad));
  for (const bad of [{namespace:undefined},{kind:'Other'},{apiGroup:'*'},{resource:'pods/log'},{subresource:'*'},{fieldSelectorName:'a'}])
    assert.throws(()=>evaluate([obj,binding],bad));
});


test('unproven custom-resource scope never yields a RoleBinding-only grant', () => {
  const cr = role('reader',[rule({verbs:['*'],resources:['*'],apiGroups:['*']})],'');
  const rb = bind({roleKind:'ClusterRole'});
  const req = {apiGroup:'example.com',resource:'widgets'};
  const onlyNamespace = evaluate([cr,rb],req);
  assert.equal(onlyNamespace.status,unknown);
  assert.equal(onlyNamespace.matches.length,0);
  assert.match(onlyNamespace.reasons.join(' '), /Namespace-Geltungsbereichs/);
  assert.equal(evaluate([cr,rb],{apiGroup:'apps',resource:'pods'}).status,unknown);
  assert.equal(evaluate([cr,rb],{...req,name:'bob'}).status,absent);
  const cluster = bind({name:'cluster',namespace:'',roleKind:'ClusterRole'});
  const both = evaluate([cr,rb,cluster],req);
  assert.equal(both.status,granted);
  assert.deepEqual(both.matches.map(match => match.bindingKind),['ClusterRoleBinding']);
  assert.throws(()=>evaluate([cr,rb],{apiGroup:'admissionregistration.k8s.io',resource:'validatingwebhookconfigurations'}));
  assert.equal(evaluate([cr,cluster],{namespace:'',apiGroup:'admissionregistration.k8s.io',resource:'validatingwebhookconfigurations'}).status,granted);
});
