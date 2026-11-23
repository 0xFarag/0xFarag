// © Nasser Aldin Farag (0xFarag). All rights reserved.
// Kubernetes RBAC v1 resource-request semantics. No cluster connection or API discovery.
const group = 'rbac.authorization.k8s.io';
const version = group + '/v1';
const roleKinds = ['Role', 'ClusterRole'];
const bindingKinds = ['RoleBinding', 'ClusterRoleBinding'];
const kinds = [...roleKinds, ...bindingKinds];
const subjectKinds = ['User', 'Group', 'ServiceAccount'];
const roleLookup = new WeakMap();
const maxObjects = 1000;
const maxProofs = 500;

function requireValue(ok, message) {
  if (!ok) throw Error(message);
}
function object(value, label) {
  requireValue(value && typeof value === 'object' && !Array.isArray(value), label + ' muss ein JSON-Objekt sein.');
  return value;
}
function text(value, label, {empty = false, max = 253} = {}) {
  requireValue(typeof value === 'string' && (empty || value.trim().length > 0) && value.length <= max &&
    !/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/u.test(value), label + ' ist ungültig.');
  return value;
}
function list(value, label, min = 0, max = 256) {
  requireValue(Array.isArray(value) && value.length >= min && value.length <= max, 'Ungültige Anzahl für ' + label + '.');
  return value;
}
function strings(value, label, min = 0, empty = false) {
  return list(value, label, min).map(v => text(v, label, {empty}));
}
function token(value, label) {
  requireValue(typeof value === 'string' && /^[a-z0-9][a-z0-9.-]{0,252}$/.test(value), label + ' benötigt einen konkreten API-Wert.');
  return value;
}
function objectName(value) {
  const name = text(value, 'Objektname');
  requireValue(name !== '.' && name !== '..' && !/[/%]/.test(name), 'Ungültiger Kubernetes-Objektname.');
  return name;
}
function accountName(value) {
  const name = text(value, 'ServiceAccount-Name');
  requireValue(name.split('.').every(part => /^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/.test(part)),
    'Ungültiger ServiceAccount-Name.');
  return name;
}
function ns(value) {
  requireValue(typeof value === 'string' && /^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$/.test(value), 'Ein gültiger Namespace fehlt.');
  return value;
}
function knownFields(row, keys, label) {
  requireValue(Object.keys(row).every(key => keys.includes(key)), label + ' enthält nicht unterstützte Felder.');
}
function key(kind, namespace, name) { return JSON.stringify([kind, namespace, name]); }

function normalizeRule(raw, roleKind) {
  const rule = object(raw, 'Regel');
  knownFields(rule, ['verbs','apiGroups','resources','resourceNames','nonResourceURLs'], 'Regel');
  const verbs = strings(rule.verbs, 'Verben', 1);
  const urls = strings(rule.nonResourceURLs ?? [], 'Nicht-Ressourcen-URLs');
  if (urls.length) {
    requireValue(roleKind === 'ClusterRole' && ['resources','apiGroups','resourceNames'].every(k => !Object.hasOwn(rule, k) ||
      Array.isArray(rule[k]) && !rule[k].length), 'Nicht-Ressourcen-URLs und Ressourcenregeln können nicht kombiniert werden.');
    return {nonResource: true};
  }
  return {verbs, apiGroups: strings(rule.apiGroups, 'API-Gruppen', 1, true), resources: strings(rule.resources, 'Ressourcen', 1),
    resourceNames: strings(rule.resourceNames ?? [], 'Ressourcennamen')};
}

function normalizeSubject(raw, namespace) {
  const value = object(raw, 'Subjekt');
  knownFields(value, ['kind','name','namespace','apiGroup'], 'Subjekt');
  requireValue(subjectKinds.includes(value.kind), 'Nicht unterstützter Subjekttyp.');
  const name = text(value.name, 'Subjektname');
  if (value.kind === 'ServiceAccount') {
    requireValue((value.apiGroup ?? '') === '', 'Ein ServiceAccount gehört zur Core-API-Gruppe.');
    return {kind: value.kind, name: accountName(name), namespace: ns(value.namespace === undefined || value.namespace === '' ? namespace : value.namespace)};
  }
  requireValue([undefined, '', group].includes(value.apiGroup) && [undefined, ''].includes(value.namespace),
    'API-Gruppe oder Namespace des Benutzers oder der Gruppe widerspricht RBAC v1.');
  return {kind: value.kind, name};
}

export function inspectPolicy(input) {
  const roles = [], bindings = [], warnings = [];
  const byRole = new Map(), seen = new Set();
  let count = 0, wrappers = 0, partial = false;
  function visit(raw, depth = 0, inheritedKind) {
    requireValue(depth <= 3, 'Zu viele verschachtelte Listen.');
    const item = object(raw, 'RBAC-Objekt');
    const kind = item.kind ?? inheritedKind;
    const apiVersion = item.apiVersion ?? (inheritedKind ? version : undefined);
    requireValue(!inheritedKind || kind === inheritedKind, 'Der Objekttyp widerspricht der typisierten Liste.');
    const elementKind = kinds.find(type => type + 'List' === kind);
    if (kind === 'List' || elementKind) {
      requireValue(++wrappers <= maxObjects && apiVersion === (elementKind ? version : 'v1'), 'Unbekannte Listenversion oder zu viele Listen.');
      const meta = object(item.metadata ?? {}, 'Listenmetadaten');
      requireValue((meta.continue === undefined || typeof meta.continue === 'string') &&
        (meta.remainingItemCount === undefined || Number.isSafeInteger(meta.remainingItemCount) && meta.remainingItemCount >= 0),
        'Ungültige Angaben zur Vollständigkeit der Liste.');
      if (meta.continue || meta.remainingItemCount > 0) partial = true;
      for (const value of list(item.items, 'Listenobjekte', 0, maxObjects)) visit(value, depth + 1, elementKind);
      return;
    }
    requireValue(apiVersion === version && kinds.includes(kind),
      'Unterstützt werden Role, ClusterRole, RoleBinding und ClusterRoleBinding der RBAC API v1.');
    requireValue(++count <= maxObjects, 'Höchstens 1’000 RBAC-Objekte pro Snapshot.');
    const metadata = object(item.metadata, 'Metadaten');
    const name = objectName(metadata.name);
    const namespaced = kind === 'Role' || kind === 'RoleBinding';
    requireValue(namespaced || [undefined, ''].includes(metadata.namespace), 'Ein Clusterobjekt darf keinen Namespace tragen.');
    const namespace = namespaced ? ns(metadata.namespace) : '';
    const id = key(kind, namespace, name);
    requireValue(!seen.has(id), 'Doppeltes Objekt mit gleichem Typ, Namespace und Namen.');
    seen.add(id);
    const origin = {kind, namespace, name, objectIndex: count};
    if (roleKinds.includes(kind)) {
      const aggregated = item.aggregationRule != null;
      if (aggregated) {
        requireValue(kind === 'ClusterRole', 'Eine Role kann keine Aggregationsregel tragen.');
        object(item.aggregationRule, 'Aggregationsregel');
      }
      const rules = list(item.rules ?? [], 'Regeln').map(rule => normalizeRule(rule, kind));
      const role = {...origin, aggregated, rules};
      byRole.set(id, role);
      roles.push(role);
      return;
    }
    const ref = object(item.roleRef, 'Rollenverweis');
    requireValue(ref.apiGroup === group && roleKinds.includes(ref.kind) &&
      (namespaced || ref.kind === 'ClusterRole'), 'Ungültiger Rollenverweis oder ClusterRoleBinding auf eine Role.');
    const roleRef = {kind: ref.kind, name: objectName(ref.name)};
    bindings.push({...origin, roleRef, subjects: list(item.subjects ?? [], 'Subjekte').map(s => normalizeSubject(s, namespace))});
  }
  if (Array.isArray(input)) for (const value of list(input, 'RBAC-Objekte', 0, maxObjects)) visit(value);
  else visit(input);
  if (partial) warnings.push('Der Listenexport weist weitere Seiten aus.');
  const missing = bindings.filter(b => !byRole.has(key(b.roleRef.kind, b.roleRef.kind === 'Role' ? b.namespace : '', b.roleRef.name)));
  if (missing.length) warnings.push(missing.length + ' Bindungen verweisen auf fehlende Rollen.');
  const aggregated = roles.filter(role => role.aggregated).length;
  if (aggregated) warnings.push(aggregated + ' aggregierte Clusterrollen benötigen einen separaten Nachweis.');
  if (roles.some(role => role.rules.some(rule => rule.nonResource))) warnings.push('Nicht-Ressourcen-URLs liegen ausserhalb dieses Ressourcenprofils.');
  const model = {roles, bindings, warnings, counts: {roles: roles.length, bindings: bindings.length}, partial};
  roleLookup.set(model, byRole);
  return model;
}

const knownClusterResources = new Map([
  ['', ['namespaces','nodes','persistentvolumes','componentstatuses']],
  [group, ['clusterroles','clusterrolebindings']],
  ['apiextensions.k8s.io', ['customresourcedefinitions']], ['storage.k8s.io', ['storageclasses','volumeattachments','csidrivers','csinodes']],
  ['apiregistration.k8s.io', ['apiservices']], ['networking.k8s.io', ['ingressclasses']],
  ['scheduling.k8s.io', ['priorityclasses']], ['certificates.k8s.io', ['certificatesigningrequests']]
]);

function requestAttributes(raw) {
  const r = object(raw, 'Prüfanfrage');
  requireValue(subjectKinds.includes(r.kind), 'Nicht unterstützter Subjekttyp.');
  const name = text(r.name, 'Subjektname');
  const groups = new Set(strings(r.groups ?? [], 'Explizite Gruppen'));
  let username = name;
  if (r.kind === 'Group') { groups.add(name); username = null; }
  if (r.kind === 'ServiceAccount') username = 'system:serviceaccount:' + ns(r.subjectNamespace) + ':' + accountName(name);
  const namespace = r.namespace === '' ? '' : ns(r.namespace);
  const verb = token(r.verb, 'Verb'), resource = token(r.resource, 'Ressource');
  const apiGroup = r.apiGroup === '' ? '' : token(r.apiGroup, 'API-Gruppe');
  const subresource = r.subresource ? token(r.subresource, 'Subressource') : '';
  requireValue(!(namespace && knownClusterResources.get(apiGroup)?.includes(resource)),
    'Die angegebene Clusterressource benötigt einen leeren Anfrage-Namespace.');
  const nameAttribute = text(r.resourceName ?? '', 'Ressourcenname', {empty: true});
  const selector = text(r.fieldSelectorName ?? '', 'Namensselektor', {empty: true});
  requireValue(!selector || ['list','watch'].includes(verb), 'Ein Namensselektor ist nur für list/watch zulässig.');
  let effectiveName = nameAttribute;
  if (['list','watch'].includes(verb)) effectiveName = selector;
  if (verb === 'deletecollection' || verb === 'create' && !subresource) effectiveName = '';
  return {username, groups, namespace, verb, resource, apiGroup, subresource, effectiveName};
}

function subjectMatches(subject, request) {
  if (subject.kind === 'Group') return request.groups.has(subject.name);
  if (subject.kind === 'ServiceAccount') return request.username === 'system:serviceaccount:' + subject.namespace + ':' + subject.name;
  return request.username === subject.name;
}
function ruleMatches(rule, r) {
  if (rule.nonResource) return false;
  const match = (values, v) => values.includes('*') || values.includes(v);
  if (!match(rule.verbs, r.verb) || !match(rule.apiGroups, r.apiGroup)) return false;
  const combined = r.subresource ? r.resource + '/' + r.subresource : r.resource;
  return (match(rule.resources, combined) || r.subresource && rule.resources.includes('*/' + r.subresource))
    && (!rule.resourceNames.length || r.effectiveName !== '' && rule.resourceNames.includes(r.effectiveName));
}

export function evaluateAccess(model, input) {
  const roles = roleLookup.get(model);
  requireValue(roles, 'Öffnen Sie zuerst einen RBAC-Snapshot.');
  const request = requestAttributes(input);
  const matches = [], reasons = [];
  let count = 0;
  if (model.partial) reasons.push('Der Snapshot enthält eine nicht vollständig exportierte Liste.');
  for (const binding of model.bindings) {
    if (binding.kind === 'RoleBinding' && binding.namespace !== request.namespace) continue;
    if (!binding.subjects.some(s => subjectMatches(s, request))) continue;
    const {kind, name} = binding.roleRef;
    const role = roles.get(key(kind, kind === 'Role' ? binding.namespace : '', name));
    if (!role || role.aggregated) {
      reasons.push(binding.kind + ' ' + binding.name + ' · ' + (role ? 'Clusterrolle aggregiert.' : 'Rollenbeleg fehlt.'));
      continue;
    }
    role.rules.forEach((rule, i) => {
      if (!ruleMatches(rule, request)) return;
      count++;
      if (matches.length < maxProofs) matches.push({bindingKind: binding.kind, bindingName: binding.name, namespace: binding.namespace,
        roleKind: role.kind, roleName: role.name, ruleIndex: i + 1, bindingIndex: binding.objectIndex, roleIndex: role.objectIndex});
    });
  }
  if (count > matches.length) reasons.push('Die ersten ' + maxProofs + ' von ' + count + ' Regelverweisen werden angezeigt.');
  return {status: count ? 'granted_in_snapshot' : reasons.length ? 'indeterminate' : 'no_grant_in_snapshot',
    matches, reasons, matchCount: count};
}
