"""Offline attack-surface projections, provenance and conservative suggestions.

An imported identifier is not an identity, an owner or an authorization policy.
Catalogues deliberately retain exact routes rather than guessing path templates.
"""
from __future__ import annotations

import copy
import hashlib
import re
from urllib.parse import parse_qsl, urlsplit

from .imports import _digest as import_digest, resolve_imported_entry
from .model import _path, _target
from .openapi import catalog as openapi_catalog
from .oracles import canonical, digest, seal


class SurfaceError(ValueError):
    pass


def _id(kind, *values):
    return kind + '-' + hashlib.sha256(canonical(values)).hexdigest()[:24]


def _unique(values):
    return [value for _, value in sorted({canonical(v): v for v in values}.items())]


def _safe_params(path):
    return sorted({name for name, _ in parse_qsl(urlsplit(path).query, keep_blank_values=True,
                                               max_num_fields=500)})


def _provenance(ref):
    shapes = {'import': {'kind', 'import_digest', 'entry_id', 'profile', 'locations'},
              'openapi': {'kind', 'projection_digest', 'operation'},
              'adapter': {'kind', 'adapter_profile', 'projection_digest', 'record_id', 'location'},
              'discovery': {'kind', 'observation_digest', 'plan_digest', 'operation_id', 'observed_at'}}
    if not isinstance(ref, dict) or ref.get('kind') not in shapes or set(ref) != shapes[ref['kind']]:
        raise SurfaceError('invalid_surface_source_reference')
    for field, value in ref.items():
        if field != 'locations' and not isinstance(value, str):
            raise SurfaceError('invalid_surface_source_reference')
        if field.endswith('_digest') and (not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value)):
            raise SurfaceError('invalid_surface_source_digest')
        if isinstance(value, str) and (len(value) > 8192 or any(ord(c) < 32 for c in value)):
            raise SurfaceError('invalid_surface_source_reference')
    if ref['kind'] == 'import':
        if not isinstance(ref['locations'], list) or len(ref['locations']) > 100:
            raise SurfaceError('invalid_surface_source_locations')
        allowed = {'profile', 'entry_index', 'location', 'origin_basis', 'response_location'}
        if any(not isinstance(location, dict) or set(location) - allowed for location in ref['locations']):
            raise SurfaceError('invalid_surface_source_locations')
        for location in ref['locations']:
            for key, value in location.items():
                if key == 'entry_index':
                    if type(value) is not int or not 0 <= value <= 10000:
                        raise SurfaceError('invalid_surface_source_index')
                elif key == 'response_location' and value is None:
                    continue
                elif not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 32 for c in value):
                    raise SurfaceError('invalid_surface_source_location')
    if ref['kind'] == 'discovery':
        from datetime import datetime
        observed = datetime.fromisoformat(ref['observed_at'].replace('Z', '+00:00'))
        if observed.tzinfo is None:
            raise SurfaceError('surface_timestamp_timezone_required')
    if ref['kind'] == 'adapter':
        if ref['adapter_profile'] not in {'nmap-xml-v1', 'nuclei-jsonl-v1'} or not re.fullmatch(r'adapter-record-[0-9a-f]{24}', ref['record_id']):
            raise SurfaceError('invalid_adapter_provenance')
        pattern = (r'/nmaprun/host/[0-9]{1,5}/ports/[0-9]{1,5}/address/[0-9]{1,5}'
                   if ref['adapter_profile'] == 'nmap-xml-v1' else r'/lines/[0-9]{1,4}')
        if not re.fullmatch(pattern, ref['location']):
            raise SurfaceError('invalid_adapter_source_location')


def _scope_state(scope, origin, method=None, path=None):
    if scope is None:
        return 'unbound'
    if origin not in scope['origins']:
        return 'outside_scope'
    if method is None:
        return 'origin_declared'
    return ('operation_declared' if any(op['origin'] == origin and op['method'] == method
            and op['path'] == path for op in scope['operations']) else 'operation_not_authorized')


def _catalog(observations, scope=None):
    if not isinstance(observations, list) or len(observations) > 5000:
        raise SurfaceError('surface_observation_limit')
    if scope is not None:
        from .scope import validate_scope
        scope = validate_scope(scope)
    observations = _unique(copy.deepcopy(observations))
    if len(canonical(observations)) > 16 * 1048576:
        raise SurfaceError('surface_projection_bytes_exceeded')
    assets, endpoints = {}, {}
    for item in observations:
        if not isinstance(item, dict) or item.get('source_kind') not in {'import', 'openapi', 'http-discovery', 'service-discovery', 'nmap-import', 'scanner-import', 'scanner-origin-import'}:
            raise SurfaceError('invalid_surface_observation')
        origin = item.get('origin')
        service = item['source_kind'] in {'service-discovery', 'nmap-import'}
        asset_only = service or item['source_kind'] == 'scanner-origin-import'
        required = {'source_kind', 'origin', 'source_refs', 'tech_hints'}
        if not asset_only:
            required |= {'method', 'path', 'parameters', 'status', 'execution_blockers'}
        if set(item) != required:
            raise SurfaceError('invalid_surface_projection_fields')
        if service:
            from .scope import canonical_origin
            if not isinstance(origin, str) or not origin.startswith('tcp://') or canonical_origin(origin) != origin:
                raise SurfaceError('invalid_service_origin')
            parsed = urlsplit(origin)
            if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or not parsed.hostname or not parsed.port:
                raise SurfaceError('invalid_service_origin')
        else:
            origin = _target(origin)
        aid = _id('asset', origin)
        asset = assets.setdefault(aid, {'asset_id': aid, 'kind': 'service' if service else 'webapp',
            'origin': origin, 'scope_id': scope['id'] if scope else None,
            'scope_state': _scope_state(scope, origin), 'ownership': 'unknown',
            'identity': 'unknown', 'source_refs': [], 'tech_hints': []})
        refs = item.get('source_refs')
        if not isinstance(refs, list) or not refs or len(refs) > 100:
            raise SurfaceError('missing_surface_provenance')
        for ref in refs:
            _provenance(ref)
        asset['source_refs'].extend(refs)
        for hint in item.get('tech_hints', []):
            if not isinstance(hint, dict) or hint.get('basis') not in {'observed', 'scanner_attested'} or hint.get('verification') != 'hint':
                raise SurfaceError('invalid_technology_hint')
            if set(hint) - {'product', 'version', 'protocol_version', 'basis', 'verification', 'source'}:
                raise SurfaceError('invalid_technology_projection')
            if hint.get('product') not in {'nginx', 'apache', 'iis', 'gunicorn', 'uvicorn', 'openresty', 'express', 'php', 'asp.net', 'openssh', 'ssh', 'smtp', 'ftp', 'http'}:
                raise SurfaceError('unsupported_technology_hint')
            sources = {'nmap_service_probe'} if hint['basis'] == 'scanner_attested' else {'server', 'x-powered-by', 'service_banner'}
            if hint.get('source') not in sources:
                raise SurfaceError('invalid_technology_hint_source')
            for name in ('version', 'protocol_version'):
                if hint.get(name) is not None and (not isinstance(hint[name], str) or len(hint[name]) > 32 or not re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,3}', hint[name])):
                    raise SurfaceError('invalid_technology_version_hint')
            asset['tech_hints'].append(hint)
        if asset_only:
            continue
        method, path = item.get('method'), item.get('path')
        if not isinstance(item['execution_blockers'], list) or len(item['execution_blockers']) > 100 or any(not isinstance(reason, str) or not re.fullmatch(r'[a-z][a-z0-9_:-]{0,127}', reason) for reason in item['execution_blockers']):
            raise SurfaceError('invalid_surface_blocker_projection')
        if not isinstance(item['parameters'], list) or len(item['parameters']) > 500:
            raise SurfaceError('invalid_surface_parameters')
        for parameter in item['parameters']:
            if not isinstance(parameter, dict) or set(parameter) - {'in', 'name', 'required', 'type'} or parameter.get('in') not in {'path', 'query', 'header', 'cookie'} or not isinstance(parameter.get('name'), str) or len(parameter['name']) > 128:
                raise SurfaceError('invalid_surface_parameter_projection')
        if method not in {'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'}:
            raise SurfaceError('invalid_surface_method')
        _path(path)
        eid = _id('endpoint', origin, method, path)
        ep = endpoints.setdefault(eid, {'endpoint_id': eid, 'asset_id': aid, 'origin': origin,
            'method': method, 'path': path, 'parameters': [], 'source_refs': [],
            'source_kinds': [], 'observed_statuses': [], 'execution_blockers': [],
            'scope_state': _scope_state(scope, origin, method, path),
            'identity': 'unknown', 'owner': 'unknown', 'tenant': 'unknown',
            'coverage': 'not_tested'})
        ep['source_refs'].extend(refs)
        ep['source_kinds'].append(item['source_kind'])
        ep['parameters'].extend(item.get('parameters', []))
        ep['execution_blockers'].extend(item.get('execution_blockers', []))
        status = item.get('status')
        if status is not None:
            if type(status) is not int or not 100 <= status <= 599:
                raise SurfaceError('invalid_surface_status')
            ep['observed_statuses'].append(status)
    for asset in assets.values():
        asset['source_refs'] = _unique(asset['source_refs'])
        asset['tech_hints'] = _unique(asset['tech_hints'])
    for endpoint in endpoints.values():
        for field in ('parameters', 'source_refs', 'source_kinds', 'observed_statuses', 'execution_blockers'):
            endpoint[field] = _unique(endpoint[field])
    value = {'schema_version': 1, 'kind': 'surface-catalog', 'scope': scope,
        'scope_digest': scope.get('scope_digest') if scope else None,
        'observations': observations, 'assets': sorted(assets.values(), key=lambda a: a['asset_id']),
        'endpoints': sorted(endpoints.values(), key=lambda e: e['endpoint_id']),
        'coverage': {'observed_assets': len(assets), 'known_endpoints': len(endpoints),
                     'tested_endpoints': 0, 'not_tested_endpoints': len(endpoints),
                     'unknown_total_surface': True},
        'limitations': ['Discovery is not vulnerability testing or proof of ownership.',
                       'Identity, object ownership and tenant membership are never inferred.',
                       'Source digests bind safe projections, not omitted original secrets or bytes.',
                       'No complete attack-surface denominator is established.']}
    return seal('surface-catalog', value, 'catalog_digest')


def build_catalog(imports, *, declarations=None, scope=None):
    """Build one catalogue offline from parser receipts and explicit OpenAPI origins.

    ``declarations`` is a list of ``{origin, openapi: document}``. Server URLs in
    those documents are ignored. No raw document descriptions/examples persist.
    """
    if not isinstance(imports, list) or len(imports) > 100:
        raise SurfaceError('invalid_import_sources')
    declarations = [] if declarations is None else declarations
    if not isinstance(declarations, list) or len(declarations) > 100:
        raise SurfaceError('invalid_declarations')
    observations = []
    for batch in imports:
        if not isinstance(batch, dict) or batch.get('kind') != 'import-batch' or batch.get('schema_version') != 1:
            raise SurfaceError('invalid_import_batch')
        content = {k: v for k, v in batch.items() if k != 'import_sha256'}
        if batch.get('import_sha256') != import_digest(content):
            raise SurfaceError('import_digest_mismatch')
        if not isinstance(batch.get('entries'), list) or len(batch['entries']) > 1000:
            raise SurfaceError('invalid_import_entries')
        for raw in batch['entries']:
            entry = resolve_imported_entry(raw, {})  # verifies the original redacted entry ID
            if not entry.get('origin') or not entry.get('path') or not entry.get('method'):
                continue
            refs = [{'kind': 'import', 'import_digest': batch['import_sha256'],
                     'entry_id': entry['id'], 'profile': batch['format_profile'],
                     'locations': copy.deepcopy(entry['source_refs'])}]
            observations.append({'source_kind': 'import', 'origin': entry['origin'],
                'method': entry['method'], 'path': entry['path'],
                'parameters': [{'in': 'query', 'name': p} for p in _safe_params(entry['path'])],
                'source_refs': refs, 'status': entry.get('response', {}).get('status'),
                'execution_blockers': list(entry.get('execution_blockers', [])), 'tech_hints': []})
    for declaration in declarations:
        if not isinstance(declaration, dict) or set(declaration) != {'origin', 'openapi'}:
            raise SurfaceError('explicit_openapi_origin_required')
        origin = _target(declaration['origin'])
        indexed = openapi_catalog(declaration['openapi'])
        projection = [{'method': op['method'], 'path': op['path'],
            'parameters': [{'in': p['in'], 'name': p['name'], 'required': p['required'],
                            'type': p['type']} for p in op['parameters']]} for op in indexed['operations']]
        source_digest = digest('openapi-surface', {'origin': origin, 'operations': projection})
        for op in projection:
            blockers = ['explicit_fixture_values_required'] if '{' in op['path'] else []
            observations.append(dict(op, source_kind='openapi', origin=origin, status=None,
                source_refs=[{'kind': 'openapi', 'projection_digest': source_digest,
                              'operation': op['method'] + ' ' + op['path']}],
                execution_blockers=blockers, tech_hints=[]))
    return _catalog(observations, scope)


def verify_catalog(value):
    try:
        expected = _catalog(value['observations'], value['scope'])
        return [] if canonical(expected) == canonical(value) else ['surface_catalog_mismatch']
    except (KeyError, TypeError, ValueError, RecursionError, AttributeError):
        return ['invalid_surface_catalog']


def merge_catalogs(catalogs, *, scope=None):
    """Union known surfaces without discarding any source-observation reference.

    Rebinding the view to an explicit current scope never changes the original
    referenced executions or grants authorization to previously observed URLs.
    """
    if not isinstance(catalogs, list) or len(catalogs) > 100:
        raise SurfaceError('invalid_catalog_merge')
    if any(verify_catalog(c) for c in catalogs):
        raise SurfaceError('invalid_catalog_merge_source')
    if scope is None and catalogs:
        roots = {c['scope_digest'] for c in catalogs}
        if len(roots) > 1:
            raise SurfaceError('explicit_current_scope_required')
        scope = catalogs[0]['scope']
    return _catalog([observation for catalog in catalogs for observation in catalog['observations']], scope)


def candidate_experiments(catalog):
    """Suggest supported families; never infer a principal, owner or policy."""
    if verify_catalog(catalog):
        raise SurfaceError('invalid_surface_catalog')
    candidates = []
    for endpoint in catalog['endpoints']:
        families = ['authz', 'misconfig']
        if endpoint['parameters']:
            families.append('injection')
        if endpoint['method'] in {'POST', 'PUT', 'PATCH', 'DELETE'}:
            families.append('business_logic')
        for family in families:
            blockers = list(endpoint['execution_blockers'])
            blockers.append('explicit_check_configuration_required')
            if endpoint['scope_state'] != 'operation_declared':
                blockers.append('explicit_operation_authorization_required')
            if family in {'authz', 'business_logic'}:
                blockers.extend(['identity_binding_required', 'owner_binding_required', 'policy_and_controls_required'])
            else:
                blockers.append('check_controls_required')
            candidates.append({'candidate_id': _id('candidate', endpoint['endpoint_id'], family),
                'endpoint_id': endpoint['endpoint_id'], 'asset_id': endpoint['asset_id'],
                'family': family, 'evidence_level': 'hint', 'executable': False,
                'source_refs': copy.deepcopy(endpoint['source_refs']), 'blockers': sorted(set(blockers)),
                'reason': 'observed_operation_supports_explicit_experiment_preparation'})
    return seal('experiment-candidates', {'schema_version': 1, 'kind': 'experiment-candidates',
        'catalog_digest': catalog['catalog_digest'], 'catalog': copy.deepcopy(catalog),
        'candidates': candidates}, 'candidate_digest')


def verify_candidates(value):
    try:
        expected = candidate_experiments(value['catalog'])
        return [] if canonical(value) == canonical(expected) else ['candidate_projection_mismatch']
    except (KeyError, TypeError, ValueError, RecursionError):
        return ['invalid_candidates']


def diff_catalogs(baseline, current):
    """Source-bound surface delta; disappearance never means vulnerability fixed."""
    if verify_catalog(baseline) or verify_catalog(current):
        raise SurfaceError('invalid_delta_catalog')
    before = {e['endpoint_id']: e for e in baseline['endpoints']}
    after = {e['endpoint_id']: e for e in current['endpoints']}
    rows = []
    for eid in sorted(before.keys() | after.keys()):
        b, a = before.get(eid), after.get(eid)
        if b is None:
            transition = 'new'
        elif a is None:
            transition = 'not_observed'
        else:
            fields = ('method', 'path', 'parameters', 'observed_statuses', 'execution_blockers', 'scope_state')
            transition = 'unchanged' if all(b[f] == a[f] for f in fields) else 'changed'
        rows.append({'endpoint_id': eid, 'transition': transition, 'retest_status': 'not_retested',
                     'before': b, 'after': a})
    before_assets = {a['asset_id']: a for a in baseline['assets']}
    after_assets = {a['asset_id']: a for a in current['assets']}
    asset_rows = []
    for aid in sorted(before_assets.keys() | after_assets.keys()):
        b, a = before_assets.get(aid), after_assets.get(aid)
        if b is None:
            transition = 'new'
        elif a is None:
            transition = 'not_observed'
        else:
            fields = ('origin', 'kind', 'tech_hints', 'scope_state')
            transition = 'unchanged' if all(b[f] == a[f] for f in fields) else 'changed'
        asset_rows.append({'asset_id': aid, 'transition': transition, 'retest_status': 'not_retested',
                           'before': b, 'after': a})
    categories = {'added': 'new', 'changed': 'changed', 'removed': 'not_observed', 'unchanged': 'unchanged'}
    return seal('surface-delta', {'schema_version': 1, 'kind': 'surface-delta',
        'baseline_catalog_digest': baseline['catalog_digest'], 'current_catalog_digest': current['catalog_digest'],
        'baseline': copy.deepcopy(baseline), 'current': copy.deepcopy(current), 'transitions': rows,
        'asset_transitions': asset_rows,
        'endpoint_ids': {key: [r['endpoint_id'] for r in rows if r['transition'] == state] for key, state in categories.items()},
        'asset_ids': {key: [r['asset_id'] for r in asset_rows if r['transition'] == state] for key, state in categories.items()},
        'selected_endpoint_ids': [r['endpoint_id'] for r in rows if r['transition'] in {'new', 'changed'}],
        'selected_asset_ids': [r['asset_id'] for r in asset_rows if r['transition'] in {'new', 'changed'}],
        'not_retested_endpoint_ids': [r['endpoint_id'] for r in rows],
        'limitations': ['A surface delta is offline reanalysis, not a vulnerability retest.',
                       'Not observed does not establish removal, remediation or complete discovery.']}, 'delta_digest')


def verify_surface_delta(value):
    try:
        return [] if canonical(diff_catalogs(value['baseline'], value['current'])) == canonical(value) else ['surface_delta_mismatch']
    except (KeyError, TypeError, ValueError, RecursionError):
        return ['invalid_surface_delta']


def plan_delta_checks(delta, checks):
    """Select an explicit check inventory plus its dependency closure, offline.

    ``checks`` contains ``{check_id, endpoint_ids, asset_ids, requires,
    dependencies_complete}``. IDs refer to a separately approved check inventory;
    this selection never grants execution authorization or compiles payloads.
    """
    if verify_surface_delta(delta):
        raise SurfaceError('invalid_surface_delta')
    if not isinstance(checks, list) or len(checks) > 1000:
        raise SurfaceError('invalid_delta_check_inventory')
    indexed = {}
    for check in checks:
        if not isinstance(check, dict) or set(check) != {'check_id', 'endpoint_ids', 'asset_ids', 'requires', 'dependencies_complete'}:
            raise SurfaceError('invalid_delta_check_binding')
        cid = check['check_id']
        if not isinstance(cid, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}', cid) or cid in indexed:
            raise SurfaceError('invalid_delta_check_id')
        if any(not isinstance(check[f], list) or len(check[f]) > 1000 or any(not isinstance(v, str) for v in check[f]) for f in ('endpoint_ids', 'asset_ids', 'requires')) or type(check['dependencies_complete']) is not bool:
            raise SurfaceError('invalid_delta_dependencies')
        indexed[cid] = copy.deepcopy(check)
    if any(set(c['requires']) - indexed.keys() for c in checks):
        raise SurfaceError('unknown_delta_control_dependency')
    pending = {cid: set(c['requires']) for cid, c in indexed.items()}
    resolved = set()
    while pending:
        ready = {cid for cid, deps in pending.items() if deps <= resolved}
        if not ready:
            raise SurfaceError('cyclic_delta_control_dependency')
        resolved.update(ready)
        for cid in ready:
            del pending[cid]
    changed_endpoints = set(delta['endpoint_ids']['added'] + delta['endpoint_ids']['changed'] + delta['endpoint_ids']['removed'])
    changed_assets = set(delta['asset_ids']['added'] + delta['asset_ids']['changed'] + delta['asset_ids']['removed'])
    known_endpoints = {r['endpoint_id'] for r in delta['transitions']}
    known_assets = {r['asset_id'] for r in delta['asset_transitions']}
    unknown = [cid for cid, c in indexed.items() if not c['dependencies_complete']
               or set(c['endpoint_ids']) - known_endpoints or set(c['asset_ids']) - known_assets
               or not (c['endpoint_ids'] or c['asset_ids'] or c['requires'])]
    # A newly discovered surface with no declared affected-check binding also
    # invalidates a confident selective recommendation.
    mapped_endpoints = set().union(*(set(c['endpoint_ids']) for c in checks)) if checks else set()
    mapped_assets = set().union(*(set(c['asset_ids']) for c in checks)) if checks else set()
    uncovered = sorted((changed_endpoints - mapped_endpoints) | (changed_assets - mapped_assets))
    reasons = {}
    for cid, check in indexed.items():
        refs = sorted(set(check['endpoint_ids']) & changed_endpoints | set(check['asset_ids']) & changed_assets)
        if refs:
            reasons[cid] = [{'reason': 'surface_changed', 'source_ids': refs}]
    if unknown or uncovered:
        for cid in indexed:
            reasons.setdefault(cid, []).append({'reason': 'unknown_dependency_full_approved_inventory',
                                                'source_ids': sorted(set(unknown + uncovered))})
    direct = set(reasons)
    # A changed control affects dependent checks; each selected check also
    # requires its complete prerequisite closure.
    while True:
        added = {cid for cid, c in indexed.items() if set(c['requires']) & set(reasons)} - set(reasons)
        if not added:
            break
        for cid in sorted(added):
            reasons[cid] = [{'reason': 'depends_on_changed_check', 'source_ids': sorted(set(indexed[cid]['requires']) & set(reasons))}]
    pending = list(reasons)
    while pending:
        cid = pending.pop()
        for dependency in indexed[cid]['requires']:
            if dependency not in reasons:
                reasons[dependency] = [{'reason': 'required_control', 'source_ids': [cid]}]
                pending.append(dependency)
    value = {'schema_version': 1, 'kind': 'delta-check-plan', 'delta': copy.deepcopy(delta),
        'checks': copy.deepcopy(checks), 'selected_check_ids': sorted(reasons),
        'dependency_check_ids': sorted(set(reasons) - direct),
        'not_retested_check_ids': sorted(set(indexed) - set(reasons)),
        'all_checks_current_retest_status': 'not_retested',
        'unknown_dependencies': sorted(set(unknown + uncovered)), 'reasons': reasons,
        'limitations': ['Selection is not execution or authorization.',
                       'Unselected checks retain their original historical evidence and not_retested status.',
                       'Full approved inventory may still lack checks for newly discovered surfaces.']}
    return seal('delta-check-plan', value, 'plan_digest')


def verify_delta_check_plan(value):
    try:
        expected = plan_delta_checks(value['delta'], value['checks'])
        return [] if canonical(expected) == canonical(value) else ['delta_check_plan_mismatch']
    except (KeyError, TypeError, ValueError, RecursionError):
        return ['invalid_delta_check_plan']
