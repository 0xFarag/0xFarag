"""Explicitly authorized discovery through the existing budget and HTTP engine.

No ambient credentials, redirects, guessed subnets or automatic scope growth.
Plans are pure; callers bind execution approval to the exact ``plan_digest``.
"""
from __future__ import annotations

import copy
import re
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from . import engine
from .evidence import verify_report
from .model import _path, _target, load_contract, contract_digest
from .oracles import canonical, digest, seal
from .surface import _catalog, _id, _unique, verify_catalog


class DiscoveryError(ValueError):
    pass


def _operation_id(origin, method, path):
    return _id('discover', origin, method, path)


def plan_discovery(scope, seeds):
    """Plan explicit HTTP paths and/or hosts and ports, without DNS or sockets.

    HTTP seed: ``{kind:'http', origin, paths:['/'], follow_links:False,
    max_depth:0}``. Network seed: ``{kind:'service', host, ports:[22]}``.
    Only exact approved GET operations may be followed. HTTP data is anonymous;
    credentialed vulnerability checks belong to the controlled check runner.
    """
    from .scope import validate_scope
    scope = validate_scope(scope)
    if not isinstance(seeds, list) or not 1 <= len(seeds) <= 100:
        raise DiscoveryError('explicit_discovery_seeds_required')
    approved = {(o['origin'], o['method'], o['path'], o['purpose']): o for o in scope['operations']}
    normalized, operations = [], {}
    for seed in seeds:
        if not isinstance(seed, dict):
            raise DiscoveryError('invalid_discovery_seed')
        kind = seed.get('kind', 'http')
        if kind == 'http':
            if set(seed) - {'kind', 'origin', 'paths', 'follow_links', 'max_depth'}:
                raise DiscoveryError('unsupported_http_seed_fields')
            origin = _target(seed.get('origin'))
            paths = seed.get('paths')
            if not isinstance(paths, list) or not 1 <= len(paths) <= 1000:
                raise DiscoveryError('explicit_discovery_paths_required')
            paths = sorted(set(_path(p) for p in paths))
            follow, depth = seed.get('follow_links', False), seed.get('max_depth', 0)
            if type(follow) is not bool or type(depth) is not int or not 0 <= depth <= 5:
                raise DiscoveryError('invalid_crawl_bounds')
            if not follow and depth:
                raise DiscoveryError('depth_requires_link_following')
            for path in paths:
                if (origin, 'GET', path, 'discovery') not in approved:
                    raise DiscoveryError('discovery_operation_outside_scope')
            possible = sorted({p for o, m, p, purpose in approved if o == origin and m == 'GET'
                               and purpose == 'discovery'}) if follow else paths
            normalized.append({'kind': 'http', 'origin': origin, 'paths': paths,
                               'follow_links': follow, 'max_depth': depth})
            for path in possible:
                oid = _operation_id(origin, 'GET', path)
                operations[oid] = {'operation_id': oid, 'origin': origin, 'method': 'GET',
                                   'path': path, 'purpose': 'discovery',
                                   'effect': approved[(origin, 'GET', path, 'discovery')]['effect']}
        elif kind == 'service':
            if set(seed) != {'kind', 'host', 'ports'}:
                raise DiscoveryError('explicit_service_seed_required')
            host, ports = seed['host'], seed['ports']
            if not isinstance(host, str) or not host or not host.isascii() or any(c in host for c in '/@?#%\\'):
                raise DiscoveryError('invalid_service_host')
            if not isinstance(ports, list) or not 1 <= len(ports) <= 256 or any(type(p) is not int or not 1 <= p <= 65535 for p in ports):
                raise DiscoveryError('explicit_service_ports_required')
            host = host.lower()
            if ':' in host and not host.startswith('['):
                host = '[' + host + ']'
            normalized.append({'kind': 'service', 'host': host, 'ports': sorted(set(ports))})
            for port in sorted(set(ports)):
                origin = 'tcp://' + host + ':' + str(port)
                if (origin, 'CONNECT', '/', 'service') not in approved:
                    raise DiscoveryError('service_operation_outside_scope')
                oid = _operation_id(origin, 'CONNECT', '/')
                operations[oid] = {'operation_id': oid, 'origin': origin, 'method': 'CONNECT',
                                   'path': '/', 'purpose': 'service',
                                   'effect': approved[(origin, 'CONNECT', '/', 'service')]['effect']}
        else:
            raise DiscoveryError('unsupported_discovery_kind')
    if len(operations) > 1000:
        raise DiscoveryError('discovery_operation_limit')
    value = {'schema_version': 1, 'kind': 'discovery-plan', 'scope': scope,
        'scope_digest': scope['scope_digest'], 'seeds': _unique(normalized),
        'operations': sorted(operations.values(), key=lambda op: op['operation_id']),
        'request_upper_bound': min(len(operations), scope['limits']['max_requests']),
        'eligible_operation_count': len(operations), 'effects': sorted({o['effect'] for o in operations.values()}),
        'limitations': ['Discovery does not establish permission, ownership or vulnerabilities.',
                       'Only explicit scoped paths, hosts and ports are eligible.',
                       'HTML links are followed within the exact reviewed operations; JavaScript is not executed.',
                       'GET operations may still have application side effects; permission is operator supplied.']}
    return seal('discovery-plan', value, 'plan_digest')


def verify_discovery_plan(value):
    try:
        expected = plan_discovery(value['scope'], value['seeds'])
        return [] if canonical(expected) == canonical(value) else ['discovery_plan_mismatch']
    except (KeyError, TypeError, ValueError, RecursionError):
        return ['invalid_discovery_plan']


class _Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag in {'a', 'link'} and len(self.links) < 1000:
            for name, value in attrs:
                if name == 'href' and isinstance(value, str) and len(value) <= 8192:
                    self.links.append(value)


def _capture_projection(capture, origin, path, approved):
    """Retain allowlisted projections only; never raw links, headers or bodies."""
    headers = [(str(k).lower(), v) for k, v in capture.get('headers', [])]
    hints = []
    for name, value in headers:
        if name not in {'server', 'x-powered-by'} or not isinstance(value, str):
            continue
        match = re.search(r'(?i)\b(nginx|apache|iis|gunicorn|uvicorn|openresty|express|php|asp\.net)(?:[/ ]([0-9]+(?:\.[0-9]+){0,3}))?\b', value[:1024])
        if match:
            version = match.group(2)
            hints.append({'product': match.group(1).lower(), 'version': version if version is None or len(version) <= 32 else None,
                          'basis': 'observed', 'verification': 'hint', 'source': name})
    links = []
    if capture.get('complete'):
        parser = _Links()
        try:
            parser.feed(capture.get('body', b'').decode('utf-8', errors='replace'))
            links = parser.links
        except (ValueError, RecursionError):
            links = []
    # Redirects remain disabled in the HTTP engine. A Location is only a link
    # candidate, and needs the same explicit allowlist as every other link.
    links.extend(v for k, v in headers if k == 'location' and isinstance(v, str) and len(v) <= 8192)
    allowed, excluded = [], 0
    for link in links[:1000]:
        try:
            url = urlsplit(urljoin(origin + path, link))
            target = _target(url.scheme + '://' + url.netloc)
            candidate_path = _path((url.path or '/') + ('?' + url.query if url.query else ''))
            if url.fragment or target != origin or (target, candidate_path) not in approved:
                excluded += 1
                continue
            allowed.append(candidate_path)
        except (ValueError, TypeError):
            excluded += 1
    return {'tech_hints': _unique(hints), 'approved_links': sorted(set(allowed)),
            'excluded_link_count': excluded, 'raw_values_retained': False,
            'verification_level': 'evaluation_attested'}


def _http_contract(scope, operation):
    limits = scope['limits']
    return load_contract({'version': 1, 'name': 'Scoped surface discovery',
        'target': operation['origin'], 'identities': {'anonymous': {'headers': {}}},
        'limits': {'max_requests': 1, 'concurrency': 1,
                   'timeout_seconds': min(60, limits['timeout_seconds']),
                   'max_response_bytes': min(1048576, limits['max_response_bytes'])},
        'cases': [{'id': operation['operation_id'], 'identity': 'anonymous',
                   'method': 'GET', 'path': operation['path'], 'expect': {'status': [200]}}]})


def _surface_observations(observations):
    projected = []
    for item in observations:
        source = [{'kind': 'discovery', 'observation_digest': item['observation_digest'],
                   'plan_digest': item['plan_digest'], 'operation_id': item['operation_id'],
                   'observed_at': item['observed_at']}]
        if item['purpose'] == 'discovery' and item['state'] == 'responded':
            projected.append({'source_kind': 'http-discovery', 'origin': item['origin'],
                'method': 'GET', 'path': item['path'], 'parameters': [], 'source_refs': source,
                'status': item['status'], 'execution_blockers': [],
                'tech_hints': item['projection']['tech_hints']})
        elif item['purpose'] == 'service' and item['probe']['state'] == 'open':
            hints = []
            if item['probe']['protocol_hint']:
                version = item['probe']['version_hint']
                hints = [{'product': item['probe']['protocol_hint'], 'version': None,
                          'protocol_version': version if version is None or len(version) <= 32 else None,
                          'basis': 'observed', 'verification': 'hint', 'source': 'service_banner'}]
            projected.append({'source_kind': 'service-discovery', 'origin': item['origin'],
                              'source_refs': source, 'tech_hints': hints})
    return projected


def execute_discovery(plan, *, context=None, credential_resolver=None):
    from .scope import context_for_scope, probe_service
    if verify_discovery_plan(plan):
        raise DiscoveryError('invalid_discovery_plan')
    if context is None:
        context = context_for_scope(plan['scope'], max_requests=plan['request_upper_bound'])
    bound_scope = getattr(context, 'scope_policy', None)
    if not isinstance(bound_scope, dict) or bound_scope.get('scope_digest') != plan['scope_digest']:
        raise DiscoveryError('discovery_context_scope_mismatch')
    before = context.snapshot()
    operations = {op['operation_id']: op for op in plan['operations']}
    approved = {(op['origin'], op['path']) for op in plan['operations'] if op['purpose'] == 'discovery'}
    queue, rules = deque(), {}
    for seed in plan['seeds']:
        if seed['kind'] == 'http':
            previous = rules.get(seed['origin'], {'follow_links': False, 'max_depth': 0})
            rules[seed['origin']] = {'follow_links': previous['follow_links'] or seed['follow_links'],
                                    'max_depth': max(previous['max_depth'], seed['max_depth'])}
            queue.extend((_operation_id(seed['origin'], 'GET', path), 0) for path in seed['paths'])
        else:
            for port in seed['ports']:
                origin = 'tcp://' + seed['host'] + ':' + str(port)
                queue.append((_operation_id(origin, 'CONNECT', '/'), 0))
    observations, reports, visited = [], [], set()
    while queue and len(visited) < plan['request_upper_bound']:
        oid, depth = queue.popleft()
        if oid in visited:
            continue
        visited.add(oid)
        operation = operations[oid]
        value = dict(operation, schema_version=1, kind='discovery-observation', plan_digest=plan['plan_digest'])
        if operation['purpose'] == 'service':
            probe = probe_service(context, operation['origin'], operation_id=oid,
                                  banner_bytes=min(128, plan['scope']['limits']['max_response_bytes']))
            value.update(state=probe['state'], probe=probe,
                         observed_at=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'))
        else:
            projection = {'tech_hints': [], 'approved_links': [], 'excluded_link_count': 0,
                          'raw_values_retained': False, 'verification_level': 'evaluation_attested'}
            def capture(item):
                projection.update(_capture_projection(item, operation['origin'], operation['path'], approved))
            report = engine.run(_http_contract(plan['scope'], operation), context=context,
                                observation_sink=capture, request_kind='discovery')
            reports.append(report)
            result = report['results'][0]
            state = 'responded' if result['outcome'] in {'pass', 'fail'} else ('blocked' if result['outcome'] == 'inconclusive' else 'error')
            value.update(state=state, status=result.get('status'), result=copy.deepcopy(result),
                         report_root=report['evidence']['root_sha256'], projection=projection,
                         observed_at=report['finished_at'])
            rule = rules[operation['origin']]
            if state == 'responded' and rule['follow_links'] and depth < rule['max_depth']:
                queue.extend((_operation_id(operation['origin'], 'GET', p), depth + 1) for p in projection['approved_links'])
        observations.append(seal('discovery-observation', value, 'observation_digest'))
        ledger = context.snapshot()
        if ledger['cancelled'] or context.remaining('application') <= 0:
            break
    ledger = context.snapshot()
    catalog = _catalog(_surface_observations(observations), plan['scope'])
    not_visited = [op['operation_id'] for op in plan['operations'] if op['operation_id'] not in visited]
    value = {'schema_version': 1, 'kind': 'discovery-execution', 'plan': copy.deepcopy(plan),
        'observations': observations, 'http_reports': reports, 'catalog': catalog,
        'ledger_before': before, 'ledger': ledger,
        'coverage': {'eligible_operations': len(operations), 'attempted_operations': len(visited),
            'dispatched_requests': ledger['dispatched_total'] - before['dispatched_total'],
            'not_visited_ids': not_visited,
            'inconclusive_ids': [o['operation_id'] for o in observations if o['state'] in {'blocked', 'error'}],
            'unknown_total_surface': True},
        'limitations': ['Discovered surfaces are observations, not confirmed vulnerabilities.',
                       'Closed ports and missing paths do not establish vulnerability remediation.',
                       'No raw banner, response body or unapproved discovered URL is retained.',
                       'Extracted technology and link projections are signer-attested hints.']}
    return seal('discovery-execution', value, 'execution_digest')


def verify_discovery(value):
    try:
        if value.get('kind') == 'discovery-plan':
            return verify_discovery_plan(value)
        if value.get('kind') != 'discovery-execution' or value.get('schema_version') != 1:
            return ['unsupported_discovery_artifact']
        if digest('discovery-execution', value, 'execution_digest') != value['execution_digest']:
            return ['discovery_execution_digest_mismatch']
        if verify_discovery_plan(value['plan']) or verify_catalog(value['catalog']):
            return ['discovery_source_invalid']
        reports = {r['evidence']['root_sha256']: r for r in value['http_reports']}
        if len(reports) != len(value['http_reports']) or any(verify_report(r) for r in reports.values()):
            return ['invalid_discovery_report']
        operations = {op['operation_id']: op for op in value['plan']['operations']}
        seen, referenced = set(), set()
        for observation in value['observations']:
            oid = observation['operation_id']
            if oid in seen or oid not in operations:
                return ['invalid_discovery_observation_selection']
            seen.add(oid)
            if any(observation[k] != v for k, v in operations[oid].items()):
                return ['discovery_operation_binding_mismatch']
            if observation['plan_digest'] != value['plan']['plan_digest'] or digest('discovery-observation', observation, 'observation_digest') != observation['observation_digest']:
                return ['discovery_observation_digest_mismatch']
            if observation['purpose'] == 'discovery':
                report = reports[observation['report_root']]
                referenced.add(observation['report_root'])
                expected_contract = _http_contract(value['plan']['scope'], operations[oid])
                if report['target'] != observation['origin'] or report['contract_sha256'] != contract_digest(expected_contract):
                    return ['discovery_contract_binding_mismatch']
                if observation['observed_at'] != report['finished_at']:
                    return ['discovery_timestamp_binding_mismatch']
                if len(report['results']) != 1 or canonical(report['results'][0]) != canonical(observation['result']):
                    return ['discovery_report_binding_mismatch']
                result = report['results'][0]
                state = 'responded' if result['outcome'] in {'pass', 'fail'} else ('blocked' if result['outcome'] == 'inconclusive' else 'error')
                if result['id'] != oid or result['path'] != observation['path'] or observation['state'] != state or observation['status'] != result.get('status'):
                    return ['discovery_response_binding_mismatch']
            elif observation['probe']['scope_digest'] != value['plan']['scope_digest'] or observation['probe']['origin'] != observation['origin'] or observation['state'] != observation['probe']['state']:
                return ['discovery_service_binding_mismatch']
        if referenced != set(reports):
            return ['unreferenced_discovery_report']
        if canonical(_catalog(_surface_observations(value['observations']), value['plan']['scope'])) != canonical(value['catalog']):
            return ['discovery_catalog_derivation_mismatch']
        before, ledger = value['ledger_before'], value['ledger']
        # Recalculate counts from ledger entries; a changed summary with a new
        # envelope digest is not sufficient to manufacture dispatched evidence.
        for snapshot in (before, ledger):
            sent = [r for r in snapshot['requests'] if r['state'] in {'finished', 'dispatched'}]
            if snapshot['dispatched_total'] != len(sent) or sum(snapshot['by_kind'].values()) != len(sent):
                return ['discovery_ledger_summary_mismatch']
            if any(count != sum(r['kind'] == kind for r in sent) for kind, count in snapshot['by_kind'].items()):
                return ['discovery_ledger_kind_mismatch']
        earlier = {r['sequence'] for r in before['requests']}
        current_entries = [r for r in ledger['requests'] if r['sequence'] not in earlier]
        if any(r['operation_id'] not in seen for r in current_entries):
            return ['discovery_unattributed_dispatch']
        for observation in value['observations']:
            matching = [r for r in current_entries if r['operation_id'] == observation['operation_id']]
            if len(matching) > 1 or any(r['kind'] != observation['purpose'] for r in matching):
                return ['discovery_dispatch_binding_mismatch']
            if observation['state'] != 'blocked' and (len(matching) != 1 or matching[0]['state'] not in {'finished', 'dispatched'}):
                return ['discovery_missing_dispatch']
        expected = {'eligible_operations': len(operations), 'attempted_operations': len(seen),
            'dispatched_requests': ledger['dispatched_total'] - before['dispatched_total'],
            'not_visited_ids': [op['operation_id'] for op in value['plan']['operations'] if op['operation_id'] not in seen],
            'inconclusive_ids': [o['operation_id'] for o in value['observations'] if o['state'] in {'blocked', 'error'}],
            'unknown_total_surface': True}
        if canonical(expected) != canonical(value['coverage']) or not 0 <= expected['dispatched_requests'] <= value['plan']['request_upper_bound']:
            return ['discovery_coverage_mismatch']
        return []
    except (KeyError, TypeError, ValueError, RecursionError, AttributeError):
        return ['invalid_discovery_execution']
