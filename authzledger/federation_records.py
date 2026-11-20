"""Offline retention and semantic reconstruction of a bounded federation sidecar.

The retained catalog is derived from typed source rows. Original bytes and free
text stay outside the workspace. Its digests bind inputs without attesting the
truth of a scanner assertion or authorizing a network operation.
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

from .federation_offline import (MAX_RECORDS, PORT_STATES, SEVERITIES, SOURCE_NAMES,
                                 _scope, project_federation)
from .oracles import canonical, digest, seal
from .scope import _address_allowed

KIND = 'federation-receipt'
_DIGEST = re.compile(r'[a-f0-9]{64}')
_LOCATORS = {
    'ffuf': re.compile(r'/results/(0|[1-9][0-9]{0,6})'),
    'nuclei': re.compile(r'line:([1-9][0-9]{0,6})'),
    'nmap': re.compile(r'/nmaprun/host\[([1-9][0-9]{0,6})\]/ports/port\[([1-9][0-9]{0,6})\]'),
}
_DISPOSITIONS = {
    'ffuf': {'accepted', 'out_of_scope', 'unresolved_scope', 'unsupported_target', 'unsupported_request_context'},
    'nmap': {'accepted', 'out_of_scope', 'unresolved_scope', 'unsupported_protocol'},
    'nuclei': {'accepted', 'out_of_scope', 'unresolved_scope', 'unsupported_protocol',
               'unsupported_target', 'unsupported_raw_record'},
}


def _require(condition, reason='invalid_federation_projection'):
    if not condition:
        raise ValueError(reason)


def _shape(value, names):
    _require(type(value) is dict and value.keys() == set(names))


def _hash(value):
    _require(isinstance(value, str) and _DIGEST.fullmatch(value))


def _bounded_int(value, low, high):
    return type(value) is int and low <= value <= high


def _choice(value, choices):
    return (value is None or type(value) is str) and value in choices


def federation_preview_digest(projection):
    return hashlib.sha256(canonical(projection)).hexdigest()


def _opaque(label, value):
    return None if value is None else digest('federation-' + label, value)


def check_assessment_scope(scope, services):
    selected = _scope(services)
    _require(sorted(selected) == services, 'invalid_retained_service_order')
    granted = {op['origin'] for op in scope['operations']
               if op['purpose'] == 'service' and op['method'] == 'CONNECT'
               and op['effect'] == 'read' and op['path'] == '/'}
    for service, identity in selected.items():
        _require(service in granted and _address_allowed(scope, identity['asset']),
                 'federation_service_outside_assessment_scope')


def _details(profile, fields):
    result = dict(fields)
    names = {'nmap': ('reason', 'name'), 'ffuf': (), 'nuclei': ('template_id', 'matcher')}
    for name in names[profile]:
        result[name + '_digest'] = _opaque(name, result.pop(name))
    return result


def _source_rows(projection):
    graph = projection['graph']
    endpoints = {e['key']: e['service'] for e in graph['endpoints']}
    observations = {o['record']: o for o in graph['observations']}
    profiles = {name: profile for profile, name in SOURCE_NAMES.items()}
    sources = []
    for source in projection['receipts']:
        profile = profiles[source['source']]
        rows = []
        for entry in source['records']:
            row = dict(entry)
            if entry['disposition'] == 'accepted':
                observation = observations[source['source'] + '#' + entry['locator']]
                target = observation['target']
                row['service'] = endpoints.get(target, target)
                if target in endpoints:
                    parsed = urlsplit(target)
                    row['scheme'] = parsed.scheme
                    row['path_digest'] = _opaque('path', parsed.path)
                row['asserted'] = _details(profile, observation['asserted'])
            rows.append(row)
        sources.append({'profile': profile, 'sha256': source['sha256'], 'records': rows})
    return sources


def _check_details(profile, data):
    if profile == 'ffuf':
        _shape(data, ['status', 'length', 'method'])
        _require(_bounded_int(data['status'], 100, 599) and _choice(data['method'], {None, 'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'})
                 and (data['length'] is None or _bounded_int(data['length'], 0, 2**53-1)))
    elif profile == 'nmap':
        _shape(data, ['state', 'method', 'confidence', 'reason_digest', 'name_digest'])
        _require(_choice(data['state'], PORT_STATES) and _choice(data['method'], {None, 'table', 'probed'})
                 and (data['confidence'] is None or _bounded_int(data['confidence'], 0, 10)))
        for field in ('reason_digest', 'name_digest'):
            if data[field] is not None:
                _hash(data[field])
    else:
        _shape(data, ['matched', 'source_severity', 'template_id_digest', 'matcher_digest'])
        _require((data['matched'] is None or type(data['matched']) is bool)
                 and (data['source_severity'] is None or _choice(data['source_severity'], SEVERITIES)))
        _require(data['matched'] is not True or data['template_id_digest'] is not None)
        for field in ('template_id_digest', 'matcher_digest'):
            if data[field] is not None:
                _hash(data[field])


def _catalog(sources, allowed):
    _require(type(sources) is list and 1 <= len(sources) <= len(SOURCE_NAMES))
    service_set, endpoints, hints, profiles = set(), {}, [], []
    accepted, omitted = 0, 0
    for source in sources:
        _shape(source, ['profile', 'sha256', 'records'])
        profile = source['profile']
        _require(isinstance(profile, str) and profile in SOURCE_NAMES and profile not in profiles)
        profiles.append(profile)
        _hash(source['sha256'])
        rows = source['records']
        _require(type(rows) is list and len(rows) <= MAX_RECORDS)
        previous = ()
        for index, row in enumerate(rows):
            _require(isinstance(row, dict) and isinstance(row.get('locator'), str))
            loc = _LOCATORS[profile].fullmatch(row['locator'])
            _require(loc and _choice(row.get('disposition'), _DISPOSITIONS[profile]))
            ordinal = tuple(int(n) for n in loc.groups())
            _require(ordinal > previous and (profile != 'ffuf' or ordinal == (index,)))
            previous = ordinal
            if row['disposition'] != 'accepted':
                _shape(row, ['locator', 'disposition'])
                omitted += 1
                continue
            names = ['locator', 'disposition', 'service', 'asserted']
            if profile != 'nmap':
                names += ['scheme', 'path_digest']
            _shape(row, names)
            _require(isinstance(row['service'], str) and row['service'] in allowed,
                     'federation_observation_outside_selected_scope')
            _check_details(profile, row['asserted'])
            service_set.add(row['service'])
            accepted += 1
            if profile != 'nmap':
                _hash(row['path_digest'])
                _require(_choice(row['scheme'], {'http', 'https'}))
                ref = {k: row[k] for k in ('service', 'scheme', 'path_digest')}
                eid = digest('federation-endpoint', ref)
                endpoints[eid] = {'id': eid, **ref}
                if profile == 'nuclei' and row['asserted']['matched'] is True:
                    hints.append({'endpoint_id': eid, 'source_sha256': source['sha256'],
                                  'locator': row['locator'], 'evidence_level': 'hint'})
    _require(profiles == [p for p in SOURCE_NAMES if p in profiles])
    return {'services': sorted(service_set), 'endpoints': [endpoints[k] for k in sorted(endpoints)],
            'source_hints': hints, 'accepted_records': accepted, 'omitted_records': omitted}


def build_federation_receipt(assessment, services, sources, preview_digest=None):
    allowed = sorted(_scope(services))
    check_assessment_scope(assessment['scope'], allowed)
    projection = project_federation(allowed, sources)
    actual = federation_preview_digest(projection)
    if preview_digest is not None:
        _require(preview_digest == actual, 'federation_preview_digest_mismatch')
    rows = _source_rows(projection)
    value = {'kind': KIND, 'schema_version': 1, 'assessment_id': assessment['id'],
             'scope_digest_at_import': assessment['scope']['scope_digest'],
             'preview_digest': actual, 'allowed_services': allowed, 'sources': rows,
             'catalog': _catalog(rows, allowed)}
    return seal(KIND, value, 'receipt_digest')


def validate_federation_receipt(value, assessment):
    _shape(value, ['kind', 'schema_version', 'assessment_id', 'scope_digest_at_import',
                   'preview_digest', 'allowed_services', 'sources', 'catalog', 'receipt_digest'])
    _require(value['kind'] == KIND and type(value['schema_version']) is int and value['schema_version'] == 1)
    _require(value['assessment_id'] == assessment['id'], 'federation_assessment_mismatch')
    for field in ('scope_digest_at_import', 'preview_digest', 'receipt_digest'):
        _hash(value[field])
    check_assessment_scope(assessment['scope'], value['allowed_services'])
    catalog = _catalog(value['sources'], value['allowed_services'])
    _require(canonical(value['catalog']) == canonical(catalog), 'federation_catalog_mismatch')
    _require(value['receipt_digest'] == digest(KIND, value, 'receipt_digest'), 'federation_digest_mismatch')
