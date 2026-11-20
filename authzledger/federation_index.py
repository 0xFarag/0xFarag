"""Rebuild a passive surface index from an integrity-verified frozen assessment.

IDs are scoped to one assessment. A joined endpoint is a protocol and path
identity, never proof of a shared HTTP method, an executed test or an owner.
Source families remain visible even when literal addresses and paths coincide.
"""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from .oracles import canonical, digest, seal
from .platform_reports import verify_platform
from .scope import _address_allowed
from .surface import build_catalog

SURFACE_KINDS = {'surface-catalog', 'import-batch', 'adapter-receipt', 'discovery-execution',
                 'playbook-execution', 'federation-receipt'}
AMBIGUOUS_TARGET = {
    'unsupported_url', 'unsupported_request_target', 'unsupported_request_method', 'invalid_request_line',
    'unsupported_request_line', 'request_target_mismatch', 'request_target_unverifiable', 'request_origin_mismatch',
    'host_origin_mismatch', 'missing_host_header', 'url_credentials_require_mapping', 'invalid_header',
    'duplicate_header', 'non_ascii_header', 'unsupported_http_version', 'unsupported_http_framing',
}
INCOMPLETE_TARGET = {
    'redacted_path_requires_mapping', 'redacted_query_requires_mapping', 'unsupported_query', 'duplicate_query_name',
    'credential_echo_requires_mapping', 'url_fragment_omitted',
}


def _legacy_rows(artifact):
    """Return actual snapshot pointers for observations or their import entries."""
    value = artifact['value']
    kind = artifact['kind']
    if kind == 'import-batch':
        # build_catalog intentionally skips incomplete observations. Retain a
        # source-level disposition for every skipped input entry as well.
        try:
            rows = {r['source_refs'][0]['entry_id']: r for r in build_catalog([value])['observations']}
        except ValueError:
            # A legacy receipt can verify independently of the stricter surface
            # catalogue. An unsupported batch cannot supply unverified routes.
            rows = {}
        for index, raw in enumerate(value['entries']):
            row = rows.get(raw['id'])
            if row is None:
                row = {'source_kind': 'import', 'omission_reason': 'unresolved_source_record',
                       'source_refs': [{'profile': value['format_profile'], 'import_digest': value['import_sha256'],
                                        'entry_id': raw['id']}]}
            yield f'/entries/{index}', row
        return
    if kind == 'surface-catalog':
        catalogs = [('', value)]
    elif kind in {'adapter-receipt', 'discovery-execution'}:
        catalogs = [('/catalog', value['catalog'])]
        if kind == 'adapter-receipt':
            covered = {ref['record_id'] for row in value['catalog']['observations'] for ref in row['source_refs']
                       if ref['kind'] == 'adapter'}
            for index, record in enumerate(value['records']):
                if record['record_id'] not in covered:
                    # A closed / filtered Nmap port belongs to the retained
                    # source inventory and cannot be presented as an open asset.
                    yield f'/records/{index}', {'source_kind': 'nmap-import' if value['profile'] == 'nmap-xml-v1'
                                                else 'scanner-import', 'omission_reason': 'legacy_catalog_omission',
                        'source_refs': [{'profile': value['profile'], 'projection_digest': value['source_projection_digest'],
                                         'record_id': record['record_id'], 'state': record['state']}]}

    elif kind == 'playbook-execution':
        catalogs = [(f'/steps/{i}/execution/catalog', step['execution']['catalog'])
                    for i, step in enumerate(value['steps'])
                    if (step.get('execution') or {}).get('kind') == 'discovery-execution']
    else:
        return
    for prefix, catalog in catalogs:
        for index, row in enumerate(catalog['observations']):
            yield f'{prefix}/observations/{index}', row


def _identity(origin):
    parts = urlsplit(origin)
    host = parts.hostname
    try:
        address = str(ipaddress.ip_address(host))
        host = address
    except ValueError:
        address = None
    authority = f'[{host}]' if ':' in host else host
    port = parts.port or {'http': 80, 'https': 443}.get(parts.scheme)
    return f'tcp://{authority}:{port}', address


def _federation_rows(artifact):
    for index, source in enumerate(artifact['value']['sources']):
        for row_index, row in enumerate(source['records']):
            source_ref = {'profile': source['profile'], 'sha256': source['sha256'], 'locator': row['locator']}
            yield f'/sources/{index}/records/{row_index}', source['profile'], source_ref, row


def build_surface_index(snapshot):
    """Derive a new view without altering historical snapshots, receipts or reports.

    One positive scanner event remains a source-attested hint. Non-accepted
    records retain their reason and source pointer, without becoming surfaces.
    The computed digest binds a view to the supplied snapshot. Signature trust
    for an exported package remains the responsibility of the bundle verifier.
    """
    if verify_platform(snapshot):
        raise ValueError('invalid_platform_snapshot_for_surface_index')
    assessment = snapshot['assessment']
    assessment_id = assessment['id']
    scope = assessment['scope']
    origins = set(scope['origins'])
    operations = {(op['origin'], op['method'], op['path']) for op in scope['operations']}
    artifact_digests = {row['artifact_id']: row['source_digest'] for row in snapshot['inventory']}
    services, endpoints, observations, omissions = {}, {}, {}, {}
    # An explicitly excluded observation cannot reappear through an already
    # materialised legacy catalogue or a duplicate retained federation receipt.
    excluded_legacy, excluded_external = set(), set()
    for a in snapshot['artifacts']:
        if not a['included']:
            if a['kind'] == 'federation-receipt':
                excluded_external.update(canonical(ref) for _, _, ref, _ in _federation_rows(a))
            else:
                excluded_legacy.update(digest('native-surface-row', row) for _, row in _legacy_rows(a))

    def attach(table, key, value, pointer):
        entry = table.setdefault(key, value)
        refs = entry.setdefault('artifact_refs', {})
        refs[artifact['artifact_id'], pointer] = {'artifact_id': artifact['artifact_id'],
                'artifact_digest': artifact_digests[artifact['artifact_id']], 'pointer': pointer}
        return entry

    def omit(reason, family, kind, ref, pointer):
        value = {'reason': reason, 'source_family': family, 'source_kind': kind, 'source_ref': ref}
        key = digest('surface-index-omission', [assessment_id, value])
        attach(omissions, key, value, pointer)

    def add(family, kind, ref, pointer, service, scheme, path_digest, method, level, scope_state, asserted):
        service_id = digest('surface-index-service', [assessment_id, service])
        endpoint_id = None
        if path_digest is not None:
            endpoint_id = digest('surface-index-endpoint', [assessment_id, service_id, scheme, path_digest])
        value = {'source_family': family, 'source_kind': kind, 'source_ref': ref,
                 'service_id': service_id, 'endpoint_id': endpoint_id, 'method': method,
                 'evidence_level': level, 'scope_state': scope_state, 'asserted': asserted}
        key = digest('surface-index-observation', [assessment_id, value])
        attach(observations, key, {'id': key, **value}, pointer)
        service_row = services.setdefault(service_id, {'id': service_id, 'origin': service,
                                          'source_families': set(), 'observation_ids': set()})
        service_row['source_families'].add(family)
        service_row['observation_ids'].add(key)
        if endpoint_id is not None:
            endpoint = endpoints.setdefault(endpoint_id, {'id': endpoint_id, 'service_id': service_id,
                    'scheme': scheme, 'path_digest': path_digest, 'source_families': set(), 'observation_ids': set()})
            endpoint['source_families'].add(family)
            endpoint['observation_ids'].add(key)

    for artifact in snapshot['artifacts']:
        if artifact['kind'] not in SURFACE_KINDS:
            continue
        if not artifact['included']:
            # Only the artifact's existing scope/inclusion decision is disclosed.
            omit('excluded_artifact', 'offline_federation' if artifact['kind'] == 'federation-receipt'
                 else 'legacy_surface', artifact['kind'], {}, '')
            continue
        if artifact['kind'] == 'federation-receipt':
            for pointer, kind, ref, row in _federation_rows(artifact):
                if canonical(ref) in excluded_external:
                    omit('excluded_source', 'offline_federation', kind, ref, pointer)
                    continue
                if row['disposition'] != 'accepted':
                    omit(row['disposition'], 'offline_federation', kind, ref, pointer)
                    continue
                fields = row['asserted']
                method = fields.get('method') if kind == 'ffuf' else None
                level = None if kind == 'nuclei' and fields['matched'] is not True else 'hint'
                add('offline_federation', kind, ref, pointer, row['service'], row.get('scheme'),
                    row.get('path_digest'), method, level, 'service_declared', dict(fields))
            continue
        for pointer, row in _legacy_rows(artifact):
            kind, method, path = row['source_kind'], row.get('method'), row.get('path')
            row_digest = digest('native-surface-row', row)
            ref = {'observation_digest': row_digest, 'source_refs_digest': digest('native-surface-refs', row['source_refs']),
                   'reference_count': len(row['source_refs'])}
            if row_digest in excluded_legacy:
                omit('excluded_source', 'legacy_surface', kind, ref, pointer)
                continue
            blockers = set(row.get('execution_blockers', []))
            reason = row.get('omission_reason')
            if blockers & AMBIGUOUS_TARGET:
                reason = 'ambiguous_target_binding'
            elif blockers & INCOMPLETE_TARGET:
                reason = 'incomplete_target_binding'
            if reason:
                if reason == 'legacy_catalog_omission':
                    ref['source_state'] = row['source_refs'][0]['state']
                omit(reason, 'legacy_surface', kind, ref, pointer)
                continue
            origin = row['origin']
            service, literal = _identity(origin)
            if origin not in origins or literal is not None and not _address_allowed(scope, literal):
                omit('outside_snapshot_scope', 'legacy_surface', kind, ref, pointer)
                continue
            state = 'origin_declared' if method is None else (
                'operation_declared' if (origin, method, path) in operations else 'operation_not_authorized')
            asserted = {'source_status': row.get('status'), 'tech_hints': [dict(h) for h in row['tech_hints']],
                        'execution_blockers': list(row.get('execution_blockers', []))}
            level = 'hint' if kind in {'nmap-import', 'scanner-import', 'scanner-origin-import'} else None
            add('legacy_surface', kind, ref, pointer, service, urlsplit(origin).scheme,
                digest('federation-path', path) if path is not None else None, method, level, state, asserted)

    def sorted_rows(table):
        return [table[key] for key in sorted(table)]

    for table in (observations, omissions):
        for row in table.values():
            row['artifact_refs'] = sorted_rows(row['artifact_refs'])
    for table in (services, endpoints):
        for row in table.values():
            row['source_families'] = sorted(row['source_families'])
            row['observation_ids'] = sorted(row['observation_ids'])
    summary = {'services': len(services), 'endpoints': len(endpoints), 'observations': len(observations),
               'omissions': len(omissions),
               'mixed_services': sum(len(v['source_families']) > 1 for v in services.values()),
               'mixed_endpoints': sum(len(v['source_families']) > 1 for v in endpoints.values())}
    return seal('federated-surface-index', {'kind': 'federated-surface-index', 'schema_version': 1,
                'assessment_id': assessment_id, 'scope_digest': scope['scope_digest'],
                'snapshot_digest': snapshot['snapshot_digest'], 'summary': summary, 'services': sorted_rows(services),
                'endpoints': sorted_rows(endpoints), 'observations': sorted_rows(observations),
                'omissions': sorted_rows(omissions)}, 'index_digest')
