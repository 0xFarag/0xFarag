"""Offline, provenance-bound CVE candidates and partial standards mappings.

Version matching identifies candidates, never proves exploitability. Numeric
upstream versions are intentionally distinct from distro/backport/prerelease
versions; unsupported schemes are explicit instead of guessed lexically.
"""
from __future__ import annotations

import copy
from datetime import date
import re
from urllib.parse import urlsplit

from .oracles import canonical, seal

_VERSION = re.compile(r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){1,3}\Z")
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
_MAX_BYTES = 4 * 1024 * 1024


def _text(value, label, limit=4096):
    if not isinstance(value, str) or not value.strip() or len(value) > limit or any(ord(c) < 32 for c in value):
        raise ValueError("invalid " + label)
    return value


def _version(value):
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise ValueError("unsupported version: numeric upstream dotted versions required")
    parts = tuple(int(v) for v in value.split('.'))
    return parts + (0,) * (4 - len(parts))


def _provenance(value):
    if not isinstance(value, dict) or set(value) != {'url', 'retrieved_at', 'publisher'}:
        raise ValueError('invalid knowledge provenance')
    url = urlsplit(_text(value['url'], 'source URL'))
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query:
        raise ValueError('knowledge source must be an HTTPS URL without credentials or query')
    _text(value['publisher'], 'source publisher', 200)
    try:
        if date.fromisoformat(value['retrieved_at']).isoformat() != value['retrieved_at']:
            raise ValueError()
    except (TypeError, ValueError):
        raise ValueError('invalid source retrieval date') from None
    return copy.deepcopy(value)


def validate_knowledge_pack(pack):
    """Normalize a curated data-only pack. Provenance is an operator attestation."""
    required = {'schema_version', 'kind', 'id', 'version', 'entries', 'limitations'}
    if not isinstance(pack, dict) or set(pack) - required - {'pack_digest'} or required - set(pack):
        raise ValueError('invalid knowledge pack fields')
    if type(pack['schema_version']) is not int or pack['schema_version'] != 1 or pack['kind'] != 'knowledge-pack':
        raise ValueError('unsupported knowledge pack schema')
    _text(pack['id'], 'pack id', 200); _text(pack['version'], 'pack version', 100)
    if not isinstance(pack['entries'], list) or len(pack['entries']) > 1000:
        raise ValueError('invalid knowledge entries')
    if not isinstance(pack['limitations'], list) or len(pack['limitations']) > 64:
        raise ValueError('invalid knowledge limitations')
    for item in pack['limitations']:
        _text(item, 'limitation')
    result = {k: copy.deepcopy(pack[k]) for k in required}
    seen = set()
    for entry in result['entries']:
        fields = {'cve', 'product', 'version_scheme', 'affected', 'prerequisites', 'source'}
        if not isinstance(entry, dict) or set(entry) != fields or not isinstance(entry['cve'], str) or not _CVE.fullmatch(entry['cve']):
            raise ValueError('invalid CVE entry')
        _text(entry['product'], 'product', 200)
        if entry['version_scheme'] != 'numeric-dotted':
            raise ValueError('unsupported knowledge version scheme')
        key = (entry['cve'], entry['product'])
        if key in seen:
            raise ValueError('duplicate CVE product entry')
        seen.add(key)
        if not isinstance(entry['affected'], list) or not 1 <= len(entry['affected']) <= 100:
            raise ValueError('invalid affected ranges')
        for interval in entry['affected']:
            if not isinstance(interval, dict) or not interval or set(interval) - {'eq', 'gte', 'gt', 'lte', 'lt'}:
                raise ValueError('invalid version range')
            if ('eq' in interval and len(interval) != 1) or {'gte', 'gt'} <= interval.keys() or {'lte', 'lt'} <= interval.keys():
                raise ValueError('ambiguous version range')
            values = {op: _version(v) for op, v in interval.items()}
            low = values.get('gte', values.get('gt'))
            high = values.get('lte', values.get('lt'))
            if low is not None and high is not None and (low > high or (low == high and ('gt' in values or 'lt' in values))):
                raise ValueError('empty version range')
        if not isinstance(entry['prerequisites'], list) or not entry['prerequisites'] or len(entry['prerequisites']) > 64:
            raise ValueError('CVE prerequisites must be explicitly retained')
        for item in entry['prerequisites']:
            _text(item, 'CVE prerequisite')
        _provenance(entry['source'])
    result['entries'].sort(key=lambda e: (e['product'], e['cve']))
    result = seal('knowledge-pack', result, 'pack_digest')
    if len(canonical(result)) > _MAX_BYTES:
        raise ValueError('knowledge pack exceeds size limit')
    if 'pack_digest' in pack and canonical(result) != canonical(pack):
        raise ValueError('knowledge pack digest or canonical ordering mismatch')
    return result


def verify_knowledge_pack(pack):
    try:
        if 'pack_digest' not in pack:
            raise ValueError('knowledge pack is not sealed')
        validate_knowledge_pack(pack)
        return []
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        return [str(exc) or 'invalid knowledge pack']


def builtin_knowledge_pack():
    """A small reviewed pack, not a comprehensive or automatically updated feed."""
    source = {'publisher': 'Apache HTTP Server Project', 'retrieved_at': '2026-10-20',
              'url': 'https://httpd.apache.org/security/vulnerabilities_24.html'}
    prerequisites = ['Product and upstream version identity must be verified independently of a spoofable banner.',
                     'Configuration, backported fixes and request-path reachability require controlled validation.',
                     'Code-execution impact additionally depends on the affected CGI configuration.']
    return validate_knowledge_pack({'schema_version': 1, 'kind': 'knowledge-pack', 'id': 'apache-httpd-reviewed',
        'version': '2026.10.20', 'entries': [
            {'cve': 'CVE-2021-41773', 'product': 'apache:http_server', 'version_scheme': 'numeric-dotted',
             'affected': [{'eq': '2.4.49'}], 'prerequisites': prerequisites, 'source': {**source, 'url': source['url'] + '#CVE-2021-41773'}},
            {'cve': 'CVE-2021-42013', 'product': 'apache:http_server', 'version_scheme': 'numeric-dotted',
             'affected': [{'gte': '2.4.49', 'lte': '2.4.50'}], 'prerequisites': prerequisites, 'source': {**source, 'url': source['url'] + '#CVE-2021-42013'}}],
        'limitations': ['Two curated Apache advisories only; absence of candidates is not absence of vulnerabilities.',
                        'Offline data has a pinned review date and never updates itself.',
                        'Version matches remain hints; no controlled vulnerability experiment is performed.']})


def _matches(version, interval):
    value = _version(version)
    comparisons = {'eq': lambda a, b: a == b, 'gte': lambda a, b: a >= b, 'gt': lambda a, b: a > b,
                   'lte': lambda a, b: a <= b, 'lt': lambda a, b: a < b}
    return all(comparisons[op](value, _version(other)) for op, other in interval.items())


def match_cve_candidates(observations, pack=None):
    pack = builtin_knowledge_pack() if pack is None else validate_knowledge_pack(pack)
    if not isinstance(observations, list) or len(observations) > 1000:
        raise ValueError('invalid product observations')
    retained, candidates, coverage = [], [], []
    for index, item in enumerate(observations):
        required = {'product', 'version', 'source_ref', 'source_kind'}
        if not isinstance(item, dict) or set(item) != required:
            raise ValueError('product observation requires exact product/version/source provenance')
        for key in required:
            _text(item[key], 'product observation ' + key, 512)
        if item['source_kind'] not in {'banner', 'authenticated_inventory', 'manual', 'import'}:
            raise ValueError('unsupported product observation source')
        retained.append(copy.deepcopy(item))
        relevant = [e for e in pack['entries'] if e['product'] == item['product']]
        try:
            _version(item['version'])
            status = 'evaluated' if relevant else 'product_not_in_pack'
        except ValueError:
            status = 'unsupported_version_scheme'
        coverage.append({'observation_index': index, 'source_ref': item['source_ref'], 'status': status})
        if status != 'evaluated':
            continue
        for entry in relevant:
            if any(_matches(item['version'], interval) for interval in entry['affected']):
                candidates.append({'id': 'cve-' + entry['cve'] + '-' + str(index), 'cve': entry['cve'],
                    'product': item['product'], 'version': item['version'], 'evidence_level': 'hint',
                    'status': 'candidate', 'reason': 'product_version_match_only',
                    'source_ref': item['source_ref'], 'source_kind': item['source_kind'],
                    'pack_digest': pack['pack_digest'], 'advisory': copy.deepcopy(entry['source']),
                    'prerequisites': copy.deepcopy(entry['prerequisites']), 'controls': [],
                    'exploitability': 'not_established', 'retest_status': 'not_retested',
                    'severity': 'not_assessed', 'cvss': {'status': 'not_scored', 'vector': None, 'score': None}})
    result = seal('knowledge-result', {'schema_version': 1, 'kind': 'knowledge-result', 'pack': pack,
        'observations': retained, 'candidates': candidates, 'coverage': coverage,
        'limitations': pack['limitations']}, 'result_digest')
    if len(canonical(result)) > _MAX_BYTES:
        raise ValueError('knowledge result exceeds size limit')
    return result


def verify_knowledge_result(result):
    try:
        expected = match_cve_candidates(result['observations'], result['pack'])
        if canonical(expected) != canonical(result):
            raise ValueError('knowledge result differs from source observations and pinned pack')
        return []
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
        return [str(exc) or 'invalid knowledge result']


def validate_standard_refs(refs, evidence_refs):
    """Reviewed partial references only, using the existing pinned 1.1 catalog."""
    from .assessment_reports import reporting_catalog
    catalog = reporting_catalog()
    if not isinstance(refs, list) or len(refs) > 64 or not isinstance(evidence_refs, list):
        raise ValueError('invalid standards mapping')
    result, seen = [], set()
    for ref in refs:
        fields = {'standard', 'version', 'id', 'relation', 'rationale', 'evidence_refs'}
        if not isinstance(ref, dict) or set(ref) != fields:
            raise ValueError('invalid standards reference fields')
        for key in ('standard', 'version', 'id', 'relation'):
            _text(ref[key], 'standards reference ' + key, 512)
        standard = catalog['standards'].get(ref['standard'])
        if not standard or ref['version'] != standard['version'] or ref['id'] not in standard['ids']:
            raise ValueError('reference is not in the pinned standards catalog')
        if ref['relation'] not in catalog['relations']:
            raise ValueError('standards mapping cannot claim certification or full compliance')
        _text(ref['rationale'], 'mapping rationale')
        if not isinstance(ref['evidence_refs'], list) or not ref['evidence_refs'] or not all(isinstance(v, str) for v in ref['evidence_refs']) or not set(ref['evidence_refs']) <= set(evidence_refs):
            raise ValueError('standards mapping evidence is missing or unrelated')
        key = (ref['standard'], ref['id'])
        if key in seen:
            raise ValueError('duplicate standards mapping')
        seen.add(key); result.append(copy.deepcopy(ref))
    return sorted(result, key=lambda r: (r['standard'], r['id']))
