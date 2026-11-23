"""Read-only, bounded federation view of local export profiles.

The input scope selects literal TCP services solely for the view. This API has
no transport, resolver, command launcher, workspace writer or proof evaluator.
Originals remain with their owner. Fixed logical source names and original-byte
digests identify records without retaining filesystem paths or raw messages.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlsplit

from .adapters import MAX_RECORDS, _json, _xml
from .imports import _SENSITIVE, _TOKEN
from .model import _path

MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_SOURCE_BYTES = MAX_TOTAL_BYTES
PROJECTION_FORMAT = 'authzledger.demo-d.projection/v1'
SOURCE_NAMES = {'nmap': 'nmap.xml', 'ffuf': 'ffuf.json', 'nuclei': 'nuclei.jsonl',
                'nikto': 'nikto.xml', 'nessus': 'nessus.xml', 'gobuster': 'gobuster.txt',
                'feroxbuster': 'feroxbuster.jsonl'}
PORT_STATES = {'open', 'closed', 'filtered', 'unfiltered', 'open|filtered', 'closed|filtered', 'unknown'}
SEVERITIES = {'info', 'low', 'medium', 'high', 'critical', 'unknown'}
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}')
SIMPLE_PATH = re.compile(r'/[A-Za-z0-9/._~-]*')


def _identifier(value):
    if value is None:
        return None
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value) or _TOKEN.fullmatch(value):
        raise ValueError('unsupported_identifier')
    return value


def _number(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('invalid_numeric_value')
    return value


def _ip(text):
    if not isinstance(text, str) or '%' in text:
        raise ValueError('expected_literal_address')
    return str(ipaddress.ip_address(text))


def _display_ip(address):
    return '[' + address + ']' if ':' in address else address


def _service(address, port):
    return f'tcp://{_display_ip(address)}:{port}'


def _scope(values):
    if not isinstance(values, (tuple, list)) or not 1 <= len(values) <= 32:
        raise ValueError('invalid_service_scope')
    allowed = {}
    for value in values:
        if not isinstance(value, str) or len(value) > 100:
            raise ValueError('invalid_service_scope')
        try:
            parts = urlsplit(value)
            address = _ip(parts.hostname)
            port = _number(parts.port, 1, 65535)
        except ValueError:
            raise ValueError('invalid_service_scope') from None
        key = _service(address, port)
        if value != key:
            raise ValueError('scope_requires_canonical_literal_service')
        allowed[key] = {'key': key, 'asset': address, 'port': port, 'transport': 'tcp'}
    return allowed


def _http_identity(url):
    # This profile admits ordinary public path segments only. Targets carrying
    # query/fragment/userinfo, encoded paths or credential-looking segments
    # remain receipt dispositions; no original target is copied on rejection.
    if (not isinstance(url, str) or len(url) > 8192 or not url.isascii()
            or any(ord(c) <= 32 or ord(c) == 127 for c in url)
            or any(c in url for c in ('?', '#', '@', '%', '\\'))):
        return None, None, 'unsupported_target'
    try:
        parts = urlsplit(url)
        defaults = {'http': 80, 'https': 443}
        if parts.scheme not in defaults or not parts.netloc:
            return None, None, 'unsupported_target'
        port = _number(parts.port if parts.port is not None else defaults[parts.scheme], 1, 65535)
        path = _path(parts.path or '/')
        if (not SIMPLE_PATH.fullmatch(path)
                or any(_TOKEN.fullmatch(p) or _SENSITIVE.search(p) for p in path.split('/'))):
            return None, None, 'unsupported_target'
    except ValueError:
        return None, None, 'unsupported_target'
    try:
        address = _ip(parts.hostname)
    except ValueError:
        return None, None, 'unresolved_scope'
    host = _display_ip(address)
    authority = host if port == defaults[parts.scheme] else f'{host}:{port}'
    if parts.netloc not in {host, f'{host}:{port}'}:
        return None, None, 'unsupported_target'
    return _service(address, port), f'{parts.scheme}://{authority}{path}', None


def _nmap_entries(raw):
    root, _ = _xml(raw)
    for host_no, host in enumerate(root.findall('host'), 1):
        ips = set()
        for item in host.findall('address'):
            family = item.get('addrtype')
            if family in {'ipv4', 'ipv6'}:
                try:
                    ip = _ip(item.get('addr'))
                except ValueError:
                    raise ValueError('invalid_nmap_address') from None
                if ('ipv6' if ':' in ip else 'ipv4') != family:
                    raise ValueError('invalid_nmap_address')
                ips.add(ip)
        if len(host.findall('ports')) > 1:
            raise ValueError('ambiguous_nmap_port_locator')
        for port_no, item in enumerate(host.findall('ports/port'), 1):
            loc = f'/nmaprun/host[{host_no}]/ports/port[{port_no}]'
            if len(ips) != 1 or item.get('protocol') != 'tcp':
                yield loc, None, None, None, None, 'unresolved_scope' if len(ips) != 1 else 'unsupported_protocol'
                continue
            raw_port = item.get('portid', '')
            if not re.fullmatch(r'[0-9]{1,5}', raw_port):
                raise ValueError('invalid_nmap_port')
            service = _service(next(iter(ips)), _number(int(raw_port), 1, 65535))
            states = item.findall('state')
            descriptions = item.findall('service')
            if len(states) != 1 or len(descriptions) > 1 or states[0].get('state') not in PORT_STATES:
                raise ValueError('ambiguous_nmap_record')
            description = descriptions[0].attrib if descriptions else {}
            method = description.get('method')
            confidence = description.get('conf')
            if (method not in {None, 'table', 'probed'}
                    or confidence is not None and not re.fullmatch(r'(?:[0-9]|10)', confidence)):
                raise ValueError('invalid_nmap_service')
            fields = {'state': states[0].get('state'), 'reason': _identifier(states[0].get('reason')),
                      'name': _identifier(description.get('name')), 'method': method,
                      'confidence': int(confidence) if confidence is not None else None}
            yield loc, service, None, 'service_state', fields, None


def _http_entry(url, loc, kind, fields):
    service, target, disposition = _http_identity(url)
    return loc, service, target, kind, fields, disposition


def _json_object(raw):
    try:
        return _json(raw.decode('utf-8-sig'))
    except UnicodeError:
        raise ValueError('expected_utf8_json') from None


def _ffuf_entries(raw):
    document = _json_object(raw)
    rows = document.get('results')
    if not isinstance(rows, list) or len(rows) > MAX_RECORDS:
        raise ValueError('invalid_ffuf_results')
    config = document.get('config', {})
    if not isinstance(config, dict):
        raise ValueError('invalid_ffuf_request_context')
    # A raw request, custom headers, data or substituted method can change
    # routing, credentials and the meaning of the recorded transaction.
    method = config.get('method')
    if method == '':
        method = None
    supported_context = method in ('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', None) and not any(
        config.get(key) for key in ('headers', 'requestfile', 'rawrequest', 'cookies',
                                    'data', 'postdata', 'sni', 'follow_redirects', 'proxyurl',
                                    'replayproxyurl', 'client-cert', 'client-key'))
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError('invalid_ffuf_record')
        loc = f'/results/{i}'
        if not supported_context:
            yield loc, None, None, None, None, 'unsupported_request_context'
            continue
        fields = {'status': _number(row.get('status'), 100, 599),
                  'length': _number(row['length'], 0, 2**53 - 1) if 'length' in row else None,
                  'method': method}
        entry = _http_entry(row.get('url'), loc, 'http_result', fields)
        if entry[-1] is None and row.get('host'):
            parts = urlsplit(row['url'])
            if row['host'] not in (parts.netloc, parts.hostname):
                yield loc, None, None, None, None, 'unresolved_scope'
                continue
        yield entry


def _nuclei_identity_matches(row, service, endpoint):
    """All optional producer origin assertions must agree with matched-at."""
    parts = urlsplit(endpoint)
    address = parts.hostname
    port = urlsplit(service).port
    if row.get('scheme') not in (None, parts.scheme):
        return False
    reported_port = row.get('port')
    if reported_port is not None:
        if not ((type(reported_port) is str and reported_port == str(port))
                or (type(reported_port) is int and reported_port == port)):
            return False
    try:
        if row.get('ip') is not None and _ip(row['ip']) != address:
            return False
    except ValueError:
        return False
    origins = [row['url']] if row.get('url') is not None else []
    host = row.get('host')
    if host is not None:
        literal = _display_ip(address)
        if host not in (address, literal, f'{literal}:{port}'):
            origins.append(host)
    for origin in origins:
        origin_service, origin_url, reason = _http_identity(origin)
        if reason or origin_service != service or urlsplit(origin_url).scheme != parts.scheme:
            return False
    return True


def _nuclei_entries(raw):
    # Bound line count before splitting a source dominated by empty lines.
    if raw.count(b'\n') + int(not raw.endswith(b'\n')) > MAX_RECORDS:
        raise ValueError('source_record_limit')
    for index, line in enumerate(raw.split(b'\n'), 1):
        if not line.strip():
            continue
        if len(line) > 262144:
            raise ValueError('nuclei_line_limit')
        row = _json_object(line)
        loc = f'line:{index}'
        if row.get('type') != 'http':
            yield loc, None, None, None, None, 'unsupported_protocol'
            continue
        # Profiles with embedded credentials or raw traffic belong to the
        # existing dedicated, redacting traffic import workbench.
        if any(row.get(k) for k in ('request', 'response', 'curl-command', 'extracted-results')):
            yield loc, None, None, None, None, 'unsupported_raw_record'
            continue
        info = row.get('info', {})
        status = row.get('matcher-status')
        if not isinstance(info, dict) or status is not None and type(status) is not bool:
            raise ValueError('invalid_nuclei_match')
        severity = info.get('severity')
        if severity is not None and (not isinstance(severity, str) or severity not in SEVERITIES):
            raise ValueError('invalid_nuclei_severity')
        fields = {'template_id': _identifier(row.get('template-id')), 'matcher': _identifier(row.get('matcher-name')),
                  'matched': status, 'source_severity': severity}
        if status is True and not fields['template_id']:
            raise ValueError('missing_nuclei_template')
        entry = _http_entry(row.get('matched-at'), loc, 'template_match', fields)
        if entry[-1] is None and not _nuclei_identity_matches(row, entry[1], entry[2]):
            yield loc, None, None, None, None, 'unresolved_scope'
            continue
        yield entry


def project_federation(allowed_services, sources):
    """Project bytes from supported source families into one offline view.

    Supply a list of canonical tcp://IP:port services and (profile, bytes)
    pairs. Repeat submissions of the same bytes are idempotent. A second
    different input claiming the same logical source is ambiguous and rejected.
    A parse failure produces no partial result; ValueError carries an error code.
    """
    allowed = _scope(allowed_services)
    if not isinstance(sources, (list, tuple)) or not 1 <= len(sources) <= 12:
        raise ValueError('invalid_sources')
    inputs = {}
    total = 0
    for source in sources:
        if not isinstance(source, (list, tuple)) or len(source) != 2:
            raise ValueError('invalid_source')
        profile, raw = source
        if not isinstance(profile, str) or profile not in SOURCE_NAMES:
            raise ValueError('unsupported_profile')
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_SOURCE_BYTES:
            raise ValueError('invalid_source_bytes')
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise ValueError('total_bytes_limit')
        if profile in inputs and inputs[profile] != raw:
            raise ValueError('conflicting_source_for_profile')
        inputs[profile] = raw

    services, endpoints = {}, {}
    observations, receipts = [], []
    finding_records = {}
    from .federation_scanners import feroxbuster_entries, gobuster_entries, nessus_entries, nikto_entries
    parsers = {'nmap': _nmap_entries, 'ffuf': _ffuf_entries, 'nuclei': _nuclei_entries,
               'nikto': nikto_entries, 'nessus': nessus_entries, 'gobuster': gobuster_entries,
               'feroxbuster': feroxbuster_entries}
    for profile, parse in parsers.items():
        if profile not in inputs:
            continue
        source_name = SOURCE_NAMES[profile]
        raw = inputs[profile]
        records = []
        for loc, service, endpoint, kind, fields, disposition in parse(raw):
            if len(records) >= MAX_RECORDS:
                raise ValueError('source_record_limit')
            if disposition is None and service not in allowed:
                disposition = 'out_of_scope'
            records.append({'locator': loc, 'disposition': disposition or 'accepted'})
            if disposition is not None:
                continue
            services[service] = allowed[service]
            if endpoint:
                endpoints[endpoint] = {'key': endpoint, 'service': service}
            target = endpoint or service
            record = f'{source_name}#{loc}'
            level = 'hint' if kind != 'template_match' or fields['matched'] is True else None
            observations.append({'record': record, 'kind': kind, 'target': target,
                                 'evidence_level': level, 'asserted': fields})
            if kind == 'template_match' and fields['matched'] is True:
                finding_records.setdefault(target, []).append(record)
        receipts.append({'source': source_name, 'sha256': hashlib.sha256(raw).hexdigest(), 'records': records})
    graph = {'assets': sorted({s['asset'] for s in services.values()}),
             'services': [services[k] for k in sorted(services)],
             'endpoints': [endpoints[k] for k in sorted(endpoints)],
             'observations': observations,
             'findings': [{'target': target, 'evidence_level': 'hint', 'records': records}
                          for target, records in sorted(finding_records.items())]}
    return {'format': PROJECTION_FORMAT, 'scope': {'allowed_services': sorted(allowed)},
            'graph': graph, 'receipts': receipts}
