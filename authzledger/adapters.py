"""Bounded offline adapters for explicit Nmap XML and Nuclei HTTP JSONL profiles.

Scanner claims remain source-attested hints. No subprocesses, DNS, template
execution, remote references, raw responses, extracted secrets or NSE output.
"""
from __future__ import annotations

import copy
import io
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import unquote, urlsplit

from .imports import parse_import
from .model import _json_value, _path, _target
from .oracles import canonical, digest, seal
from .scope import canonical_origin, validate_scope
from .surface import _catalog, _id

PROFILES = ('nmap-xml-v1', 'nuclei-jsonl-v1')
MAX_BYTES = 4 * 1048576
MAX_RECORDS = 1000
_METHODS = {'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'}
_STATES = {'open', 'closed', 'filtered', 'unfiltered', 'open|filtered', 'closed|filtered', 'unknown'}
_SEVERITIES = {'info', 'low', 'medium', 'high', 'critical', 'unknown'}
_PRODUCTS = {'nginx': 'nginx', 'apache httpd': 'apache', 'apache': 'apache',
             'microsoft iis httpd': 'iis', 'openssh': 'openssh', 'openresty': 'openresty',
             'gunicorn': 'gunicorn', 'uvicorn': 'uvicorn', 'php': 'php', 'express': 'express'}
_COMMON = {'record_id', 'record_kind', 'title', 'evidence_level', 'verification_level',
           'origin', 'method', 'path', 'state', 'reported_severity', 'reported_template_id',
           'cve_references', 'tech_hints', 'source_location', 'execution_blockers'}


class AdapterError(ValueError):
    pass


def _record(kind, location, origin, method, path, state):
    return {'record_kind': kind, 'title': 'Imported TCP service observation' if kind == 'nmap-service' else 'Imported HTTP scanner claim',
        'evidence_level': 'hint', 'verification_level': 'source_attested',
        'origin': origin, 'method': method, 'path': path, 'state': state,
        'reported_severity': None, 'reported_template_id': None,
        'cve_references': [], 'tech_hints': [], 'source_location': location,
        'execution_blockers': ['external_claim_requires_controlled_validation']}


def _xml(raw):
    if b'\x00' in raw:
        raise AdapterError('xml_utf8_required')
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeError:
        raise AdapterError('xml_utf8_required') from None
    declaration = re.match(r'\s*<\?xml\s+[^?]*\?>', text)
    if declaration:
        encoding = re.search(r'encoding\s*=\s*[\'"]([^\'"]+)[\'"]', declaration.group(), re.I)
        if encoding and encoding.group(1).lower() not in {'utf-8', 'utf8'}:
            raise AdapterError('xml_utf8_required')
    # Native Nmap emits this inert declaration. It is accepted unchanged, not
    # stripped. External identifiers, subsets and entity declarations are not.
    declarations = re.findall(r'<!DOCTYPE[^>]*>', text, re.I)
    if len(declarations) > 1 or any(d != '<!DOCTYPE nmaprun>' for d in declarations):
        raise AdapterError('xml_doctype_forbidden')
    if re.search(r'<!ENTITY\b', text, re.I):
        raise AdapterError('xml_entities_forbidden')
    if re.search(r'<!DOCTYPE', text, re.I) and not declarations:
        raise AdapterError('xml_doctype_forbidden')
    depth = nodes = 0
    try:
        parser = ET.iterparse(io.BytesIO(raw), events=('start', 'end'))
        for event, element in parser:
            if event == 'start':
                depth += 1; nodes += 1
                if depth > 32 or nodes > 20000 or len(element.attrib) > 64:
                    raise AdapterError('xml_structure_limit')
                if any(len(k) > 128 or len(v) > 262144 for k, v in element.attrib.items()):
                    raise AdapterError('xml_attribute_limit')
            else:
                depth -= 1
        root = parser.root
    except ET.ParseError:
        raise AdapterError('malformed_nmap_xml') from None
    if root.tag != 'nmaprun' or root.get('scanner', 'nmap') != 'nmap':
        raise AdapterError('unsupported_nmap_root')
    return root, bool(declarations)


def _nmap(raw):
    root, native_doctype = _xml(raw)
    records, skipped = [], {'unsupported_protocol': 0, 'host_without_ip': 0}
    addresses = set()
    for hindex, host in enumerate(root.findall('host')):
        ips = []
        for address in host.findall('address'):
            kind = address.get('addrtype')
            if kind not in {'ipv4', 'ipv6'}:
                continue
            try:
                ip = ipaddress.ip_address(address.get('addr', ''))
                if ip.version != (4 if kind == 'ipv4' else 6):
                    raise ValueError
            except ValueError:
                raise AdapterError('invalid_nmap_ip_address') from None
            ips.append(str(ip)); addresses.add(str(ip))
        if not ips:
            skipped['host_without_ip'] += 1
            continue
        for pindex, port in enumerate(host.findall('./ports/port')):
            if port.get('protocol') != 'tcp':
                skipped['unsupported_protocol'] += 1
                continue
            try:
                number = int(port.get('portid', ''))
                if not 1 <= number <= 65535:
                    raise ValueError
            except ValueError:
                raise AdapterError('invalid_nmap_port') from None
            states = port.findall('state')
            if len(states) != 1 or states[0].get('state') not in _STATES:
                raise AdapterError('invalid_nmap_port_state')
            service = port.find('service')
            method = service.get('method', 'unknown') if service is not None else 'unknown'
            if method not in {'table', 'probed', 'unknown'}:
                method = 'unknown'
            confidence = service.get('conf') if service is not None else None
            confidence = int(confidence) if confidence and confidence.isdecimal() and 0 <= int(confidence) <= 10 else None
            hints = []
            if service is not None and method == 'probed':
                product = _PRODUCTS.get(service.get('product', '').lower())
                version = service.get('version', '')
                version = version if len(version) <= 32 and re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,3}', version) else None
                if product:
                    hints.append({'product': product, 'version': version, 'basis': 'scanner_attested',
                                  'verification': 'hint', 'source': 'nmap_service_probe'})
            for aindex, ip in enumerate(sorted(set(ips))):
                display = '[' + ip + ']' if ':' in ip else ip
                origin = canonical_origin('tcp://' + display + ':' + str(number))
                item = _record('nmap-service', f'/nmaprun/host/{hindex}/ports/{pindex}/address/{aindex}', origin,
                               'CONNECT', '/', states[0].get('state'))
                item.update(service_method=method, service_confidence=confidence, tech_hints=copy.deepcopy(hints))
                records.append(item)
                if len(records) > MAX_RECORDS:
                    raise AdapterError('adapter_record_limit')
    source = {'source_records': len(records), 'host_count': len(root.findall('host')),
              'ip_addresses': sorted(addresses), 'skipped': skipped,
              'omitted_script_count': len(list(root.iter('script'))),
              'native_empty_doctype': native_doctype,
              'source_format_version': root.get('xmloutputversion') if len(root.get('xmloutputversion', '')) <= 16 and re.fullmatch(r'[0-9]+\.[0-9]+', root.get('xmloutputversion', '')) else None}
    return records, source


def _json(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise AdapterError('duplicate_scanner_json_key')
            result[key] = value
        return result
    def invalid(_):
        raise AdapterError('nonfinite_scanner_json')
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
        _json_value(value, 'scanner event')
        if not isinstance(value, dict):
            raise AdapterError('scanner_event_object_required')
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise AdapterError('malformed_scanner_json') from None


def _nuclei(raw):
    lines = raw.splitlines()
    if len(lines) > MAX_RECORDS:
        raise AdapterError('adapter_record_limit')
    records, skipped, count = [], {'unsupported_protocol': 0}, 0
    for index, line in enumerate(lines, 1):
        if not line.strip():
            continue
        if len(line) > 262144:
            raise AdapterError('scanner_line_limit')
        event = _json(line); count += 1
        if event.get('type') != 'http':
            skipped['unsupported_protocol'] += 1
            continue
        url = event.get('matched-at')
        if not isinstance(url, str) or len(url) > 8192:
            raise AdapterError('nuclei_http_match_url_required')
        parsed = urlsplit(url)
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise AdapterError('unsafe_scanner_target')
        origin = _target(parsed.scheme + '://' + parsed.netloc)
        original_path = _path((parsed.path or '/') + ('?' + parsed.query if parsed.query else ''))
        method, credential_headers = None, []
        request = event.get('request')
        if isinstance(request, str):
            request_line = request.split('\n', 1)[0].rstrip('\r')
            match = re.fullmatch(r'([A-Z]+) (\S+) HTTP/[0-9.]+', request_line)
            if match and match.group(1) in _METHODS and match.group(2) in {original_path, url}:
                method = match.group(1)
            # Feed known credential headers through the existing redactor so
            # even short credentials echoed in ordinary paths are removed.
            # Neither these headers nor the parser's header projection persists.
            for header in request.split('\n')[1:]:
                header = header.rstrip('\r')
                if not header:
                    break
                name, separator, value = header.partition(':')
                if separator and re.fullmatch(r'[A-Za-z0-9-]{1,128}', name) and re.search(r'auth|cookie|token|password|secret|credential|session|api.?key|csrf|xsrf', name, re.I):
                    credential_headers.append({'name': name, 'value': value.strip()})
        # Existing parser owns credential-labeled paths and query redaction.
        # GET below is only a parser input; absent methods remain null in output.
        projection = parse_import(json.dumps({'log': {'version': '1.2', 'entries': [{
            'request': {'url': url, 'method': method or 'GET', 'headers': credential_headers, 'httpVersion': 'HTTP/1.1'},
            'response': {'status': 200}}]}}).encode(), 'har-1.2')['entries'][0]
        item = _record('nuclei-http', f'/lines/{index}', origin, method, projection['path'], 'reported_match')
        item['execution_blockers'].extend(projection['execution_blockers'])
        if method is None:
            item['execution_blockers'].append('request_method_unknown')
        info = event.get('info', {})
        if not isinstance(info, dict):
            raise AdapterError('invalid_nuclei_info')
        severity = info.get('severity')
        item['reported_severity'] = severity if isinstance(severity, str) and severity in _SEVERITIES else None
        template = event.get('template-id')
        if isinstance(template, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}', template):
            item['reported_template_id'] = template
        classification = info.get('classification', {})
        if isinstance(classification, dict):
            cves = classification.get('cve-id', [])
            cves = [cves] if isinstance(cves, str) else cves
            if isinstance(cves, list):
                item['cve_references'] = sorted({c.upper() for c in cves[:100] if isinstance(c, str) and re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,16}', c, re.I)})
        records.append(item)
    return records, {'source_records': count, 'skipped': skipped, 'omitted_raw_fields': True}


def _integer(value, maximum):
    return type(value) is int and 0 <= value <= maximum


def _validate_source(profile, source, records):
    """Validate the retained source grammar even when a receipt is rehashed."""
    nmap = profile == 'nmap-xml-v1'
    fields = {'source_records', 'skipped'} | ({'host_count', 'ip_addresses', 'omitted_script_count',
        'native_empty_doctype', 'source_format_version'} if nmap else {'omitted_raw_fields'})
    if not isinstance(source, dict) or set(source) != fields or not _integer(source['source_records'], MAX_RECORDS):
        raise AdapterError('invalid_adapter_source_inventory')
    skipped_fields = {'unsupported_protocol', 'host_without_ip'} if nmap else {'unsupported_protocol'}
    skipped = source['skipped']
    if not isinstance(skipped, dict) or set(skipped) != skipped_fields or any(not _integer(v, 20000) for v in skipped.values()):
        raise AdapterError('invalid_adapter_skipped_inventory')
    if source['source_records'] != len(records) + (0 if nmap else skipped['unsupported_protocol']):
        raise AdapterError('adapter_source_count_mismatch')
    if not nmap:
        if source['omitted_raw_fields'] is not True:
            raise AdapterError('invalid_scanner_projection_basis')
        return
    if (not _integer(source['host_count'], 20000) or not _integer(source['omitted_script_count'], 20000)
            or type(source['native_empty_doctype']) is not bool):
        raise AdapterError('invalid_nmap_source_inventory')
    version = source['source_format_version']
    if version is not None and (not isinstance(version, str) or not re.fullmatch(r'[0-9]{1,7}\.[0-9]{1,7}', version)):
        raise AdapterError('invalid_nmap_format_version')
    addresses = source['ip_addresses']
    if not isinstance(addresses, list) or len(addresses) > 20000:
        raise AdapterError('invalid_nmap_source_addresses')
    if any(not isinstance(ip, str) or str(ipaddress.ip_address(ip)) != ip for ip in addresses) or addresses != sorted(set(addresses)):
        raise AdapterError('invalid_nmap_source_addresses')
    if any(urlsplit(item['origin']).hostname not in addresses for item in records):
        raise AdapterError('nmap_record_address_not_in_source')


def _validate_record(profile, item):
    nmap = profile == 'nmap-xml-v1'
    kind = 'nmap-service' if nmap else 'nuclei-http'
    if item['record_kind'] != kind:
        raise AdapterError('adapter_record_profile_mismatch')
    if item['title'] != _record(kind, '', '', None, None, None)['title']:
        raise AdapterError('invalid_adapter_title')
    origin, path, method = item['origin'], item['path'], item['method']
    if not isinstance(origin, str) or len(origin) > 8192 or canonical_origin(origin) != origin:
        raise AdapterError('invalid_adapter_origin')
    if not isinstance(path, str) or len(path) > 8192 or _path(path) != path:
        raise AdapterError('invalid_adapter_path')
    blockers = item['execution_blockers']
    if not isinstance(blockers, list) or len(blockers) > 10 or len(set(blockers)) != len(blockers):
        raise AdapterError('invalid_adapter_blockers')
    allowed = {'external_claim_requires_controlled_validation', 'request_method_unknown',
        'redacted_query_requires_mapping', 'redacted_path_requires_mapping',
        'credential_echo_requires_mapping', 'duplicate_query_name', 'unsupported_query',
        'duplicate_header', 'invalid_header'}
    if not blockers or blockers[0] != 'external_claim_requires_controlled_validation' or any(b not in allowed for b in blockers):
        raise AdapterError('invalid_adapter_blockers')
    severity, template = item['reported_severity'], item['reported_template_id']
    if severity is not None and (not isinstance(severity, str) or severity not in _SEVERITIES):
        raise AdapterError('invalid_reported_severity')
    if template is not None and (not isinstance(template, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}', template)):
        raise AdapterError('invalid_reported_template_id')
    cves = item['cve_references']
    if (not isinstance(cves, list) or len(cves) > 100 or any(not isinstance(c, str) or not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,16}', c) for c in cves)
            or cves != sorted(set(cves))):
        raise AdapterError('invalid_reported_cve_reference')
    location = item['source_location']
    pattern = r'/nmaprun/host/[0-9]{1,5}/ports/[0-9]{1,5}/address/[0-9]{1,5}' if nmap else r'/lines/[0-9]{1,4}'
    if not isinstance(location, str) or not re.fullmatch(pattern, location):
        raise AdapterError('invalid_adapter_source_location')
    if nmap:
        if (not origin.startswith('tcp://') or method != 'CONNECT' or path != '/' or item['state'] not in _STATES
                or severity is not None or template is not None or cves or blockers != ['external_claim_requires_controlled_validation']):
            raise AdapterError('invalid_nmap_service_record')
        ipaddress.ip_address(urlsplit(origin).hostname)
        if item['service_method'] not in {'table', 'probed', 'unknown'}:
            raise AdapterError('invalid_nmap_service_method')
        confidence = item['service_confidence']
        if confidence is not None and not _integer(confidence, 10):
            raise AdapterError('invalid_nmap_service_confidence')
        hints = item['tech_hints']
        if not isinstance(hints, list) or len(hints) > 1 or (item['service_method'] != 'probed' and hints):
            raise AdapterError('invalid_nmap_service_hint')
        for hint in hints:
            if (not isinstance(hint, dict) or set(hint) != {'product', 'version', 'basis', 'verification', 'source'}
                    or hint['product'] not in set(_PRODUCTS.values()) or hint['basis'] != 'scanner_attested'
                    or hint['verification'] != 'hint' or hint['source'] != 'nmap_service_probe'):
                raise AdapterError('invalid_nmap_service_hint')
            version = hint['version']
            if version is not None and (not isinstance(version, str) or len(version) > 32 or not re.fullmatch(r'[0-9]+(?:\.[0-9]+){0,3}', version)):
                raise AdapterError('invalid_nmap_service_version')
    else:
        if (not origin.startswith(('https://', 'http://')) or (method is not None and method not in _METHODS)
                or item['state'] != 'reported_match' or item['tech_hints'] != []
                or ('request_method_unknown' in blockers) != (method is None)):
            raise AdapterError('invalid_nuclei_http_record')
        # The legacy importer is the one credential-path/query policy. Applying
        # it again is equivalent after percent-decoding the fixed REDACTED
        # marker; the parser may scrub that marker's encoded echo on a repeat.
        projection = parse_import(json.dumps({'log': {'version': '1.2', 'entries': [{
            'request': {'url': origin + path, 'method': method or 'GET', 'headers': [], 'httpVersion': 'HTTP/1.1'},
            'response': {'status': 200}}]}}).encode(), 'har-1.2')['entries'][0]
        required = set(projection['execution_blockers']) - {'credential_echo_requires_mapping'}
        if projection['origin'] != origin or unquote(projection['path']) != unquote(path) or not required.issubset(blockers):
            raise AdapterError('unredacted_scanner_target')


def _receipt(profile, records, source_inventory, scope):
    if profile not in PROFILES or not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise AdapterError('unsupported_adapter_profile')
    scope = validate_scope(scope) if scope is not None else None
    records = copy.deepcopy(records)
    for item in records:
        expected = _COMMON | ({'service_method', 'service_confidence'} if profile == 'nmap-xml-v1' else set())
        if not isinstance(item, dict) or set(item) - {'record_id'} != expected - {'record_id'}:
            raise AdapterError('invalid_adapter_record_fields')
        if item['evidence_level'] != 'hint' or item['verification_level'] != 'source_attested':
            raise AdapterError('scanner_claim_cannot_be_confirmed')
        _validate_record(profile, item)
        original_id = item.pop('record_id', None)
        item['record_id'] = _id('adapter-record', item)
        if original_id is not None and original_id != item['record_id']:
            raise AdapterError('adapter_record_digest_mismatch')
    _validate_source(profile, source_inventory, records)
    projection = digest('adapter-source', {'profile': profile, 'records': records, 'inventory': source_inventory})
    observations = []
    for item in records:
        refs = [{'kind': 'adapter', 'adapter_profile': profile, 'projection_digest': projection,
                 'record_id': item['record_id'], 'location': item['source_location']}]
        if profile == 'nmap-xml-v1':
            if item['state'] == 'open':
                observations.append({'source_kind': 'nmap-import', 'origin': item['origin'],
                                      'source_refs': refs, 'tech_hints': item['tech_hints']})
        elif item['method'] is None:
            observations.append({'source_kind': 'scanner-origin-import', 'origin': item['origin'],
                                  'source_refs': refs, 'tech_hints': []})
        else:
            observations.append({'source_kind': 'scanner-import', 'origin': item['origin'],
                'method': item['method'], 'path': item['path'], 'source_refs': refs,
                'parameters': [], 'status': None, 'execution_blockers': item['execution_blockers'],
                'tech_hints': []})
    catalog = _catalog(observations, scope)
    return seal('adapter-receipt', {'schema_version': 1, 'kind': 'adapter-receipt',
        'profile': profile, 'scope': scope, 'records': records,
        'source_inventory': copy.deepcopy(source_inventory), 'source_projection_digest': projection,
        'catalog': catalog, 'inventory': {'retained_records': len(records), 'hint_records': len(records),
            'confirmed_findings': 0, 'assets': len(catalog['assets']), 'endpoints': len(catalog['endpoints']),
            'outside_scope_assets': sum(a['scope_state'] == 'outside_scope' for a in catalog['assets'])},
        'limitations': ['External scanner results are source-attested hints, never AuthzLedger-confirmed findings.',
            'Import is offline and neither authorizes targets nor executes scanner templates.',
            'Source projection hashes exclude raw input, raw banners, request/response bodies and secrets.',
            'Reported severity and CVE references are unverified external claims, not an assessed AuthzLedger severity.',
            'Closed, filtered, absent and omitted ports do not prove remediation.',
            'Only the documented adapter profile subset is supported.']}, 'receipt_digest')


def import_adapter(raw, format_profile, scope=None):
    """Import explicit profile bytes offline; see docs/adapters-1.5.0.md."""
    if type(raw) is not bytes or not raw or len(raw) > MAX_BYTES:
        raise AdapterError('invalid_or_oversized_adapter_input')
    if format_profile not in PROFILES:
        raise AdapterError('unsupported_adapter_profile')
    records, inventory = _nmap(raw) if format_profile == 'nmap-xml-v1' else _nuclei(raw)
    return _receipt(format_profile, records, inventory, scope)


def verify_adapter_receipt(value):
    try:
        expected = _receipt(value['profile'], value['records'], value['source_inventory'], value['scope'])
        return [] if canonical(expected) == canonical(value) else ['adapter_receipt_mismatch']
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
        return ['invalid_adapter_receipt']
