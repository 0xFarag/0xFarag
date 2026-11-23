"""Offline readers for saved Nikto, Nessus, Gobuster and feroxbuster reports.

© Nasser Aldin Farag (0xFarag). All rights reserved.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

from .adapters import MAX_RECORDS
from .federation_offline import MAX_SOURCE_BYTES, _http_entry, _http_identity, _ip, _json_object, _number, _service


class _ReportTree(ET.TreeBuilder):
    """Reject DTDs and bound allocation while the XML tree is being built."""

    def __init__(self):
        super().__init__()
        self.depth = self.nodes = 0

    def start(self, tag, attrs):
        self.depth += 1
        self.nodes += 1
        if (self.depth > 32 or self.nodes > 20000 or len(attrs) > 64
                or len(tag) > 256 or any(len(k) > 128 or len(v) > 262144 for k, v in attrs.items())):
            raise ValueError('xml_structure_limit')
        return super().start(tag, attrs)

    def end(self, tag):
        self.depth -= 1
        return super().end(tag)

    def doctype(self, name, pubid, system):
        raise ValueError('xml_doctype_forbidden')


def _text(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_SOURCE_BYTES:
        raise ValueError('invalid_source_bytes')
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise ValueError('expected_utf8_export') from None
    if '\x00' in text:
        raise ValueError('expected_utf8_export')
    return text


def _xml(raw, allowed_roots):
    text = _text(raw)
    declaration = re.match(r'<\?xml[ \t\r\n]+([^?]+)\?>', text)
    if declaration:
        encoding = re.search(r'\bencoding\s*=\s*[\'"]([^\'"]+)[\'"]', declaration[1], re.I)
        if encoding and encoding[1].lower() not in {'utf-8', 'utf8'}:
            raise ValueError('expected_utf8_export')
    # Some Nikto versions emit a local DTD path. Remove only this prolog
    # spelling before parsing. The named DTD is never opened or interpreted.
    declared_root = None
    if 'niktoscan' in allowed_roots:
        offset = declaration.end() if declaration else 0
        native = re.match(
            r'''[ \t\r\n]*<!DOCTYPE\s+(niktoscans?)\s+SYSTEM\s+(["'])([A-Za-z0-9_./ -]{0,512}nikto\.dtd)\2\s*>''',
            text[offset:], flags=re.ASCII)
        if native:
            path = native[3]
            if '//' in path or path.rsplit('/', 1)[-1] != 'nikto.dtd':
                raise ValueError('xml_doctype_forbidden')
            declared_root = native[1]
            text = text[:offset] + text[offset + native.end():]
    try:
        root = ET.fromstring(text, parser=ET.XMLParser(target=_ReportTree(), encoding='utf-8'))
    except ET.ParseError:
        raise ValueError('malformed_scanner_xml') from None
    if root.tag not in allowed_roots or (declared_root and declared_root != root.tag):
        raise ValueError('unsupported_scanner_root')
    return root


def _literal_host(label, declared_ips):
    """Match producer-supplied addresses without resolving DNS or ambiguous hosts."""
    ips = set()
    for value in declared_ips:
        try:
            ips.add(_ip(value))
        except ValueError:
            return None
    if label:
        try:
            ips.add(_ip(label))
        except ValueError:
            pass  # A DNS label is never resolved or emitted.
    return ips.pop() if len(ips) == 1 else None


def _decimal(value, digits, low, high):
    if not isinstance(value, str) or len(value) > digits or not re.fullmatch('[0-9]+', value):
        raise ValueError('invalid_scanner_integer')
    return _number(int(value), low, high)


def _omit(locator, reason):
    return locator, None, None, None, None, reason


def nikto_entries(raw):
    root = _xml(raw, {'niktoscan', 'niktoscans'})
    scans = [root] if root.tag == 'niktoscan' else root.findall('niktoscan')
    if not scans:
        raise ValueError('missing_nikto_scan')
    count = 0
    for scan_no, scan in enumerate(scans, 1):
        for details_no, details in enumerate(scan.findall('scandetails'), 1):
            explicit = details.get('targetip')
            address = _literal_host(details.get('targethostname'), [explicit] if explicit is not None else [])
            port = details.get('targetport')
            for item_no, item in enumerate(details.findall('item'), 1):
                count += 1
                if count > MAX_RECORDS:
                    raise ValueError('source_record_limit')
                loc = f'scan:{scan_no}/details:{details_no}/item:{item_no}'
                item_id = item.get('id')
                _decimal(item_id, 12, 0, 999999999999)
                if address is None or port is None:
                    yield _omit(loc, 'unresolved_scope')
                    continue
                service = _service(address, _decimal(port, 5, 1, 65535))
                yield loc, service, None, 'nikto_item', {'item_id': item_id}, None


def nessus_entries(raw):
    root = _xml(raw, {'NessusClientData_v2'})
    reports = root.findall('Report')
    if not reports:
        raise ValueError('missing_nessus_report')
    count = 0
    for report_no, report in enumerate(reports, 1):
        for host_no, host in enumerate(report.findall('ReportHost'), 1):
            declared = [node.text for node in host.findall('HostProperties/tag') if node.get('name') == 'host-ip']
            address = _literal_host(host.get('name'), declared)
            for item_no, item in enumerate(host.findall('ReportItem'), 1):
                count += 1
                if count > MAX_RECORDS:
                    raise ValueError('source_record_limit')
                loc = f'report:{report_no}/host:{host_no}/item:{item_no}'
                port = _decimal(item.get('port'), 5, 0, 65535)
                fields = {'plugin_id': _decimal(item.get('pluginID'), 9, 1, 999999999),
                          'source_severity': _decimal(item.get('severity'), 1, 0, 4)}
                if address is None:
                    yield _omit(loc, 'unresolved_scope')
                elif item.get('protocol') != 'tcp':
                    yield _omit(loc, 'unsupported_protocol')
                elif port == 0:
                    yield _omit(loc, 'unsupported_target')
                else:
                    yield loc, _service(address, port), None, 'nessus_item', fields, None


_GOBUSTER_ROW = re.compile(
    r'([^\s]+) +\(Status: *([0-9]{3})\)(?: +\[Size: *([0-9]{1,16})\])?'
    r'(?: +\[--> +[^\]\r\n]+\])? *'
)


def gobuster_entries(raw):
    text = _text(raw)
    if text.count('\n') + int(not text.endswith('\n')) > MAX_RECORDS:
        raise ValueError('source_record_limit')
    records = 0
    for index, line in enumerate(text.split('\n'), 1):
        line = line.removesuffix('\r')
        if not line.strip(' '):
            continue
        if (len(line) > 16384 or not line.isprintable()
                or not (match := _GOBUSTER_ROW.fullmatch(line.lstrip(' ')))):
            raise ValueError('invalid_gobuster_result')
        target, code, size = match.groups()
        records += 1
        loc = f'line:{index}'
        fields = {'status': _number(int(code), 100, 599),
                  'length': _number(int(size), 0, 2**53 - 1) if size is not None else None}
        if '://' not in target:
            yield _omit(loc, 'unresolved_scope')
        else:
            yield _http_entry(target, loc, 'gobuster_result', fields)
    if not records:
        raise ValueError('missing_gobuster_results')


def feroxbuster_entries(raw):
    """Read UTF-8 response JSONL; preserve physical lines for metadata and omissions."""
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_SOURCE_BYTES:
        raise ValueError('invalid_source_bytes')
    if raw.count(b'\n') + int(not raw.endswith(b'\n')) > MAX_RECORDS:
        raise ValueError('source_record_limit')
    responses = 0
    for index, line in enumerate(raw.split(b'\n'), 1):
        if len(line) > 262144:
            raise ValueError('feroxbuster_line_limit')
        if not line.strip():
            continue
        row = _json_object(line)
        kind = row.get('type')
        loc = f'line:{index}'
        if kind in ('configuration', 'statistics', 'log'):
            yield _omit(loc, 'source_metadata')
            continue
        if kind != 'response':
            raise ValueError('unsupported_feroxbuster_record')
        responses += 1
        method = row.get('method')
        if not isinstance(method, str) or not method:
            raise ValueError('invalid_feroxbuster_method')
        if any(type(row[name]) is not bool for name in ('wildcard', 'truncated') if name in row):
            raise ValueError('invalid_feroxbuster_response_flag')
        fields = {'status': _number(row.get('status'), 100, 599),
                  'length': _number(row['content_length'], 0, 2**53 - 1) if 'content_length' in row else None,
                  'method': method}
        if row.get('wildcard') or method not in {'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'}:
            yield _omit(loc, 'unsupported_request_context')
            continue
        entry = _http_entry(row.get('url'), loc, 'feroxbuster_response', fields)
        if entry[-1]:
            yield _omit(loc, entry[-1])
            continue
        endpoint = urlsplit(entry[2])
        if 'path' in row and row['path'] != endpoint.path:
            yield _omit(loc, 'unsupported_target')
            continue
        if 'original_url' in row:
            original_service, original_url, reason = _http_identity(row['original_url'])
            if reason or original_service != entry[1] or urlsplit(original_url).scheme != endpoint.scheme:
                yield _omit(loc, 'unresolved_scope')
                continue
        yield entry
    if not responses:
        raise ValueError('missing_feroxbuster_responses')
