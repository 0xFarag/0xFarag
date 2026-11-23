"""Offline saved-report boundaries. © Nasser Aldin Farag (0xFarag). All rights reserved."""
import unittest
import json

from authzledger.federation_scanners import feroxbuster_entries, gobuster_entries, nessus_entries, nikto_entries


def nikto(details, wrapped=False):
    scan = b'<niktoscan>' + details + b'</niktoscan>'
    return b'<niktoscans>' + scan + b'</niktoscans>' if wrapped else scan


def nessus(body):
    return b'<NessusClientData_v2><Report>' + body + b'</Report></NessusClientData_v2>'


class OfflineScannerTests(unittest.TestCase):
    def test_feroxbuster_only_actual_responses_and_original_line_numbers(self):
        url = 'https://192.0.2.8/docs'
        response = {'type': 'response', 'url': url, 'original_url': 'https://192.0.2.8/',
                    'path': '/docs', 'status': 403, 'method': 'GET', 'content_length': 0,
                    'headers': {'private': 'sensitive'}, 'wildcard': False}
        document = [b'{"type":"configuration","target_url":"sensitive"}', b'', json.dumps(response).encode(),
                    b'{"type":"log","message":"sensitive"}', b'{"type":"statistics","requests":3910}']
        rows = list(feroxbuster_entries(b'\r\n'.join(document)))
        self.assertEqual(rows[1], ('line:3', 'tcp://192.0.2.8:443', url, 'feroxbuster_response',
                                   {'status': 403, 'method': 'GET', 'length': 0}, None))
        self.assertEqual([row[-1] for row in rows], ['source_metadata', None, 'source_metadata', 'source_metadata'])
        self.assertNotIn('sensitive', repr(rows))
        del response['content_length']
        self.assertIsNone(list(feroxbuster_entries(json.dumps(response).encode()))[0][4]['length'])

    def test_feroxbuster_conflicting_origins_and_wildcards_get_receipts_only(self):
        base = {'type': 'response', 'url': 'https://192.0.2.9/view', 'status': 200, 'method': 'GET'}
        for change, reason in [({'original_url': 'https://192.0.2.10/'}, 'unresolved_scope'),
                               ({'wildcard': True}, 'unsupported_request_context'),
                               ({'url': 'https://192.0.2.9/view?key=secret'}, 'unsupported_target'),
                               ({'url': 'https://auth.invalid/view'}, 'unresolved_scope'),
                               ({'method': 'OTHER'}, 'unsupported_request_context'),
                               ({'path': '/elsewhere'}, 'unsupported_target')]:
            with self.subTest(change=change):
                row, = feroxbuster_entries(json.dumps({**base, **change}).encode())
                self.assertEqual(row, ('line:1', None, None, None, None, reason))

    def test_feroxbuster_rejects_invalid_limits_types_and_malformed_input(self):
        base = {'type': 'response', 'url': 'http://192.0.2.8/', 'status': 200, 'method': 'GET'}
        bad = [b'{"type":"log"}', b'{"type":"other"}', b'[]', b'\n' * 1001, b' ' * 262145,
               b'{"type":"log","type":"response"}', b'{"invalid":', b'\xff']
        bad += [json.dumps({**base, **fields}).encode() for fields in
                [{'status': True}, {'status': 600}, {'content_length': -1}, {'method': None},
                 {'wildcard': 'false'}, {'truncated': 1}]]
        for raw in bad:
            with self.subTest(raw=raw[:120]), self.assertRaises(ValueError):
                list(feroxbuster_entries(raw))

    def test_nikto_numeric_string_is_preserved_and_free_text_is_omitted(self):
        raw = nikto(b'<scandetails targetip="192.0.2.1" targethostname="training.invalid" targetport="443">'
                    b'<item id="000017" method="GET"><uri>/secret</uri><description>secret</description></item>'
                    b'</scandetails>', wrapped=True)
        self.assertEqual(list(nikto_entries(raw)), [
            ('scan:1/details:1/item:1', 'tcp://192.0.2.1:443', None, 'nikto_item', {'item_id': '000017'}, None)])

    def test_nikto_conflicts_and_no_source_port_stay_unresolved(self):
        for details in [b'targetip="192.0.2.1" targethostname="192.0.2.2" targetport="443"',
                        b'targethostname="dns.invalid" targetport="443"', b'targetip="192.0.2.1"',
                        b'targetip="bogus" targethostname="192.0.2.1" targetport="443"']:
            with self.subTest(details=details):
                raw = nikto(b'<scandetails ' + details + b'><item id="1"/></scandetails>')
                self.assertEqual(list(nikto_entries(raw))[0][1:], (None, None, None, None, 'unresolved_scope'))

    def test_only_nikto_local_dtd_prolog_is_ignored(self):
        body = nikto(b'<scandetails targetport="80" targetip="192.0.2.1"><item id="1"/></scandetails>',
                     wrapped=True)
        stem = b'<?xml version="1.0" encoding="UTF-8"?>\n'
        for path in [b'nikto.dtd', b'docs/nikto.dtd', b'/does-not-exist/usr/share/nikto.dtd']:
            self.assertEqual(list(nikto_entries(stem + b'<!DOCTYPE niktoscans SYSTEM "' + path + b'">' + body)),
                             list(nikto_entries(body)))
        for declaration in [b'<!DOCTYPE niktoscans SYSTEM "//remote/nikto.dtd">',
                            b'<!DOCTYPE niktoscans SYSTEM "https://remote/nikto.dtd">',
                            b'<!DOCTYPE niktoscans SYSTEM "file:///tmp/nikto.dtd">',
                            b'<!DOCTYPE niktoscans SYSTEM "evil-nikto.dtd">',
                            b'<!DOCTYPE niktoscan SYSTEM "nikto.dtd">',
                            b'<!DOCTYPE niktoscans SYSTEM "nikto.dtd" [<!ENTITY sample "x">]>',
                            b'<!DOCTYPE niktoscans SYSTEM "nikto.dtd"><!DOCTYPE niktoscans SYSTEM "nikto.dtd">']:
            with self.subTest(declaration=declaration), self.assertRaises(ValueError):
                list(nikto_entries(stem + declaration + body))

    def test_nessus_tcp_records_source_severity_only(self):
        raw = nessus(b'<ReportHost name="training.invalid"><HostProperties><tag name="host-ip">2001:db8::1</tag>'
                     b'</HostProperties><ReportItem pluginID="27" port="443" protocol="tcp" severity="4">'
                     b'<plugin_output>secret</plugin_output></ReportItem></ReportHost>')
        self.assertEqual(list(nessus_entries(raw)), [
            ('report:1/host:1/item:1', 'tcp://[2001:db8::1]:443', None, 'nessus_item',
             {'plugin_id': 27, 'source_severity': 4}, None)])

    def test_nessus_does_not_assign_ambiguous_host_global_or_udp_to_service(self):
        raw = nessus(b'<ReportHost name="192.0.2.1"><HostProperties><tag name="host-ip">192.0.2.2</tag>'
                     b'</HostProperties><ReportItem pluginID="3" port="443" protocol="tcp" severity="0"/>'
                     b'</ReportHost><ReportHost name="192.0.2.1">'
                     b'<ReportItem pluginID="5" port="0" protocol="tcp" severity="0"/>'
                     b'<ReportItem pluginID="6" port="53" protocol="udp" severity="0"/></ReportHost>')
        rows = list(nessus_entries(raw))
        self.assertEqual([(r[0], r[-1]) for r in rows], [
            ('report:1/host:1/item:1', 'unresolved_scope'),
            ('report:1/host:2/item:1', 'unsupported_target'), ('report:1/host:2/item:2', 'unsupported_protocol')])
        self.assertTrue(all(r[1:5] == (None, None, None, None) for r in rows))

    def test_gobuster_projection_and_missing_scope(self):
        raw = (b'\r\nhttps://192.0.2.1/docs (Status: 302) [Size: 0] [--> /secret]\r\n'
               b'/relative (Status: 403)\nhttps://name.invalid/a (Status: 200)\n'
               b'https://192.0.2.1/a?token=secret (Status: 200)\n')
        rows = list(gobuster_entries(raw))
        self.assertEqual(rows[0], ('line:2', 'tcp://192.0.2.1:443', 'https://192.0.2.1/docs',
                                   'gobuster_result', {'status': 302, 'length': 0}, None))
        self.assertEqual([r[-1] for r in rows[1:]], ['unresolved_scope', 'unresolved_scope', 'unsupported_target'])
        self.assertNotIn('secret', repr(rows))
        self.assertIsNone(list(gobuster_entries(b'http://192.0.2.1/ (Status: 200)'))[0][4]['length'])

    def test_invalid_structure_and_oversized_inputs(self):
        for reader, raw in [
            (nikto_entries, b'<!DOCTYPE niktoscan><niktoscan/>'),
            (nikto_entries, b'<?xml version="1.0" encoding="utf-16"?><niktoscan/>'),
            (nessus_entries, b'<!DOCTYPE n [<!ENTITY a "hidden">]><NessusClientData_v2/>'),
            (nessus_entries, b'<NessusClientData_v2/>'),
            (nessus_entries, nessus(b'<x>' * 33 + b'</x>' * 33)),
            (nikto_entries, nikto(b'<scandetails><item id="string"/></scandetails>')),
            (nikto_entries, nikto(b'<scandetails>' + b'<item id="1"/>' * 1001 + b'</scandetails>')),
            (gobuster_entries, b'https://192.0.2.1/ (Status: 200)\nunknown banner'),
            (gobuster_entries, b'path (Status: 099)'),
            (gobuster_entries, b'path (Status: 200) [Size: 9007199254740992]'),
            (gobuster_entries, b'line\x00\n'), (gobuster_entries, b'\n' * 1001),
            (gobuster_entries, b'   '), (gobuster_entries, b'\xff')]:
            with self.subTest(reader=reader.__name__, prefix=raw[:40]), self.assertRaises(ValueError):
                list(reader(raw))
