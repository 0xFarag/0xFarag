"""Contract tests for source-bound, non-executing federation projections."""
import hashlib
import json
import socket
import subprocess
import unittest
from unittest.mock import patch

from authzledger.federation_offline import MAX_SOURCE_BYTES, MAX_TOTAL_BYTES, project_federation

SCOPE = ['tcp://192.0.2.10:443']
TARGET = 'https://192.0.2.10/docs'
NMAP = b'''<!DOCTYPE nmaprun>
<nmaprun scanner="nmap"><host><address addrtype="ipv4" addr="192.0.2.10"/>
<ports><port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>
<service name="https" method="table" conf="3"/></port></ports></host></nmaprun>'''


def ffuf(url=TARGET, **fields):
    return json.dumps({'results': [{'url': url, 'status': 200, **fields}]}).encode()


def match(flag=True, **fields):
    value = {'matched-at': TARGET, 'type': 'http', 'template-id': 'fixture',
             'info': {'severity': 'critical'}, **fields}
    if flag is not None:
        value['matcher-status'] = flag
    return json.dumps(value).encode()


def view(*sources):
    return project_federation(SCOPE, sources)


class FederationOfflineTests(unittest.TestCase):
    def test_three_formats_build_one_graph_without_network_or_process(self):
        sources = [('nmap', NMAP), ('ffuf', ffuf(length=0)), ('nuclei', match() + b'\n' + match(False))]
        with (patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS')),
              patch.object(socket, 'socket', side_effect=AssertionError('network')),
              patch.object(subprocess, 'Popen', side_effect=AssertionError('process'))):
            result = view(*sources)
        graph = result['graph']
        self.assertEqual(graph['assets'], ['192.0.2.10'])
        self.assertEqual(graph['services'], [{'key': SCOPE[0], 'asset': '192.0.2.10', 'port': 443, 'transport': 'tcp'}])
        self.assertEqual(graph['endpoints'], [{'key': TARGET, 'service': SCOPE[0]}])
        self.assertEqual([o['evidence_level'] for o in graph['observations']], ['hint', 'hint', 'hint', None])
        self.assertEqual(graph['observations'][0]['asserted']['method'], 'table')
        self.assertEqual(graph['observations'][1]['asserted'], {'status': 200, 'length': 0, 'method': None})
        self.assertEqual(graph['findings'], [{'target': TARGET, 'evidence_level': 'hint', 'records': ['nuclei.jsonl#line:1']}])
        for receipt, (_, raw) in zip(result['receipts'], sources):
            self.assertEqual(receipt['sha256'], hashlib.sha256(raw).hexdigest())

    def test_order_and_reimport_are_idempotent(self):
        f, n = ('ffuf', ffuf()), ('nmap', NMAP)
        self.assertEqual(view(f, n), view(n, f, n, f))

    def test_second_distinct_file_same_logical_path_is_ambiguous(self):
        with self.assertRaisesRegex(ValueError, 'conflicting_source'):
            view(('ffuf', ffuf()), ('ffuf', ffuf(length=0)))

    def test_unresolved_and_out_of_scope_do_not_materialise_assets(self):
        for url, reason in [('https://192.0.2.10:444/docs', 'out_of_scope'),
                            ('http://192.0.2.10/docs', 'out_of_scope'),
                            ('https://public.example/docs', 'unresolved_scope')]:
            with self.subTest(url=url):
                result = view(('ffuf', ffuf(url)))
                self.assertEqual(result['graph']['observations'], [])
                self.assertEqual(result['graph']['services'], [])
                self.assertEqual(result['receipts'][0]['records'], [{'locator': '/results/0', 'disposition': reason}])

    def test_sensitive_and_ambiguous_targets_never_escape(self):
        for url in ['https://user:CANARY@192.0.2.10/docs', TARGET + '?api_key=CANARY',
                    TARGET + '#CANARY', TARGET + '/token/CANARY', TARGET + '/../CANARY',
                    TARGET + '/%2fCANARY', TARGET + '\\CANARY', TARGET + '\nCANARY']:
            with self.subTest(url=url):
                result = view(('ffuf', ffuf(url)))
                self.assertEqual(result['receipts'][0]['records'][0]['disposition'], 'unsupported_target')
                self.assertNotIn('CANARY', json.dumps(result))

    def test_raw_nuclei_fields_and_negative_evidence(self):
        raw = b'\n'.join([match(None), match(False), match(True, request='PRIVATE_CANARY')])
        result = view(('nuclei', raw))
        self.assertEqual(result['graph']['findings'], [])
        obs = result['graph']['observations']
        self.assertEqual([o['asserted']['matched'] for o in obs], [None, False])
        self.assertTrue(all(o['evidence_level'] is None for o in obs))
        self.assertNotIn('PRIVATE_CANARY', json.dumps(result))
        self.assertEqual(result['receipts'][0]['records'][2]['disposition'], 'unsupported_raw_record')

    def test_multihomed_host_is_unresolved_and_udp_is_unsupported(self):
        original = b'<ports>'
        for raw, reason in [(NMAP.replace(original, b'<address addrtype="ipv4" addr="192.0.2.99"/><ports>'), 'unresolved_scope'),
                            (NMAP.replace(b'"tcp"', b'"udp"'), 'unsupported_protocol')]:
            with self.subTest(reason=reason):
                result = view(('nmap', raw))
                self.assertEqual(result['graph']['observations'], [])
                self.assertEqual(result['receipts'][0]['records'][0]['disposition'], reason)

    def test_documents_fail_atomically_on_ambiguity_or_limits(self):
        for source in [('ffuf', b'{"results":[],"results":[]}'), ('nmap', b'<!DOCTYPE nmaprun SYSTEM "file:///dev/null"><nmaprun/>'),
                       ('ffuf', b' ' * (MAX_SOURCE_BYTES + 1)), ('ffuf', ffuf(length=True)),
                       ('nuclei', b'\n' * 1001), ('nuclei', match('false')),
                       ('ffuf', json.dumps({'results': [{}] * 1001}).encode())]:
            with self.subTest(profile=source[0]), self.assertRaises(ValueError):
                view(('nmap', NMAP) if source[0] != 'nmap' else ('ffuf', ffuf()), source)

    def test_all_callers_share_the_same_combined_byte_budget(self):
        first = NMAP.ljust(MAX_TOTAL_BYTES // 2, b' ')
        second = ffuf().ljust(MAX_TOTAL_BYTES // 2, b' ')
        self.assertEqual(view(('nmap', first), ('ffuf', second))['graph']['assets'], ['192.0.2.10'])
        with self.assertRaisesRegex(ValueError, 'total_bytes_limit'):
            view(('nmap', first), ('ffuf', second + b' '))

    def test_scope_requires_canonical_literal_and_port(self):
        for service in ['192.0.2.10', 'tcp://www.example:443', 'tcp://192.0.2.10:0',
                        'tcp://192.0.2.10:443/unused', 'tcp://[fe80::1%lan]:443', 'tcp://user@192.0.2.10:443']:
            with self.subTest(service=service), self.assertRaises(ValueError):
                project_federation([service], [('ffuf', ffuf())])
        value = project_federation(['tcp://[2001:db8::1]:80'], [('ffuf', ffuf('http://[2001:db8::1]:80/docs'))])
        self.assertEqual(value['graph']['endpoints'][0]['key'], 'http://[2001:db8::1]/docs')

    def test_unsupported_protocol_and_absent_measurement_remain_visible(self):
        result = view(('ffuf', ffuf()), ('nuclei', match(type='dns')))
        self.assertIsNone(result['graph']['observations'][0]['asserted']['length'])
        self.assertEqual(result['receipts'][1]['records'][0]['disposition'], 'unsupported_protocol')

    def test_ffuf_declared_request_context_and_virtual_host(self):
        row = json.loads(ffuf())
        row['config'] = {'method': 'POST'}
        self.assertEqual(view(('ffuf', json.dumps(row).encode()))['graph']['observations'][0]['asserted']['method'], 'POST')
        row['config']['headers'] = {'Authorization': 'CANARY'}
        result = view(('ffuf', json.dumps(row).encode()))
        self.assertEqual(result['receipts'][0]['records'][0]['disposition'], 'unsupported_request_context')
        self.assertNotIn('CANARY', json.dumps(result))
        mismatch = view(('ffuf', ffuf(host='other.example')))
        self.assertEqual(mismatch['receipts'][0]['records'][0]['disposition'], 'unresolved_scope')

    def test_ambiguous_port_locator_and_non_utf8_rejected(self):
        with self.assertRaisesRegex(ValueError, 'ambiguous_nmap_port_locator'):
            view(('nmap', NMAP.replace(b'</host>', b'<ports/></host>')))
        with self.assertRaises(ValueError):
            view(('ffuf', ffuf().decode().encode('utf-16')))

    def test_nuclei_conflicting_identity_is_unresolved_and_groups_share_only_target(self):
        raw = b'\n'.join([match(host='198.51.100.4'), match(ip='198.51.100.5'),
                          match(host=TARGET), match(ip='192.0.2.10', **{'template-id': 'other-rule'})])
        result = view(('nuclei', raw))
        self.assertEqual([r['disposition'] for r in result['receipts'][0]['records']],
                         ['unresolved_scope', 'unresolved_scope', 'accepted', 'accepted'])
        self.assertEqual(len(result['graph']['observations']), 2)
        self.assertEqual(result['graph']['findings'], [
            {'target': TARGET, 'evidence_level': 'hint', 'records': ['nuclei.jsonl#line:3', 'nuclei.jsonl#line:4']}])

    def test_nuclei_optional_service_claims_must_agree(self):
        conflicts = [{'port': '8443'}, {'port': True}, {'port': 443.0}, {'port': '0443'}, {'scheme': 'http'},
                     {'url': 'https://198.51.100.20/docs'}, {'url': 'https://192.0.2.10:8443/other'},
                     {'url': 'http://192.0.2.10:443'}, {'url': 'https://192.0.2.10/?token=PRIVATE_CANARY'}]
        for fields in conflicts:
            with self.subTest(fields=fields):
                result = view(('nuclei', match(host='192.0.2.10', **fields)))
                self.assertEqual(result['receipts'][0]['records'][0]['disposition'], 'unresolved_scope')
                self.assertEqual(result['graph']['findings'], [])
                self.assertNotIn('PRIVATE_CANARY', json.dumps(result))
        for port in ('443', 443):
            raw = match(port=port, url='https://192.0.2.10:443/base', scheme='https', host='192.0.2.10:443')
            self.assertEqual(view(('nuclei', raw))['receipts'][0]['records'][0]['disposition'], 'accepted')

    def test_nuclei_ipv6_port_scope_is_consistent_across_producer_fields(self):
        target = 'https://[2001:db8::7]:8443/a'
        fields = {'matched-at': target, 'url': 'https://[2001:db8::7]:8443/base',
                  'port': '8443', 'host': '[2001:db8::7]:8443', 'ip': '2001:0db8:0:0:0:0:0:7', 'scheme': 'https'}
        scope = ['tcp://[2001:db8::7]:8443']
        self.assertEqual(project_federation(scope, [('nuclei', match(**fields))])['graph']['endpoints'][0]['key'], target)
        fields['url'] = 'https://[2001:db8::7]/a'
        result = project_federation(scope, [('nuclei', match(**fields))])
        self.assertEqual(result['receipts'][0]['records'][0]['disposition'], 'unresolved_scope')

    def test_ffuf_routing_overrides_are_outside_the_narrow_profile(self):
        for flags in [{'follow_redirects': True}, {'sni': 'elsewhere.example'}, {'proxyurl': 'http://proxy.example'},
                      {'client-key': '/private/key'}, {'method': 0}]:
            with self.subTest(flags=flags):
                row = json.loads(ffuf())
                row['config'] = flags
                result = view(('ffuf', json.dumps(row).encode()))
                self.assertEqual(result['receipts'][0]['records'][0]['disposition'], 'unsupported_request_context')

    def test_ffuf_native_and_legacy_request_context_fields(self):
        for key in ('postdata', 'data', 'replayproxyurl'):
            for value in ('', 'CONTEXT_CANARY'):
                with self.subTest(key=key, present=bool(value)):
                    document = json.loads(ffuf())
                    document['config'] = {'method': 'POST', key: value}
                    result = view(('ffuf', json.dumps(document).encode()))
                    record = result['receipts'][0]['records'][0]
                    if value:
                        self.assertEqual(record['disposition'], 'unsupported_request_context')
                        self.assertEqual(result['graph']['observations'], [])
                    else:
                        self.assertEqual(record['disposition'], 'accepted')
                        self.assertEqual(result['graph']['observations'][0]['asserted']['method'], 'POST')
                    self.assertNotIn('CONTEXT_CANARY', json.dumps(result))

    def test_no_raw_paths_from_ffuf_configuration_are_retained(self):
        result = json.loads(ffuf(resultfile='/home/PRIVATE_CANARY/report'))
        result['commandline'] = 'PRIVATE_CANARY'
        projection = view(('ffuf', json.dumps(result).encode()))
        self.assertNotIn('PRIVATE_CANARY', json.dumps(projection))


if __name__ == '__main__':
    unittest.main()
