"""Offline scanner projections never manufacture controlled vulnerability proof."""
import copy
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import unittest
from unittest.mock import patch

from authzledger.adapters import AdapterError, import_adapter, verify_adapter_receipt
from authzledger.oracles import seal
from authzledger.surface import build_catalog, merge_catalogs, verify_catalog
from tests.test_discovery150 import batch, scope


def nmap_xml(service='', state='open', doctype='<!DOCTYPE nmaprun>'):
    return (f'<?xml version="1.0" encoding="UTF-8"?>{doctype}'
        '<nmaprun scanner="nmap" xmloutputversion="1.05" args="PRIVATE_ARGS">'
        '<host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>'
        '<hostnames><hostname name="PRIVATE_HOSTNAME"/></hostnames><ports>'
        f'<port protocol="tcp" portid="22"><state state="{state}"/>{service}'
        '<script id="test" output="PRIVATE_NSE"><table><elem>PRIVATE_SECRET</elem></table></script>'
        '</port></ports></host></nmaprun>').encode()


def nuclei(**changes):
    value = {'type': 'http', 'matched-at': 'https://api.example.test/objects/12',
        'request': 'GET /objects/12 HTTP/1.1\r\nAuthorization: Bearer PRIVATE_TOKEN\r\n',
        'response': 'HTTP/1.1 200 OK\r\n\r\nPRIVATE_RESPONSE',
        'extracted-results': ['PRIVATE_EXTRACTION'], 'template-id': 'CVE-2023-12345',
        'info': {'name': 'PRIVATE_DESCRIPTION', 'severity': 'critical',
                 'classification': {'cve-id': ['cve-2023-12345']}}}
    value.update(changes)
    return json.dumps(value).encode()


class AdapterTests(unittest.TestCase):
    def test_nmap_offline_native_doctype_and_probed_safe_hint(self):
        raw = nmap_xml('<service name="ssh" product="OpenSSH" version="9.2" method="probed" conf="10" extrainfo="PRIVATE_BANNER"/>')
        original = raw
        with patch.object(socket, 'socket', side_effect=AssertionError('network')), patch.object(socket, 'getaddrinfo', side_effect=AssertionError('DNS')), patch.object(subprocess, 'Popen', side_effect=AssertionError('process')):
            receipt = import_adapter(raw, 'nmap-xml-v1')
        self.assertEqual(raw, original)
        self.assertEqual(verify_adapter_receipt(receipt), [])
        self.assertEqual(verify_catalog(receipt['catalog']), [])
        self.assertTrue(receipt['source_inventory']['native_empty_doctype'])
        self.assertEqual(receipt['source_inventory']['omitted_script_count'], 1)
        self.assertEqual(receipt['inventory']['confirmed_findings'], 0)
        self.assertEqual(receipt['catalog']['assets'][0]['ownership'], 'unknown')
        self.assertEqual(receipt['catalog']['assets'][0]['tech_hints'][0]['version'], '9.2')
        self.assertNotIn('PRIVATE_', json.dumps(receipt))

    def test_actual_published_sample_preserves_bytes_and_provenance_label(self):
        source = Path(__file__).parents[1] / 'fixtures/adapters/nmap-7.92-publishedsample.xml'
        raw = source.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), '9ad6c819c2e29b7cb3d9aa6d1627d3f3eb11932e0013d28d9e35afd9b4f7e088')
        receipt = import_adapter(raw, 'nmap-xml-v1')
        self.assertEqual(receipt['source_inventory']['host_count'], 1)
        self.assertTrue(receipt['source_inventory']['native_empty_doctype'])
        self.assertEqual(receipt['source_inventory']['ip_addresses'], ['45.33.32.156'])
        self.assertEqual(receipt['records'], [])
        self.assertEqual(verify_adapter_receipt(receipt), [])

    def test_xml_external_identifiers_entities_and_other_dtds_are_rejected(self):
        for declaration in ['<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd">',
            '<!DOCTYPE nmaprun PUBLIC "a" "https://outside.invalid/a.dtd">',
            '<!DOCTYPE nmaprun [<!ENTITY x "SECRET">]>', '<!DOCTYPE other>',
            '<!DOCTYPE nmaprun []>', '<!doctype nmaprun>', '<!DOCTYPE nmaprun><!DOCTYPE nmaprun>']:
            with self.subTest(declaration=declaration), self.assertRaises(AdapterError):
                import_adapter(nmap_xml(doctype=declaration), 'nmap-xml-v1')
        with self.assertRaises(AdapterError):
            import_adapter(nmap_xml('<service product="&unknown;"/>'), 'nmap-xml-v1')

    def test_xml_encoding_malformed_depth_bytes_and_record_limits(self):
        values = [b'<nmaprun>', b'\x00<nmaprun/>', b'<?xml version="1.0" encoding="UTF-16"?><nmaprun/>',
                  b'<nmaprun>' + b'<x>' * 33 + b'</x>' * 33 + b'</nmaprun>', b'x' * (4 * 1048576 + 1)]
        for value in values:
            with self.subTest(size=len(value)), self.assertRaises(ValueError):
                import_adapter(value, 'nmap-xml-v1')
        raw = b'<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports>' + b'<port protocol="tcp" portid="22"><state state="open"/></port>' * 1001 + b'</ports></host></nmaprun>'
        with self.assertRaisesRegex(AdapterError, 'record_limit'):
            import_adapter(raw, 'nmap-xml-v1')

    def test_table_product_and_unrecognized_banner_never_become_technology(self):
        for service in ['<service product="OpenSSH" version="9.2" method="table" conf="3"/>',
                        '<service product="PRIVATE_BANNER" version="9.2" method="probed" conf="10"/>']:
            receipt = import_adapter(nmap_xml(service), 'nmap-xml-v1')
            self.assertEqual(receipt['records'][0]['tech_hints'], [])
        receipt = import_adapter(nmap_xml('<service product="OpenSSH" version="9.2 PRIVATE_SECRET" method="probed"/>'), 'nmap-xml-v1')
        self.assertIsNone(receipt['records'][0]['tech_hints'][0]['version'])
        self.assertNotIn('PRIVATE_', json.dumps(receipt))

    def test_closed_ports_are_source_claims_and_outside_scope_is_not_authorized(self):
        policy = scope(['http://127.0.0.1:8080'], [{'origin': 'http://127.0.0.1:8080', 'method': 'GET', 'path': '/', 'purpose': 'discovery'}])
        receipt = import_adapter(nmap_xml(), 'nmap-xml-v1', policy)
        self.assertEqual(receipt['inventory']['outside_scope_assets'], 1)
        self.assertEqual(receipt['catalog']['assets'][0]['scope_state'], 'outside_scope')
        closed = import_adapter(nmap_xml(state='closed'), 'nmap-xml-v1', policy)
        self.assertEqual(closed['records'][0]['state'], 'closed')
        self.assertEqual(closed['catalog']['assets'], [])
        self.assertEqual(closed['inventory']['confirmed_findings'], 0)
        self.assertEqual(verify_adapter_receipt(closed), [])

    def test_nuclei_claim_severity_remains_unverified_and_raw_secrets_omitted(self):
        receipt = import_adapter(nuclei(), 'nuclei-jsonl-v1')
        record = receipt['records'][0]
        self.assertEqual(record['reported_severity'], 'critical')
        self.assertEqual(record['cve_references'], ['CVE-2023-12345'])
        self.assertEqual(record['evidence_level'], 'hint')
        self.assertEqual(record['verification_level'], 'source_attested')
        self.assertEqual(receipt['inventory']['confirmed_findings'], 0)
        self.assertEqual(receipt['catalog']['endpoints'][0]['coverage'], 'not_tested')
        self.assertEqual(receipt['catalog']['endpoints'][0]['observed_statuses'], [])
        self.assertNotIn('PRIVATE_', json.dumps(receipt))
        self.assertEqual(verify_adapter_receipt(receipt), [])

    def test_nuclei_target_redaction_and_unknown_method_do_not_invent_get(self):
        url = 'https://api.example.test/token/PRIVATE_PASSWORD?api_key=PRIVATE_QUERY'
        receipt = import_adapter(nuclei(**{'matched-at': url, 'request': 'GET /different HTTP/1.1'}), 'nuclei-jsonl-v1')
        self.assertIsNone(receipt['records'][0]['method'])
        self.assertEqual(receipt['catalog']['endpoints'], [])
        self.assertEqual(len(receipt['catalog']['assets']), 1)
        self.assertNotIn('PRIVATE_', json.dumps(receipt))
        self.assertIn('request_method_unknown', receipt['records'][0]['execution_blockers'])
        self.assertEqual(verify_adapter_receipt(receipt), [])

    def test_short_credentials_echoed_in_normal_paths_are_redacted(self):
        receipt = import_adapter(nuclei(**{'matched-at': 'https://api.example.test/object/shortkey',
            'request': 'GET /object/shortkey HTTP/1.1\r\nAuthorization: Bearer shortkey\r\n\r\n'}), 'nuclei-jsonl-v1')
        self.assertNotIn('shortkey', json.dumps(receipt))
        self.assertIn('credential_echo_requires_mapping', receipt['records'][0]['execution_blockers'])
        self.assertEqual(verify_adapter_receipt(receipt), [])

    def test_jsonl_skips_unimplemented_protocol_and_reports_inventory(self):
        receipt = import_adapter(b'{"type":"dns","matched-at":"outside.invalid","info":{"severity":"critical"}}\n' + nuclei(), 'nuclei-jsonl-v1')
        self.assertEqual(receipt['source_inventory']['source_records'], 2)
        self.assertEqual(receipt['source_inventory']['skipped']['unsupported_protocol'], 1)
        self.assertEqual(len(receipt['records']), 1)
        self.assertNotIn('outside.invalid', json.dumps(receipt))

    def test_bad_jsonl_duplicate_keys_and_credentials_in_authority_rejected(self):
        for raw in [b'{"type":"http","type":"dns"}', b'{"x":NaN}', b'{', b'[]',
                    nuclei(**{'matched-at': 'https://user:password@app.example.test/'}),
                    nuclei(**{'matched-at': 'file:///etc/passwd'}),
                    nuclei(**{'matched-at': 'https://app.example.test/#secret'})]:
            with self.subTest(raw=raw[:50]), self.assertRaises(ValueError):
                import_adapter(raw, 'nuclei-jsonl-v1')

    def test_rehashed_receipts_cannot_inject_claims_secrets_or_fake_counts(self):
        source = import_adapter(nuclei(), 'nuclei-jsonl-v1')
        changes = [('title', 'PRIVATE_SECRET'), ('state', 'confirmed'), ('reported_severity', 'owned'),
                   ('source_location', '/secret/PRIVATE_TOKEN'), ('path', '/token/PRIVATE_PASSWORD'),
                   ('execution_blockers', []), ('tech_hints', [{'product': 'SECRET'}])]
        for field, value in changes:
            forged = copy.deepcopy(source)
            forged['records'][0][field] = value
            forged['records'][0].pop('record_id')
            forged = seal('adapter-receipt', forged, 'receipt_digest')
            with self.subTest(field=field):
                self.assertTrue(verify_adapter_receipt(forged))
        forged = copy.deepcopy(source)
        forged['inventory']['confirmed_findings'] = 1
        forged = seal('adapter-receipt', forged, 'receipt_digest')
        self.assertTrue(verify_adapter_receipt(forged))
        closed = import_adapter(nmap_xml(state='closed'), 'nmap-xml-v1')
        closed['records'][0]['title'] = 'PRIVATE_SECRET'
        closed['records'][0].pop('record_id')
        self.assertTrue(verify_adapter_receipt(seal('adapter-receipt', closed, 'receipt_digest')))

    def test_merging_scanner_and_traffic_keeps_canonical_operation_and_sources(self):
        a = build_catalog([batch()]); b = import_adapter(nuclei(), 'nuclei-jsonl-v1')['catalog']
        catalog = merge_catalogs([a, b])
        self.assertEqual(verify_catalog(catalog), [])
        self.assertEqual(len(catalog['endpoints']), 1)
        self.assertEqual({ref['kind'] for ref in catalog['endpoints'][0]['source_refs']}, {'import', 'adapter'})
        self.assertEqual(catalog['endpoints'][0]['owner'], 'unknown')
        self.assertEqual(catalog['endpoints'][0]['coverage'], 'not_tested')


if __name__ == '__main__':
    unittest.main()
