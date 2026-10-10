"""Offline parser security and provenance tests using synthetic format fixtures."""

import base64
import copy
import hashlib
import json
from pathlib import Path
import socket
import unittest
from unittest.mock import patch
from xml.sax.saxutils import escape

from authzledger.imports import ImportError, parse_import, resolve_imported_entry


FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "imports"


def har(url="https://api.example.test/invoices/A", headers=None, body=None):
    request = {"method": "GET", "url": url, "httpVersion": "HTTP/1.1", "headers": headers or []}
    if body is not None:
        request["method"] = "POST"
        request["postData"] = {"mimeType": "application/json", "text": body}
    return {"log": {"version": "1.2", "entries": [{"request": request,
            "response": {"status": 403, "content": {"text": "private response"}}}]}}


def parse_har(value, limits=None):
    return parse_import(json.dumps(value).encode(), "har-1.2", limits)


def burp(request, url="https://api.example.test/invoices/A", response=b"HTTP/1.1 403 Forbidden\r\n\r\n", raw=False):
    if raw:
        req = '<request base64="false">' + escape(request.decode()) + '</request>'
    else:
        req = '<request base64="true">' + base64.b64encode(request).decode() + '</request>'
    return ("<items><item><url>" + escape(url) + "</url>" + req
            + '<response base64="true">' + base64.b64encode(response).decode()
            + "</response></item></items>").encode()


class ImportTests(unittest.TestCase):
    def test_three_profiles_normalize_real_message_fields_without_secret_values(self):
        for filename, profile in (("burp-http-messages.xml", "burp-xml"),
                                  ("zap-traditional-json-plus.json", "zap-json-plus"),
                                  ("har-1.2.json", "har-1.2")):
            with self.subTest(profile=profile):
                raw = (FIXTURES / filename).read_bytes()
                batch = parse_import(raw, profile)
                entry = batch["entries"][0]
                self.assertEqual(entry["method"], "GET")
                self.assertEqual(entry["origin"], "https://api.example.test")
                self.assertEqual(entry["path"], "/invoices/invoice-A")
                self.assertEqual(entry["headers"], {"accept": "application/json"})
                self.assertEqual(entry["response"], {"status": 200, "body_retained": False})
                self.assertFalse(entry["execution_blockers"])
                self.assertTrue(entry["secret_slots"])
                self.assertNotIn("IMPORT_CANARY", json.dumps(batch))
                self.assertEqual(parse_import(raw, profile), batch)
                self.assertEqual(entry["source_refs"][0]["profile"], profile)

    def test_import_performs_no_network_or_external_file_read(self):
        raw = (FIXTURES / "har-1.2.json").read_bytes()
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("network")), \
                patch.object(socket, "socket", side_effect=AssertionError("network")), \
                patch("builtins.open", side_effect=AssertionError("file read")):
            self.assertEqual(len(parse_import(raw, "har-1.2")["entries"]), 1)

    def test_raw_secret_rotation_does_not_change_projection_digest_or_ids(self):
        first = har(headers=[{"name": "Authorization", "value": "Bearer first-secret-value"}])
        second = copy.deepcopy(first)
        second["log"]["entries"][0]["request"]["headers"][0]["value"] = "Bearer second-secret-value"
        a, b = parse_har(first), parse_har(second)
        self.assertEqual(a, b)
        self.assertNotEqual(a["import_sha256"], hashlib.sha256(json.dumps(first).encode()).hexdigest())
        self.assertEqual(a["hash_basis"], "redacted-normalized-projection-v1")

    def test_xml_rejects_dtd_xxe_and_entity_expansion(self):
        inputs = [b'<!DOCTYPE items SYSTEM "file:///etc/passwd"><items/>',
                  b'<!DOCTYPE items [<!ENTITY x SYSTEM "http://example.test">]><items>&x;</items>',
                  b'<!DOCTYPE items [<!ENTITY x "xx"><!ENTITY y "&x;&x;">]><items>&y;</items>']
        for raw in inputs:
            with self.subTest(raw=raw), self.assertRaisesRegex(ImportError, "xml_declarations_forbidden"):
                parse_import(raw, "burp-xml")

    def test_utf16_xml_cannot_bypass_dtd_rejection(self):
        with self.assertRaises(ImportError):
            parse_import('<!DOCTYPE items><items/>'.encode("utf-16"), "burp-xml")

    def test_json_duplicate_keys_nan_and_nesting_fail_closed(self):
        for raw in (b'{"log":{},"log":{}}', b'{"x":NaN}', b'{"x":1e999}',
                    b'[' * 65 + b'0' + b']' * 65, b'{"x":"\\ud800"}'):
            with self.subTest(raw=raw), self.assertRaises(ImportError):
                parse_import(raw, "har-1.2")

    def test_size_entry_header_and_decoded_base64_bounds(self):
        with self.assertRaisesRegex(ImportError, "oversized"):
            parse_import(b"<items/>", "burp-xml", {"max_file_bytes": 2})
        value = har()
        value["log"]["entries"] *= 2
        with self.assertRaises(ImportError):
            parse_har(value, {"max_entries": 1})
        with self.assertRaises(ImportError):
            parse_har(har(headers=[{"name": "Accept", "value": "x"}] * 2), {"max_headers": 1})
        raw = burp(b"GET /invoices/A HTTP/1.1\r\n\r\n" + b"A" * 100)
        with self.assertRaises(ImportError):
            parse_import(raw, "burp-xml", {"max_body_bytes": 10, "max_header_bytes": 10})

    def test_xml_depth_and_duplicate_fields_are_bounded(self):
        for raw in (b"<items>" + b"<x>" * 65 + b"</x>" * 65 + b"</items>",
                    b"<items><item><url>x</url><url>y</url></item></items>"):
            with self.assertRaises(ImportError):
                parse_import(raw, "burp-xml")

    def test_malformed_base64_has_constant_safe_error(self):
        raw = b'<items><item><url>https://example.test/</url><request base64="true">SECRET_BAD%%%</request></item></items>'
        with self.assertRaises(ImportError) as caught:
            parse_import(raw, "burp-xml")
        self.assertEqual(str(caught.exception), "invalid_base64")
        self.assertNotIn("SECRET", str(caught.exception))

    def test_incomplete_message_is_visible_and_not_executable(self):
        batch = parse_import(burp(b"GET /invoices/A HTTP/1.1", response=b""), "burp-xml")
        entry = batch["entries"][0]
        self.assertIn("incomplete_request", entry["execution_blockers"])
        self.assertIn("missing_response", entry["gaps"])
        self.assertIsNone(entry["response"]["status"])

    def test_missing_response_does_not_invent_observation(self):
        value = har()
        del value["log"]["entries"][0]["response"]
        entry = parse_har(value)["entries"][0]
        self.assertEqual(entry["response"], {"status": None, "body_retained": False})
        self.assertIn("missing_response", entry["gaps"])

    def test_header_query_json_and_error_canaries_do_not_escape(self):
        value = har("https://api.example.test/invoices/A?api_key=CANARY_QUERY&mode=CANARY_MODE",
                    [{"name": "Authorization", "value": "Bearer CANARY_AUTH"},
                     {"name": "Cookie", "value": "session=CANARY_COOKIE"},
                     {"name": "X-Custom", "value": "CANARY_CUSTOM"}],
                    json.dumps({"password": "CANARY_JSON", "label": "CANARY_LABEL", "count": 2}))
        value["log"]["entries"][0]["response"]["content"]["text"] = "CANARY_ERROR"
        batch = parse_har(value)
        encoded = json.dumps(batch)
        self.assertNotIn("CANARY_", encoded)
        self.assertIn("redacted_query_requires_mapping", batch["entries"][0]["execution_blockers"])
        self.assertIn("redacted_json_requires_mapping", batch["entries"][0]["execution_blockers"])
        self.assertEqual(batch["entries"][0]["json"]["count"], 2)

    def test_known_credential_echoed_in_safe_header_and_path_is_removed(self):
        value = har("https://api.example.test/invoices/CANARY_ECHO", [
            {"name": "Authorization", "value": "Bearer CANARY_ECHO"},
            {"name": "Accept", "value": "application/CANARY_ECHO"}])
        batch = parse_har(value)
        self.assertNotIn("CANARY_ECHO", json.dumps(batch))
        self.assertIn("credential_echo_requires_mapping", batch["entries"][0]["execution_blockers"])

    def test_credentials_are_redacted_when_echoed_in_a_different_entry(self):
        value = har(headers=[{"name": "Authorization", "value": "Bearer CROSS_ENTRY_CANARY"}])
        value["log"]["entries"].extend(har("https://api.example.test/CROSS_ENTRY_CANARY")["log"]["entries"])
        batch = parse_har(value)
        self.assertNotIn("CROSS_ENTRY_CANARY", json.dumps(batch))
        self.assertIn("credential_echo_requires_mapping", batch["entries"][1]["execution_blockers"])

    def test_sensitive_path_userinfo_and_token_shaped_segments_redacted(self):
        for url in ("https://user:CANARY_PASSWORD@api.example.test/token/CANARY_PATH",
                    "https://api.example.test/session/" + "Z" * 40):
            batch = parse_har(har(url))
            self.assertNotIn("CANARY", json.dumps(batch))
            self.assertNotIn("Z" * 40, json.dumps(batch))
            self.assertIn("redacted_path_requires_mapping", batch["entries"][0]["execution_blockers"])

    def test_duplicate_queries_preserve_order_and_block_execution(self):
        entry = parse_har(har("https://api.example.test/x?b=1&a=2&b=3"))["entries"][0]
        self.assertEqual([pair[0] for pair in entry["query_pairs"]], ["b", "a", "b"])
        self.assertIn("duplicate_query_name", entry["execution_blockers"])

    def test_duplicate_headers_and_smuggling_framing_block_execution(self):
        raw = b"GET /invoices/A HTTP/1.1\r\nX-Trace: one\r\nx-trace: two\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n0\r\n\r\n"
        entry = parse_import(burp(raw), "burp-xml")["entries"][0]
        self.assertIn("duplicate_header", entry["execution_blockers"])
        self.assertIn("unsupported_http_framing", entry["execution_blockers"])
        self.assertIn("content_length_mismatch", entry["execution_blockers"])

    def test_request_target_host_and_method_disagreements_block_execution(self):
        raw = b"GET /different HTTP/1.1\r\nHost: attacker.example.test\r\n\r\n"
        entry = parse_import(burp(raw), "burp-xml")["entries"][0]
        self.assertIn("request_target_mismatch", entry["execution_blockers"])
        self.assertIn("host_origin_mismatch", entry["execution_blockers"])

    def test_zap_alert_without_message_remains_unverified_source_assertion(self):
        value = {"site": [{"@name": "https://api.example.test", "alerts": [
            {"pluginid": "90034", "riskcode": "3", "desc": "SECRET_ALERT", "instances": []}]}]}
        entry = parse_import(json.dumps(value).encode(), "zap-json-plus")["entries"][0]
        self.assertIn("missing_request", entry["execution_blockers"])
        self.assertEqual(entry["source_assertions"][0]["verification"], "not_verified")
        self.assertEqual(entry["source_assertions"][0]["risk_code"], "3")
        self.assertNotIn("SECRET", json.dumps(entry))

    def test_different_origin_is_observed_but_never_authorized(self):
        batch = parse_har(har("https://out-of-scope.example.test/object/1"))
        self.assertEqual(batch["entries"][0]["origin"], "https://out-of-scope.example.test")
        self.assertNotIn("authorized", batch)
        self.assertTrue(any("does not authorize" in line for line in batch["limitations"]))

    def test_raw_xml_message_and_numeric_json_are_supported(self):
        body = b'{"count":2,"enabled":true}'
        raw = b"POST /invoices/A HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        entry = parse_import(burp(raw, raw=True), "burp-xml")["entries"][0]
        self.assertEqual(entry["json"], {"count": 2, "enabled": True})
        self.assertFalse(entry["execution_blockers"])

    def test_binary_form_and_invalid_json_bodies_are_not_silently_repaired(self):
        for raw, expected in (
                (b"POST /invoices/A HTTP/1.1\r\nContent-Type: application/octet-stream\r\n\r\n\xff", "unsupported_body_format"),
                (b'POST /invoices/A HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"x":1,"x":2}', "invalid_json_body")):
            entry = parse_import(burp(raw), "burp-xml")["entries"][0]
            self.assertIn(expected, entry["execution_blockers"])
            self.assertNotIn("json", entry)

    def test_har_version_query_projection_and_response_size_checks(self):
        value = har()
        value["log"]["version"] = "1.1"
        with self.assertRaisesRegex(ImportError, "unsupported_har_version"):
            parse_har(value)
        value = har("https://api.example.test/x?a=1")
        value["log"]["entries"][0]["request"]["queryString"] = [{"name": "a", "value": "2"}]
        self.assertIn("query_projection_mismatch", parse_har(value)["entries"][0]["execution_blockers"])
        value = har()
        value["log"]["entries"][0]["response"]["content"] = {"encoding": "base64", "text": base64.b64encode(b"x" * 20).decode()}
        with self.assertRaises(ImportError):
            parse_har(value, {"max_body_bytes": 10})

    def test_custom_redaction_and_invalid_limits_cannot_disable_safety(self):
        entry = parse_har(har(headers=[{"name": "Accept", "value": "application/json"}]),
                          {"redact_headers": ["Accept"]})["entries"][0]
        self.assertFalse(entry["headers"])
        self.assertEqual(len(entry["secret_slots"]), 1)
        for limits in ({"max_entries": True}, {"max_entries": 501}, {"allow_entities": True},
                       {"redact_headers": ["bad\r\nname"]}):
            with self.assertRaises(ImportError):
                parse_har(har(), limits)

    def test_malformed_structures_never_return_raw_parser_values(self):
        for value in ({"log": []}, {"log": {"version": "1.2", "entries": "SECRET"}},
                      har(headers=[{"name": [], "value": "SECRET"}])):
            with self.assertRaises(ImportError) as caught:
                parse_har(value)
            self.assertNotIn("SECRET", str(caught.exception))

    def test_wrong_version_types_produce_blocker_without_decoder_exception(self):
        for version in ({}, [], None, True):
            value = har()
            value["log"]["entries"][0]["request"]["httpVersion"] = version
            self.assertIn("unsupported_http_version", parse_har(value)["entries"][0]["execution_blockers"])

    def test_har_missing_body_and_ambiguous_length_are_visible(self):
        value = har(headers=[{"name": "Content-Length", "value": "12"}])
        value["log"]["entries"][0]["request"]["bodySize"] = 12
        blockers = parse_har(value)["entries"][0]["execution_blockers"]
        self.assertIn("missing_request_body", blockers)
        self.assertIn("content_length_mismatch", blockers)

    def test_redaction_work_has_a_batch_budget(self):
        value = har(body=json.dumps([f"private-value-{i}" for i in range(1001)]))
        with self.assertRaisesRegex(ImportError, "redaction_slot_count_exceeded"):
            parse_har(value)
        value = har(body=json.dumps({f"token-{i}": f"private-value-{i}" for i in range(900)}))
        for offset in range(1, 5):
            extra = har(body=json.dumps({f"token-{i}": f"private-value-{i + offset * 900}" for i in range(900)}))
            value["log"]["entries"].extend(extra["log"]["entries"])
        with self.assertRaisesRegex(ImportError, "redaction_budget_exceeded"):
            parse_har(value)

    def test_explicit_mapping_preserves_original_and_binds_safe_receipts(self):
        entry = parse_har(har("https://api.example.test/x?page=original", body='{"label":"original","count":1}'))["entries"][0]
        original = copy.deepcopy(entry)
        mappings = {slot["id"]: {"literal": "public-value"} for slot in entry["secret_slots"]}
        result = resolve_imported_entry(entry, mappings)
        self.assertEqual(entry, original)
        self.assertEqual(result["source_entry_id"], entry["id"])
        self.assertNotEqual(result["id"], entry["id"])
        self.assertEqual(result["path"], "/x?page=public-value")
        self.assertEqual(result["json"]["label"], "public-value")
        self.assertFalse(result["execution_blockers"])
        self.assertFalse(result["secret_slots"])
        self.assertEqual(result, resolve_imported_entry(entry, mappings))
        self.assertEqual(len(result["mapping_receipts"]), 2)

    def test_mapping_cannot_redirect_scope_or_insert_credential_literals(self):
        value = har("https://api.example.test/token/hidden?api_key=hidden", [
            {"name": "Authorization", "value": "Bearer hidden"}], '{"password":"hidden"}')
        entry = parse_har(value)["entries"][0]
        for slot in entry["secret_slots"]:
            with self.subTest(slot=slot), self.assertRaises(ImportError):
                resolve_imported_entry(entry, {slot["id"]: {"literal": "https://evil.example.test"}})
        public = parse_har(har("https://api.example.test/x?next=x"))["entries"][0]
        result = resolve_imported_entry(public, {public["secret_slots"][0]["id"]: {"literal": "https://evil.example.test/path"}})
        self.assertEqual(result["origin"], public["origin"])
        self.assertTrue(result["path"].startswith("/x?next=https%3A%2F%2Fevil.example.test"))
        for literal in ("Bearer new-secret", "a" * 64, "bad\r\nheader", {"nested": "unsupported"}):
            with self.assertRaises(ImportError):
                resolve_imported_entry(public, {public["secret_slots"][0]["id"]: {"literal": literal}})

    def test_credential_query_body_can_only_be_explicitly_omitted(self):
        entry = parse_har(har("https://api.example.test/x?token=hidden", body='{"password":"hidden","count":1}'))["entries"][0]
        result = resolve_imported_entry(entry, {slot["id"]: {"omit": True} for slot in entry["secret_slots"]})
        self.assertEqual(result["path"], "/x")
        self.assertEqual(result["json"], {"count": 1})
        self.assertFalse(result["execution_blockers"])
        self.assertNotIn("hidden", json.dumps(result))

    def test_partial_mapping_reindexes_query_and_retains_other_blockers(self):
        entry = parse_har(har("https://api.example.test/x?a=one&b=two&b=three"))["entries"][0]
        first = resolve_imported_entry(entry, {"slot-1": {"omit": True}})
        self.assertIn("redacted_query_requires_mapping", first["execution_blockers"])
        self.assertIn("duplicate_query_name", first["execution_blockers"])
        second = resolve_imported_entry(first, {"slot-2": {"literal": "public"}, "slot-3": {"omit": True}})
        self.assertEqual(second["path"], "/x?b=public")
        self.assertEqual(second["source_entry_id"], entry["id"])
        self.assertEqual(second["parent_entry_id"], first["id"])
        self.assertIn("duplicate_query_name", second["execution_blockers"])
        self.assertNotIn("redacted_query_requires_mapping", second["execution_blockers"])

    def test_mapping_rejects_changed_source_unknown_slots_and_ambiguous_array_removal(self):
        entry = parse_har(har(body='["private"]'))["entries"][0]
        changed = copy.deepcopy(entry)
        changed["origin"] = "https://evil.example.test"
        with self.assertRaisesRegex(ImportError, "digest_mismatch"):
            resolve_imported_entry(changed, {})
        with self.assertRaisesRegex(ImportError, "unknown_import_mapping_slot"):
            resolve_imported_entry(entry, {"slot-999": {"literal": "x"}})
        with self.assertRaisesRegex(ImportError, "array_member_omission_unsupported"):
            resolve_imported_entry(entry, {"slot-1": {"omit": True}})
        self.assertEqual(resolve_imported_entry(entry, {"slot-1": {"literal": "public"}})["json"], ["public"])

    def test_uuid_resource_identifiers_remain_usable_but_known_uuid_credentials_redact(self):
        identifier = "c01dbeda-9860-4f44-b473-bb2fc67b4797"
        entry = parse_har(har("https://api.example.test/invoices/" + identifier))["entries"][0]
        self.assertTrue(entry["path"].endswith(identifier))
        self.assertFalse(entry["execution_blockers"])
        query = parse_har(har("https://api.example.test/invoices?id=unknown"))["entries"][0]
        mapped = resolve_imported_entry(query, {"slot-1": {"literal": identifier}})
        self.assertTrue(mapped["path"].endswith(identifier))
        credential = har("https://api.example.test/invoices/" + identifier,
                         [{"name": "Authorization", "value": "Bearer " + identifier}])
        self.assertNotIn(identifier, json.dumps(parse_har(credential)))

    def test_genuine_chromium_playwright_har_capture_imports_without_origin_corruption(self):
        raw = (FIXTURES / "chromium-real.har").read_bytes()
        provenance = json.loads((FIXTURES / "chromium-real.provenance.json").read_text())
        self.assertEqual(hashlib.sha256(raw).hexdigest(), provenance["sha256"])
        self.assertEqual(provenance["producer"]["browser"], "Chromium")
        self.assertEqual(provenance["producer"]["exporter"], "Playwright BrowserContext recordHar")
        self.assertFalse(provenance["source_scope"]["external_targets"])
        original = json.loads(raw)
        self.assertEqual(original["log"]["creator"], provenance["producer"]["har_creator"])
        batch = parse_import(raw, "har-1.2")
        self.assertEqual(len(batch["entries"]), 2)
        get, post = batch["entries"]
        self.assertEqual(get["origin"], provenance["source_scope"]["origin"])
        self.assertEqual(get["path"], "/public/invoices/invoice-A")
        self.assertFalse(get["execution_blockers"])
        self.assertEqual(get["response"]["status"], 200)
        self.assertEqual(post["path"], "/public/preview")
        self.assertEqual(post["origin"], get["origin"])
        self.assertEqual(post["json"], {"invoice": "[REDACTED]", "count": 2})
        self.assertEqual(post["execution_blockers"], ["redacted_json_requires_mapping"])
        self.assertFalse(any(entry["response"]["body_retained"] for entry in batch["entries"]))

    def test_credential_json_and_query_values_still_redact_cross_entry_echoes(self):
        value = har("https://api.example.test/x?token=QUERY_CREDENTIAL",
                    body='{"password":"BODY_CREDENTIAL"}')
        value["log"]["entries"].extend(har("https://api.example.test/QUERY_CREDENTIAL/BODY_CREDENTIAL")["log"]["entries"])
        batch = parse_har(value)
        self.assertNotIn("QUERY_CREDENTIAL", json.dumps(batch))
        self.assertNotIn("BODY_CREDENTIAL", json.dumps(batch))


if __name__ == "__main__":
    unittest.main()
