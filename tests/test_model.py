import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from authzledger.model import ContractError, contract_digest, load_contract, plan


def example():
    return {"version": 1, "name": "Invoice controls", "target": "http://127.0.0.1:8765",
            "identities": {"owner": {"headers": {"Authorization": {"env": "TEST_OWNER"}}},
                           "peer": {"headers": {}}},
            "cases": [{"id": "owner", "identity": "owner", "method": "GET", "path": "/invoice/1",
                       "expect": {"status": [200], "json": {"/owner": "owner"}}},
                      {"id": "other", "identity": "peer", "method": "GET", "path": "/invoice/1",
                       "requires": ["owner"], "expect": {"status": [403, 404], "json_absent": ["/amount"]}}]}


class ModelTests(unittest.TestCase):
    def test_normalization_defaults_stable_digest_and_no_mutation(self):
        source = example()
        before = copy.deepcopy(source)
        normalized = load_contract(source)
        self.assertEqual(source, before)
        self.assertEqual(normalized["limits"], {"max_requests": 50, "timeout_seconds": 5,
                                               "max_response_bytes": 65536, "concurrency": 4})
        self.assertEqual(normalized, load_contract(normalized))
        reordered = dict(reversed(list(normalized.items())))
        self.assertEqual(contract_digest(normalized), contract_digest(reordered))
        self.assertEqual(len(contract_digest(normalized)), 64)

    def test_plan_does_not_resolve_or_expose_credentials_headers_or_expected_values(self):
        source = example()
        with patch.dict(os.environ, {"TEST_OWNER": "never-expose-runtime-secret"}):
            normalized = load_contract(source)
            summary = plan(normalized)
        rendered = json.dumps(summary)
        self.assertNotIn("never-expose-runtime-secret", rendered)
        self.assertNotIn("Authorization", rendered)
        self.assertNotIn("/owner", rendered)
        self.assertEqual(summary["request_count"], 2)
        self.assertEqual(summary["cases"][1]["requires"], ["owner"])

    def test_origin_validation_and_default_port_normalization(self):
        source = example()
        for target in ("https://example.com:443/", "https://example.com"):
            source["target"] = target
            self.assertEqual(load_contract(source)["target"], "https://example.com")
        source["target"] = "http://[::1]:8765"
        self.assertEqual(load_contract(source)["target"], "http://[::1]:8765")
        for target in ("file:///tmp/file", "https://name:secret@example.com", "https://example.com/api",
                       "http://example.com#x", "http://example.com?", "http://example.com:",
                       "http://example.com:65536", "http://evil%2eexample", "http://example.com\\@other",
                       "http://example.com\n", "http://[::1%25eth0]"):
            with self.subTest(target=target):
                source["target"] = target
                with self.assertRaises(ContractError):
                    load_contract(source)

    def test_traversal_and_parser_escapes_are_rejected(self):
        source = example()
        for path in ("//other/path", "http://other/path", "/../admin", "/a/./b", "/%2e%2e/admin",
                     "/%252e%252e/admin", "/%2fother", "/a%5cb", "/a%3fb", "/a%23b",
                     "/x%0d%0aHost:other", "/x?x=%250a", "/x#fragment", "/x y", "/x%q0"):
            with self.subTest(path=path):
                source["cases"][0]["path"] = path
                with self.assertRaises(ContractError):
                    load_contract(source)
        source["cases"][0]["path"] = "/records?id=1&filter=a%20b"
        self.assertEqual(load_contract(source)["cases"][0]["path"], "/records?id=1&filter=a%20b")

    def test_mutating_methods_need_opt_in(self):
        source = example()
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            source["cases"][0]["method"] = method
            source["cases"][0]["body"] = {"enabled": True}
            with self.assertRaises(ContractError):
                load_contract(source)
            self.assertEqual(load_contract(source, allow_mutations=True)["cases"][0]["body"], {"enabled": True})
        source["cases"][0]["method"] = "GET"
        with self.assertRaises(ContractError):
            load_contract(source, allow_mutations=True)

    def test_limit_validation_and_request_budget(self):
        source = example()
        for key, bad in (("concurrency", True), ("concurrency", 17), ("timeout_seconds", float("nan")),
                         ("timeout_seconds", 0), ("max_response_bytes", 1048577), ("max_requests", 1001),
                         ("max_requests", 1), ("max_response_bytes", 1.5)):
            with self.subTest(key=key, bad=bad):
                source["limits"] = {key: bad}
                with self.assertRaises(ContractError):
                    load_contract(source)

    def test_unknown_fields_fail_at_every_level(self):
        for level in ("root", "limits", "identity", "case", "expect", "env"):
            source = example()
            target = {"root": source, "limits": source.setdefault("limits", {}),
                      "identity": source["identities"]["owner"], "case": source["cases"][0],
                      "expect": source["cases"][0]["expect"],
                      "env": source["identities"]["owner"]["headers"]["Authorization"]}[level]
            target["typo"] = True
            with self.subTest(level=level), self.assertRaises(ContractError):
                load_contract(source)

    def test_header_validation(self):
        for headers in ({"Host": "other"}, {"X-Forwarded-Host": "other"}, {"Accept-Encoding": "gzip"},
                        {"Authorization": "literal-secret"}, {"Cookie": "secret"}, {"X-Api-Key": "secret"},
                        {"X-Test": "a\r\nb"}, {"Accept": "a", "accept": "b"},
                        {"Authorization": {"env": "BAD-NAME"}}):
            source = example()
            source["identities"]["owner"]["headers"] = headers
            with self.subTest(headers=headers), self.assertRaises(ContractError):
                load_contract(source)
        for headers in ({"Authorization": "token"}, {"X-User-ID": "other"}, {"X-Role": "admin"},
                        {"Accept": {"env": "TEST_ACCEPT"}}):
            source = example()
            source["cases"][0]["headers"] = headers
            with self.subTest(headers=headers), self.assertRaises(ContractError):
                load_contract(source)

    def test_dependency_validation(self):
        for modification in ("missing", "cycle", "self", "duplicate_id", "duplicate_dependency", "identity"):
            source = example()
            if modification == "missing":
                source["cases"][1]["requires"] = ["missing"]
            elif modification == "cycle":
                source["cases"][0]["requires"] = ["other"]
            elif modification == "self":
                source["cases"][0]["requires"] = ["owner"]
            elif modification == "duplicate_id":
                source["cases"][1]["id"] = "owner"
            elif modification == "duplicate_dependency":
                source["cases"][1]["requires"] = ["owner", "owner"]
            else:
                source["cases"][0]["identity"] = "undefined"
            with self.subTest(modification=modification), self.assertRaises(ContractError):
                load_contract(source)

    def test_matrix_expansion_and_collision_detection(self):
        source = example()
        source["cases"] = []
        source["matrices"] = [{"id": "invoice", "method": "GET", "path": "/invoice/1", "rules": [
            {"identity": "owner", "expect": {"status": [200]}},
            {"identity": "peer", "requires": ["invoice:owner"], "expect": {"status": [403]}}]}]
        normalized = load_contract(source)
        self.assertEqual([case["id"] for case in normalized["cases"]], ["invoice:owner", "invoice:peer"])
        self.assertEqual(normalized["cases"][1]["requires"], ["invoice:owner"])
        source["cases"] = [normalized["cases"][0]]
        with self.assertRaises(ContractError):
            load_contract(source)

    def test_invalid_json_checks_and_values(self):
        for expectation in ({"status": [True]}, {"status": []}, {"status": [200, 200]},
                            {"status": [200], "json": {"owner": "owner"}},
                            {"status": [200], "json": {"/bad~escape": 1}},
                            {"status": [200], "json": {"/x": float("inf")}},
                            {"status": [200], "json_absent": ["/x", "/x"]},
                            {"status": [200], "json": {"/x": 1}, "json_absent": ["/x"]}):
            source = example()
            source["cases"][0]["expect"] = expectation
            with self.subTest(expectation=expectation), self.assertRaises(ContractError):
                load_contract(source)

    def test_duplicate_file_keys_and_oversized_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "contract.json"
            path.write_text('{"version":1,"version":2}', encoding="utf-8")
            with self.assertRaises(ContractError):
                load_contract(path)
            path.write_bytes(b" " * (2 * 1048576 + 1))
            with self.assertRaises(ContractError):
                load_contract(path)
            path.write_text(json.dumps(example()), encoding="utf-8")
            self.assertEqual(load_contract(path)["name"], "Invoice controls")


if __name__ == "__main__":
    unittest.main()
