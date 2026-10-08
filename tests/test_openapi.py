import copy
import unittest

from authzledger.model import ContractError
from authzledger.openapi import catalog, compile_contract


def spec():
    return {"openapi": "3.1.0", "info": {"title": "Invoice API", "version": "1"},
            "servers": [{"url": "https://ignored.invalid/v9"}],
            "security": [{"bearer": []}], "components": {"parameters": {
                "invoiceId": {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}}},
            "paths": {"/invoices/{id}": {"parameters": [{"$ref": "#/components/parameters/invoiceId"}],
                "get": {"operationId": "getInvoice", "responses": {"200": {"description": "Success"}},
                    "parameters": [{"name": "detail", "in": "query", "schema": {"type": "boolean"}}]},
                "delete": {"security": [], "responses": {"204": {"description": "Deleted"}}}}}}


def config():
    return {"name": "Invoice rules", "target": "http://127.0.0.1:8080", "base_path": "/v1",
            "identities": {"owner": {"headers": {}}},
            "selections": [{"operation": "GET /invoices/{id}", "id": "owner-access", "identity": "owner",
                            "parameters": {"path": {"id": "owner-1"}, "query": {"detail": True}},
                            "expect": {"status": [200], "json": {"/owner": "owner"}}}]}


class OpenAPITests(unittest.TestCase):
    def test_catalog_local_refs_and_operation_security_override(self):
        value = catalog(spec())
        self.assertEqual(value["operation_count"], 2)
        get, delete = value["operations"]
        self.assertEqual(get["security"], [{"bearer": []}])
        self.assertEqual(delete["security"], [])
        self.assertTrue(delete["mutating"])
        self.assertNotIn("target", value)

    def test_compile_preserves_explicit_policy_and_does_not_use_spec_server(self):
        result = compile_contract(spec(), config())
        self.assertEqual(result["target"], "http://127.0.0.1:8080")
        self.assertEqual(result["cases"][0]["path"], "/v1/invoices/owner-1?detail=true")
        self.assertEqual(result["cases"][0]["expect"]["json"], {"/owner": "owner"})

    def test_operation_parameter_overrides_path_parameter(self):
        doc = spec()
        doc["paths"]["/invoices/{id}"]["get"]["parameters"].append({"name": "id", "in": "path", "required": True, "schema": {"type": "integer"}})
        conf = config()
        with self.assertRaises(ContractError):
            compile_contract(doc, conf)
        conf["selections"][0]["parameters"]["path"]["id"] = 42
        self.assertIn("/42?", compile_contract(doc, conf)["cases"][0]["path"])

    def test_no_permission_inference(self):
        conf = config()
        del conf["selections"][0]["expect"]
        with self.assertRaises(ContractError):
            compile_contract(spec(), conf)

    def test_remote_reference_cycle_and_ambiguous_siblings_are_rejected(self):
        for ref in ({"$ref": "https://example.invalid/params.json"},
                    {"$ref": "#/components/parameters/invoiceId"},
                    {"$ref": "#/components/parameters/other", "in": "query"}):
            with self.subTest(ref=ref):
                doc = spec()
                doc["components"]["parameters"]["invoiceId"] = ref
                with self.assertRaises(ContractError):
                    catalog(doc)

    def test_fixture_cannot_inject_path_routing_or_traversal(self):
        for value in ("../private", "x/y", "%2fsecret", "..", "x?admin=1", "x#fragment", "\r\nHost: other"):
            with self.subTest(value=value):
                conf = config()
                conf["selections"][0]["parameters"]["path"]["id"] = value
                with self.assertRaises(ContractError):
                    compile_contract(spec(), conf)

    def test_query_value_cannot_add_an_extra_parameter(self):
        doc = spec()
        doc["paths"]["/invoices/{id}"]["get"]["parameters"][0]["schema"]["type"] = "string"
        conf = config()
        conf["selections"][0]["parameters"]["query"]["detail"] = "yes&admin=true"
        self.assertTrue(compile_contract(doc, conf)["cases"][0]["path"].endswith("detail=yes%26admin%3Dtrue"))

    def test_missing_unknown_or_wrong_type_parameter_is_rejected(self):
        for parameters in ({}, {"path": {"id": "a", "other": "b"}}, {"path": {"id": "a"}, "query": {"detail": 1}}):
            with self.subTest(parameters=parameters):
                conf = config()
                conf["selections"][0]["parameters"] = parameters
                with self.assertRaises(ContractError):
                    compile_contract(spec(), conf)

    def test_mutating_import_requires_explicit_opt_in(self):
        conf = config()
        conf["selections"][0]["operation"] = "DELETE /invoices/{id}"
        conf["selections"][0]["parameters"].pop("query")
        with self.assertRaises(ContractError):
            compile_contract(spec(), conf)
        self.assertEqual(compile_contract(spec(), conf, allow_mutations=True)["cases"][0]["method"], "DELETE")

    def test_required_body_and_non_json_media_types(self):
        doc = spec()
        doc["paths"]["/invoices/{id}"]["put"] = {"requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object"}}}}}
        conf = config()
        conf["selections"][0]["operation"] = "PUT /invoices/{id}"
        conf["selections"][0]["parameters"].pop("query")
        with self.assertRaises(ContractError):
            compile_contract(doc, conf, allow_mutations=True)
        conf["selections"][0]["body"] = {"owner": "owner"}
        self.assertEqual(compile_contract(doc, conf, allow_mutations=True)["cases"][0]["body"], {"owner": "owner"})
        doc["paths"]["/invoices/{id}"]["put"]["requestBody"]["content"] = {"application/xml": {}}
        with self.assertRaises(ContractError):
            compile_contract(doc, conf, allow_mutations=True)

    def test_required_complex_parameter_blocks_compilation(self):
        doc = spec()
        doc["paths"]["/invoices/{id}"]["get"]["parameters"] = [{"name": "filter", "in": "query", "required": True, "schema": {"type": "object"}}]
        self.assertFalse(catalog(doc)["operations"][0]["parameters"][-1]["supported"])
        with self.assertRaises(ContractError):
            compile_contract(doc, config())

    def test_malformed_security_template_and_nonfinite_values_rejected(self):
        for change in (lambda d: d.update(security="bearer"),
                       lambda d: d["paths"].update({"/bad/{missing}": {"get": {}}}),
                       lambda d: d.update(openapi="2.0")):
            doc = spec()
            change(doc)
            with self.assertRaises(ContractError):
                catalog(doc)
        conf = config()
        conf["selections"][0]["parameters"]["query"]["detail"] = float("nan")
        with self.assertRaises(ContractError):
            compile_contract(spec(), conf)


if __name__ == "__main__":
    unittest.main()
