# OpenAPI import

The importer reads an offline OpenAPI **3.0.x or 3.1.x JSON** document. It makes no network requests. It catalogs supported HTTP operations, path/query parameters, effective security declarations and JSON request-body requirements.

Security declarations are descriptive metadata. They do not establish ownership, tenant boundaries or role permissions. The operator supplies those expectations explicitly. No passing or failing authorization result is inferred from the specification.

## CLI

```sh
python -m authzledger import-openapi examples/openapi-invoices.json --out catalog.json
python -m authzledger import-openapi examples/openapi-invoices.json --config examples/import-policy.json --out imported-contract.json
python -m authzledger plan imported-contract.json
```

The output file must not already exist. The catalog is not executable. The second command compiles the selected operations and policy into the ordinary validated contract format; it still sends no requests.

## Configuration

`name`, `target`, `identities` and `selections` are required. `base_path` and `limits` are optional. A selection contains:

```json
{
  "operation": "GET /invoices/{id}",
  "id": "owner-access",
  "identity": "owner",
  "parameters": {"path": {"id": "owner-1"}},
  "expect": {"status": [200], "json": {"/owner": "owner"}}
}
```

Add `requires`, `headers` and a JSON `body` where applicable. A second selection of the same operation can test another identity or object, but every case ID must be unique. The contract validator checks dependencies, identity references and request limits after compilation.

## Supported boundary

- Primitive string, integer, number and boolean path/query parameters. Path uses `simple` serialization; query uses `form`. Values are encoded and revalidated against the core path boundary.
- Operation parameters override matching path-level parameters, as identified by `(in, name)`.
- Local JSON-pointer references for imported objects, with cycle/depth limits. Remote references and ambiguous reference siblings are rejected. No remote schemas are fetched.
- Required JSON request bodies and explicit mutating methods with `--allow-mutations`. Body values are not validated against the complete OpenAPI/JSON Schema vocabulary.
- The operator always sets the target origin and base path. Specification `servers`, callbacks, links, webhooks and response examples are never executed.
- Up to 1000 catalog operations, 100 parameters per parameter list, 4 MiB document size and bounded JSON/reference depth.

YAML, OpenAPI 2, automatic login flows, complex parameter serialization, multipart bodies, required header/cookie parameters, automatic schema-generated values and complete schema validation are not supported by this importer. Use a hand-reviewed contract where the core request format supports the needed request, or adapt the API fixture. Optional unsupported parameters can be omitted. The importer deliberately does not invent fixture IDs or successful permissions.

The accompanying invoice example is synthetic. Replace the target, object IDs, accounts and assertions for an authorized test environment.
