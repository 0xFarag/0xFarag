# Authorization contract

A version 1 contract describes a fixed set of requests and the authorization assertions each request must satisfy. Unknown fields are rejected to expose misspellings and accidental assumptions early.

`init --target ORIGIN --out authorization.json` creates three GET cases: `owner-access`, `other-access` and `cross-user-denied`. The denial case depends on both positive controls, so a failed control for the other identity blocks the denial check instead of being counted as access-control success. Replace both placeholder resource paths and add suitable content assertions before running. Credentials are referenced as `AUTHZ_OWNER_TOKEN` and `AUTHZ_OTHER_TOKEN`; the command sends no requests and refuses to overwrite an existing file.

## Example

Save this as `authorization.json` and adapt the target and paths to an API you are authorised to test. This example describes the format; it does not start an API server.

```json
{
  "version": 1,
  "name": "Invoice authorization",
  "target": "http://127.0.0.1:8765",
  "limits": {
    "max_requests": 50,
    "timeout_seconds": 5,
    "max_response_bytes": 65536,
    "concurrency": 4
  },
  "identities": {
    "owner": {"headers": {"Authorization": {"env": "OWNER_TOKEN"}}},
    "peer": {"headers": {"Authorization": {"env": "PEER_TOKEN"}}},
    "anonymous": {"headers": {}}
  },
  "cases": [
    {
      "id": "owner-own-invoice",
      "identity": "owner",
      "method": "GET",
      "path": "/invoices/owner-1",
      "expect": {"status": [200], "json": {"/owner": "owner"}}
    },
    {
      "id": "peer-own-invoice",
      "identity": "peer",
      "method": "GET",
      "path": "/invoices/peer-1",
      "expect": {"status": [200], "json": {"/owner": "peer"}}
    },
    {
      "id": "peer-cannot-read-owner",
      "identity": "peer",
      "method": "GET",
      "path": "/invoices/owner-1",
      "requires": ["owner-own-invoice", "peer-own-invoice"],
      "expect": {"status": [403, 404], "json_absent": ["/amount"]}
    },
    {
      "id": "anonymous-cannot-read-owner",
      "identity": "anonymous",
      "method": "GET",
      "path": "/invoices/owner-1",
      "requires": ["owner-own-invoice"],
      "expect": {"status": [401, 403, 404]}
    }
  ]
}
```

The value of each credential environment variable is the complete header value expected by the API, including an authentication scheme such as `Bearer ` where required. Resolve credentials at execution time. Planning does not read their values.

## Fields

| Field | Purpose |
| --- | --- |
| `version` | Contract schema version; use `1`. |
| `name` | Human-readable scope name; appears in reports. |
| `target` | Explicit HTTP(S) origin; credentials, base paths, query strings, fragments and origin URL escapes are rejected. |
| `limits` | Bounds for total requests, timeout, response bytes and concurrency. |
| `identities` | Named request identities and their configured headers. |
| `cases` | Explicit request and assertion definitions. |
| `matrices` | Optional shorthand for applying identity rules to one request. |

Each case has a unique `id`, a declared `identity`, a supported `method`, a validated relative `path` and an `expect` object. Optional fields are `requires`, `body` and literal per-case `headers`. Authentication and security-sensitive headers are not allowed in per-case overrides; configure identity headers using environment references instead.

Per-case headers are limited to `Accept`, `Accept-Language`, `Content-Type`, `User-Agent`, `Cache-Control`, `Pragma`, `X-Request-ID` and `X-Correlation-ID`, matched without case sensitivity. Routing, proxy and connection headers cannot be configured at either level.

The supported methods are GET, HEAD, OPTIONS, POST, PUT, PATCH and DELETE. The last four require `--allow-mutations` for both `plan` and `run`. A `body` is a JSON value, not a file reference or shell expression; GET and HEAD bodies are rejected.

| Expectation | Check |
| --- | --- |
| `status` | Response status must match one of the listed integers. |
| `json` | Values selected by JSON pointers must equal the specified values. |
| `json_absent` | The selected JSON pointers must be absent. |

Use status and content assertions together where the API's error format supports them. A denial status alone does not establish that sensitive response content was withheld. Content assertions require a response that can be evaluated as JSON; choose expectations that match the API's documented response format.

JSON pointers follow RFC 6901: `/owner` selects an object member, `/items/0` an array element, `~1` escapes `/` and `~0` escapes `~` within a member name. An empty pointer addresses the entire document.

## Execution limits

| Setting | Default | Accepted range |
| --- | --- | --- |
| `max_requests` | `50` | Integer from `1` to `1000` |
| `timeout_seconds` | `5` | Number from `0.1` to `60` |
| `max_response_bytes` | `65536` | Integer from `1` to `1048576` |
| `concurrency` | `4` | Integer from `1` to `16` |

The expanded contract must fit `max_requests`. A contract file is limited to 2 MiB and a JSON request body to 1 MiB. The runner requests uncompressed responses and refuses encoded responses instead of decompressing them.

`timeout_seconds` sets a per-request deadline for socket I/O, including TLS negotiation, response headers and body reads. Incremental header or body delivery does not reset that deadline. Blocking operating-system DNS resolution remains outside that mechanism; use an outer process or CI job timeout when a total execution limit is required.

## Establish controls before denial checks

`requires` names prerequisite case IDs. The runner waits for those cases to finish and sends a dependent request only if every prerequisite passed. Otherwise the dependent result is `inconclusive` and no request is sent for it.

In the example, Owner's successful owner check establishes that the resource exists. Peer's successful owner check establishes that Peer's identity works. Together they make Peer's cross-user denial result more meaningful than a denial check performed with an expired token or missing resource.

Dependencies are explicit. AuthzLedger does not infer control cases. Duplicate IDs, unknown identities, unknown prerequisites and dependency cycles are configuration errors.

## Matrix shorthand

The following fragment expands to `invoice:owner` and `invoice:peer`:

```json
{
  "matrices": [
    {
      "id": "invoice",
      "method": "GET",
      "path": "/invoices/owner-1",
      "rules": [
        {
          "identity": "owner",
          "expect": {"status": [200], "json": {"/owner": "owner"}}
        },
        {
          "identity": "peer",
          "requires": ["invoice:owner"],
          "expect": {"status": [403, 404]}
        }
      ]
    }
  ]
}
```

This is a fragment, not a complete contract. Include the version, name, target and identities. Expanded cases use the same validation, limits and dependency rules as explicit cases.

## Scope and repeatability

- Use exact relative paths. Traversal, redirects and paths that escape the configured target are not accepted.
- Keep tokens and session values in environment variables, not names, URLs, paths, literal headers or request bodies.
- Inspect `plan` before execution. Limits constrain the run, including matrix expansion.
- Commit the contract with the test data setup needed to reproduce it; keep credentials outside version control.
- Compare before/after runs using the same normalized contract. Its digest identifies that configuration; environment-variable names are part of it, resolved secret values are not.

