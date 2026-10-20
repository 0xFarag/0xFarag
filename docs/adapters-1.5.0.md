# Offline scanner adapters in 1.5.0

External scanner output joins the same source-bound surface catalogue as Burp,
ZAP, HAR, OpenAPI and controlled discovery. Import never runs a scanner,
executes a template, resolves a hostname or grants target authorization.
Imported vulnerability claims remain `hint` / `source_attested`; they do not
satisfy an AuthzLedger oracle, control, reproducer or retest obligation.

## Exact supported profiles

| Profile | Accepted subset | Retained projection | Deliberate omissions |
| --- | --- | --- | --- |
| `nmap-xml-v1` | UTF-8 Nmap XML; explicit IPv4/IPv6 addresses; TCP port records | IP and port, reported port state, probe/table method and confidence, narrowly allowlisted product with numeric version only when method is `probed` | Hostnames, command arguments, MAC/OS/CPE details, raw banners, NSE output, UDP and SCTP service observations |
| `nuclei-jsonl-v1` | Nuclei JSONL events with `type: http` and absolute `matched-at` HTTP(S) URL | Safe target, explicit request method when its first line matches the target, bounded template ID and CVE references, reported severity | Template execution, template bodies, request/response headers and bodies, extracted values, descriptions and arbitrary metadata; non-HTTP event protocols are counted as skipped |

An absent or mismatching Nuclei request line leaves `method: null`. That event
creates an observed web origin, not an invented GET endpoint. Matching explicit
methods produce the same canonical operation IDs as imported traffic. A Nuclei
claim's reported severity is separate from an AuthzLedger assessed severity.
Imported critical claims can therefore be unverified hints.

Open Nmap TCP ports create service assets. Closed, filtered and other port states
remain in the receipt inventory but do not create open-service assets or imply
remediation. IP-only hosts without explicit ports remain in the source inventory;
the adapter does not invent a service, HTTP scheme or endpoint. Table-derived
service names do not become observed technology or software-version claims.
Unsupported products and nonnumeric versions are omitted. All retained
technology claims are explicitly `scanner_attested`, never locally verified.

## API and integration

```python
from authzledger.adapters import import_adapter, verify_adapter_receipt
from authzledger.surface import merge_catalogs

receipt = import_adapter(raw_bytes, "nmap-xml-v1", scope=approved_scope)
assert verify_adapter_receipt(receipt) == []
catalog = merge_catalogs([existing_catalog, receipt["catalog"]], scope=approved_scope)
```

`scope` may be omitted for an unbound offline view. A declared current scope
labels outside-scope observations rather than silently discarding them or
authorizing them. Active discovery or validation still needs its own reviewed
exact plan, operation allowlist, network boundary and execution budget.

The sealed `adapter-receipt` includes `receipt_digest`, `profile`, safe `records`,
`source_inventory`, `source_projection_digest`, the verified `catalog`, derived
inventory counters and limitations. Each record has a stable `record_id`,
generated `source_location`, `evidence_level: hint` and
`verification_level: source_attested`. Catalogue provenance identifies the
adapter profile, safe projection digest, source record and location. It merges
with traffic/discovery provenance without guessing identities, object ownership
or tenant membership. All imported endpoints initially remain `not_tested`.

The digest binds the retained safe projection. It is **not** a raw-file checksum,
proof that the external scanner ran, or a scanner signature. Differences only in
omitted banners, credentials or raw output intentionally need not change that
digest. The external source's time, omitted host metadata and scan arguments are
not represented as locally attested execution facts. Review the retained paths
before persistence: like the existing import policy, ordinary path identifiers
remain visible unless credential-labeled or token-like.

Workbench `import_source` accepts both profile names and retains the receipt in
the assessment. Its catalogue union preserves imported traffic, declarations,
controlled discovery and adapter sources. Reports preserve adapter receipts in
the signed source inventory. Imported claims are shown separately from findings
whose prerequisites and controls were executed by AuthzLedger.

## Bounded parsing and validation

- Input is bytes, nonempty and at most 4 MiB. At most 1,000 retained records.
- XML is UTF-8 only, depth at most 32, at most 20,000 elements, at most 64
  attributes per element, bounded attribute names and values.
- Native Nmap's exact inert `<!DOCTYPE nmaprun>` is accepted unchanged. External
  identifiers (`SYSTEM`/`PUBLIC`), internal subsets, entity declarations, other
  doctypes and malformed XML are rejected. The input is never rewritten to make
  an unsafe declaration acceptable. XML stylesheet instructions are inert and
  never opened. The existing Burp XML parser policy is unchanged.
- JSONL has at most 1,000 lines and 256 KiB per line. Duplicate keys, nonfinite
  values, malformed JSON, unsupported URL schemes and URL userinfo are rejected.
  Unknown event protocols are counted explicitly, not interpreted as HTTP.
- The existing traffic import redaction policy removes query values and
  credential-labeled/token-like path values. Raw requests supply the method and
  known credential header values to that redactor, so short credentials echoed
  in an ordinary target path are also removed. Raw bytes and header projections
  are never retained.
- The independent verifier checks field grammars, source/counter consistency,
  hint-only claims and catalogue rederivation even if an object was rehashed.
  Closed/noncatalog records receive the same safe-field validation.

These parsers do not claim arbitrary scanner compatibility. Nessus, Qualys,
generic XML, Nuclei non-HTTP protocols, direct scanner invocation, arbitrary NSE
scripts and arbitrary Nuclei template execution are not implemented adapters.

## Fixture provenance and format references

`fixtures/adapters/nmap-7.92-publishedsample.xml` is the second, **nmap**, XML
block published in [upstream Nmap issue 2371](https://github.com/nmap/nmap/issues/2371),
retrieved on 2026-10-20. It is a **publishedsample**, not an AuthzLedger-run native
capture. The original block's UTF-8 bytes and CRLF line endings are retained
(999 bytes, SHA-256
`9ad6c819c2e29b7cb3d9aa6d1627d3f3eb11932e0013d28d9e35afd9b4f7e088`).
It establishes compatibility with the native empty doctype and stylesheet PI;
it contains an IP-only host and does not prove service-port adapter coverage.
Locally authored XML fixtures in `tests/test_adapters150.py` cover TCP service,
closed-state, secret-bearing banner/NSE, scope and hostile-document cases. Nmap
was not installed in the implementation environment, and no external target
was scanned to produce these fixtures.

Primary format references:

- [Nmap XML output documentation](https://nmap.org/book/output-formats-xml-output.html):
  native host/port output and the distinction between table lookup and service probes.
- [ProjectDiscovery Nuclei output API](https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3/pkg/output):
  source field names including `template-id`, `type`, `matched-at`, `request` and `info`.

`python -m unittest tests.test_adapters150 tests.test_discovery150 -q` exercises
both adapters, hostile input rejection, raw-secret omission, rehashed receipt
validation, source deduplication and the existing controlled discovery boundary.
