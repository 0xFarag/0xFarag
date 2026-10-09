# Security model

AuthzLedger evaluates configured authorization assertions. It does not discover complete API coverage, establish permission to test a service or certify that an application is secure.

## Execution boundary

The operator supplies the target, identities, paths, methods and expectations. Requests stay within the validated target and paths. Redirects, ambient proxies and ambient credentials are disabled. Supplied OpenAPI documents can be indexed offline; there is no live endpoint discovery, automatic exploitation or target selection.

Request count, concurrency, timeout and response size are bounded. The per-request socket deadline includes TLS negotiation, response headers and body reads; operating-system DNS resolution can still block independently. Missing credential variables fail before any requests are sent. The CLI requires explicit opt-in for POST, PUT, PATCH and DELETE. These controls constrain execution; they do not guarantee that an endpoint is free of side effects. Use an authorised environment and controlled records, with a job-level timeout for a process-wide limit.

The runtime depends on Python's standard library, the host and its TLS implementation. It is not a sandbox. Review contracts and protect the machine and CI job that execute them. An operator who can change the contract can change its intended target and assertions. Origin validation does not pin DNS resolution or verify ownership of the destination; use environment-level network controls where an IP boundary is required.

## Outcome semantics

| Outcome | Meaning |
| --- | --- |
| `pass` | Every configured assertion for the case passed. |
| `fail` | A response was evaluated and at least one configured assertion failed. |
| `error` | The request or evaluation could not complete reliably. |
| `inconclusive` | A prerequisite did not pass; this request was not sent. |

A failed positive control must not become a successful denial test. Dependencies make that distinction explicit. Errors and inconclusive results require investigation and are not evidence of a resolved vulnerability.

## Evidence contents

Reports exclude resolved environment credentials, raw response bodies, response headers, expected/observed assertion values and detailed network exceptions. The reports retain:

- Target URL and contract digest.
- Case IDs, identity names, methods and paths.
- Outcomes, HTTP statuses, timings and check results.
- Stable reasons and response hashes where available.

Treat those fields as operational metadata. A path or case name may still reveal sensitive information, and a response hash is not encryption. Keep secrets out of contract metadata and apply appropriate access and retention controls to artifacts.

HTML escapes untrusted report text and uses no JavaScript or external assets. Sanitized error reasons preserve diagnostic categories without copying remote responses or exception details into the evidence.

## Integrity and trust

Each sealed report hashes its case records and metadata in stable order. Its root is stored at `evidence.root_sha256` and printed as `Evidence anchor` after a run. `verify` checks internal consistency. `verify --anchor` additionally compares the report with a separately trusted root hash.

An internal hash chain alone does not detect someone rewriting both the report and its hashes. Retain the anchor outside the editable artifact bundle, for example in an independently controlled CI record. A hash saved beside the report in the same writable directory is not an independent trust anchor.

Successful verification establishes consistency with the checked hashes or anchor. It does not authenticate the operator, prove that requests actually occurred or establish the truth of a compromised runner's output. AuthzLedger does not issue digital signatures.

Verification also rejects contradictory declared prerequisites: duplicate or undefined references, dependency cycles, and assessed requests whose required controls did not pass. Blocked records must not claim an HTTP status, response digest or nonzero request duration. Records without a `requires` field remain compatible and declare no prerequisites. This is a consistency check on the report, not authentication of its author or proof of network execution.

Comparison verifies both reports and requires matching contract digests, schema versions, tool metadata, contract names and targets. The complete case-ID set must also match, including cases that did not run. Each case must retain the same identity, method, path, prerequisites and control type. Contradictory metadata is rejected even when the supplied contract digests match.

A prior `pass` becoming `fail` or `error` is a regression. A prior `fail` or `error` becoming `pass` is resolved. Transitions involving `inconclusive` remain separate and are never treated as resolved. The version 1 `added` and `removed` fields are reserved and remain empty; a changed case set requires a new baseline, not a same-contract comparison.

## Local demonstration

The demo binds a loopback fixture to an ephemeral port and uses synthetic identities and records. Its vulnerable and corrected stages share the same target and contract digest. Before/after results demonstrate the authorization assertions and retest workflow for that fixture only.

## Reporting a defect

Use the [security reporting policy](../SECURITY.md) for credential leakage, scope escapes, unsafe report rendering or evidence-verification defects. Ordinary feature requests belong in the issue tracker.


## Studio boundary

Studio is a loopback-only, single-operator workbench, not a production web service. The server requires an exact loopback Host, a same-origin header for POST, and a random session capability for every API route. Cross-site requests are rejected. The capability is printed in the local URL fragment, cleared from the address bar and retained in tab-scoped session storage. Assets contain no capability. Access logging is disabled, responses use no-store and no-referrer, and the live UI disallows inline scripts, third-party resources and framing.

The server limits request bodies to 4 MiB, connections to sixteen request handlers and one execution job at a time. It has no arbitrary file-read/write route. Imports do not fetch remote references. Plan tokens bind the exact normalized contract and mutation setting for ten minutes; authorization must also be confirmed before execution. These are operator-error and browser-origin controls, not a sandbox against local malware or a user who possesses the session capability.

Changing an untrusted contract can redirect its referenced environment credentials to another operator-approved origin. Review origins and credential mappings before execution. No server-generated plan proves ownership of the target. Use isolated test credentials and appropriate network boundaries.

The pre-release subscription catalogue is empty. Studio does not process payments, accept bank details, enforce user seats or provide multi-user isolation.
