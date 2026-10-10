# AuthzLedger 1.1.0 — stable release candidate

**Controlled experiment → traceable finding → bounded reproducer → targeted fix evidence.**

This candidate completes the integrated F01–F08 workflow and adds a verified native Burp message-import path. Final publication requires the frozen-source tests, isolated wheel verification and exact-commit CI gates in the [release runbook](docs/release-runbook-1.1.0.md). These notes do not assert that the `v1.1.0` tag or download assets are already live. The stable **v1.0.0 (`c0d4446`)** tag and historical evidence remain unchanged.

## Integrated scope

| Capability | Delivered workflow |
|---|---|
| F01 — request import | Offline Burp raw request/response, DTD-free Burp XML, ZAP JSON-plus and HAR parsing. Redaction, unresolved fields and identity/object mapping remain explicit. Native Burp 2026.9.2, ZAP 2.17.0 / reports 0.43.0 and Playwright/Chromium HAR evidence is retained. |
| F02 — controlled contrast | Explicit variants, methods, headers, bodies, typed markers, optional tenant binding and principal/owner/denial controls. Scope, deadlines and request budget are shared. Invalid controls remain inconclusive. |
| F03 — workflow assessment | Graphical step identities, headers and bodies; state and effect-count oracles; isolated transitions, replay, idempotency and cleanup. Advanced versioned specifications remain available. |
| F04 — reproducer reduction | Approved removable units, fresh controls for each accepted reduction and bounded final minimality checks. A multi-variant source first produces a separately executed single-variant baseline; the original is preserved. Confirmed workflow reduction is also available in Studio. |
| F05 — selective retest | Multiple selected variants with prerequisite closure. ComparisonEnvelope v1 binds the full baseline and current observations; omitted cases remain `not_retested`. |
| F06 — Studio | Consistent Navy/Blue and Gold interface, Inspector, keyboard controls, command palette, execution selector and job recovery. Source, plan and budget changes invalidate stale execution review. |
| F07 — reports and proof | One frozen snapshot drives JSON, HTML and PDF. Changed report details or new evidence require refreezing. Ed25519 packages bind file inventories; Studio displays the public-key fingerprint. |
| F08 — reasoned selection | Explicit dependency/impact models explain retest selections. Unknown changes require full scope; finite assurance shares the global request budget. |

## Native Burp acceptance and parser hardening

The [F01 addendum](docs/burp-native-import-v1.md) adds `burp-http-pair-v1`: unchanged complete Raw messages saved natively from Burp Community 2026.9.2, with explicit source-origin metadata. The observed menu label is **Save selected text to file**, used with no selection. This is separate from native **Save item** XML.

The retained public capture contains one native request followed by four independent controlled requests. Original file hashes, native UI receipts, source projection and the confirmed controlled execution are checked by `tools/check_native_burp.py`. Its native Save item XML contains a DTD and is retained as a **negative** fixture: it must return `xml_declarations_forbidden`. DTD/entity rejection is unchanged; no XML is stripped or rewritten. The original acceptance records remain historical records.

Import hardening also preserves malformed vertical-tab/form-feed header bytes as blockers instead of trimming them, and prevents ZAP header normalization from discarding malformed trailing content. Raw Studio uploads preserve binary bytes through bounded base64 transport. An imported response or scanner assertion remains unverified until a fresh controlled execution establishes a finding.

## Reproduce the three proofs

Follow [INSTALL.md](INSTALL.md) to install the wheel and pinned reporting extra. From an empty working directory:

```sh
python -I -m authzledger assessment demo --out assessment-demo
python -I -m authzledger assessment verify assessment-demo/03-selective-retest-proof/snapshot.json
python -I -m authzledger verify-bundle assessment-demo/proof --public-key assessment-demo/trusted-public.pem
python -I /path/to/verify_bundle.py assessment-demo/proof --public-key assessment-demo/trusted-public.pem
```

The fixture is shut down before report creation, signing or verification. The temporary private signing key is removed. Its public key is a **local demo trust anchor**, not independently authenticated publisher identity.

1. **Request → reproducer:** the authored import becomes a controlled confirmed finding; three approved irrelevant units are removed using twelve reduction requests. The claim is `1-minimal within approved units`.
2. **403 leakage versus controls:** protected content inside HTTP 403 yields `denial_data_disclosure`; an invalid control yields `inconclusive`; HTTP 200 containing only an error object is `rejected`.
3. **Selective retest:** five baseline cases become four current cases including prerequisites. One selected finding becomes `fix_verified`; the omitted finding remains `not_retested`. JSON/HTML/PDF bind the preserved baseline and current evidence.

The combined assessment demo uses **35 loopback HTTP requests**. The separate `tools/check_selective100.py` fixture executes **100 baseline cases → ten current cases (seven selected plus three controls)**, for 110 requests total; 90 omitted cases remain `not_retested`. These are fixture measurements, not production efficiency estimates or a comparison against commercial scanners. The authored assessment XML is separate from the genuine native exporter evidence.

## Verification boundaries

The standalone verifier checks signature, file inventory, hashes, JSON structure and report anchors. The installed verifier additionally checks supported source-bound report, contract, finding, comparison, snapshot, workflow and renderer semantics. Authenticate the public key separately for a real handover. Neither verifier proves that a remote system was honestly observed, identifies the operator by itself or supplies a trusted timestamp.

Default oracle evidence records evaluation attestations. Selected public captured inputs can be reevaluated, but their derivation from discarded raw response bodies cannot be independently reconstructed. Standards mappings describe scoped evidence, not global compliance. Import, report generation and verification are local; active assessments contact only the explicitly authorized target. No universal scanner replacement, external security review or performance guarantee is claimed.

## Distribution and rights

The intended release assets are `authzledger-1.1.0-source.zip`, `authzledger-1.1.0-py3-none-any.whl`, `authzledger-1.1.0-proof.zip`, `verify_bundle.py` and `SHA256SUMS.txt`. A published release must identify the exact reviewed commit and matching checksums. The source and proof archives include reproducible public labs and notices; private keys, operator histories and local assessment directories are excluded. Authenticate the checksum list or its delivery channel independently.

Core execution has no third-party Python runtime dependency. PDF reporting uses `reportlab==4.4.9` and bundled DejaVu 2.37 fonts with their separate licence notices. Signing requires OpenSSL with Ed25519 support. Final test counts, environment and byte digests belong to the release receipts; historical development receipts retain their original versions and counts.

Copyright © 2026 **Nasser Aldin Farag / 0xFarag**. All rights legally held in the author's protectable contributions remain reserved. [LICENSE](LICENSE), [NOTICE.txt](NOTICE.txt) and third-party font licences remain in force. Publication does not grant a general commercial licence. Billing is disabled.
