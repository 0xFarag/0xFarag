# AuthzLedger 1.5 — development candidate

**An integrated local assessment suite: permitted scope → discovery → controlled checks → reproducible evidence → selective retest → signed handover.**

This candidate builds directly on the 1.1.0 authorization and workflow foundation. It is not a declaration of stable publication, a complete final CI run or a live release asset. The whole A/B/C work package belongs to one 1.5 release. See the [suite implementation map and S15 acceptance gates](docs/suite-1.5.0.md) and [release record](docs/release-1.5.0.md).

## Candidate changes

- Persistent local assessment workspaces with engagement/RoE references, revision checks, verified evidence chains and interrupted-job records. Studio now defaults to `~/.authzledger/history.sqlite3`; `--history` selects another file and `--session-only` makes ephemeral use explicit. Credentials remain runtime-only and interrupted work is not automatically replayed.
- Scope policies bind origin, method, path, purpose and effect with explicit network boundaries, expiry and limits. Validated destinations are pinned; ambient proxies and automatic redirects remain disabled.
- Provenance-bound surface catalogs from supported traffic/OpenAPI data, bounded HTTP discovery and explicit TCP service probes. Selected Nmap XML and Nuclei JSONL imports retain safe source hints; they do not execute external scanners.
- A curated versioned check registry wraps existing Contrast/Workflow contracts and adds selected configuration, information and arithmetic-template predicates. Controls, evidence ceilings and limitations remain visible. Static approved playbooks compose sealed plans under one shared budget and stop after inconclusive prerequisites.
- Source-bound check retests preserve legacy Contrast semantics, including `fix_verified` and `not_retested`. Offline surface deltas remain distinct from retests. Local finite schedules require an explicit running invocation; no daemon is installed.
- A small offline reviewed CVE knowledge pack records source/version prerequisites and produces candidates only. No broad vulnerability feed or universal version interpretation is claimed.
- Frozen platform snapshots retain typed sources, nested controls, findings, comparisons and review decisions. JSON/HTML/PDF and Ed25519 packages share the same evidence inventory; the independent verifier remains a separate asset.
- CLI and Studio expose the same main assessment path. Three actual loopback demos cover authorization/reduction, discovery-to-check and selective fix proof with one-byte tamper rejection.

## Reproduce the candidate

Follow [INSTALL.md](INSTALL.md). From an installed wheel outside the checkout:

```sh
python -I -m authzledger assessment demo150 --out platform150-demo \
  --standalone-verifier /absolute/independent/verify_bundle.py
python -I -m authzledger studio --history ./engagement.sqlite3 --open
```

PDF requires `reportlab==4.4.9`; signing requires OpenSSL with Ed25519 support. Use a new demo output path. Actual counts, timings and versions belong to its receipts; no final 1.5 test total is asserted here. All fixtures stop before the evidence is exported and signed. The demo key is a local consistency anchor, not proof of publisher identity.

## Scope and release boundaries

The arithmetic check confirms only its two curated expression predicates. CORS header reflection and information signatures remain hints; a required-header omission confirms only the configured omission. Native network support is bounded connection/banner observation, not an exhaustive host vulnerability scanner. Arbitrary plugins, dynamic attack chains, C2, credential attacks, Internet-wide scanning, distributed agents, hosted multi-tenancy and enterprise RBAC are outside this local candidate.

Existing scanners already provide evidence, quality models and retests. AuthzLedger's proposed advantage is traceable contract/control/oracle/source continuity in selected domains; no competitor benchmark or whole-market replacement is claimed. Standards mappings are partial, and signatures bind exact bytes rather than truth of execution.

Final stability requires complete regression, browser gates, actual A/B/C receipts, installed-wheel verification, historical compatibility and exact-version publication checks. Film/channel material is prepared as [unpublished drafts](docs/launch-1.5.0.md). Historical release notes below remain unchanged.

---

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
