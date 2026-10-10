# AuthzLedger 1.1.0.dev0 — development release review

**Controlled experiment → traceable finding → proven reproducer → targeted fix evidence.**

The integrated producer is **1.1.0.dev0**. Stable **1.1.0 publication is blocked**: 87 of 88 contract acceptance scenarios are verified; F01-01 remains partial. A genuine versioned Burp export, its provenance and a safely compatible Burp export/parser profile are still required. Native ZAP 2.17.0 with reports add-on 0.43.0 and a Playwright HAR capture are separately verified. Authored XML/JSON samples and a successful synthetic demo cannot replace those captures. DTD-bearing XML remains rejected.

The existing stable **v1.0.0 (`c0d4446`)** and its evidence remain unchanged. A patch label such as 1.1.5 would not resolve the missing acceptance evidence; after the gate closes, the correct target is 1.1.0.

## Integrated scope

| Capability | Delivered development workflow |
|---|---|
| F01 — request import | Offline Burp XML, ZAP JSON-plus and HAR parsing, source-bound redaction and explicit identity/object mapping. Genuine Burp exporter acceptance remains incomplete; native ZAP and Playwright HAR captures are verified. |
| F02 — controlled contrast | Explicit authorization predicates and principal, owner and denial controls; shared scope, deadline and request budget. Invalid controls remain inconclusive. |
| F03 — workflow assessment | Bounded transitions, replay and idempotency checks with fresh fixtures, independently observed state and explicit cleanup. |
| F04 — reproducer reduction | Selected removable units, a fresh proof for each accepted reduction and bounded final minimality checks. Original evidence is preserved. |
| F05 — selective retest | Dependency-complete selections and ComparisonEnvelope v1 bind the full baseline and current observations. Omitted cases remain `not_retested`. |
| F06 — Studio | Assessment workspace, Inspector, keyboard workflow, review-bound execution, job recovery and command palette use the same services as the CLI. |
| F07 — reports and proof | One assessment snapshot drives JSON, HTML and PDF. Signed report inventories bind source evidence and rendered files. |
| F08 — reasoned selection | Explicit dependency/impact models explain retest selections; unknown changes require full scope. Finite assurance shares the global budget. |

## Reproduce the three proofs

Follow [INSTALL.md](INSTALL.md) to install the development wheel and the pinned reporting extra. Then, from an empty working directory:

```sh
python -I -m authzledger assessment demo --out assessment-demo
python -I -m authzledger assessment verify assessment-demo/03-selective-retest-proof/snapshot.json
python -I -m authzledger verify-bundle assessment-demo/proof --public-key assessment-demo/trusted-public.pem
python -I /path/to/verify_bundle.py assessment-demo/proof --public-key assessment-demo/trusted-public.pem
```

The fixture is shut down before the command creates reports, signs the package or verifies it. The private signing key is temporary and removed. The generated public key is a **local demo trust anchor only**, not proof of publisher identity.

1. **Request → reproducer:** a synthetic imported request becomes a controlled confirmed finding; three selected irrelevant units are removed using twelve reduction requests. The claim is `1-minimal within approved units`.
2. **403 leakage versus controls:** a protected marker inside HTTP 403 is recorded as `denial_data_disclosure`; an invalid control yields `inconclusive`; HTTP 200 with only an error object is `rejected`.
3. **Selective retest and independent package:** five baseline cases become four current cases including prerequisites. One selected finding becomes `fix_verified`; the omitted finding stays `not_retested`. The baseline is preserved, and JSON/HTML/PDF are bound by the signed inventory.

A separate retained selective-retest proof under `evidence/1.1.0-release-review/selective100/` executes **100 baseline cases → ten current cases (seven selected plus three controls)**; 90 remain `not_retested`. Its total is **110 HTTP requests**, and both verifiers pass after fixture shutdown. Every request category is reported, including zero counts. This separate measurement is not the small five-case assessment demo.

The combined assessment demo uses **35 loopback HTTP requests**. These are reproducible fixture measurements, not production efficiency estimates. See the retained proof and installed-wheel receipt under `evidence/1.1.0-release-review/`; historical development receipts remain under `evidence/1.1.0-dev0/`.

## Verification boundaries

The standalone verifier checks signature, file inventory, hashes, JSON structure and report anchors. The installed main verifier additionally checks supported source-bound report, contract, finding, comparison, snapshot, workflow and renderer semantics. Authenticate the public key separately for a real handover. Neither verifier proves that a remote system behaved truthfully, identifies the operator by itself or supplies a trusted timestamp.

Default oracle evidence records evaluation attestations. Selected public captured inputs can be reevaluated, but their derivation from discarded raw response bodies cannot be independently reconstructed. Standards mappings describe scoped evidence, not global compliance. AuthzLedger is a local workbench; the demonstrations use synthetic labs. No market-superiority, external-security-review or performance guarantee is claimed.

## Distribution and rights

The review assets are the versioned source ZIP, wheel, public `proof.zip`, independent `verify_bundle.py` and `SHA256SUMS.txt`. The source ZIP contains this release record, acceptance ledger, installation instructions, reproducible lab commands and retained public proof. It excludes private keys, local histories and operator assessment directories. SHA-256 validates bytes against the supplied list; authenticate that list or its delivery channel independently.

Core execution has no third-party Python runtime dependency. PDF reporting uses `reportlab==4.4.9` and bundled DejaVu fonts with their licence notices. Signing needs OpenSSL with Ed25519 support. The measured environment and exact artifact hashes are recorded in the evidence receipts, rather than implied by this prose.

Copyright © 2026 **Nasser Aldin Farag / 0xFarag**. All rights legally held in the author's protectable contributions remain reserved. [LICENSE](LICENSE), [NOTICE.txt](NOTICE.txt) and third-party font licences remain in force. Publication does not grant a general commercial licence. Billing is disabled.

## Stable publication condition

Close F01-01 using genuine exports and a verified safe parser profile; freeze; set the producer to 1.1.0; repeat unit, six browser suites, check-tools, wheel isolation and both verifiers; require `tools/release_gate110.py` and CI to pass on the final commit; only then create the new immutable `v1.1.0` tag and release. The exact sequence is in [docs/release-1.1.0.md](docs/release-1.1.0.md). No stable 1.1.0 publication is represented by these development artifacts.
