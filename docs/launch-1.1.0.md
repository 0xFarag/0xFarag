# AuthzLedger 1.1.0 — release communication and publication handoff

Prepared 10 October 2026. Owner: Nasser Aldin Farag / 0xFarag.

**Publication status: these are prepared drafts. This document does not record a published 1.1.0 release, uploaded assets or social posts.** The observed producer is `1.1.0.dev0`. The retained acceptance record has 87 verified scenarios and one partially verified scenario, F01-01. Stable 1.0.0 remains the released reference until the production gates pass.

## One message across every channel

**Controlled experiment → traceable finding → evidenced reproducer → scoped fix verification.**

AuthzLedger is a local authorization assessment workbench for penetration testers and AppSec engineers. It connects an explicit rule, valid controls, a reviewed request budget and retained evidence through investigation, reduction, retesting and handover. Studio and CLI use the same services.

**Primary call to action:** Reproduce the lab. Inspect the evidence. Verify the package.

**Secondary call to action:** Share a reproducible issue with the tool version, supported export profile and a sanitised fixture. Keep credentials and client data out of public issues.

Use the current development documentation while F01-01 is open. Switch launch links to the exact stable release permalink only after publication and download verification. Do not use `/releases/latest` for evidence references: its destination can change.

| Destination | Status and intended use |
| --- | --- |
| https://github.com/0xFarag/0xFarag/tree/authzledger-v1.1.0 | Development branch; verify remote availability before sharing. |
| https://github.com/0xFarag/0xFarag/blob/authzledger-v1.1.0/docs/acceptance-1.1.0.md | Detailed acceptance ledger; branch content can change. Use the final commit permalink for frozen evidence. |
| https://github.com/0xFarag/0xFarag/releases/tag/v1.0.0 | Existing stable release reference. |
| https://github.com/0xFarag/0xFarag/releases/tag/v1.1.0 | Reserved stable launch destination; not asserted to exist by this document. |

## Readiness states and version decision

| State | Permitted description | Publication action |
| --- | --- | --- |
| **A — current development evidence** | `1.1.0.dev0`; F01–F08 integrated; 87/88 scenarios verified; F01-01 partly verified. Genuine Chromium/Playwright HAR and ZAP exports checked. Genuine compatible Burp XML remains missing. | Development update only. Keep the production gate closed. No stable release announcement or stable-download CTA. |
| **B — conditional stable release** | `1.1.0`, after all 88 scenarios are verified and the final version, source commit, distribution, CI and publication checks pass. | Publish the verified immutable release, then use the stable copy below. |

**Version decision:** `1.1.0` is the correct stable target for the integrated F01–F08 feature scope. `1.1.5` would imply a separately scoped fix release; it cannot resolve incomplete 1.1.0 acceptance. Transparent disclosure is necessary while F01-01 is open, but it does not make the binding full-scope contract pass.

F01-01 requires unmodified exports produced by installed, version-recorded Burp and ZAP tools, provenance and byte digests, plus import → mapping → controlled execution evidence. Genuine HAR and ZAP captures are now verified. The ZAP evidence uses ZAP 2.17.0 with reports add-on 0.43.0, an unchanged Traditional JSON-plus export, explicit mapping and four budgeted AuthzLedger requests. The remaining gap is a genuine, contract-compatible Burp XML export and its DTD-safe procedure. DTD-bearing Burp exports remain rejected. Do not strip a DTD, author a replacement XML file, relax entity protection or label a format fixture as a genuine exporter capture. A DTD-safe, contract-compliant export procedure must be demonstrated, or the stable release remains blocked.

## Claim register

These references support specific statements. Retained development receipts are historical evidence for that producer; they do not prove that a later edited commit or final distribution passed the same checks.

| Permitted claim | Repository evidence | Boundary that must travel with it |
| --- | --- | --- |
| All eight capability areas are integrated. | [Product contract](product-1.1.0.md), [acceptance ledger](acceptance-1.1.0.md). | Integration is distinct from full exporter acceptance. F01-01 remains partial in state A. |
| The recorded development verification passed 492 tests with zero failures, errors or skips. | [Unit receipt](../evidence/1.1.0-dev0/unit-tests.json), [verification record](verification-1.1.0.md). | Linux x86_64 / CPython 3.12.14; completed 2026-10-10T14:50:33Z. Do not reuse this count as the result of a future final run. |
| Six browser suites passed for the recorded development build. | [Verification record](verification-1.1.0.md), six browser receipts in `evidence/1.1.0-dev0/`. | Covers the named flows in the recorded Chromium environment; not full browser or accessibility certification. |
| The development wheel ran outside the checkout. | [Installed-wheel receipt](../evidence/1.1.0-dev0/installed-wheel.json). | Tied to its recorded wheel SHA-256 and `1.1.0.dev0`; not evidence for an unbuilt stable wheel. |
| The three assessment demos issued 35 real loopback requests. | [Assessment demo receipt](../evidence/1.1.0-dev0/assessment-demos.json). | Synthetic owned service; not an external customer assessment. Requests include the demo's controlled operations. |
| The demo removed three approved units using 12 reduction requests. | [Assessment demo receipt](../evidence/1.1.0-dev0/assessment-demos.json), [CLI guide](assessment-cli.md). | `1-minimal within approved units`; not global minimality or measured operator-time savings. |
| A 403 response with protected content can produce `denial_data_disclosure`; invalid controls produce `inconclusive`; a 200 error object can be `rejected`. | [Assessment demo receipt](../evidence/1.1.0-dev0/assessment-demos.json), `tests/test_experiments.py`. | Exact configured oracle and control bindings determine the outcome. A status code alone is insufficient. |
| Selective retesting preserves `fix_verified` and `not_retested` as different outcomes. | [Assessment demo receipt](../evidence/1.1.0-dev0/assessment-demos.json), [ComparisonEnvelope contract](comparison-envelope-v1.md). | The demo selects four cases from five including controls. A fix assertion is scoped to the bound rule and current valid evidence. |
| A genuine ZAP export is retained and used in a controlled AuthzLedger run. | [Original report](../fixtures/imports/zap-real.json), [ZAP provenance](../fixtures/imports/zap-real.provenance.json), [retained execution](../fixtures/imports/zap-real.execution.json). | ZAP 2.17.0 / reports 0.43.0; one capture request and four separately budgeted AuthzLedger requests. Native alert metadata does not confirm the authorization finding; the separate controlled run does. This closes only the ZAP component of F01-01. |
| A separate 100-case baseline was selectively retested as seven variants plus three fresh controls. | [Selective-100 receipt](../evidence/1.1.0-release-review/selective100/acceptance.json), `tools/check_selective100.py`. | 100 baseline requests + 10 retest requests = 110 real loopback requests; 90 cases remain `not_retested`. Seven query variants share one synthetic resource/identity/rule binding. This is distinct from the 35-request assessment demo, and establishes no general time saving. |
| Studio and CLI share services and one execution-budget model. | [Product contract](product-1.1.0.md), `tests/test_studio_assessments.py`, `tests/test_assessment_cli.py`, `tests/test_execution.py`. | Controls, setup, reads, reduction, replay, separately approved PDP calls and cleanup count. This is not an unbounded scanner. |
| JSON, HTML and PDF derive from one assessment snapshot. | [Reporting profile](reporting-profile-1.1.0.md), `tests/test_assessment_reports.py`, PDF QA receipts. | PDF requires the pinned reporting extra. Reviewer commentary is separate from computed findings. |
| A recipient can check a signed package without installing AuthzLedger. | [Standalone verifier](../tools/verify_bundle.py), [reporting profile](reporting-profile-1.1.0.md). | Requires Python and OpenSSL with Ed25519 support, and a separately trusted public key. The standalone check does not reconstruct new assessment semantics. |
| Imported data is parsed offline and reviewed before execution. | [Import boundaries](../fixtures/imports/README.md), `tests/test_imports.py`. | Supported profiles and limits apply; source URLs are not automatically contacted. Unknown or lossy mappings remain blockers. |
| Rights remain reserved to Nasser Aldin Farag / 0xFarag as stated in the existing notices. | [LICENSE](../LICENSE), [NOTICE](../NOTICE.txt), [rights guide](rights.md). | Source visibility does not grant a general software-use or commercial licence; third-party licences remain in force. |

### Verification depth: exact wording

| Check | What it establishes | What it does not establish |
| --- | --- | --- |
| SHA-256 download check | Downloaded bytes match the supplied checksum list. | Publisher identity or trustworthy origin when both file and checksum come from the same untrusted source. |
| Standalone package verifier | Trusted-key signature, inventory, file sizes/hashes and report anchors. | New assessment semantics, correctness of a signed narrative, or truthful remote execution. |
| Main package verifier | The preceding checks plus supported contract, finding, comparison, snapshot and trace reconstruction; exact report rendering where applicable. | Independent observation of the remote target, operator identity, trusted timestamps or universal standards compliance. |
| Oracle verification | `captured_inputs_replayed` re-evaluates approved retained oracle inputs. `evaluation_attested` records the producer's evaluation without those inputs. | Independent reconstruction of selected values from a discarded raw response. |

Use **“independently verifiable package integrity”** when discussing the standalone tool. Use **“retained assessment semantics are also checked by the main verifier”** for the additional level. Avoid the unqualified phrase “independently proven vulnerability.”

## A — current development update: ready to use after destination checks

### GitHub development note / PR summary

**Title:** AuthzLedger 1.1.0.dev0 — integrated assessment workflow and remaining exporter gate

AuthzLedger's 1.1 development build connects request import, controlled authorization experiments, workflow checks, bounded reduction, source-bound selective retesting and signed assessment handover in one local workbench. Studio and CLI share the same services and request budget.

The retained baseline development record reports 492 passing tests, six passing browser suites and a wheel checked outside the checkout. Subsequent runs after the genuine ZAP addition must be read from their own release-review receipts. The acceptance ledger verifies 87 of 88 scenarios.

F01-01 remains partially verified. Genuine Chromium/Playwright HAR and ZAP 2.17.0 exports are checked; Burp currently has an authored format fixture. A genuine Burp export and verified DTD-safe procedure are still required. DTD-bearing XML is rejected.

Three reproducible synthetic labs show request-to-reproducer, 403 disclosure versus invalid controls, and a selective retest that preserves omitted findings as `not_retested`. Signed packages support an independent integrity check; the main verifier also checks retained assessment semantics. Neither verifier independently observes remote execution.

Stable 1.0.0 remains the released version. This is a development evidence update, not a 1.1.0 production release.

Reproduce the lab. Inspect the evidence. Verify the package:
https://github.com/0xFarag/0xFarag/tree/authzledger-v1.1.0

### LinkedIn main update

AuthzLedger 1.1 is at its final acceptance gate.

The local workbench now connects a selected request to an explicit rule, valid controls, a retained finding, a smaller reproducer and a scoped fix assessment. Studio and CLI use the same services and request budget.

The important distinctions stay visible: a 403 response can still disclose protected content; failed controls leave a result inconclusive; a selective retest does not turn omitted findings into verified fixes.

The retained baseline verification passed 492 tests, six browser suites and an installation check outside the checkout. Genuine HAR and ZAP exports are now checked. Acceptance stands at 87/88 scenarios: a genuine Burp export and verified DTD-safe procedure remain open. The stable release remains 1.0.0.

The three demonstrations use real HTTP requests against synthetic local fixtures. Package signatures establish integrity; the main verifier additionally checks retained assessment semantics. Neither independently proves remote execution.

Reproduce the lab. Inspect the evidence. Verify the package:
https://github.com/0xFarag/0xFarag/tree/authzledger-v1.1.0

### LinkedIn short update

AuthzLedger 1.1.0.dev0 connects controlled authorization experiments, evidenced reproducers and selective fix verification in one local workbench.

87/88 acceptance scenarios are verified. Genuine HAR and ZAP exports are checked. A genuine Burp export with a verified DTD-safe procedure remains the release gate; stable 1.0.0 is unchanged.

Reproduce the synthetic labs and inspect the evidence:
https://github.com/0xFarag/0xFarag/tree/authzledger-v1.1.0

### X development update

```text
AuthzLedger 1.1.0.dev0: 87/88 scenarios verified. Genuine HAR and ZAP exports checked. The Burp export/DTD gate remains open. Stable stays 1.0.0. Inspect the local lab evidence: https://github.com/0xFarag/0xFarag/tree/authzledger-v1.1.0
```

### Website development wording

**Headline:** From a controlled request to a reviewable fix assessment.

**Body:** AuthzLedger is a local authorization workbench with shared Studio and CLI services. Explore the integrated 1.1 development workflow through reproducible synthetic labs, explicit controls, bounded requests and retained evidence.

**Status line:** 1.1.0.dev0 · 87/88 acceptance scenarios verified · genuine HAR/ZAP checked · Burp export/DTD gate open · stable version: 1.0.0.

**Primary button:** Inspect the development evidence.

**Secondary button:** View stable 1.0.0.

## B — stable 1.1.0 copy: conditional, unpublished

**Do not publish this section as release copy until state B is verified.** The paragraphs below are prepared for that state. Before activation, attach the exact final commit, complete acceptance record and CI run to the release record; replace any development-only measurements with final receipts. This document contains no assertion that those steps have happened.

### GitHub release title

**AuthzLedger 1.1.0 — Controlled findings, reproducible proof**

### GitHub release body

AuthzLedger 1.1.0 connects a selected request to a controlled authorization experiment, a traceable finding, an evidenced reproducer and scoped fix verification.

The local Studio workspace and CLI use the same services. Operators review the rule, identities, resources, controls and request budget before execution. Invalid controls leave observations inconclusive; omitted retest cases remain `not_retested`.

**Included in 1.1.0**

- **Import and mapping:** offline Burp HTTP-message XML, ZAP Traditional JSON with requests/responses, and HAR import through explicitly documented profiles. Consult the export-profile evidence for exact tool versions and the accepted DTD-safe procedure.
- **Contrast Lab:** explicit authorization rules and controlled identity, object, route and field variants. Protected data in a denial response is evaluated independently of the HTTP status.
- **Workflow Contracts:** isolated state transitions, replay and idempotency checks with independent state reads and budgeted cleanup.
- **Minimal Reproducer:** bounded reduction of approved units, fresh controls and retained proof for accepted candidates. Minimality is stated only within the approved units when verified.
- **Selective retests:** source-bound comparisons retain original evidence and distinguish scoped `fix_verified` outcomes from `not_retested` coverage.
- **Studio assessment workspace:** import, binding, plan review, investigation, reduction, retest and handover with a shared Inspector and command palette.
- **Reports and proof:** JSON, HTML and PDF from one assessment snapshot, with a signed inventory of the actual exported files.
- **Impact selection and assurance:** explainable dependency selection and finite workflow assurance under a shared request budget.

**Reproduce the evidence**

For an authorised source copy with the reporting extra installed:

```sh
python3 tools/check_assessment.py --out artifacts/assessment-proof
python3 tools/check_workflows110.py --out artifacts/workflow-proof
python3 tools/check_selective100.py --out artifacts/selective100-proof
```

Use new output directories. The assessment lab demonstrates:

1. An imported request becomes a confirmed finding and an evidenced, reduced reproducer.
2. A 403 response containing the protected marker is compared with invalid-control and safe 200 error-object counterexamples.
3. A selective retest verifies one scoped fix while an omitted finding stays `not_retested`; proof is rendered and verified after the fixture server stops.

A separate 100-case demonstration retains the full baseline and selects seven variants plus three fresh controls: ten retest requests, with 90 cases explicitly `not_retested`. The baseline and retest together issue 110 requests. This is a declared synthetic measurement, not a general efficiency claim.

These are real HTTP executions against synthetic local fixtures. They are not customer assessments or an independent product benchmark. The request-to-reproducer lab uses an explicitly authored Burp-format fixture; genuine exporter interoperability has its own acceptance evidence.

**Choose a download**

| Asset | Use |
| --- | --- |
| `authzledger-1.1.0-source.zip` | Source, tests, import profiles, lab scripts, documentation, rights notices and retained release evidence. Extract and follow `INSTALL.md`. |
| `authzledger-1.1.0-py3-none-any.whl` | Install the Python package in an isolated environment. PDF output additionally requires the pinned reporting extra. |
| `authzledger-1.1.0-proof.zip` | Inspect the generated three-demo evidence and separate 100-case selective-retest proof, including reports, receipts and demonstration public keys. Read the verifier and trust boundaries before review. |
| `verify_bundle.py` | Check evidence-package integrity without installing AuthzLedger, using Python, OpenSSL with Ed25519 support and a separately trusted public key. |
| `SHA256SUMS.txt` | Verify the downloaded assets byte-for-byte. Checksum verification alone does not authenticate a publisher. |

**Verification boundaries**

The standalone verifier checks trusted-key signatures, the file inventory, byte integrity and report anchors. The main verifier additionally reconstructs supported assessment semantics and verifies exact report rendering. Neither independently proves truthful remote execution, operator identity or a trusted timestamp.

Oracle inputs are independently re-evaluated only when explicitly retained as `captured_inputs_replayed`. Otherwise the record is `evaluation_attested`; the projection from discarded raw responses remains producer-attested. A scoped verified fix does not establish that an application is universally secure. Standards references are evidence-linked mappings, not compliance certification.

Python 3.10+ is required. The verified runtime and exact build dependencies are recorded with the release evidence. PDF uses ReportLab 4.4.9 and bundled licensed DejaVu fonts; signing uses OpenSSL with Ed25519 support. The core runner is local and uses the Python standard library. See `INSTALL.md`, `docs/assessment-cli.md`, `docs/acceptance-1.1.0.md` and `docs/verification-1.1.0.md` in the tagged source.

Reproduce the lab. Inspect the evidence. Verify the package.

Copyright © 2026 Nasser Aldin Farag (0xFarag). All rights reserved. Use and redistribution remain subject to `LICENSE`, `NOTICE.txt`, applicable law and any separately agreed permission. Third-party rights and licences are preserved.

### Asset presentation and download checks

Use the preceding table order in the release body: source → wheel → proof → standalone verifier → checksums. GitHub may sort the native asset list independently; do not promise a fixed native display order. Preserve exact filenames in all channel links.

The five assets above match the current `tools/package_release.py` distribution contract. The proof ZIP contains the three-demo outputs and the separate 100-case selective-retest outputs. Each demonstration public key is a local demo trust anchor, not independent publisher authentication. Do not list a 1.1 video unless it has actually been recorded, verified and uploaded. Lab scripts and retained receipts are also included in the source archive. Generated demo private keys must never become release assets.

Download the published source ZIP, wheel, proof ZIP, verifier and checksum file, then run `sha256sum --check SHA256SUMS.txt` in that download directory. Match the remote tag to the tested commit and retain a publication receipt. A successful local package command alone is not a publication result.

### LinkedIn main post

AuthzLedger 1.1.0 is available.

A useful authorization finding needs an explicit rule, valid controls and evidence another engineer can inspect. A fix assessment also needs to show exactly what was retested.

This release brings that workflow into one local workbench: import a request, review the experiment, investigate the finding, reduce the reproducer and run a source-bound selective retest. Studio and CLI share the same services and request budget.

Three reproducible labs make the distinctions concrete:

• A request becomes an evidenced reproducer while the original is retained.
• A 403 response containing protected data is distinguished from invalid controls and a safe 200 error object.
• A selected finding receives scoped fix verification; omitted findings remain not_retested.

JSON, HTML and PDF reports derive from the same snapshot. Signed packages support an independent integrity check; the main verifier also checks retained assessment semantics. Neither independently proves remote execution.

The demonstrations use synthetic local fixtures. Supported export profiles and verification limits are documented with the evidence.

Reproduce the lab. Inspect the evidence. Verify the package:
https://github.com/0xFarag/0xFarag/releases/tag/v1.1.0

### LinkedIn short post

AuthzLedger 1.1.0 is available: controlled authorization experiments, evidenced reproducers and source-bound selective retests in one local Studio and CLI workflow.

Invalid controls remain inconclusive. Omitted findings remain not_retested. Signed reports retain the evidence and the verification limits.

Reproduce the synthetic labs. Inspect the evidence. Verify the package:
https://github.com/0xFarag/0xFarag/releases/tag/v1.1.0

### X main post

```text
AuthzLedger 1.1.0: controlled authorization experiments, evidenced reproducers and scoped fix verification. Omitted findings stay not_retested. Reproduce the local labs. Inspect the evidence. https://github.com/0xFarag/0xFarag/releases/tag/v1.1.0
```

### X optional thread

Each block is one post. Publish the main post once; use these as replies, not a duplicate launch post.

```text
1/ A status code is not an authorization verdict. The lab compares protected content in a 403 response, invalid principal controls and a safe 200 error object. The configured oracle and valid controls determine the finding.
```

```text
2/ Reduction preserves the original evidence. Each accepted candidate must reproduce the same rule violation with fresh controls. “1-minimal” applies only within the explicitly approved removable units when that check passes.
```

```text
3/ Selective retests retain the baseline and its scope. A verified fix applies to the bound rule and current evidence. Omitted findings remain not_retested. Every request, including controls and cleanup, consumes the shared budget.
```

```text
4/ JSON, HTML and PDF share one snapshot. The standalone verifier checks signed package integrity against a separately trusted key. The main verifier also checks retained assessment semantics. Neither independently proves remote execution.
```

```text
5/ These are synthetic local labs with real HTTP requests. Export profiles, dependencies and evidence limits are documented. Reproduce the lab. Inspect the evidence. Verify the package. https://github.com/0xFarag/0xFarag/releases/tag/v1.1.0
```

### Website / landing copy

**Eyebrow:** AuthzLedger 1.1.0 · Local authorization workbench

**Headline:** From a controlled request to a reviewable fix assessment.

**Body:** Bind the rule, identities and controls. Review the budget. Retain the finding, reduce its reproducer and verify a scoped fix through the same Studio and CLI services. Export consistent reports and a signed evidence package for review.

**Primary button:** Reproduce the lab.

**Secondary button:** Inspect the release evidence.

**Evidence line:** Reproducible synthetic labs · Explicit request budgets · Original evidence retained · Omitted retests stay visible.

**Boundary line:** Local workbench. Supported export profiles only. The standalone verifier checks package integrity; the main verifier adds retained semantic checks. Neither independently proves remote execution.

**Rights line:** © 2026 Nasser Aldin Farag / 0xFarag. All rights reserved. See the release licence and notices.

Both buttons resolve through the verified 1.1.0 release and its tagged documentation. Do not point at an unverified hosted demo or imply that a multi-user cloud service exists.

## Video decision and visual treatment

**No matching 1.1.0 release video was found in `media/` when this document was prepared.** The existing files are explicitly labelled 1.0 and 0.3.4. YouTube and Short publication therefore remain out of the current launch copy. Do not relabel the 1.0 video, imply it demonstrates F01–F08, or invent timestamps, recording receipts or a published video URL.

A 1.1 recording is optional and must not delay a technically complete text release. If produced later, capture the three actual lab flows from the released build. Retain the source run receipts, exact frame-visible states, captions and video checksum before writing a matching description.

| Element | Direction |
| --- | --- |
| Brand | Keep the existing 0xFarag / AuthzLedger identity and Navy/Gold assets. `brand/hero.svg` is the existing source, not evidence of new features. |
| Palette | Existing brand references: navy `#071722`, gold `#C8A66B`, pale text `#EDF5F7`; Studio uses navy `#07131D`. Use gold sparingly for emphasis, not as a success status. |
| Main visual | Use a real Studio capture from the same verified build. Prefer the finding, its controls and the linked retest in a readable crop. |
| Proof visibility | Keep rule identity, control state, request count, source references and `not_retested` labels readable. Never retouch a result or remove a material limitation. |
| Labels | Show `1.1.0.dev0` and “Development build” for state A. Show `1.1.0` only for the verified release build. Label synthetic local fixtures in the image or adjoining caption. |
| Layout | One clear focal result with generous spacing; supporting evidence follows. Preserve the existing typography and logo. No invented badges, unrelated lock imagery, feature montages or decorative code. |
| Accessibility | Status text accompanies colour; maintain readable contrast, visible focus in walkthroughs and accurate captions. Platform crops must not hide controls or scope. |
| Claims | No market-superiority badge, independent-certification mark, customer result, performance speedup or “world first” statement without its own reproducible evidence. |

The two existing development screenshots, `evidence/1.1.0-dev0/studio-investigation.png` and `studio-handover.png`, may illustrate the labelled development state after visual and secret review. Their existence does not establish that final-release screenshots have been captured.

## Publication order for 10 October 2026

Dependencies determine the order. No elapsed-time estimate is substituted for a passing gate.

| Priority | Action | Required evidence before continuing |
| --- | --- | --- |
| 1 | Resolve or retain the F01-01 blocker. | Existing genuine HAR/ZAP evidence retained; genuine, unchanged, versioned Burp export and provenance; accepted DTD-safe procedure; import/mapping/controlled-run receipts. If unavailable, select state A and keep production publication closed. |
| 2 | Freeze the complete candidate at the correct producer version. | All 88 ledger rows verified; package/runtime version `1.1.0`; original stable tag, roots and historical evidence unchanged; reviewed source commit. |
| 3 | Execute the final technical verification. | Complete unit/adversarial suite with required extras and no unexplained skips; six browser suites; release, comparison, assessment and workflow check tools; report rendering review. Receipts identify the exact candidate. |
| 4 | Build and validate the distribution outside the checkout. | Installed wheel runs the required demonstrations, reports and both verification paths; source and wheel inventory reviewed; version and hashes recorded; no credentials, private keys or client data. |
| 5 | Run the release gate; push the reviewed branch; require CI. | `tools/release_gate110.py` passes and `verify` / `browser` pass on the same final commit. Reconcile release notes, CHANGELOG, INSTALL and release metadata with that result. |
| 6 | Publish once through the gated release workflow. | `v1.1.0` targets the tested commit. No existing tag or asset is replaced. Release body and the five intended assets exist. |
| 7 | Read back and download the public release. | Remote release is neither draft nor prerelease; tag SHA matches; downloaded hashes match; release and documentation links resolve. Record the URL and receipts. |
| 8 | Apply matching landing wording, then publish the main LinkedIn post and X post. | Each destination uses the same verified release URL and state B copy. Read back actual posts and retain their URLs. A prepared draft is not a sent post. Use state A only if communicating the incomplete development status. |
| 9 | Publish optional thread or later video only when useful and verified. | Thread adds evidence detail. Any video has a matching 1.1 capture and its own receipt; otherwise omit YouTube/Short. |

This launch package prepares coherent copy; it does not certify account access, record permissions granted to another operator, or assert completion of any external action. The technical release record and returned publication URLs remain the authoritative completion evidence.
