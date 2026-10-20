# AuthzLedger 1.5 launch drafts and film plan

**Prepared drafts. Not published. No release film has been produced by this document.** Activate publication only after the full 1.5 release gates pass, the stable release resolves to the verified commit and the downloads pass checksum verification. While publication gates remain open, identify demonstrations as pre-publication builds.

The public message is: **From permitted scope to reproducible evidence.**

Use the established 0xFarag identity and its existing N logo, with navy, blue and restrained gold accents. Use the same original logo asset across formats. Keep technical screens readable and avoid decorative terminal output, invented alerts or fabricated benchmarks.

## Claim discipline

- Publish only capabilities exercised by the release evidence; describe their supported domains and limits.
- Keep findings, hints, failed prerequisites and `not_retested` visible. Do not remove them to make a demo look cleaner.
- Use exact test totals or measured durations only from the final immutable receipts, with the relevant runtime and scope.
- Do not claim that Nessus, Qualys, Rapid7 or Greenbone have no validation, evidence, quality indicators or retests. No comparative product benchmark is supplied by the local demos.
- Do not call the repository open source unless its actual licence meets that description. Refer to the licence and notices for permitted use.
- Release links below are intended destinations, not verified live URLs. Confirm them before publication.

Intended release URL: `https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0`.

## GitHub release draft

**Title:** AuthzLedger 1.5 — Controlled assessments. Reproducible evidence.

AuthzLedger 1.5 connects permitted scope, discovery and controlled checks in one local assessment suite for expert pentesters and AppSec teams.

Start with captured traffic or explicitly reviewed discovery targets. Inspect the known surface and the prerequisites for each check. Run a bounded plan through the shared execution context, investigate the controls and observations, then retest the original claim after a change.

The release extends the existing authorization and workflow foundation with persistent assessments, a versioned check registry, scoped service and HTTP discovery, selected offline Nmap/Nuclei result adapters, static approved playbooks and a unified evidence handover. Selected retests preserve their source binding. Omitted cases remain `not_retested`.

JSON, HTML and PDF are generated from a frozen snapshot. An Ed25519-signed inventory binds the delivered files. The independent verifier checks integrity against a separately trusted public key; the main verifier also checks supported retained semantics.

Three reproducible loopback demos cover authorization evidence, discovery-to-check, and a selective fix proof. The last demonstration changes one byte in a copied package and shows verification failing.

Read the exact supported profiles, test receipts and trust boundaries in the release record. These demos establish specific synthetic behavior; they are not a comparative scanner benchmark.

## LinkedIn draft

A security finding is useful when another engineer can understand the conditions, reproduce the observation and verify the fix.

AuthzLedger 1.5 brings that workflow into one local assessment workspace:

• Persistent local assessments, explicit scope and bounded discovery.
• Versioned checks with visible prerequisites and controls.
• Evidence tied to the source request and the tested context.
• Selective retests that preserve `not_retested` for everything omitted.
• JSON, HTML and PDF bound into an Ed25519-signed handover.

It builds on AuthzLedger's authorization and workflow contracts. Selected offline adapters connect specialist-tool results to that workflow. Static reviewed playbooks compose supported checks without dynamic attack chaining. The purpose is to make the path from observation to defensible conclusion easier to follow, and easier to review.

The release includes reproducible local demonstrations and their verification receipts. Supported detection profiles and their limits are documented alongside the code.

AuthzLedger 1.5:
https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0

## X draft

AuthzLedger 1.5 connects scoped discovery, control-bound checks and source-bound retests. Omitted cases stay not_retested. The handover is signed and independently verifiable.

https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0

## YouTube draft

**Title:** AuthzLedger 1.5 — From Discovery to a Verifiable Fix

**Description:**

An end-to-end demonstration of AuthzLedger's local assessment workflow: permitted scope, controlled discovery, evidence-bound checks, selective retesting and signed handover.

The recording uses owned disposable loopback fixtures. You will see an authorization finding, a deliberately missing configured response header, a selected fix with another case still `not_retested`, and a failed verification after one package byte is changed.

These examples demonstrate the supported contracts and evidence boundaries. They do not establish whole-application security or general scanner superiority.

Release, installation and reproducible evidence:
https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0

## Reddit draft

**Title:** AuthzLedger 1.5: local assessment workflows with controls, scoped retests and signed evidence

I am building AuthzLedger around the gap between an observed signal and a reviewable security conclusion.

The local workbench connects imported traffic and scoped discovery to versioned checks. A check carries its prerequisites, controls, observation references and evidence limits. The existing authorization and workflow contracts remain the foundation; discovery does not grant permission to test a new target.

The release includes persistent assessments, explicit service/HTTP discovery, selected offline scanner-result adapters, static approved playbooks and a unified handover. It does not launch Nmap/Nuclei or load arbitrary executable plugins. Source-bound retests preserve the original evidence and leave omitted cases as `not_retested`. JSON, HTML and PDF share a frozen snapshot and are bound by a signed inventory.

The public loopback demos include a failed-control case, a 403 response containing protected fixture data, and a one-byte package tamper rejected by both verification paths. The standalone verifier establishes integrity; it does not independently observe the tested application.

I would welcome technical feedback on control validity, retest comparability and evidence portability. The native check families are deliberately narrow: the arithmetic check is not general SQLi/RCE, and CORS reflection remains a hint. The supported profiles, reproducible examples and licence are documented in the release:
https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0

Before submitting, check the destination community's current rules and whether a technical article or code link is the required format. This draft does not authorise posting to a particular community.

## Release film concept

**Format:** 75–90 seconds, 16:9 master with a separately composed 9:16 cut. English narration. Product screens remain readable; pauses are retained around status changes. All product evidence comes from an actual run of the verified build. An optional avatar may introduce or close the film, but must not replace the real product recording.

| Time | Real capture | Narration | Evidence to retain |
|---|---|---|---|
| 0–8 s | Existing brand mark, then a real authorization finding with its control panel visible | “A finding needs more than a result. It needs a test you can explain.” | Build identifier and the actual selected finding |
| 8–20 s | Scope review: loopback targets, allowed operations, expiry and request budget; open a retained traffic source | “Start with permitted scope and captured traffic. Keep the conditions explicit.” | Scope digest, source reference and reviewed plan |
| 20–34 s | Actual bounded discovery; select the observed endpoint and the chosen supported profile | “Discover the approved surface. Select a check and inspect what it requires.” | Discovery receipt, attempted operations and excluded links |
| 34–48 s | Run the check; show positive control, target observation and the narrow finding claim | “Controls establish whether the observation can support the conclusion.” | Control result, observation reference and evidence level |
| 48–63 s | Select one baseline finding, execute its retest, show `fix_verified` next to `not_retested` | “After a change, retest the original claim. Keep everything you did not retest visible.” | Original and current source anchors, retained comparison |
| 63–78 s | Export the actual frozen package; run isolated verifier; change one byte in a copy and show rejection | “Deliver evidence that can be checked. A changed byte must not pass.” | Original package hash, tampered package hash, verifier exit codes |
| 78–90 s | Return to the same assessment and close on the existing 0xFarag branding | “AuthzLedger. Controlled assessments. Reproducible evidence.” | Verified release destination, once publication gates pass |

### Capture procedure

1. Use the final verified build and a new output directory. Record the exact source commit, wheel hash, runtime and fixture command.
2. Run `python3 tools/check_platform150.py --out artifacts/film-proof` and retain the real receipt. For an installed wheel, pass the separately copied verifier explicitly.
3. Record the Studio workflow with the same owned fixtures. Do not animate a mock interface and present it as execution evidence. If a view cannot perform the claimed step, fix the product path or narrow the film claim.
4. Keep tokens, session URLs, private keys and unrelated personal data out of the capture. Use synthetic identities and fixture data only.
5. Edits may remove idle time, add captions and highlight existing controls. They may not invent requests, change counters, replace a failed verdict with success or hide `not_retested`.
6. Create the vertical version from separate readable crops. Avoid shrinking the entire desktop into an unreadable strip.
7. Verify the exported film against the retained run: every visible result, count and claim must have a matching source artifact. Publish only after the stable release gates pass.

**Current deliverable:** screenplay, capture plan and channel copy. The [suite contract](suite-1.5.0.md) and its actual acceptance receipts govern every claim. Video capture, voice production, rendering and publication require their own completed artifacts and checks; none is asserted here.

Copyright © 2026 Nasser Aldin Farag (0xFarag). All rights reserved, subject to the repository's existing licence and notices.
