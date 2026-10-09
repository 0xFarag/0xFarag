# AuthzLedger 1.0 — Release and adoption

**Authorization Intelligence, built on evidence.**

**Know who can do what. Prove what changed.**

The launch should make one engineering claim easy to inspect: a declared access boundary can be traced through policy evaluation, controlled application behavior, a change and a verifiable retest. The real product, its source and its evidence carry that claim.

This document defines acceptance gates and prepared release communication. It does not record that publication, remote CI, social posts or the proposed content schedule have occurred. Completed verification belongs in the release's [validation record](validation.md), with the exact commit and artifact hashes.

## Release scope

Version 1.0 builds on the 0.3.4 engine, explicit access matrix, positive-control dependencies, offline OpenAPI import, Studio, strict retests and redacted reports. Its release surface adds:

- A three-layer Living Authorization Graph with separately named intent, policy and observation inputs.
- Graph intelligence comparisons that keep drift, regressions, changed permissions and missing evidence distinguishable.
- Separate local policy rules and an explicit opt-in OPA decision adapter.
- Deterministic explanations and optional, grounded local Ollama advice that cannot alter verdicts.
- Bounded assurance runs and synchronous watch iterations, with verifiable local SQLite history.
- Dependency-complete selective retest plans and local execution jobs.
- Ed25519-signed evidence manifests, external-key verification and a standalone verification path.
- Studio and CLI access to the same core workflow.

The [product description](product-1.0.md) defines the behavior and trust boundaries. Hosted Retest-as-a-Service, billing, durable multi-user infrastructure and immutable storage are not part of this release.

## Immediate implementation order and acceptance

Each gate produces reviewable evidence before the next dependent step. Failures receive a concrete correction and a rerun of the affected checks. Independent tasks may proceed in parallel, but a release label does not substitute for acceptance.

| Priority | Work | Acceptance evidence |
| --- | --- | --- |
| 1 | Preserve the 0.3.4 baseline and freeze the 1.0 scope | Exact source commit, compatibility review and passing existing engine, contract, matrix, report and Studio checks. Preserve prior outcome semantics and execution limits. |
| 2 | Implement the graph and evaluator inputs | Tests show independent intent/evaluator/observation states, unknown propagation, report-to-contract binding, invalid inputs and explicit evaluator provenance. A real OPA response is accepted only through its configured boundary; failures do not become allows. |
| 3 | Implement differential intelligence and control orchestration | Known drift and regression fixtures are classified correctly. Identity rebinding or changed prerequisite definitions create `context_drift`, never a same-contract fix. Relaxed permission, removed coverage, failed control and unexpected HTTP error are distinguished from repaired enforcement or proven escalation. |
| 4 | Implement signed packages and independent verification | A package verifies with an externally trusted key. Graph attachments require their exact source contract and matching report; explanation attachments match the graph. Changed files, missing files, wrong keys, manifest manipulation and unsafe paths are rejected. Verify a package through the standalone path. Protect the private key and exclude it from release assets. |
| 5 | Implement history and bounded assurance | Recorded runs survive process restart; altered chain entries are detected. Iteration and aggregate request limits are enforced. Interrupted or incomplete runs cannot masquerade as completed assurance. Document the limits of local anchors and history truncation. |
| 6 | Implement selective retests and optional reasoning | Retests contain exactly the selected cases and their prerequisite closure, with stable ordering. Planning sends no requests. AI disabled, unavailable and malformed-advice cases preserve deterministic verdicts; advice references are checked. |
| 7 | Complete Studio and CLI acceptance | Actual browser checks exercise graph inspection, selected-case details, disagreement states, history, retests and export. Confirm keyboard navigation, narrow layout and absence of browser errors. Exercise corresponding CLI commands. |
| 8 | Build and verify distributable artifacts | Install the built wheel in a clean environment outside the checkout. Execute the synthetic demo, graph, assurance, retest, signing and independent verification. Check package metadata, version consistency, dependency requirements and artifact SHA-256 values. |
| 9 | Publish and verify the GitHub release | Tag the tested commit as `v1.0.0`; publish the final assets and release notes. Read the remote tag/release back, download the published assets and match their hashes. Record whether remote CI actually completed. |
| 10 | Publish approved channel content | Use the verified release permalink, tested demonstrations and final media. Verify each publication independently; retain the final URL. A prepared draft or queued upload is not a published post. |

No comparative benchmark, customer quote, independent certification or external penetration test may be inferred from authored local fixtures. Optional evaluator and AI integrations must state what was actually exercised. If a release surface is incomplete, repair it before presenting that surface as shipping functionality.

### Distribution checklist

The release should expose one clear entry point: [GitHub releases](https://github.com/0xFarag/0xFarag/releases). Attach the installable wheel, source distribution or source archive, SHA-256 list and measured validation record. Include a synthetic signed demonstration package and its standalone verification instructions if those assets pass their checks.

Any public demonstration signing key identifies only that demonstration. Its fingerprint must be published through a separately trusted record; recipients must not treat a key carried inside the same downloadable package as self-authenticating. Never publish the private key.

State the supported Python/runtime environment and the OpenSSL requirement for signing. Optional OPA and Ollama endpoints require deliberate configuration; the default experience should remain usable without them. Keep rights and permissions consistent with the existing [LICENSE](../LICENSE); source visibility is not an open-source or commercial-use grant.

## Prepared GitHub release copy

Use the following copy after the acceptance record and remote release are verified. Add the actual validation results and final asset links, without estimated test counts.

### Title

**AuthzLedger 1.0 — Authorization Intelligence, built on evidence**

### Release body

Know who can do what. Prove what changed.

AuthzLedger 1.0 connects intended permission, evaluated policy and observed application behavior in a Living Authorization Graph. The differences between those layers become reviewable evidence: policy disagreement, enforcement disagreement and authorization changes that require investigation.

The 0.3.4 foundation remains central: explicit contracts, access matrices, bounded HTTP execution, positive-control dependencies and strict retests. Version 1.0 adds separate local/OPA policy evaluation, graph intelligence comparisons, bounded continuous assurance, local run history, dependency-complete selective retests and Ed25519-signed evidence packages with independent verification.

Studio and CLI expose the same core workflow. Deterministic explanations are available by default; optional local AI advice supports review and never changes a verdict.

Start with the synthetic local demonstration. Inspect the contract and control trace, examine the graph, retest the selected boundary and verify the exported evidence against a trusted public key. Then adapt the workflow to an explicitly authorized environment.

This release is a local workbench. Evidence describes configured checks and observation windows; signatures establish package integrity against a supplied trusted key. Source access and use are governed by the repository's rights and permissions.

## Prepared LinkedIn launch copy

Publish once with the verified release permalink and a real product demonstration. Keep the author's existing profile and qualifications unchanged.

> Know who can do what. Prove what changed.
>
> I have released AuthzLedger 1.0, an authorization engineering workbench that connects three layers: intended permission, evaluated policy and observed behavior.
>
> A denial result is only useful when its test conditions hold. AuthzLedger runs explicit controls first, keeps blocked checks inconclusive and separates changed permissions from repaired enforcement.
>
> The workflow includes an inspectable authorization graph, policy/observation comparisons, selective retests, local assurance history and signed evidence packages that another engineer can verify independently.
>
> The demonstration follows one synthetic access boundary from contract to finding, fix and verified retest. Studio and CLI expose the same core operations.
>
> Release, source and validation: https://github.com/0xFarag/0xFarag/releases
>
> Built by 0xFarag, Switzerland.
>
> #ApplicationSecurity #Authorization #Pentesting

Replace the releases index with the verified `v1.0.0` permalink when available. Do not add performance figures before a reproducible measurement supports them.

## Prepared technical community copy

Adapt the introduction to the channel's rules. A community post should supply a reproducible technical example and invite engineering scrutiny; repeated identical promotion across forums weakens credibility.

> AuthzLedger 1.0 is a local workbench for versioned API authorization contracts. It reconciles intended access, a separate policy decision and controlled HTTP observations, then preserves the result for retesting and independent evidence verification.
>
> The interesting case is failed test conditions: if an actor's positive control fails, its dependent denial checks remain inconclusive. A relaxed contract or removed relationship is a policy change, not a remediation result.
>
> The synthetic example, implementation and validation are included in the release. I am looking for concrete feedback on boundary modelling, evaluator input mapping and retest evidence.
>
> https://github.com/0xFarag/0xFarag/releases

A longer engineering article should show the JSON contract, control DAG, graph relationship and before/after evidence for the same fixture. Explain what remains unknown. Link the reproducible materials before making a product claim.

## Release film: evidence carries the story

Produce one 55-second master and derive a vertical cut from the same tested workflow. Capture real Studio/CLI states using synthetic data. Never fabricate a result, animate a nonexistent feature or present a local fixture as a customer assessment.

| Time | Picture | Message |
| --- | --- | --- |
| 0–4 seconds | One access boundary on a quiet dark canvas | “Know who can do what.” |
| 4–12 seconds | The intended actor/resource relationship and its reviewed rule | “Every boundary starts with a contract.” |
| 12–23 seconds | Separate policy decision and actual graph disagreement | “Intent. Policy. Behavior.” |
| 23–34 seconds | Passing actor/resource controls, then the actual failed assertion | “The conclusion follows the controls.” |
| 34–44 seconds | Corrected fixture, dependency-complete retest and matching-contract comparison | “Prove what changed.” |
| 44–51 seconds | Signed package and successful independent verification with the trusted key | “Evidence another engineer can verify.” |
| 51–55 seconds | Product name, release version and final destination | “AuthzLedger — Authorization Intelligence, built on evidence.” |

Select a fixture whose actual graph and report support every sentence. If a control fails, show the inconclusive state. If a denial response leaks a field, show the relevant failed absence assertion rather than implying that all data became accessible.

Use restrained typography, one focal relationship and legible inspector detail. A roughly 62:38 division between the working canvas and explanation pane can guide the wide composition; mobile needs its own readable crop. Keep critical text inside platform-safe areas, provide accurate captions and verify the final frames against the source evidence. Sound and pacing may heighten attention; the product result remains untouched.

## Thirty-day adoption pipeline

The pipeline begins on the verified publication date. These are proposed execution windows, not scheduled automations or promises of background publishing.

| Window | Deliverable | Measure |
| --- | --- | --- |
| Days 1–3 | Verified release, one clear launch post and one reproducible demonstration | Successful independent installation and verification; broken-link or onboarding defects corrected. |
| Days 4–10 | Two technical examples: expired credentials and a real assertion-level denial failure | Readers can reproduce the behavior; record concrete issues and time to first reviewed graph. |
| Days 11–20 | Publish a measured retest comparison and invite a small number of authorized design-partner evaluations | Same declared scope and fixtures, documented manual baseline, retest elapsed time, false positives and inconclusive cases. No speedup claim without both measurements. |
| Days 21–30 | Resolve the highest-impact workflow defects and publish a concise learning report | Repeated use, independently checked packages, retest completion and specific improvements backed by issues or evidence. |

Use GitHub issues and discussions as the public feedback route. Keep private target data and credentials out of them. Do not send unsolicited direct messages as part of this plan. Design-partner participation, applicable usage permission and any permission to quote results must be explicit.

## Ninety-day establishment pipeline

| Window | Focus | Completion standard |
| --- | --- | --- |
| Days 31–45 | Reliability and scope precision | Fix prioritized real-world modelling and UX failures. Document evaluator support and unsupported cases. Preserve contract compatibility or publish a migration. |
| Days 46–60 | CI and team handoff | A reviewer can reproduce a retest and verify a package without the original operator. Publish a sanitized example with exact runner, contract and trust-key setup. |
| Days 61–75 | Comparative evidence | Run a declared authorization corpus against documented competitor workflows and record versions, settings, preparation effort, detection, noise and coverage limits. Make scripts and raw results inspectable. |
| Days 76–90 | Product direction | Choose the next investment using repeat use and observed customer constraints. Evaluate hosted delivery only if local job workflows show actual demand and its isolation, retention and licensing requirements are understood. |

Track activation, repeat use and reviewability: time to the first valid graph, control-gated checks completed, verified packages, successful retest handoffs and evaluator errors. Download and impression counts are secondary. Public customer figures or testimonials require an identifiable source and permission.

## Positioning discipline

The strongest competitive claim is specific: **a reviewable authorization change, supported by controlled observations and independently verifiable evidence.** The [official-source comparison](product-1.0.md#competitive-position) recognizes existing Burp, AuthMatrix, Autorize, ZAP and Tenable authorization functions.

Avoid universal scanner replacement, unsupported world-first claims, unmeasured time savings, implied independent certification and guaranteed virality. Expert adoption comes from a problem they recognize, a result they can reproduce and evidence they can challenge.
