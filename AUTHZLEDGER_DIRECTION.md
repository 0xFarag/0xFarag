# AuthzLedger direction

**Authorization Intelligence, built on evidence.**  
Know who can do what. Prove what changed.

## Available today

[v0.3.4](https://github.com/0xFarag/0xFarag/releases/tag/v0.3.4) is a source-visible local pre-release. It includes an access-matrix compiler, positive-control dependencies, contract and trace manifests, same-contract retest comparisons, a CLI, local Studio and a synthetic fault corpus. Current evidence uses hashes, not digital signatures. The existing rights notice applies; source visibility is not an open-source licence.

## The product question

Who may access which resource under which conditions, and which controlled observation supports that conclusion?

The first use case is recurring tenant and role regression testing in B2B SaaS. Intended access, a connected policy engine's decision and the application's actual behavior will remain separate records. A successful request must never silently become the intended permission.

## Acceptance gates for 1.0

| Priority | Capability | Evidence required before release |
| --- | --- | --- |
| P0 | Control and verifier correctness | Failed, missing or cyclic prerequisites cannot validate a dependent result; malformed evidence fails cleanly. |
| P0 | Stable contracts and migrations | Existing fixtures retain their semantics; unknown permissions remain unknown; policy edits are never reported as fixes. |
| P0 | Safe controlled execution | Target scope, budgets, credentials and mutation behavior remain explicit; failure-path tests and threat model are reviewed. |
| P1 | Portable signed evidence | Independent offline verification rejects tampering and untrusted keys; legacy integrity and authenticated provenance are distinct. |
| P1 | Three-layer authorization model | Intent, one supported policy-decision adapter and observed behavior retain source, context and version. Unsupported semantics stay unknown. |
| P1 | Durable history and differential analysis | Run provenance and immutable baselines explain access changes; a changed contract does not establish remediation. |
| P1 | Studio and CLI workflow | Import, review, plan, run, explain, retest and verify operate on the same model; supported platforms and accessibility are documented. |

Version 1.0 will be released when its technical acceptance gates pass. Pilot adoption and commercial validation are tracked separately. No release date, market-first claim or enterprise capability is implied by this roadmap.

## What follows

Control freshness, change-aware retesting and reusable adapters precede hosted team features. Continuous assurance requires authorised runners, revocable scope, bounded execution and explicit handling of stale or incomplete evidence. AI assistance may explain evidence and suggest tests; it does not decide whether access is authorised or whether a finding is valid.

## How progress will be demonstrated

Reproducible fixtures, regression tests, documented limitations and reviewable changes. Synthetic benchmarks will remain clearly distinguished from independent evaluations and customer results.

For technical collaboration or employment conversations: [Nasser Aldin Farag on LinkedIn](https://www.linkedin.com/in/nasser-aldin-farag-974697412/).
