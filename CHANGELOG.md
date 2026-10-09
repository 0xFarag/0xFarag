# AuthzLedger changelog

## 1.0.0 — 2026-10-09

Three-layer authorization graphs, independent policy evaluation, differential drift and source-aware retests, durable history, finite assurance, advisory local reasoning, Ed25519 evidence packages and Studio/CLI workflows. Existing v0.3.4 engine and foundation verifier hardening retained. See RELEASE_NOTES.md and docs/product-1.0.md for exact scope and limits.

# Release notes

## 0.3.4 — 9 October 2026

First GitHub distribution candidate, based on the private 0.3.3 core.

- Documented source startup, isolated wheel installation, local demo and evidence verification.
- Added the missing contribution guide and repository verification workflow.
- Made the optional browser acceptance script portable.
- Replaced internal subscription-price proposals with an empty pre-release catalogue. Billing remains disabled.
- Updated the version and Studio footer for the pre-release.
- Preserved the original brand mark and existing rights notices.

The authorization engine, contracts, control semantics and evidence algorithms are unchanged from 0.3.3. See [validation](docs/validation.md) for actual checks and remaining limits.

## 0.3.3 — 8 October 2026, private revision

Fixed keyboard focus after permission-matrix activation. The selected rule editor receives focus and its heading announces the relationship. Earlier private revisions introduced the local Studio, policy matrix, offline OpenAPI import, control-aware execution and same-contract retest comparison.
