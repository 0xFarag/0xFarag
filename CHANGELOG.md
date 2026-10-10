# AuthzLedger changelog

## 1.1.0.dev0 — unreleased integration, 2026-10-10

Release review: top-level release metadata, notes and installation instructions now identify the actual development producer. The public review distribution includes the three synthetic assessment demonstrations and their signed proof, with separate main/standalone verification instructions. Native ZAP and Playwright HAR captures are verified; F01-01 remains partial for genuine Burp and its DTD-safe profile; `release_gate110.py` intentionally prevents stable publication. This is not a 1.1.5 fix release. Historical 1.0.0 tags and evidence are preserved.

The local assessment workflow now joins offline request import and mapping, controlled authorization experiments, isolated workflow contracts, bounded reproducer reduction, source-bound selective retests, a keyboard-driven Studio Inspector, consistent assessment reports and signed report inventories. CLI and Studio share the existing HTTP engine, request budget, credential resolver and evaluation services. Finite workflow assurance adds a separate immutable history chain and cross-cycle fixture checks.

ComparisonEnvelope v1 remains the comparison foundation; existing v1 reports, evidence roots, packages and history rows remain unchanged. The eight capability areas and all 88 acceptance scenarios are tracked in `docs/acceptance-1.1.0.md`. Production 1.1.0 publication remains blocked by incomplete genuine Burp exporter acceptance and its safe DTD profile; authored fixtures do not satisfy that gate. See `docs/product-1.1.0.md` and `docs/release-1.1.0.md` for the implemented scope and exact release conditions.

## 1.0.0 — 2026-10-09

Three-layer authorization graphs, independent policy evaluation, differential drift and source-aware retests, durable history, finite assurance, advisory local reasoning, Ed25519 evidence packages and Studio/CLI workflows. Existing v0.3.4 engine and foundation verifier hardening retained. See the release notes at tag `v1.0.0` and `docs/product-1.0.md` for exact scope and limits.

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
