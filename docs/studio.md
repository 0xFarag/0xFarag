# Studio — local authorization workbench

Start `python -m authzledger studio --open`, or omit `--open` and copy the complete URL printed by the CLI. Studio binds only `127.0.0.1`; port zero selects an available port. `--port 8766` selects a fixed local port. It is a development workbench, not an Internet-facing service.

## First result

v0.3 opens in **Access matrix**. Choose **Run eight-scenario lab** to inspect 24 checks across ownership, tenant, role and invalid-fixture scenarios. The matrix compiler and migration workflow are documented in [matrix.md](matrix.md).

## Original six-case demonstration

Choose **Run local demonstration**. Studio starts the actual synthetic loopback fixture, tests its vulnerable implementation and its corrected implementation, then shows six configured checks and two resolved failures. The baseline and current reports are available through the Evidence view. No real customer target is used.

## Your API

1. Set credential environment variables in the shell that will start Studio. Supply complete header values, including `Bearer ` where the API requires it. The browser receives variable names and presence indicators, never resolved credential values.
2. Import your OpenAPI JSON description in **API import**, or load an existing contract in **Workspace**.
3. Supply the exact target origin and any explicit API base path. Define named test identities using environment references. Add positive controls and denial cases with explicit resource identifiers, expected statuses and response assertions.
4. Build the contract. Inspect the normalized JSON and choose **Preview execution plan**. The preview lists the exact target, requests, identities, prerequisite checks and credential readiness.
5. Confirm that you are authorized to test the displayed target. Executing configured mutating methods requires the separate opt-in checkbox. A plan applies to one exact normalized contract and mutation setting and expires after ten minutes; changing either requires a new preview.
6. Execute, inspect the results and export the evidence. Use a successful first report as the baseline only when that is the intended comparison. For defect remediation, preserve the original failing report as the baseline and run the identical contract after the fix.

## Retest and handover

Use **Load baseline** and **Load current report** to inspect reports from another CLI or Studio run. Reports are checked for structural and internal hash consistency before they are accepted. Comparisons require the same contract digest, case set, target, name, schema and tool metadata. A v0.1 report therefore does not compare directly with v0.2; establish a new baseline for the new version.

Export the current JSON report for machine processing, HTML for review, JUnit for CI ingestion, and the comparison HTML for a remediation handover. Report hashes alone are not signatures. Version 1.0 also exports signed proof packages when Studio is started with --signing-key and --public-key; trusted keys stay on the server.

## Session behaviour

- The session capability is carried in the printed URL fragment and cleared from the address bar by the interface. It stays in that browser tab's session storage until the tab closes. Reopening the complete CLI URL restores access while the same Studio process is running.
- Review tokens and at most eight recent jobs remain in process memory. Start with --history PATH for durable verified run history. The History panel retains contracts, reports and three-layer graphs across sessions; without that flag, runs remain session-local.
- There is one active job at a time. Requests within that job respect the contract's concurrency limit. Closing the Studio process can interrupt an incomplete run. There is no background service or resume-after-restart feature.
- Request uploads are limited to 4 MiB. A very large report may exceed the browser export/compare API limit even though JSON can be downloaded directly from a completed run; use the CLI for larger evidence bundles.
- No telemetry, external fonts or CDN assets are used. The bundled logo is the same original 0xFarag mark used in the profile branding.
- Browser interaction across the separate execution environments used to build this release could not be tested live. The HTTP API workflow and installed package were tested independently; a saved read-only preview is supplied for visual inspection. See the validation record for the precise tested scope.

If a credential was added after Studio started, restart Studio from the updated shell. Export existing evidence before restarting. A presence indicator does not establish that a token is valid; the configured positive controls test actual access.


## Version 1.0 intelligence workspace

The Authorization Intelligence panel shows intended permission, independent policy and observed behavior for each configured boundary. Unknown layers stay visible. Open a boundary to inspect its controls and evidence. Add independently reviewed local policy rules through the policy editor. Start Studio with --policy-config PATH to offer an explicitly configured OPA or local evaluator. The browser opts into that fixed configuration; it cannot choose arbitrary PDP endpoints. Proof and explanation use retained graph snapshots without re-querying policy.

Pin a graph baseline to compare policy, intent and context drift separately from behavior. History can load the exact retained graph or prepare a retest against the same origin. Review and authorise every plan before execution. Continuous assurance is finite and stops on non-pass conditions. Cancellation stops before the next cycle; in-flight requests remain deadline-bounded.

To export Instant Proof, start Studio with an operator private key and a separately trusted public key. The export contains the signed manifest, report, exact contract and graph. Private keys never enter the browser. The independently verified package is a ZIP transport; extract it before using the standalone verifier.

Deterministic explanation cites the graph and prerequisite evidence. Optional local AI requires --reasoning-config and explicit per-request opt-in. It receives only pseudonymized states and does not change findings.
