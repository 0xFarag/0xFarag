# AuthzLedger — development toward 1.1.0

**Turn a request into a controlled finding, a smaller reproducer and a verifiable fix.**

Know who can do what. Prove what changed.

![AuthzLedger by 0xFarag](brand/hero.svg)

An authorization decision has three sources: what the contract intends, what a policy engine decides, and what the application actually does. AuthzLedger connects them in a versioned authorization graph, exposes disagreements and preserves verifiable evidence through retests.

Built directly on v0.3.4: the access matrix, control dependency scheduler, offline OpenAPI import, redacted HTTP evidence, Studio and CLI remain the foundation. Version 1.0 adds policy evaluation, differential intelligence, durable history, bounded continuous assurance, grounded advisory reasoning and Ed25519 proof packages.

**[36-second release walkthrough](https://github.com/0xFarag/0xFarag/releases/download/v1.0.0/AuthzLedger_1.0_Release_wide.mp4)** · **[Release and downloads](https://github.com/0xFarag/0xFarag/releases/tag/v1.0.0)** · [Installation](INSTALL.md) · [Product architecture](docs/product-1.0.md) · [Release notes](RELEASE_NOTES.md)

## Integrated assessment workflow for 1.1.0

This development branch extends the released 1.0 foundation and **ComparisonEnvelope v1** with all eight capability areas: offline Burp/ZAP/HAR import and mapping, Contrast Lab, Workflow Contracts, bounded Minimal Reproducer, source-bound selective retests, an integrated Studio assessment workspace, HTML/PDF/JSON assessment reports and explainable impact selection. Studio and CLI call the same services and existing HTTP DAG through one request budget.

[1.1.0 product and implementation contract](docs/product-1.1.0.md) · [All 88 acceptance scenarios and remaining gates](docs/acceptance-1.1.0.md) · [Executed verification and release boundaries](docs/verification-1.1.0.md) · [ComparisonEnvelope v1](docs/comparison-envelope-v1.md) · [Binding original implementation contract](docs/implementation-1.0.5.md)

**This is the integrated 1.1.0.dev0 build, not a published 1.1.0 production release.** The released stable product remains 1.0.0 until the complete contract gates pass. The development producer has its own explicitly registered comparison profile. The acceptance ledger distinguishes implemented behaviour from fully verified scenarios, including exporter compatibility and GUI performance.

```sh
python3 -m pip install '.[reports]'
python3 -m authzledger studio --history ./authorization-history.sqlite3 --open
python3 -m authzledger assessment demo --out artifacts/assessment-demo
python3 tools/check_workflows110.py --out artifacts/workflow-demo
```

Choose **Assessment** for request import, explicit principal/object/control mapping, plan review, investigation, reduction, retest and signed handover. Ctrl/Cmd+K opens local commands. Session credentials stay in server memory; reload requires reopening the authenticated session URL. Export assessment evidence before closing the server. New assessment working state is memory-only. With `--history`, bounded workflow assurance retains an additional verified history chain beside the unchanged v1 run history; without it, Studio explicitly labels workflow history as session-only.

The three assessment demos issue real loopback HTTP requests: imported request to reduced finding; 403 disclosure versus invalid controls and a 200 error object; selective fix proof with an omitted finding explicitly `not_retested`. Report generation and package verification happen after the fixture stops. Their Burp input is an authored format fixture. A separate genuine Chromium/Playwright HAR capture is retained and tested; genuine Burp/ZAP exporter acceptance remains open. See [import profile boundaries](fixtures/imports/README.md).

Run `python3 tools/check_assessment.py --out artifacts/assessment-proof` to also invoke the standalone verifier in an isolated Python process. [CLI and reproducible demonstrations](docs/assessment-cli.md) · [Reporting profile and verification limits](docs/reporting-profile-1.1.0.md).

## Start with evidence

For a copy you are authorised to use; Python 3.10+:

```sh
git clone --branch authzledger-v1.0.0 --single-branch https://github.com/0xFarag/0xFarag.git authzledger
cd authzledger
python3 -m authzledger studio --history ./authorization-history.sqlite3 --open
```

Choose **Run eight-scenario lab** to execute real loopback HTTP tests against synthetic fixtures. Inspect the access matrix, prerequisite controls, graph and evidence. The original six-case demonstration remains available. No cloud account, credentials or paid services are required for these fixtures.

For an authorised API, define identities and resources, review each permission, generate the contract and authorise its exact scope. Unknown permissions block generation; failed controls leave dependent observations inconclusive. Credential values remain in environment variables, outside reports and graph exports.

## Three layers. One accountable workflow.

| Capability | Delivered behaviour |
| --- | --- |
| Living Authorization Graph | Stable relationships connect explicit intent, independently supplied policy and verified observations. Missing layers remain unknown. |
| Differential intelligence | Policy drift, changed intent, behavioral regressions, escalation candidates and removed coverage remain distinct. Relaxing a permission never counts as fixing the original vulnerability. |
| Control orchestration | Positive and negative assertions run in an explicit dependency DAG. A blocked request is never represented as executed. |
| Policy-as-Code / Evidence-as-Code | Independent JSON policy rules and an explicitly scoped OPA adapter join canonical contracts and sealed reports. Local rules are identified as a local evaluator. |
| Explainable reasoning | Evidence-linked deterministic explanations; optional local Ollama annotations are separately labelled and never alter decisions or CI outcomes. |
| Continuous assurance | Finite runs with request budgets, bounded intervals and checked history. Assurance applies to configured relationships and observation windows. |
| Retest workflow | Select affected cases with their complete prerequisite closure; review before executing. Studio exposes authenticated local retest jobs. |
| Instant Proof | Sign report and attachments with Ed25519; validate against a separately trusted public key. A standalone verifier does not import AuthzLedger. |
| Studio and CLI | Matrix, graph, history, policy, controlled execution and exports share domain logic. |

## Reproduce a finding and verify its retest

```sh
python3 -m authzledger demo --out artifacts/demo
python3 -m authzledger graph artifacts/demo/contract.json --report artifacts/demo/vulnerable/report.json --policy examples/authorization-policy.json --out before-graph.json
python3 -m authzledger graph artifacts/demo/contract.json --report artifacts/demo/fixed/report.json --policy examples/authorization-policy.json --out after-graph.json
python3 -m authzledger intelligence-diff before-graph.json after-graph.json --out intelligence-diff.json
python3 -m authzledger explain after-graph.json --out explanation.json
```

The same contract runs before and after the fixture fix. Reports retain outcomes and hashes rather than raw response bodies or resolved credentials. Operational metadata, paths and expected fixture values in contracts still need review before sharing.

## Sign the proof. Verify independently.

OpenSSL 3 with Ed25519 support is required for these commands:

```sh
python3 -m authzledger keygen --private operator-private.pem --public operator-public.pem
python3 -m authzledger bundle artifacts/demo/fixed/report.json --key operator-private.pem --contract artifacts/demo/contract.json --graph after-graph.json --explanation explanation.json --out proof
python3 -m authzledger verify-bundle proof --public-key operator-public.pem
python3 tools/verify_bundle.py proof --public-key operator-public.pem
```

The trusted public key is supplied separately. Signatures establish signed content integrity and key possession; they do not prove truthful execution, operator identity or a trusted timestamp. History is tamper-evident relative to retained records and anchors, not an immutable external ledger.

## Assurance in your existing pipeline

```sh
python3 -m authzledger plan authorization.json
python3 -m authzledger assure authorization.json --policy policy.json --history authorization-history.sqlite3 --out artifacts/current
python3 -m authzledger watch authorization.json --policy policy.json --history authorization-history.sqlite3 --iterations 3 --interval 5 --max-requests 150 --out artifacts/watch
python3 -m authzledger retest authorization.json --case cross-user-denied --out retest-plan.json
python3 -m authzledger history authorization-history.sqlite3
```

Retest planning sends no requests; add `--execute` with a new output directory to execute. Mutating methods require explicit `--allow-mutations`. Exit codes: `0` configured success, `1` conclusive failures/regressions, `2` invalid configuration, execution errors or inconclusive evidence. A pass establishes only the configured assertions and scope.

## Why a dedicated authorization workbench?

Burp Suite, ZAP and Tenable already provide access-control testing capabilities. AuthzLedger focuses on intended permission, evaluated policy, observed enforcement, control validity and portable proof. The authored corpus compares against a status-only reference check; it is not an independent benchmark against those products. [Positioning and primary sources](docs/product-1.0.md).

## Documentation and rights

- [Access matrix](docs/matrix.md) · [Contracts](docs/contract.md) · [OpenAPI](docs/openapi.md)
- [Signatures](docs/signatures.md) · [Assurance and history](docs/assurance.md) · [Advisory AI](docs/reasoning.md)
- [Product architecture](docs/product-1.0.md) · [Launch and adoption plan](docs/launch-1.0.md)
- [Security model](docs/security-model.md) · [Validation](docs/validation.md) · [Contributing](CONTRIBUTING.md)

AuthzLedger is the product project of **Nasser Aldin Farag (0xFarag)**. He directs its product vision, technical scope and principal design decisions. All exclusive rights legally held by him in his own protectable contributions remain reserved to him. Publication, presentation or delivery does not itself transfer ownership or grant a general commercial licence. Commercial reuse requires a separate written agreement, subject to applicable law and permissions already validly granted.

Copyright © 2026 Nasser Aldin Farag (0xFarag). All rights reserved. [Rights and commercial licensing](docs/rights.md) · [LICENSE](LICENSE) · [NOTICE](NOTICE.txt).

Billing is disabled. Independent security review, wider platform coverage, full accessibility and customer validation remain open.
