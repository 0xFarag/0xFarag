# AuthzLedger 1.5 release record

**Development candidate.** This record does not declare a stable release, a published tag or completed remote CI. The complete approved 1.5 scope must pass its acceptance gates on the exact release commit before the stable version is set and published. Historical 1.1.0 artifacts and proof roots remain unchanged.

AuthzLedger extends the local authorization workbench into an integrated assessment suite for supported domains: explicit scope, retained traffic and discovery observations, versioned checks, prerequisite controls, findings, selective retests and signed handover. Studio and CLI use the same application services and execution context.

The [suite contract](suite-1.5.0.md) maps native capabilities, selected adapters, module boundaries, Studio workflow and S15-01 through S15-30 acceptance gates. The entire A/B/C scope belongs to this one release.

## Implemented surfaces under release review

- A persistent local assessment store with revision checks, retained typed artifacts and interruption records. Runtime credentials are not workspace settings; interrupted work is not automatically replayed.
- Offline surface inventory from supported traffic imports and OpenAPI declarations, with provenance, uncertainty and missing prerequisites. Selected Nmap XML and Nuclei JSONL result adapters retain source hints through bounded safe projections; they do not launch those scanners. Inventory is not authorization to contact a target.
- Explicitly scoped network service probes and bounded HTTP discovery. Only reviewed origins, ports and operations are eligible. Automatic redirects and ambient proxies remain disabled.
- A curated check registry and profiles, with adapters for existing authorization and workflow contracts. New checks declare their evidence ceiling: a header reflection hint is not presented as proven cross-origin data theft.
- Static approved playbooks compose already sealed discovery/check plans with one scope, one budget and explicit stop conditions. Discovery cannot synthesize new attack steps; no arbitrary executable plugins are loaded.
- Source-bound retests and frozen platform snapshots retaining discovery, check, authorization and comparison artifacts. JSON, HTML and PDF share the snapshot. The signed inventory binds the delivered bytes.
- Offline surface deltas and a reviewed, limited CVE data pack preserve candidate status and unsupported version schemes. They are not new executions or proof of exploitability.
- Local finite scheduling requires a running explicit scheduler invocation. It does not install a background daemon or create remote monitoring.

The final release must reconcile this list with the exact tested source and the binding roadmap. A feature's presence in code or in the registry is not sufficient evidence of its entire promised domain.

## Reproduce the three demonstrations

From a development checkout with the report dependencies installed:

```sh
python3 tools/check_platform150.py --out artifacts/platform150-proof
```

Use a new output directory. The command creates only disposable loopback targets, sends actual requests through the product services, writes a persistent workspace, closes and reopens it, then exports and verifies evidence after every fixture listener has stopped. It also flips exactly one byte in a copy of the signed package and requires both verifiers to reject it.

| Demo | Actual workflow | Required observed result |
|---|---|---|
| A | Authored traffic import → explicit contrast contract → controls → finding → bounded reduction | Confirmed configured marker disclosure; denial-data leakage remains visible; invalid controls are inconclusive; a 200 error object is rejected |
| B | Explicit scope → TCP service probe and bounded HTTP link discovery → selected `web-quick` check → evidence | Shared dispatch ledger matches observed HTTP requests plus service connections; the exact required header omission is confirmed as a configuration finding |
| C | Two-finding baseline → one selected retest with controls → frozen report → signed package | `fix_verified` and `not_retested` coexist; original evidence is preserved; main and isolated standalone verification pass; one changed byte is rejected |

The detailed receipt is `results.json`; each demo also has its own receipt, raw typed artifacts and frozen snapshot. Receipt fields include actual HTTP-request counts, actual service-connection counts, the execution ledger, scope limits, timestamps, runtime/tool version and measured duration. `network_operations_observed` is HTTP requests plus service connections; it is not an independently measured HTTP connection count.

These are authored synthetic fixtures. They do not establish native exporter compatibility, production vulnerability prevalence, whole-application coverage or superiority over another product. Demo B confirms an explicitly configured missing header; it does not claim exploitability. The fixture banner is an authored protocol-identification example, not a real SSH server assessment.

## Installed distribution gate

The release owner must install the built wheel outside the source checkout and run the same demos through the installed package. Supply a separately copied standalone verifier so its execution does not depend on importing AuthzLedger:

```sh
python -I -m authzledger assessment demo150 --out /absolute/new/output-directory \
  --standalone-verifier /absolute/independent/verify_bundle.py
```

The isolated verifier is launched with `python -I`. It verifies package integrity relative to the supplied trusted public key. The main verifier additionally checks the retained typed semantics and supported exact renderers. Neither independently witnesses the remote application or establishes the operator's legal authority.

## Mandatory final gates

The integrated runner is `python tools/verify_release150.py --out artifacts/release150`. Its `verification.json` records actual command results, runtime, source/commit binding and log hashes. Validate candidate receipts with `python tools/release_gate150.py --receipt-dir artifacts/release150 --allow-development`. Use a fresh output directory. Development acceptance is not publication acceptance: the stable gate uses `--publication` and requires the exact clean tracked release commit.

1. Map every required item in the approved 1.5 roadmap to implemented behavior and an executed acceptance receipt. Unsupported or incomplete domains remain visible and prevent a complete stable-release claim.
2. Run the complete existing regression plus all new scope, discovery, adapter, check, playbook, knowledge, persistence, scheduling and report tests on the final tree. Retain failures and skips explicitly.
3. Run all eight browser suites, including the new complete Studio path with keyboard access, source context, scope review, real execution, retest and handover. Client/server error handling and credential boundaries must be checked.
4. Reproduce demos A/B/C and retain their actual receipts, source hashes and independent verifier result. Verify altered and missing inventory files fail.
5. Build the wheel, install it outside the checkout and run the installed package's main paths. Bind receipts to the tested wheel hash and exact commit.
6. Verify historical 1.1.0 packages without changing their bytes or producer metadata.
7. Reconcile product documentation, CLI help, registry limitations and report semantics. Report narrow check support accurately; do not turn a hint into a confirmed exploit.
8. Only then set the stable version, run the exact-commit CI/publication gates, publish immutable-version assets and verify their checksums and availability.

## Release assets

Prepare a source archive, wheel, public synthetic proof package, independent verifier, `verification.json` and checksums. The verification asset retains actual execution receipts and log hashes; CI logs are retained separately. Publication downloads the already verified immutable artifacts rather than rebuilding different bytes. The public package must contain no credentials or private key. Retain the deliberately tampered example separately and label it invalid; never confuse it with the valid proof.

Versioned download URLs and test totals belong in the final publication record only after the assets and final receipts exist. The launch drafts in [launch-1.5.0.md](launch-1.5.0.md) must remain unpublished until these gates pass.

## Boundaries

Studio defaults to persistent local history at `~/.authzledger/history.sqlite3`; `--history` selects another file and `--session-only` is explicit. Credentials remain runtime-only. Engagement and RoE references are operator declarations, not an authorization authority.

The scope is a local assessment platform in selected supported domains. It is not a claim of universal CVE coverage, credential attacks, autonomous Internet scanning, hosted multi-tenant operation or fleet-scale vulnerability management. The supported injection predicate is curated arithmetic template evaluation, not general SQLi or RCE. CORS header reflection remains a hint without a browser data-access proof. Banner/version matches and partial standards mappings remain bounded evidence. Review decisions, evidence level, technical severity and retest status are separate facts.

Copyright © 2026 Nasser Aldin Farag (0xFarag). Rights and permitted use are governed by the repository's existing licence and notices.
