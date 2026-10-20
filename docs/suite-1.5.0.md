# AuthzLedger 1.5 — integrated assessment suite

**Development candidate and implementation map.** This document describes the local 1.5 candidate, its release contract and its current supported boundaries. It does not declare a stable release, completed final gates, a published tag or a completed release film. The [release record](release-1.5.0.md) defines publication gates. All three work packages below belong to one 1.5 release; they are not future versions.

## 1. Product promise and intended users

**From permitted scope and captured traffic to a controlled assessment: discover, test, prove, selectively retest, hand over.** AuthzLedger's original promise, “Find the authorization gap. Prove the fix.”, remains the core of that workflow.

The product is a local workbench for expert application pentesters, product security engineers and AppSec teams who need to explain an application-specific claim and carry it through remediation. The essential work object is an assessment with scope, sources, immutable evidence and an evolving review context. A discovery result is a lead; a controlled observation supports a specific conclusion; a retest answers whether the original claim remains reproducible under comparable conditions.

The intended improvement over fragmented tool use is less manual reconstruction: the route, identity, source, check version, controls, result, reproducer and comparison remain linked. The intended improvement over a broad scan report is depth in supported claims, particularly authorization and stateful workflows. These are design advantages to measure with users, not established market-wide superiority. A small curated registry does not replace the breadth of established vulnerability feeds.

The first user value is continuity. Close a persistent workspace, reopen it, inspect the same evidence, select a source-bound retest and produce a verifiable handover. Credentials must be supplied again; an interrupted operation must not silently run again.

## 2. Architecture: extend the existing workbench

Studio and CLI call `WorkbenchService`; checks, discovery and static playbooks use the existing execution infrastructure. There is no second HTTP scanning engine.

| Boundary | Implementation | Responsibility and limit |
|---|---|---|
| Workspace | `workbench.py`, `history.py` | Additional SQLite tables beside legacy history; revision compare-and-swap, typed artifacts, job interruption and finite schedules. Historical evidence is not relabelled or rewritten. |
| Engagement and scope | `scope.py`, `execution.py`, `credentials.py` | Operator-supplied engagement/RoE references; exact origin, method, path, purpose and effect authorization; network binding, expiry and budgets; runtime credentials. A reference is not proof of ownership or legal authorization. |
| Sources and inventory | `imports.py`, `surface.py`, `adapters.py` | Bounded offline parsing, safe projections, provenance, inventory and candidate prerequisites. Import never grants execution permission. |
| Active discovery | `discovery.py`, `scope.py`, existing `engine.py` | Bounded HTTP paths/link discovery and explicit TCP service probes. The same context accounts for active operations. |
| Checks and composition | `detectors.py`, `playbooks.py` | Curated versioned checks, control dependencies, deterministic oracles and static reviewed step composition. No imported executable plugins. |
| Existing proof primitives | `experiments.py`, `workflows.py`, `observations.py`, `oracles.py`, `minimize.py` | Contrast and workflow execution, captured predicates, prerequisite controls and bounded reproducer reduction retain their original verification contracts. |
| Handover | `platform_reports.py`, `assessment_reports.py`, signing services | Freeze verified sources, derive coverage, render JSON/HTML/PDF and sign the exact delivered inventory. |
| User interfaces | `commands_platform.py`, `commands_assessment.py`, `studio_platform.py`, existing Studio | Shared plan/run/retest/report services; authenticated local jobs, explicit approval and persistent Inspector. |

The intent/policy/observation graph in `intelligence.build_graph` and the provenance graph in `assessments.build_evidence_graph` keep their existing contracts. The surface catalog is a versioned sidecar whose identifiers and digests link to sources; it does not reinterpret those graphs. `ComparisonEnvelope v1` and historical report producers remain compatible within their supported verification profiles.

### Rules of engagement and transport

A scope defaults to deny. The allow unit is a joint `(origin, method, path, purpose, effect)` operation; an operation approved at one origin is not automatically approved at another. TCP probes require a separate typed origin, explicit port and `CONNECT /` service operation. Allowed CIDRs are explicit; denied CIDRs further constrain them. Every resolved address must satisfy the boundary before a connection is made, and the connection uses the validated destination. Expiry is checked at dispatch, including scheduled work.

Automatic redirects and ambient environment proxies remain disabled. Discovery may observe an outside link without contacting it. `GET` and profile names such as `full-safe` are not proof that an application route has no side effects: the operator must authorize the effect. A scope revision invalidates plans and schedules bound to the earlier digest.

Controls, probes, discovery and reduction must use the reviewed request budget. Playbooks share one context and sum their upper bounds before execution. Workflow cleanup reserves are explicit. Cancellation and dispatch failures remain visible in the ledger; cleanup cannot expand the approved scope. Request limits, response limits and timeouts constrain execution rather than acting as cosmetic report labels.

### State and evidence contracts

| Retained object | Purpose | Boundary |
|---|---|---|
| Assessment revision and scope | Editable engagement context and exact authorization | Revisions are checked; earlier evidence retains its original scope. |
| Import batch / adapter receipt | Redacted provenance and bounded source assertions | A source claim is not a locally verified vulnerability. |
| Surface catalog and delta | Known assets/endpoints and observed changes | Missing from a later catalog means not observed, not fixed. Total application surface remains unknown. |
| Check/discovery/playbook plan | Exact reviewed requests, prerequisites, versions and budget | Approval binds the plan digest; changed plans require review. |
| Execution and observations | Actual outcomes, control state and dispatched ledger | Unexecuted or blocked work cannot become a successful observation. |
| Finding and comparison | Narrow claim, evidence level, sources and retest interpretation | Severity and analyst review do not rewrite observed facts. |
| Frozen platform snapshot | Consistent source inventory and derived coverage | New evidence or edited report context requires a new freeze. |
| Signed manifest | Exact artifact bytes and their inventory | Authenticity depends on the trusted key; signatures do not witness execution. |

The local store is not an encrypted vault or a hosted multi-user service. Credential references can persist; credential values are resolved at runtime. Known credential fields and reflections are rejected or redacted along supported paths, but operators still review narrative text and retained artifacts before sharing. Raw traffic archives are not silently retained as a second evidence store. Local database protection and backup remain deployment responsibilities.

## 3. Native capabilities, adapters and controlled PoCs

| Domain | Native behavior in the candidate | Evidence boundary |
|---|---|---|
| Authorization | Object, tenant, role and denial-data disclosure recipes; configured response policy; existing Contrast controls | Ownership, protected markers, role ordering and tenant claims require explicit bindings and valid controls. |
| Business logic | Existing workflow engine exposed through skipped-approval, role-transition and idempotency recipes | Fresh fixture, pre/post state, declared effect and cleanup requirements; no universal inference of business rules. |
| Web configuration | Missing explicitly required response headers | Confirms the configured omission, not exploitability. |
| Selected injection | Literal and unevaluated controls plus two curated arithmetic template probes | Confirms only the declared arithmetic evaluation predicate. No general SQL injection, arbitrary payloads or code execution claim. |
| Information/CORS signals | Diagnostic signatures, declared JSON field presence and credentialed Origin reflection | Hints only. CORS headers do not prove browser-readable sensitive data. |
| Network/service discovery | Explicit TCP connection and bounded unsolicited banner classification | No UDP sweep, SYN scan, exhaustive port range, OS fingerprint or authenticated host inventory engine. A banner is a hint. |
| HTTP discovery | Exact reviewed seeds and bounded eligible links through the existing engine | No JavaScript browser crawler, automatic login or unbounded endpoint guessing. |
| CVE knowledge | Offline reviewed data pack with explicit source and version matching | The bundled pack covers two Apache HTTP Server advisories. Numeric upstream versions only; backports/prereleases remain unsupported. Candidates never become confirmed findings. |
| Controlled PoC | Exact check recipe and existing Contrast/workflow minimal-reproducer services | Reduction is bounded and 1-minimal within approved removable units when that check completes; it is not a global minimum or an exploitation framework. |

### Interoperation with specialist tools

Burp raw messages, DTD-free Burp XML, ZAP JSON-plus and HAR retain their explicit profiles and historical native exporter evidence. OpenAPI declarations can contribute surface metadata without authorizing any declared server. Input examples, credentials and claims are not blindly promoted into executable contracts.

Two selected offline result adapters extend the inventory: `nmap-xml-v1` for TCP host/port/service observations and `nuclei-jsonl-v1` for bounded HTTP result events. Both produce sealed adapter receipts and safe catalog projections. They do not launch the tools, load their plugins or treat their results as locally confirmed findings. Exact parser boundaries and native-format evidence are release gates; a format name is not universal exporter compatibility.

Nmap service labels distinguish a port-table lookup from a probed identification. NSE output and OS fingerprints are outside the retained profile. XML external identifiers, internal subsets and entities are forbidden; the exact inert `<!DOCTYPE nmaprun>` declaration is accepted without rewriting the source. Current adapter provenance uses a published upstream sample, not a newly captured local Nmap run. See [adapter profiles](adapters-1.5.0.md). Nuclei results remain source hints: raw request/response bodies, credentials and extracted-result payloads are discarded. A method is retained only when explicitly supplied by the supported source representation; an unknown method is not invented as `GET`.

### Static approved playbooks

A playbook composes one to 32 already sealed discovery/check plans. Each step names earlier dependencies, all steps share the same scope, and the total upper bound must fit its budget. The operator approves the whole plan digest. Discovery results cannot insert new active steps, synthesize attack chains or substitute captured secrets into later requests.

Execution preserves child artifacts unchanged and stops later active work when controls or observations are inconclusive, cancellation occurs or a step errors. Skipped steps remain `not_run` with a reason. This supports repeatable expert procedures such as approved discovery followed by a preconfigured header check; it is not autonomous exploitation. No arbitrary shell, third-party Python or scanner process is invoked by a playbook.

## 4. Detection and pack contract

A curated `CheckSpec` names its check ID/version, family, required controls, oracle ID/version, capture profile, effects, severity default, evidence ceiling, lifecycle and limitations. Its canonical manifest has a content digest. A concrete specification adds explicit source references, request contract, control IDs, target case and validated parameters; compilation binds it to scope and budget.

The execution contract carries more than a boolean result: control verdicts, selected inputs, observation references, check and source digests, a reproducible recipe, credential-binding metadata without values and the request ledger. The verifier recomputes supported predicates from retained inputs. Extraction from discarded raw responses remains an attestation; this is distinct from independently replaying the remote exchange.

Profiles are selections, not permission grants: `authz-deep`/`deep-authz`, `web-quick`/`quick`, and `full-safe`. The last selects read-effect checks; the operation's effect still requires review. Missing prerequisites block execution or produce explicit inconclusive evidence. A severity label cannot increase a hint's evidence ceiling.

Current check packs are declarative manifests locked to installed curated semantics. Digest and inventory locks prevent silent content changes; revoked checks are rejected. The validator recognizes experimental, validated, deprecated and revoked lifecycle metadata. It does not provide an arbitrary plugin marketplace, runtime sandbox or automatic feed distribution. Draft authoring and organizational review are development processes, not a falsely claimed in-product approval system. A signed pack would establish content integrity, not the safety or correctness of its code.

Every added check must bring a positive case, negative case, failed-control case, unsupported-input cases, scope/budget tests and a forged-evidence rejection test. The negative corpus is a release gate for false-positive discipline. Rollback pins an older reviewed pack/version for new work; it must not rewrite previous findings. The check's technical severity, evidence quality and analyst review decision remain independent. Standards references are partial, versioned, evidence-bound mappings, never certification.

## 5. Studio workflow and handover

1. **Open or create an assessment.** Set engagement/RoE references and the exact scope. Studio defaults to a persistent local history/workspace; `--session-only` is explicit. The context line identifies the assessment, revision and selected evidence.
2. **Import and discover.** Import supported traffic or adapter results offline; inspect origin, method, sources, unknowns and blockers. Review a bounded discovery plan before approving any network requests.
3. **Choose a supported check.** Select a profile/check, bind identity and expected policy, inspect control prerequisites, effects and request limits. Advanced versioned JSON remains available for complex contracts; defaults cannot supply missing authorization intent.
4. **Review and run.** Execute the exact approved digest through the shared service. Changing scope, plan or runtime credential generation invalidates stale review. Follow job status and the actual ledger.
5. **Investigate.** The persistent Inspector shows the narrow claim, controls, source observations and evidence limits. Hints and inconclusive cases stay visible. Review labels do not erase evidence.
6. **Reproduce and retest.** Use the exact recipe or approved reduction. After a change, select original findings and their prerequisite closure. Legacy Contrast comparison preserves `fix_verified`, `violation_persists`, `inconclusive`, `testability_restored`, `regression`, `unchanged` and `not_retested`. Generic checks use their supported narrower comparison semantics; an unavailable route cannot prove a fix.
7. **Freeze and hand over.** Review report content, freeze the source inventory and render JSON/HTML/PDF from that snapshot. Sign the exported bytes and verify using a separately trusted public key. An offline delta or reanalysis is not a new retest.

CLI provides the same main path and is suitable for reviewable JSON artifacts and CI. The GUI covers the end-to-end local workflow; complex request and playbook specifications retain an advanced JSON path. Keyboard navigation and Inspector behavior require the actual browser acceptance gate, not a static mockup review.

Coverage is reported over retained explicit plans, eligible operations and observed executions. Skipped, blocked, inconclusive and omitted work must be exportable. An authorization coverage model must retain operation, principal/tenant, state and detector context; summing endpoints alone is insufficient. The current aggregate is deliberately not a percentage of application security. A valid empty report says no supported execution evidence was retained.

## 6. Positioning and comparison discipline

| Tool category | Established strength documented by its vendor | AuthzLedger's focused role |
|---|---|---|
| Nessus | Broad scan templates; audit trails explain plugin dependencies, authentication failures and execution errors [1] | Carry an explicit application claim from controls through a source-bound retest and signed handover. Do not imply Nessus lacks execution diagnostics. |
| Qualys VMDR/WAS | Asset/vulnerability workflows; WAS supports individual and grouped finding retests [2] | Local, inspectable contract/evidence continuity in supported application domains. Selective retest alone is not a unique feature claim. |
| Rapid7 Nexpose/InsightVM | Vulnerability proof and distinctions between validated vulnerability observations and version-based results [3] | Typed control/oracle/source lineage and preserved omitted coverage across the local assessment. No claim Rapid7 only reads banners. |
| OpenVAS/Greenbone | Detection-quality methods, scoped overrides and report comparisons [4] | Keep observed facts, analyst review and source-bound fix proof separately inspectable. No claim Greenbone has no quality or delta model. |
| Burp/ZAP and focused utilities | Interactive investigation, traffic capture and specialized checks | Import supported source evidence, preserve provenance and connect selected leads to explicit controlled contracts. They remain useful complements. |

Measure any superiority claim per dimension on a shared eligible corpus, using named product editions, versions and configurations. Useful dimensions are incorrect confirmation rate, control-failure classification, retained source traceability, independent reproduction success, retest comparability, omitted-case visibility and handover effort. Report request/time costs alongside controls and setup effort. Unsupported domains are coverage limitations, not detection misses. The three local demos are deterministic examples, not a competitor benchmark.

## 7. One-release priorities and acceptance gates

The A/B/C grouping is an internal delivery order for the same 1.5 release. A preserves and integrates AuthZ/API/web evidence; B adds controlled inventory/discovery and selected checks/adapters; C adds local operational durability, finite scheduling, explicit knowledge packs and verifiable handover. Enterprise readiness here means these selected local properties. Distributed agents, SaaS tenancy, organization-wide RBAC, fleet management, a broad live CVE feed, credential attacks, C2 and Internet-scale scanning are outside the candidate.

Release integration proceeds in dependency order: (1) scope and transport; (2) persistent workspace and recovery; (3) sources/catalog/discovery; (4) curated checks and static composition; (5) retests/knowledge/schedules; (6) unified Studio/CLI/reporting; (7) exact-build regression, demos, installed-wheel verification and publication gates. The source tree contains implementation for these areas; the release owner must bind each acceptance result to the final tested build. A green unit test alone does not close a complete user workflow.

| ID | Required acceptance | Primary executable evidence |
|---|---|---|
| S15-01 | Origin/method/path/purpose cannot form an unintended cross-origin permission | `tests/test_scope150.py` |
| S15-02 | Mixed DNS answers, denied ranges and mapped IPv4 cannot escape scope | `tests/test_scope150.py` |
| S15-03 | Pinned transport sends no automatic redirects; expired scope blocks dispatch | `tests/test_scope150.py` |
| S15-04 | Cancellation, response limits and a global request budget remain enforced | Scope/discovery tests and existing execution regression |
| S15-05 | Persistent and legacy history coexist in either initialization order | `tests/test_workbench150.py` |
| S15-06 | Stale revisions and tampered/reduced history tails are rejected | `tests/test_workbench150.py` |
| S15-07 | Restart preserves evidence and never silently replays an uncertain job | Workbench and Studio platform tests |
| S15-08 | Credential values and known reflections do not persist; rotation requires review | Workbench, detector and Studio platform tests |
| S15-09 | Import provenance, duplicate parameters and redactions are preserved or explicitly blocked | Existing import tests and `tests/test_discovery150.py` |
| S15-10 | OpenAPI and imported scanner assertions never authorize targets or confirm findings | Discovery and adapter tests |
| S15-11 | Nmap/nuclei parsers reject unsupported declarations, malformed/oversized input and unsafe claims | Adapter tests plus retained native-profile evidence where claimed |
| S15-12 | Real bounded HTTP discovery and service probes match the shared ledger | `tests/test_discovery150.py`, demo B |
| S15-13 | Catalog disappearance is not fixed; unknown dependency selection stays conservative | Discovery delta tests |
| S15-14 | Each native authorization/workflow recipe executes its required controls | `tests/test_detectors150.py`, existing workflow suites |
| S15-15 | Arithmetic literal echoes fail the injection predicate; arbitrary payloads are refused | `tests/test_detectors150.py` |
| S15-16 | CORS, diagnostic text, JSON fields and CVE matches retain their evidence ceilings | Detector/knowledge/report tests |
| S15-17 | Failed controls and a missing endpoint cannot become a verified fix | Detector and legacy comparison tests |
| S15-18 | Pack lock changes, revoked checks and resealed forged verdicts are rejected | Detector tests |
| S15-19 | Static playbooks bind scope/digests/budgets and halt with explicit `not_run` steps | Playbook tests and Workbench integration |
| S15-20 | Reproducer retains source binding and controls within its approved reduction budget | Existing reduction tests and demo A |
| S15-21 | Selected Contrast fix and omitted `not_retested` survive persistence/export | Detector/report tests and demo C |
| S15-22 | Finite schedules respect expiry, total budget and interrupted-run review | `tests/test_workbench150.py` |
| S15-23 | Knowledge version rules and partial standards mappings reject unsupported claims | `tests/test_knowledge150.py` |
| S15-24 | Frozen reports retain nested child evidence, controls and analyst decisions without upgrades | `tests/test_platform_reports150.py` |
| S15-25 | Exact artifact inventory verifies; altered/missing files and forged summaries fail | Platform report tests and demo C |
| S15-26 | JSON/HTML/PDF have consistent semantics and readable rendered layout | Report tests plus recorded visual review |
| S15-27 | Studio scope→import/discover→check→retest→report path works with keyboard/security boundaries | `tests/test_studio_platform150.py`, `tests/browser_platform150.cjs` and existing browser suites |
| S15-28 | A/B/C issue real requests, reopen the store, stop fixtures before export and record actual receipts | `tests/test_demo150.py`, `tools/check_platform150.py` |
| S15-29 | Built wheel works outside checkout; independent verifier imports no product code | Final installed-distribution receipt |
| S15-30 | Historical proof bytes remain valid; final regression, exact-version CI and published assets are verified | Final release owner's immutable gate record |

This table is an acceptance contract, not a declaration that all rows have passed. Missing native captures, browser results, final package receipts or release artifacts must remain explicit blockers. Release metrics and test totals belong to the actual final receipts; none is invented here. `tools/verify_release150.py` executes the integrated gate and writes `verification.json`; `tools/release_gate150.py` distinguishes candidate receipt validation from exact-commit publication acceptance. All eight browser suites remain required.

### Source references for comparison

[1] Tenable, Nessus audit trails: https://docs.tenable.com/nessus/10_12/Content/ConfigureAnAuditTrail.htm

[2] Qualys, WAS detection management and retests: https://docs.qualys.com/en/was/portal/latest/detections/manage_detections.htm

[3] Rapid7, vulnerability proof and result states: https://docs.rapid7.com/insightvm/working-with-vulnerabilities/

[4] Greenbone, reports, detection quality, overrides and delta: https://docs.greenbone.net/GSM-Manual/gos-24.10/en/reports.html

For baseline contracts see [1.1 product architecture](product-1.1.0.md), [1.1 acceptance](acceptance-1.1.0.md) and [verification](verification-1.1.0.md). Historical records keep their original producer versions and scope.
