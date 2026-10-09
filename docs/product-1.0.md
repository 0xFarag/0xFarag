# AuthzLedger 1.0

**Authorization Intelligence, built on evidence.**

**Know who can do what. Prove what changed.**

AuthzLedger connects declared access boundaries, evaluated policy decisions and controlled HTTP observations in one local authorization workbench. Every relationship has a contract. Every conclusion has prerequisites. Every retest preserves the distinction between changing a permission and repairing its enforcement.

The product is built for pentesters who need reproducible findings and AppSec engineers who need authorization changes to remain reviewable after the assessment ends. Its unit of work is a declared actor–request relationship, with the resource, assertions, controls and policy context required to assess that boundary.

## The promise

For a selected access boundary, answer four questions in one workflow:

1. What access did the team intend?
2. What does the configured policy evaluator decide?
3. What did the application actually return under passing controls?
4. What changed, and which evidence supports that conclusion?

An invoice endpoint illustrates the difference. A reviewed contract says Tenant B cannot read Tenant A's invoice. A separate policy evaluator may disagree. The application may expose the invoice, correctly withhold it, or return a denial status while leaking a protected field. AuthzLedger keeps those states visible. If Tenant B's credentials fail their control, the dependent observation remains inconclusive.

The initial scope comes from explicit contracts, a reviewed access matrix or an offline OpenAPI import. The authorization map represents that supplied scope; it is not a claim to have discovered every endpoint or permission in an application.

## The Living Authorization Graph

The graph joins three independently named evidence layers around the same relationship. A missing layer stays missing.

| Layer | Source | Meaning |
| --- | --- | --- |
| Intended permission | Reviewed, versioned contract and matrix decisions | The access boundary the operator intends to enforce. |
| Evaluated policy | Separate local rule configuration, or an explicitly configured OPA decision endpoint | The decision returned by the selected evaluator for the supplied input. |
| Observed behavior | Integrity-checked HTTP report bound to the exact contract | The configured assertions and control outcomes recorded during that run. |

Local rules provide a separate, deterministic evaluation input. They are not an attestation of the target application's deployed policy. The optional OPA adapter queries a real, explicitly allowed decision endpoint; its result still depends on the policy deployment and input mapping supplied by the operator. Neither evaluator silently replaces unknown intent or missing observations.

Relationship records retain their case identity, actor, request, controls, policy provenance and observation references. This makes the map inspectable and diffable rather than a decorative topology. Graph generation is available without AI.

## Differential Authorization Intelligence

AuthzLedger separates three classes of change:

| Change | Interpretation |
| --- | --- |
| Intent versus evaluated policy | A policy disagreement that requires review. An unexpected allow is an escalation candidate, not proof that the application exposed a resource. |
| Intended assertion versus observed result | An enforcement or assertion disagreement. Inspect content checks and passing controls before concluding that unauthorized access occurred. |
| Baseline versus current graph or report | Permission changes, policy drift, observation changes and regressions remain distinguishable. Changed scope or removed relationships remain visible. |

An HTTP status alone does not establish resource access. A failed denial assertion can also reflect an unexpected error response or changed API behavior. Strong resource assertions and the control trace are the basis for investigating impact.

The strict report comparator preserves same-contract retest semantics. Policy migration review and graph intelligence comparisons describe configuration evolution separately. Relaxing `deny` to `allow`, removing a relationship or losing its controls cannot be reported as repairing the original boundary.

Graph comparison also records `context_drift` when the source contract digest changes. This includes identity credential references and prerequisite definitions, even when a selected edge's own assertions stay unchanged. Resolved and regressed classifications require the same contract and unchanged policy assumptions.

## Controlled orchestration

Positive and negative checks share an explicit prerequisite DAG. Successful-access controls establish useful test conditions; denial checks assess the boundary. Explicit contracts can compose both kinds of check through `requires`.

For a matrix-generated denial, the actor must first demonstrate permitted access and the resource must first be accessible to a permitted actor. Only passing prerequisites release the dependent request. A failed, errored or inconclusive prerequisite blocks that request.

| Outcome | Operator meaning |
| --- | --- |
| `pass` | The configured assertions passed for this run. |
| `fail` | At least one evaluated assertion disagreed with the contract. |
| `error` | Execution or evaluation did not complete reliably. |
| `inconclusive` | Required evidence was unavailable; a blocked dependent request was not sent. |

These controls reduce misleading conclusions from expired credentials, absent fixtures and stale test data. They do not establish that credentials remain valid for every endpoint or that the target remained unchanged between requests. See the [contract format](contract.md) and [matrix workflow](matrix.md).

## Policy-as-Code and Evidence-as-Code

Contracts, reviewed matrices, evaluator configurations, reports and graph snapshots are machine-readable artifacts. Stable digests bind observations to their execution configuration; trace records connect relationships to their controls. JSON supports automation, JUnit supports CI result ingestion, and standalone HTML supports human review.

The intended workflow is one reviewable change set: update a contract or policy, inspect the affected relationships, execute the authorized checks, verify the evidence and compare with the baseline. Credentials remain environment references. Reports redact raw response bodies, response headers and resolved credentials; target paths and case metadata still require an appropriate sharing decision.

## Explainable AI Authorization Reasoning

Deterministic graph explanations are the primary explanation layer. An optional, locally configured Ollama model can add advisory interpretation grounded in relationship references. The operator controls whether that local endpoint is used and which model is available.

AI advice cannot approve a target, change a contract, release a blocked request, alter a verdict or classify a failed control as a successful denial. Model availability and advice remain separate from evidence correctness. Every proposed explanation must be reviewed against its cited relationship and original checks. No model download or external AI service is required for the default workflow.

## Continuous Authorization Assurance

`assure` executes the explicit contract, reconciles its observations with the configured policy layer and can record the result in local history. `watch` repeats authorized assurance within a declared iteration, interval and request budget.

This is bounded, synchronous continuous testing. It does not install a daemon, schedule future jobs after the process exits or enforce the target's authorization decisions. A zero-trust assurance practice here means checking declared boundaries repeatedly and treating missing evidence as missing. Assurance applies to the configured scope and completed observation windows.

SQLite history supplies a local sequence of recorded runs with a verifiable hash chain. It supports inspection and change review. The history remains writable by its operator: independent retained anchors are needed to detect replacement or truncation that also rewrites the local chain. It is not immutable storage.

## Pentester Superpowers

| Workflow | Product behavior |
| --- | --- |
| Authorization map | Build an inspectable graph from a declared contract, optional evaluator and verified report. Unknown and unobserved relationships stay visible. |
| Instant Proof | Follow a relationship to its exact assertion result, prerequisites and evidence references. Strong assertions make the record useful; the label does not imply formal proof of application security. |
| Evidence Packages | Export a manifest-bound package signed with Ed25519 and verify it independently against an externally trusted public key. |
| Selective retest jobs | Select failed or changed case IDs and include their prerequisite closure. Preview the plan before executing; retain the resulting evidence for comparison. |

The Retest-as-a-Service capability in 1.0 is a local job workflow exposed through Studio and CLI. Studio jobs belong to the running local session. There is no hosted service, customer account, remote execution fleet or commercial service-level commitment.

A selective retest creates a smaller contract with its own digest and retains the source-contract reference in its plan. Strict report comparison requires a baseline for that same selected contract; a full-scope baseline and a subset report are not interchangeable.

## Signatures and independent verification

Signing uses Ed25519 through an installed OpenSSL executable. The default testing workflow does not require OpenSSL; signing and signature verification do. Keep private keys outside shared evidence directories and source control.

A package's manifest binds its included evidence files. The verifier checks those files, their integrity and the signature against the public key supplied by the recipient. The trust decision must come from outside the package: an included public key cannot establish its own identity.

Successful verification establishes that the checked package matches the signed material and the supplied trusted key. It does not prove that HTTP requests occurred, that the runner was uncompromised, that the recorded time is independently attested or that the tested application is secure. The package can be checked using its standalone verification path without launching Studio.

The standalone verifier checks the cryptographic package protocol. AuthzLedger's own verifier additionally checks report semantics and declared prerequisites. Authentic signed bytes can still contain a logically invalid assertion by their signer; see the [signature protocol and verifier boundaries](signatures.md).

## Studio and CLI are equal interfaces

Studio offers the guided local workflow: reviewed scope, control-aware execution, graph inspection, policy/observation disagreements, history, advisory explanations, selective retests and evidence export. The CLI exposes the same core operations for reviewable scripts and CI. No feature should depend on an AI conversation to operate.

| Command | Purpose |
| --- | --- |
| `matrix`, `import-openapi`, `plan`, `run` | Prepare and execute explicit scoped checks. |
| `graph`, `explain` | Reconcile the layers and inspect deterministic or optional AI advice. |
| `policy-diff`, `diff`, `intelligence-diff` | Review policy migration, strict retests and graph evolution. |
| `assure`, `watch`, `history` | Record bounded assurance and inspect local run history. |
| `retest` | Preview a selected dependency-complete retest; execute only with explicit opt-in. |
| `keygen`, `bundle`, `verify-bundle` | Create keys, sign evidence and verify against a trusted public key. |

Illustrative commands below assume an authorized, available target and operator-supplied `authorization.json` and `policy.json`. Refer to each command's `--help` for its supported options.

```sh
python -m authzledger run authorization.json --out artifacts/current
python -m authzledger graph authorization.json --report artifacts/current/report.json --policy policy.json --out artifacts/graph.json
python -m authzledger explain artifacts/graph.json --out artifacts/explanation.json
python -m authzledger retest authorization.json --case cross-user-denied --out artifacts/retest-plan.json
```

The selected case ID must exist in the supplied contract. The last command plans without sending requests; `--execute` requests execution and an output directory. Optional AI advice uses `explain --ai-config CONFIG`. A signing workflow uses paths chosen by the operator:

```sh
python -m authzledger keygen --private signing-private.pem --public signing-public.pem
python -m authzledger bundle artifacts/current/report.json --key signing-private.pem --contract authorization.json --graph artifacts/graph.json --out artifacts/signed-evidence
python -m authzledger verify-bundle artifacts/signed-evidence --public-key signing-public.pem
```

The public-key path in the final command must resolve to a key the recipient independently trusts.

Attaching a graph requires its exact `--contract`; the signing command verifies the graph against that contract and the report before packaging. An optional explanation attachment must match the graph's source. These source checks supplement cryptographic authentication of the exported bytes.

## Competitive position

The opportunity is a coherent authorization engineering workflow: reviewed boundaries, separately evaluated policy, controlled observations, change intelligence and independently verifiable evidence. Established tools already perform important authorization testing; the distinction must be demonstrated on the same declared scenarios.

| Tool | Documented authorization capabilities | AuthzLedger's focused position |
| --- | --- | --- |
| [Burp Suite](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/access-controls/horizontal-access-controls) | Manual requests and automated Site Map replay under different sessions. [Privilege escalation testing](https://portswigger.net/burp/documentation/desktop/testing-workflow/vulnerabilities/access-controls/privilege-escalation) covers higher-privilege functionality. | Turn a selected boundary into a versioned contract, reconcile policy and observation, and retain control-aware retest evidence. |
| [AuthMatrix](https://github.com/PortSwigger/auth-matrix) and [Autorize](https://github.com/PortSwigger/autorize/blob/master/README.md) | Role/request matrices, replay, configurable enforcement detection; AuthMatrix also documents regression configuration and dependency chains. | Make the full contract–policy–observation–verification chain the product workflow. A matrix, one-click run or dependency chain alone is not a new invention. |
| [ZAP Access Control Testing](https://www.zaproxy.org/docs/desktop/addons/access-control-testing/) | Allowed/Denied/Unknown rules, inherited URL rules, user-by-URL tests, reports and API access. | Review differences between separate intent, evaluator and observation layers, retaining control provenance and signed evidence packages. |
| [Nessus Expert](https://docs.tenable.com/nessus/Content/WebApplicationScanning.htm) / Tenable WAS | Web scanning, [session validity checks](https://docs.tenable.com/web-app-scanning/Content/WAS/Scans/WebAppAuthentication.htm), and concrete [IDOR checks](https://www.tenable.com/plugins/was/114467). | Assess an application's explicitly declared authorization contract and its evolution, beyond identifying a known vulnerable component. |

Official sources reviewed on 9 October 2026. This comparison describes documented functions, not an exhaustive audit of every product edition or extension. Comparative speed, accuracy and coverage claims require published, reproducible measurements. A local fixture corpus demonstrates configured behavior; it does not establish universal superiority or a world-first claim.

## Product boundaries

AuthzLedger 1.0 is a local, single-operator workbench. Studio uses a loopback session boundary; it is not a multi-tenant production server. The matrix interface retains its explicit GET/JSON scope; the underlying contract workflow supports its documented methods and assertions. Mutating requests require explicit opt-in, and even a GET can have side effects.

No subscription, billing, hosted multi-user service, live endpoint discovery or independent security certification is implied. Use isolated test identities, explicit authorization, controlled fixtures, request budgets and an outer process timeout where needed. Repository visibility does not change the [existing rights and permissions](../LICENSE).

See the [release acceptance and launch plan](launch-1.0.md), [security model](security-model.md) and [validation record](validation.md) for execution limits, trust boundaries and recorded verification.
