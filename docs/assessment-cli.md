# Assessment workflow: shared services, explicit plans, retained proof

The 1.1.0 development integration uses the released v1 HTTP engine. Every request, including controls and workflow cleanup, passes through `ExecutionContext`. The CLI below calls the same services as Studio; planning, inspection, report generation and verification do not contact assessment targets.

## Reproduce the three demonstrations

```sh
python3 -m pip install '.[reports]'
python3 tools/check_assessment.py --out artifacts/assessment-proof
python3 tools/check_workflows110.py --out artifacts/workflow-proof
```

Both destinations must be new. The first command runs real requests against a synthetic authenticated two-tenant loopback service. It stops that service before rendering and verifying proof. The second checks isolated workflow transitions and replay effects, including fresh-fixture mutating reduction.

| Demo | Positive proof | Counterexample that must remain visible |
|---|---|---|
| Request → finding → reproducer | A synthetic Burp-format request exposes the exact protected invoice marker to the peer; explicitly selected unnecessary headers are removed with fresh controls for every attempt | Original execution is retained; 1-minimal means only within the approved removable units |
| 403 disclosure and control validity | Protected content in a 403 response confirms disclosure with valid principal/object/denial controls | The same target with an invalid principal control is inconclusive; a 200 error object without protected content is rejected |
| Selective retest and independent proof | A selected, freshly controlled rule becomes `fix_verified`; JSON/HTML/PDF bytes are signed | An omitted finding stays `not_retested`; original report roots stay intact; the standalone verifier does not independently establish execution truth |

The authored import is a parser and workflow fixture, not a capture produced by a certified third-party Burp installation. Exact export-profile compatibility is a separate acceptance gate.

Files in `assessment-proof` include the import projection, bindings, deterministic plans, original executions, reduction trace, source-bound comparison, immutable snapshots, three report formats, proof inventory and a public verification key. The temporary private key is deleted. The fixture credentials are not retained. `results.json` records measured request counts and status outcomes; wall-clock speed and manual-time savings are not inferred from request reduction.

To verify a supplied package, obtain its trusted public key through a separate verified channel. A public key included with untrusted evidence does not identify its author.

```sh
python3 -m authzledger verify-bundle artifacts/assessment-proof/proof --public-key artifacts/assessment-proof/trusted-public.pem
python3 -I tools/verify_bundle.py artifacts/assessment-proof/proof --public-key artifacts/assessment-proof/trusted-public.pem
python3 -m authzledger assessment verify artifacts/assessment-proof/03-selective-retest-proof/snapshot.json
```

The main verifier additionally checks retained assessment semantics and exact report renderings. The standalone verifier checks signature, inventory, hashes and report anchors without importing AuthzLedger. Neither establishes a truthful remote execution independently of the retained evidence and signer.

## Import and compile an authorised assessment

```sh
python3 -m authzledger assessment import traffic.har --format har-1.2 --out imported.json
python3 -m authzledger assessment mapped-plan imported.json bindings.json --entry ENTRY_ID --out experiment-plan.json
```

Supported profile names are `burp-xml`, `zap-json-plus` and `har-1.2`. [Profile boundaries and redaction](../fixtures/imports/README.md) are part of the interface. Imported observations and scanner findings never become confirmed findings by import alone.

`bindings.json` declares the exact origin, actor/owner identities, credential references, principal/tenant assertions, owner resource marker, known-denial control and rule. The demo's `01-import-to-reproducer/bindings.json` is a concrete schema example with a stopped synthetic target. Adapt a fresh specification to the authorised application; do not rewrite historical executions or comparison sources.

For redacted public query/body fields, supply `--mapping mapping.json`. This maps explicit slot IDs to `{"literal": value}` or `{"omit": true}`. Credential slots never accept literals. A remapped entry has its own identity and mapping receipts, and retains its source entry reference. Header credentials use the existing environment references in CLI or origin-/identity-scoped server session bindings in Studio.

Alternative: compile a complete explicit experiment specification:

```sh
python3 -m authzledger assessment plan experiment-spec.json --out experiment-plan.json
```

Review the exact plan, variant identities, prerequisite closure, mutation permissions, origin and request upper bound. The plan compiler prints `plan_digest`. Running requires that exact digest, not a generic yes flag:

```sh
python3 -m authzledger assessment run experiment-plan.json --approve REVIEWED_PLAN_DIGEST --out new-execution
python3 -m authzledger assessment inspect new-execution/execution.json --finding FINDING_ID
```

Provision referenced credentials through the process environment or Studio credential controls. Do not embed values in contracts, command arguments, URLs or report annotations. Runtime response projections containing known resolved credentials are redacted and become inconclusive. An arbitrary unknown string cannot be guaranteed secret-free by pattern matching; only intentionally public oracle values should use `safe_values` capture.

The default `attested` capture mode does not retain oracle values. `safe_values` can replay the predicate against its retained projection. It does not prove that the projection came from the original response solely from a body hash. Control and report contradictions are rejected in both modes.

## Reduce without losing the original proof

Select explicit removable units from the investigation in Studio, or create a JSON array for the CLI. Examples are `{"kind":"header","case_id":"variant-peer-1","name":"accept-language","occurrence":0}` and `{"kind":"query","case_id":"variant-peer-1","name":"verbose","occurrence":0}`. JSON units use `kind:"json"` and a JSON `pointer`. Protected identity, credential, resource and control bindings cannot be selected.

```sh
python3 -m authzledger assessment reduction-plan new-execution/execution.json selected-units.json --max-requests 40 --out reduction-plan.json
python3 -m authzledger assessment minimize reduction-plan.json --approve REVIEWED_REDUCTION_DIGEST --out new-reduction
```

Every candidate executes fresh controls and the same rule. Mutating reductions require a verified workflow trace with a fresh isolated fixture and cleanup on every attempt. Budget exhaustion preserves the last accepted candidate and reports `reduced; minimality not confirmed`, or `no confirmed reduction; minimality not confirmed` when no candidate was accepted. Only the completed final single-removal and repeatability gate permits the bounded `1-minimal` label.

## Retest only the selected relationships

```sh
python3 -m authzledger assessment retest-plan new-execution/execution.json --variant peer-1 --out retest-plan.json
python3 -m authzledger assessment run retest-plan.json --approve REVIEWED_RETEST_DIGEST --out retest-execution
python3 -m authzledger assessment compare new-execution/execution.json retest-execution/execution.json --out comparison.json
```

The current plan must be the exact source-derived variant/control subset. A different rule, principal binding or resource context cannot be presented as the same finding's fix. Missing selected evidence stays inconclusive, and omitted variants stay historical. `ComparisonEnvelope` keeps check-level transitions; the experiment comparison adds rule-level fix status with fresh controls.

Change-based planning uses declared dependencies:

```sh
python3 -m authzledger assessment impact-plan source-contract.json changes.json --impact-map declared-impact.json --out impact-plan.json
```

A change record contains `kind`, `id`, `before_digest`, `after_digest`; `declared-impact.json` maps `kind:id` to explicit case IDs. Unknown dependencies select full scope with a reason. Planning does not imply complete knowledge of application code or data dependencies.

## Workflow Contracts

```sh
python3 -m authzledger assessment workflow-plan workflow-spec.json --out workflow-plan.json
python3 -m authzledger assessment workflow-run workflow-plan.json --approve REVIEWED_WORKFLOW_DIGEST --out workflow-execution
```

`authzledger.lab110.workflow_spec(origin)` supplies a concrete isolated fixture specification. Short workflows declare setup, precondition, steps, independent postcondition, cleanup and typed bindings. A replay rule requires a stable operation key and an independently read effect count. Two successful HTTP responses alone do not prove duplicated effects. A lease reserves the complete sequence and cleanup before mutation; failed cleanup or reused/unknown fixture state prevents confirmation.

## Finite Workflow Assurance with durable history

Assurance runs an explicit workflow for a finite number of cycles. Each cycle creates its own fixture and independently probes its state; every control, setup, action, probe and cleanup consumes the same global request budget. It stops on a violation, inconclusive result, cleanup failure, cancellation, history failure or budget exhaustion. There is no background discovery or implied observation between cycles.

Create the following concrete assurance specification from the reviewed `workflow-spec.json` used above:

```sh
python3 - <<'PY'
import json
from pathlib import Path
workflow = json.loads(Path("workflow-spec.json").read_text(encoding="utf-8"))
spec = {
    "schema_version": 1,
    "kind": "workflow-assurance-spec",
    "workflow": workflow,
    "max_cycles": 2,
    "interval_seconds": 0,
    "max_requests_total": 12,
    "max_history_age_seconds": 300,
}
with Path("assurance-spec.json").open("x", encoding="utf-8") as output:
    json.dump(spec, output, indent=2, ensure_ascii=True, allow_nan=False)
    output.write("\n")
PY
python3 -m authzledger assessment assurance-plan assurance-spec.json --out assurance-plan.json
```

This budget fits the supplied skip-approval lab workflow: six requests per cycle, two cycles and two explicitly reserved cleanup requests in total. Review the compiler's `cycle_request_upper_bound`, `budget_cycles`, `request_upper_bound`, `cleanup_reserve` and `plan_digest`. A different workflow may require a larger approved budget. If the first complete cycle does not fit, planning fails offline. If fewer than all requested cycles fit, the plan exposes that limit and an eventual budget stop is inconclusive.

```sh
python3 -m authzledger assessment assurance-run assurance-plan.json --approve REVIEWED_ASSURANCE_PLAN_DIGEST --history assessment-history.sqlite3 --out assurance-execution
python3 -m authzledger assessment verify assurance-execution/execution.json
python3 -m authzledger assessment snapshot --assurance assurance-execution/execution.json --id engagement-01 --title 'Finite workflow assurance' --out assurance-snapshot.json
python3 -m authzledger assessment report assurance-snapshot.json --formats html pdf json --out assurance-report
python3 -m authzledger assessment bundle assurance-snapshot.json --key operator-private.pem --out assurance-proof
```

`REVIEWED_ASSURANCE_PLAN_DIGEST` is the exact digest printed by the preceding compile command. A mismatched approval sends no requests and creates neither an execution directory nor a history database. Result, snapshot, render and verification commands preserve the original cycle traces and report roots. `snapshot --assurance` retains the assurance result, its cycle traces and history receipts; it does not require separately passing each cycle through `--workflow`. It can be combined with other executions, comparisons and reductions in one assessment.

| Setting | Meaning and supported bound |
|---|---|
| `max_cycles` | Explicit finite count, 1–100. This is an upper bound, not a promise that failed prerequisites will be retried. |
| `interval_seconds` | Wait between successful cycles, 0–3,600 seconds. The application remains unobserved during that interval. |
| `max_requests_total` | One global budget, 1–100,000 attempts, including failed I/O, all controls and cleanup. It is not reset between cycles. |
| `max_history_age_seconds` | Maximum age of the latest retained record for this fixture scope, 0–31,536,000 seconds. Checked before target traffic and again before every cycle. |

History is mandatory. The service verifies the existing v1 history chain and its additive workflow chain before sending any request, then appends each completed cycle with its original trace and hash-chain receipt. Reopening the same database reuses the retained fixture registry. Its scope key binds the origin, setup method/path and fixture selector/type; renaming a workflow or rule does not erase prior fixture identity. A reused identifier is stopped before subsequent state probes/actions, with approved cleanup attempted. Independent origins or setup scopes have separate fixture registries, while integrity of the shared database is still checked as a whole. Concurrent history changes invalidate the reviewed history tail and stop the run.

An empty verified history permits a first run. A stale record, a timestamp more than five seconds in the future, a broken chain or missing append-only protection prevents a new cycle. Set the age bound deliberately for the approved interval and retained evidence; it does not establish a trusted clock or protect against complete replacement of every local anchor. Intervals, requested-but-unrun cycles and stop reasons remain explicit. Workflow state values stay `evaluation_attested` when raw response bodies are not retained.

Known resolved credentials are pinned for the workflow's reviewed origin/identities. Reflected credential values, including common URL-encoded and base64 forms, are rejected before becoming fixture identifiers or retained request bindings. This can leave cleanup pending when safely identifying the created object is impossible; the trace does not claim rollback or a confirmed finding.

## Freeze, report and sign

```sh
python3 -m authzledger assessment snapshot new-execution/execution.json retest-execution/execution.json --comparison comparison.json --reduction new-reduction/execution.json --metadata reviewed-report-metadata.json --id engagement-01 --title 'Tenant isolation assessment' --out snapshot.json
python3 -m authzledger assessment report snapshot.json --formats html pdf json --out assessment-report
python3 -m authzledger assessment bundle snapshot.json --key operator-private.pem --out assessment-proof
```

Add `--workflow workflow-execution/execution.json` for workflow traces. Metadata permits reviewer, executive summary, explicit scope/period/limitations and finding annotations for impact, remediation, business risk, reviewed CVSS 4.0 vectors and evidence-linked standard mappings. It cannot override finding/control/retest status. An inconclusive retest cannot erase a historical confirmed finding. See the [report profile](reporting-profile-1.1.0.md) for precise lifecycle states, pinned standards and renderer requirements.

Every output destination must be new. Original execution reports and Evidence-Roots remain unchanged. The package binds the actual `assessment.json`, `assessment.html` and `assessment.pdf` files. Re-exporting later creates another artifact; it does not modify an already signed package.

## Exit behaviour

`run` and `workflow-run`: `0` conclusive configured satisfaction, `1` confirmed violation, `2` invalid configuration or inconclusive execution. `assurance-run`: `0` only when every requested cycle completes with configured satisfaction; `1` on a confirmed violation (further cycles stop); `2` on an incomplete, cancelled, budget-limited or invalid run, including history/cleanup failures. Completed cycle evidence remains available when the runner returns a result. A preflight failure has no fabricated execution evidence. `minimize`: `0` completed bounded minimality gate, `2` incomplete/inconclusive reduction; the last proven candidate is still exported. Offline commands return `2` for rejected input or verification. No exit status means the entire application is secure.
