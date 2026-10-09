# Local continuous assurance and retained history

AuthzLedger runs explicit authorization contracts, binds their results to a
Living Authorization Graph, and retains the complete context for the next
comparison. Continuous assurance is a finite local sequence of controlled
checks. It observes configured boundaries at execution time; intervals between
runs are unobserved. It does not replace authorization enforcement.

## One controlled run

```bash
authzledger assure authorization.json --policy policy.json \
  --history authorization-history.sqlite3 --out artifacts/assurance-001
```

The exact target, requests, credential environment references, expectations and
controls come from the contract. Policy input is independently supplied: local
rules or an explicitly scoped OPA endpoint. Omit `--policy` to inspect intended
and observed behavior with the policy layer explicitly unknown.

Execution order is deterministic:

1. Validate the contract and policy without sending requests.
2. Verify retained history and optionally reject a stale baseline.
3. Validate all application credentials before either network channel is used.
4. Evaluate independent policy once per case, then execute the application
   contract with its declared prerequisite gates.
5. Verify the sealed report, build and bind the graph, compare it with the latest
   retained run for the same name and exact target, and append its context.

OPA decisions precede the application observation within each iteration; they
are separate snapshots, not an atomic observation of deployed policy and
application state. A precomputed `policy-evaluation` supplied through the Python
API is an explicit static snapshot and causes no PDP requests. Use a policy
configuration for fresh policy evaluation in every watch iteration.

## Bounded watch

```bash
authzledger watch authorization.json --policy policy.json \
  --history authorization-history.sqlite3 --iterations 10 --interval 30 \
  --max-requests 120 --max-history-age 3600 --out artifacts/watch-001
```

`--iterations` is required. The watch is synchronous and bounded: 1–1000
iterations, a finite 0–3600-second interval and a total request budget of
1–1,000,000 requests. It reserves every configured application case before each
iteration, including requests later blocked by a failed prerequisite. With OPA,
one additional PDP request per configured case is reserved. No hidden refresh,
discovery or retry requests are issued. The conservative reservation can stop a
watch even if some reserved requests were never sent.

The first iteration must fit the total budget. Later budget exhaustion returns
code 2 and `request-budget`, preserving all completed results. The watch stops
on an authorization mismatch, policy/intent change, removed coverage, regression,
inconclusive comparison, invalid control, execution error, stale baseline or
history integrity failure. Credentials are reread for every iteration.

| Exit code | Meaning |
|---|---|
| 0 | All completed iterations passed the configured checks and comparison gates. |
| 1 | An authorization mismatch or conclusive authorization change needs review. |
| 2 | Error, ambiguous intent, invalid/unanchored controls, inconclusive comparison, stale history, cancellation or exhausted request budget. |

A status-only successful response establishes only that status check. A generic
HTTP 200 response does not establish access to protected data. Strong controls
should assert explicit, non-secret response fields and configure protected
fields that must be absent on denial. A negative case without a declared
positive prerequisite cannot establish assurance and returns code 2.

Every declared positive prerequisite must also establish its configured
content assertions: a status-only HTTP 200 login response leaves that control
unknown and returns code 2 with `unproven-positive-control`, even if the underlying
configured status checks all passed.

The Python `watch` API also supports a `threading.Event` for cooperative
cancellation and `on_iteration(index, result)` for progress. Cancellation stops
new iterations and interrupts the interval; requests already in flight retain
their configured deadlines. Ctrl+C stops the foreground CLI process. No hosted
daemon or externally operated retest service is started.

## Dependency-complete retest

```bash
authzledger retest authorization.json --case peer-denied-owner \
  --out artifacts/retest-plan.json
```

Planning sends no HTTP requests. The result lists selected IDs, additional
prerequisite IDs, exact request count and the resulting execution contract.
Selecting a negative boundary automatically includes the declared positive
controls and their transitive prerequisites. Only existing contract cases are
included. Unknown, duplicate and empty selections are refused.

```bash
authzledger retest authorization.json --case peer-denied-owner --execute \
  --policy policy.json --history authorization-history.sqlite3 \
  --out artifacts/retest-001
```

POST, PUT, PATCH and DELETE remain explicit opt-ins through `--allow-mutations`.
Check the dependency-complete plan before authorizing mutations: a selected
read-only case can depend on a mutating control. Reduced retest coverage is
reported as a coverage change against a fuller prior graph; it is not silently
treated as a complete assessment.

## Durable, verifiable history

```bash
authzledger history authorization-history.sqlite3 --limit 20
authzledger history authorization-history.sqlite3 --run 1 \
  --out artifacts/retained-run-001.json
```

SQLite commits retain the normalized contract with credential **references**,
sealed report and complete graph. A domain-separated SHA-256 chain binds the
run ID, creation time, preceding record hash and canonical complete context.
Every read and append verifies report integrity, graph integrity, source binding,
sequence consistency and the immutable chain. Updates and deletions are blocked
by SQLite triggers. Appends use `BEGIN IMMEDIATE` and `synchronous=FULL`.

New database files use mode 0600. Existing files with group/other access, symbolic
links, hard links or another owner are refused. Resolved application credentials
are never inserted; accidentally copied values from referenced credential
environments are rejected. Contracts, fixture bodies, assertions and configured
paths must themselves contain no secrets: this history is not encrypted.

Two distinct anchors are retained for each run:

| Field | Binding |
|---|---|
| `root_sha256` | Sealed evidence report root. |
| `record_sha256` | Complete history record and preceding chain. |
| `previous_sha256` | Prior history record, or 64 zeroes for the first run. |

Keep the latest `record_sha256` outside the database. The Python method
`verify_chain(expected_root_sha256=trusted_tail)` checks that external anchor.
Local checks detect edits, gaps and removed tail rows while SQLite sequence
metadata remains intact. An administrator able to replace the database and all
anchors can replace the whole history; hash chains do not prove execution,
authorship or a trusted timestamp. Signed evidence packages and a separately
trusted public key provide an additional provenance boundary.

The baseline lookup considers the latest 1000 retained runs and compares only
the same contract name and exact target. Use one database per assessed system
and retain the policy source in version control; graphs retain policy digests,
decision provenance and input fingerprints rather than raw credential-bearing
policy context. A concurrent append between baseline selection and this run's
commit is refused instead of binding the result to an obsolete history tail.

`examples/assurance.json` is a three-case invoice boundary fixture for an
authorized local API. Set its referenced credentials privately in your shell;
the file does not create or start that target. `authzledger demo` provides the
self-contained vulnerable/fixed loopback demonstration.
