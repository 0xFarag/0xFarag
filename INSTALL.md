# Install and reproduce AuthzLedger 1.5

**Development candidate instructions.** No stable release or live 1.5 download is asserted. Use the exact candidate wheel/source selected by the release owner and preserve its producer version and hash. Final publication requires the [1.5 release gates](docs/release-1.5.0.md). Historical 1.1.0 documentation and evidence remain under their original versioned paths.

Use is subject to [LICENSE](LICENSE), [NOTICE.txt](NOTICE.txt) and any separately agreed permissions. Publication does not grant a general commercial licence.

## Requirements

Python 3.10+ and `venv`; OpenSSL with Ed25519 support for signing and both signature verifiers. The development environment is Linux / CPython 3.12; this is not certification of every operating system. Core execution, JSON and HTML use the Python standard library. PDF and the complete `demo150` command require `reportlab==4.4.9`, available through the `reports` extra. Bundled Unicode fonts retain their own licence notices.

The authored loopback labs need no administrator privileges, external credentials or paid service. Product execution is local; active work contacts only the explicitly approved targets.

## Run from the candidate checkout

From the supplied source directory:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install '.[reports]'
python -c 'import authzledger; print(authzledger.__version__); print(authzledger.__file__)'
python -m authzledger studio --open
```

A preparation branch may change. Record the exact commit for evidence and prefer checksummed immutable release assets once publication is complete. Do not silently label a development wheel as `1.5.0`.

## Install a wheel outside the checkout

Create a new working directory outside the repository. Replace the wheel filename with the exact downloaded or locally built candidate asset; its current development version may include `dev0`:

```sh
mkdir authzledger-work
cd authzledger-work
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-index --no-deps /absolute/path/to/candidate.whl
python -m pip install 'reportlab==4.4.9'
python -I -c 'import authzledger; print(authzledger.__version__); print(authzledger.__file__)'
```

The printed producer must match the tested asset and its module must resolve inside the new environment. `candidate.whl` is a placeholder: use the actual valid wheel filename. For offline installation, prepare a trusted wheelhouse and replace the ReportLab installation with `python -m pip install --no-index --find-links /path/to/wheelhouse 'reportlab==4.4.9'`.

When verified release assets and their checksum list exist, keep them together and run `sha256sum -c SHA256SUMS.txt`. Authenticate that checksum list or its delivery channel separately. A checksum list beside files detects corruption but is not publisher authentication on its own.

## Reproduce A/B/C and independently verify the proof

Copy the release's `verify_bundle.py` to a path outside the source checkout. Every output directory must be new:

```sh
python -I -m authzledger assessment demo150 --out platform150-demo \
  --standalone-verifier /absolute/independent/verify_bundle.py
python -I -m authzledger assessment verify platform150-demo/C-retest-proof/snapshot.json
python -I -m authzledger verify-bundle platform150-demo/C-retest-proof/proof \
  --public-key platform150-demo/trusted-public.pem
python -I /absolute/independent/verify_bundle.py platform150-demo/C-retest-proof/proof \
  --public-key platform150-demo/trusted-public.pem
```

From a source checkout, the command can find `tools/verify_bundle.py` automatically. The separate gate wrapper is `python tools/check_platform150.py --out artifacts/platform150-proof`; it also accepts `--standalone-verifier`.

| Output | Evidence |
|---|---|
| `A-authorization/` | Real contrast execution, bounded reduction and negative/control cases |
| `B-discovery-detect/` | Real bounded HTTP discovery plus one explicit TCP probe, followed by the configured header check |
| `C-retest-proof/` | Baseline/current/comparison with `fix_verified` and `not_retested`; valid proof and separately labelled tampered copy |
| `assessment-workspace.sqlite3` | Local retained assessment artifacts reopened and checked by the demo |
| `results.json` | Actual producer/runtime, timing, operation counts, limits and verification results |

Each demo contains typed source artifacts, a frozen snapshot and rendered reports. The fixture listeners stop before export/signing. The command generates a temporary signing key, deletes its private half, retains only the public demo key and requires a one-byte modified copy to fail both verification paths. The original valid proof remains unchanged. The public demo key establishes internal consistency, not independently authenticated publisher identity.

HTTP request counts and service-connection counts are distinct. Their sum in `network_operations_observed` is not an independently measured HTTP connection count. Exact counts and timings come from that run's receipts; these synthetic examples are not production performance measurements.

The legacy `assessment demo` and versioned acceptance scripts remain available for baseline regression. Their output paths, request counts and producer profiles are separate from `demo150`.

## Persistent Studio and ephemeral sessions

```sh
python -I -m authzledger studio --open
python -I -m authzledger studio --history ./engagement.sqlite3 --open
```

Choose one invocation. The default path is `~/.authzledger/history.sqlite3`; `--history` selects another local file. Studio binds loopback, chooses a free port and prints a private session URL. Keep the full token-bearing URL private. Stop with Ctrl+C and restart with the same database to reopen retained platform assessments. Existing legacy history shares the database through separate tables.

To explicitly avoid retaining a workspace:

```sh
python -I -m authzledger studio --session-only --open
```

Export needed evidence before closing a session-only server. Runtime credential values never become workspace settings, even with persistence. Rebind credentials after restart. Interrupted network jobs require review and are not replayed automatically. The local database is not an encrypted secret store or a multi-user service.

## Create and use a scoped assessment

Review a `ScopePolicy` JSON file before creating an assessment. It includes `schema_version: 1`, `kind: "assessment-scope"`, an ID, `authorization_ref`, explicit origins, exact operations, allowed CIDRs, UTC expiry, allowed effects and request/concurrency/timeout/response-byte limits. Operation fields are `origin`, `method`, `path`, `purpose` and optional explicit `effect`. See the [suite scope contract](docs/suite-1.5.0.md#rules-of-engagement-and-transport). Discovery metadata is not execution authorization.

```sh
python -I -m authzledger assessment create --store engagement.sqlite3 \
  --title 'Authorized API assessment' --scope reviewed-scope.json
python -I -m authzledger assessment list --store engagement.sqlite3
python -I -m authzledger assessment registry
```

Use the returned assessment ID in subsequent commands. The following uppercase identifiers are placeholders to replace with actual retained IDs/digests; plans are reviewed before running:

```sh
python -I -m authzledger assessment surface-import ASSESSMENT_ID capture.har \
  --store engagement.sqlite3 --format har-1.2
python -I -m authzledger assessment discover-plan ASSESSMENT_ID \
  --store engagement.sqlite3 --seeds reviewed-seeds.json --out discovery-plan.json
python -I -m authzledger assessment discover-run ASSESSMENT_ID PLAN_ARTIFACT_ID \
  --store engagement.sqlite3 --approve EXACT_PLAN_DIGEST
python -I -m authzledger assessment check-plan ASSESSMENT_ID reviewed-check.json \
  --store engagement.sqlite3 --out check-plan.json
python -I -m authzledger assessment check-run ASSESSMENT_ID PLAN_ARTIFACT_ID \
  --store engagement.sqlite3 --approve EXACT_PLAN_DIGEST
```

`discover-plan` and `check-plan` return retained artifact envelopes; inspect the artifact ID and its plan's digest. `check-retest-plan`, `check-retest-run`, `playbook-plan`, `playbook-run`, `delta`, `knowledge`, `schedule` and `run-due` expose the other supported workflows. `--help` lists each command's arguments. Finite schedules run only when explicitly invoked; they do not install a daemon. A plan is not permission to expand scope.

### Offline result and native traffic imports

`surface-import` supports `burp-xml`, `burp-http-pair-v1`, `zap-json-plus`, `har-1.2`, `nmap-xml-v1` and `nuclei-jsonl-v1`. The selected Nmap/Nuclei profiles are offline adapters, not scanner launchers, and all imported assertions remain source hints. Native compatibility applies only to retained verified profiles; refer to the [adapter profile](docs/adapters-1.5.0.md).

For the native Burp raw-pair profile, save complete request and response messages and supply exact capture origin metadata:

```sh
python -I -m authzledger assessment surface-import ASSESSMENT_ID burp-request.http \
  --store engagement.sqlite3 --format burp-http-pair-v1 \
  --source-origin https://api.example.test --response burp-response.http
```

The response is optional. Origin metadata does not authorize execution. Burp XML containing a DTD remains rejected; the separate Nmap root-declaration profile does not change Burp's parser. Historical unchanged native Burp/ZAP/HAR evidence is described in [the exporter record](docs/exporter-gate-1.1.0.md) and [raw Burp addendum](docs/burp-native-import-v1.md).

## Freeze, report and sign

```sh
python -I -m authzledger assessment freeze ASSESSMENT_ID --store engagement.sqlite3 --out snapshot.json
python -I -m authzledger assessment verify snapshot.json
python -I -m authzledger assessment report snapshot.json --out reports
python -I -m authzledger keygen --private operator-private.pem --public operator-public.pem
python -I -m authzledger assessment bundle snapshot.json --key operator-private.pem --out proof
python -I -m authzledger verify-bundle proof --public-key operator-public.pem
python -I /absolute/independent/verify_bundle.py proof --public-key operator-public.pem
```

Use fresh output paths. Supply a separately authenticated public key for real handover. The standalone verifier checks signature, inventory, hashes and anchors without importing AuthzLedger. The main verifier adds supported retained semantics and exact renderer checks. Neither proves that the remote application was honestly observed, confers legal authorization or provides a trusted timestamp.

## Development and release gates

```sh
python -m unittest discover -s tests -v
python tools/check_platform150.py --out artifacts/platform150-proof
python -m pip wheel --no-deps --no-build-isolation --wheel-dir dist .
```

The integrated candidate gate executes and records the complete prescribed checks:

```sh
python tools/verify_release150.py --out artifacts/release150
python tools/release_gate150.py --receipt-dir artifacts/release150 --allow-development
```

Use a new output directory. `--allow-development` validates candidate receipts and does not authorize stable publication. The stable publication gate uses `--publication` against the exact clean tracked commit after the stable version is set; it must not be substituted with the development flag. `verification.json` records executed commands, outcomes, runtime and log hashes rather than deriving success from a feature list.

Use the pinned build dependencies in `pyproject.toml`. The release owner also runs the existing regression/acceptance scripts, historical proof verification, all eight browser suites including `tests/browser_platform150.cjs`, the outside-checkout wheel gate, final exact-version CI and verified publication checks. Browser tests need their documented Playwright/Chromium environment; those are development dependencies, not product dependencies. A missing browser or skipped suite is an unresolved gate, not a pass.

See [S15-01 through S15-30](docs/suite-1.5.0.md#7-one-release-priorities-and-acceptance-gates) for the required evidence and [the release record](docs/release-1.5.0.md) for final status discipline. This document supplies commands; it does not assert they have all passed on a stable build.
