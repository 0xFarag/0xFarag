# CI integration

Run AuthzLedger against an explicitly authorised test deployment with stable fixture data. Use dedicated identities and secret-store values. Protect jobs that receive credentials from untrusted pull-request code and contract changes. Set a CI job timeout as an outer execution bound, including setup and host name resolution.

## Minimal job

After checking out the repository and selecting Python 3.10 or later:

```sh
pip install -e .
python -m authzledger plan authorization.json
python -m authzledger run authorization.json --out artifacts/current
```

Provide every environment variable named by the contract through the CI secret store. Each value must contain the complete intended header value. Do not print those values or enable shell tracing around credential handling.

Configure artifact collection to run even when the check step fails. Publish `artifacts/current/report.json`, `report.html` and `junit.xml` to an access-controlled job artifact store. Configuration failures can occur before these files exist.

For a shell script that must collect artifacts before returning the runner's exit code:

```sh
set +e
python -m authzledger run authorization.json --out artifacts/current
check_status=$?
set -e

# Invoke your CI provider's artifact collection here, when files exist.
exit "$check_status"
```

Prefer the provider's always-run artifact step where available. Do not mask the check exit status with a later successful command.

## Gate behaviour

| Exit code | Recommended handling |
| --- | --- |
| `0` | Accept this configured check set. |
| `1` | Fail the authorization regression gate and inspect failed assertions. |
| `2` | Fail the gate; resolve configuration, runtime or prerequisite-control problems. |

JUnit maps `fail` to a failure, `error` to an error and `inconclusive` to a skipped test. A skipped test is not a pass. Review the JSON/HTML outcome and process exit code together.

## Verify and retain evidence

```sh
python -m authzledger verify artifacts/current/report.json
```

To verify against a trusted anchor supplied by your evidence process:

```sh
python -m authzledger verify artifacts/current/report.json --anchor "$EXPECTED_EVIDENCE_SHA256"
```

At capture time, the anchor is the root printed by the runner and stored as `evidence.root_sha256`. For later verification, `EXPECTED_EVIDENCE_SHA256` must come from an independently retained, trusted record, not a value read from the report being checked. An anchor records integrity relative to that value; it does not attest to an uncompromised runner.

Keep the contract, its version-control revision and fixture setup associated with the report. Restrict evidence access: target URLs, paths and identity names remain visible even though response bodies and resolved credentials are omitted.

## Retest a fix

1. Retain the initial report and contract.
2. Apply the application fix while keeping identities, fixture records and contract stable.
3. Run the contract again and verify both evidence bundles.
4. Generate a comparison:

```sh
python -m authzledger diff artifacts/baseline/report.json artifacts/current/report.json --out artifacts/comparison
```

Comparison rejects different contract digests or inconsistent report metadata, case-ID sets and case definitions. Target, name, schema version and tool metadata must match; each case must preserve its identity, method, path, prerequisites and control type. Version 1 keeps `added` and `removed` empty because every configured case must be present in both reports, including inconclusive cases.

If the contract, case set or tool metadata needs to change, review the change and establish a clearly identified new baseline. Do not describe a changed assertion set as a verified fix of the previous set.

Reaching `pass` from `fail` or `error` is reported as resolved; reaching `inconclusive` is not. Review the configured coverage and individual transitions before approving a release.

## Repository verification workflow

The repository includes `.github/workflows/tests.yml` for unit tests, the loopback demo, report verification and package installation. It uses Python 3.12 on Ubuntu, read-only repository permissions and pinned action revisions. This is workflow configuration, not a claim that the remote workflow has already passed. Check actual workflow results before treating a version as verified in your environment.

