# Demo C: 100 baseline cases, 10 retest requests

Run from the matching source checkout with Python 3.10+ and OpenSSL:

```sh
python3 tools/check_selective100.py --out /tmp/authzledger-selective100-new
```

The output directory must not exist. The runner starts a synthetic service on
`127.0.0.1`, generates temporary credentials, and executes the same experiment
services used by the CLI and Studio. It imports no test modules.

| Stage | Application requests | Identity control | Object control | Negative control | Total |
| --- | ---: | ---: | ---: | ---: | ---: |
| Baseline | 97 | 1 | 1 | 1 | 100 |
| Selected retest | 7 | 1 | 1 | 1 | 10 |
| Complete demonstration | 104 | 2 | 2 | 2 | 110 |

Every other request category (`pdp`, `setup`, `state_probe`, `replay`, `reduction`,
`cleanup`, `advisory`) is explicitly zero in the retained ledger. Starting and
stopping the in-process fixture does not make setup/cleanup HTTP requests.

Seven declared query variants share one synthetic resource, identity and rule.
The baseline returns the protected marker inside HTTP 403 responses. The fixture
then removes that marker. The retest repeats the seven variants with three fresh
prerequisite controls. The comparison retains the other 90 cases as
`not_retested`; their historical results cannot establish current protection.
The selected transitions become `fix_verified` only for the configured
rule/resource/identity bindings with valid controls.

The original baseline file is written once before the retest. Its bytes and
evidence root are checked afterward. This is preservation of retained evidence,
not a claim that the filesystem is immutable. The 100-to-10 result is request
accounting for this fixture, not a general speedup measurement.

The fixture stops before comparison, signing and independent verification.
The runner signs the retained assessment, exact HTML/PDF renderings, comparison
and request receipts using a fresh temporary Ed25519 key. It removes the private
key and retains the public key. No credentials or private keys are exported.

From the generated output directory:

```sh
sha256sum --check SHA256SUMS
python3 -I verify_bundle.py proof --public-key trusted-public.pem
python3 -m authzledger verify-bundle proof --public-key trusted-public.pem
```

The standalone verifier checks the signature, exact inventory, hashes and report
anchors. AuthzLedger's main verifier additionally reconstructs retained
execution/oracle/finding/fix semantics and exact assessment renderings.
`proof.zip` transports the same package; extract it into a new directory before
verification. No application service is required for either verifier.

The generated key is a demonstration trust anchor. It does not independently
authenticate a producer, and a signature does not prove remote execution truth.
For real assessments, obtain the producer's key fingerprint through a separate
trusted channel. Local server receipts are measurements by the demonstration
runner, not third-party attestations.

`acceptance.json` records verifier outcomes, version, roots, archive hash and
key fingerprint. `request-receipts.json` contains the full per-category counts
and sanitized server-observed requests. Open `comparison.html` for all 100 case
transitions, and `assessment.html` or `assessment.pdf` for findings and limits.
Fresh ports, timestamps, credentials and signing keys mean a reproduction has
different hashes; the counts and scoped transitions remain reproducible.
