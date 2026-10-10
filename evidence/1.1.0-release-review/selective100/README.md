# Demo C: selective retest and independent package

100 baseline cases were executed against a synthetic loopback fixture. Seven
explicit query variants of one protected resource were selected for retest.
The retest executed those seven cases plus three fresh prerequisite controls.
The other 90 cases remain `not_retested`. Total HTTP dispatches: 110.

The fixture stopped before offline comparison, signing and both verifier runs.
The temporary private signing key was removed. All request categories, including
zero-count categories, are retained in `request-receipts.json` and signed in
`proof/attachments/request-receipts.json`.

## Verify retained evidence

From this directory, with Python 3.10+ and OpenSSL available:

```sh
python3 -I verify_bundle.py proof --public-key trusted-public.pem
python3 -m authzledger verify-bundle proof --public-key trusted-public.pem
```

The second command requires AuthzLedger installed. The first checks inventory,
hashes, report anchors and signature; the second also reconstructs the retained
assessment, oracle/finding/fix semantics and exact HTML/PDF outputs. No application
service is required. `proof.zip` contains the same package for transport; extract
it into a new directory before verification.

Demonstration signer fingerprint (SHA-256 of DER public key):
`3371123dce57da8bcc71a6b6e85c73169bf7aae779f133721736964ac289d9ef`

This newly generated key is a demonstration trust anchor, not authenticated
producer identity. Obtain a producer key fingerprint through a separate trusted
channel for real assessments. Signed bytes do not establish remote execution truth.

## Reproduce

From the matching source checkout, choose a new output directory:

```sh
python3 tools/check_selective100.py --out /tmp/authzledger-selective100-new
```

Existing output directories are refused. Each run uses a random port, fresh
credentials and a fresh signing key, so hashes and roots differ between runs.
The measured counts and scoped status transitions are reproducible. The baseline
file is written once before retest and checked unchanged afterward. This does not
claim an immutable filesystem or a general tenfold speedup.

Open `assessment.html` or `assessment.pdf` for findings and limitations; open
`comparison.html` to inspect all 100 case transitions and the 90 historical cases.

All rights reserved: Nasser Aldin Farag / 0xFarag.
