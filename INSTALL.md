# Install and reproduce AuthzLedger 1.1.0.dev0

**Development build; stable 1.1.0 publication is blocked by F01-01.** The released 1.0.0 tag and artifacts remain unchanged. This document describes the integrated development build; see the [acceptance ledger](docs/acceptance-1.1.0.md) for the incomplete genuine Burp exporter and DTD-safe profile gate.

AuthzLedger is distributed with rights reserved. Use is subject to [LICENSE](LICENSE), [NOTICE.txt](NOTICE.txt) and any separately agreed permissions. Publication does not grant a general commercial licence.

## Requirements

Python 3.10 or newer and `venv`. The measured environment is Linux / CPython 3.12; Windows and macOS are not certified here. Core execution, HTML and JSON require only the Python standard library. **The three-demo command exports PDF and therefore requires `reportlab==4.4.9`**, available through the `reports` extra. Bundled Unicode fonts retain their separate licences. Signing and both signature verifiers need OpenSSL with Ed25519 support.

No administrator privileges, paid service or external credentials are needed for the local labs. Their HTTP traffic is confined to fresh synthetic loopback fixtures.

## Check downloaded assets

Keep all downloaded assets and `SHA256SUMS.txt` in one directory:

```sh
sha256sum -c SHA256SUMS.txt
```

Every listed file must pass. A checksum list delivered alongside the files detects corruption; publisher authentication additionally needs a trusted delivery channel or a separately authenticated digest.

## Install the wheel outside a checkout

Create a new working directory outside the source tree. Replace the absolute wheel path with the downloaded asset location:

```sh
mkdir authzledger-work
cd authzledger-work
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-index --no-deps /absolute/path/authzledger-1.1.0.dev0-py3-none-any.whl
python -m pip install 'reportlab==4.4.9'
python -I -c 'import authzledger; print(authzledger.__version__); print(authzledger.__file__)'
```

The printed producer must be `1.1.0.dev0`, and its module path must be inside `.venv`, not the checkout. The second installation downloads the explicitly required PDF renderer and its dependencies. For an offline installation, prepare a trusted wheelhouse in advance and use `python -m pip install --no-index --find-links /path/to/wheelhouse 'reportlab==4.4.9'` instead. A core-only install can omit ReportLab, but cannot produce the PDF-bearing three-demo proof.

## Reproduce and verify all three assessment demonstrations

Every output directory must be new; existing evidence is not overwritten:

```sh
python -I -m authzledger assessment demo --out assessment-demo
python -I -m authzledger assessment verify assessment-demo/01-import-to-reproducer/snapshot.json
python -I -m authzledger assessment verify assessment-demo/03-selective-retest-proof/snapshot.json
python -I -m authzledger verify-bundle assessment-demo/proof --public-key assessment-demo/trusted-public.pem
python -I /absolute/path/verify_bundle.py assessment-demo/proof --public-key assessment-demo/trusted-public.pem
```

The demo command stops and closes its HTTP fixture before exporting reports, signing or verifying. All following commands are offline evidence checks. A temporary private key is deleted before completion; only a public demo key is retained. A freshly generated key and local timestamps mean separate runs have different bytes and roots while preserving the declared outcomes.

| Output | Expected proof |
|---|---|
| `assessment-demo/01-import-to-reproducer/` | Original controlled execution plus bounded reduction; three selected irrelevant units removed with twelve reduction requests. |
| `assessment-demo/02-denial-and-controls/` | Protected content in 403 becomes `denial_data_disclosure`; invalid controls are `inconclusive`; a 200 error object is `rejected`. |
| `assessment-demo/03-selective-retest-proof/` | Original baseline, four-case current retest and comparison; selected finding `fix_verified`, omitted finding `not_retested`. |
| `assessment-demo/reports/` | Consistent assessment JSON, HTML and PDF. |
| `assessment-demo/proof/` | Signed inventory of report artifacts and evidence. |
| `assessment-demo/results.json` | Measured outcomes and total 35 loopback requests. |

The imported XML is deliberately authored synthetic data. It is useful for reproduction and **does not establish genuine Burp exporter acceptance**. For the exact proof payload retained in this source ZIP, replace `assessment-demo` above with `evidence/1.1.0-release-review/assessment-demos` and use `tools/verify_bundle.py` as the standalone path.

The separate 100-case proof is included as `selective100` in the public proof ZIP (or under `evidence/1.1.0-release-review/selective100` in the source ZIP). After extracting the proof ZIP and changing to `authzledger-proof`:

```sh
python -I -m authzledger verify-bundle selective100/proof --public-key selective100/trusted-public.pem
python -I tools/verify_bundle.py selective100/proof --public-key selective100/trusted-public.pem
python tools/check_selective100.py --out fresh-selective100
```

That run performs 100 baseline requests followed by ten retest requests: seven selected variants and three fresh controls. All 90 omitted cases remain `not_retested`. It is separate from the 35-request assessment demo. `selective100/request-receipts.json` records every category, and its signed counterpart is inside the proof package.

The standalone verifier checks signature, file hashes, inventory, JSON structure and report anchor binding. The main verifier adds supported source-bound report/contract/finding/comparison/snapshot/workflow/renderer semantics. A successful standalone check alone cannot establish a true finding or fix. The bundled demo public key tests internal consistency; authenticate a public key through a separate trusted channel for real evidence handover.

## Start Studio

```sh
python -I -m authzledger studio --history ./authorization-history.sqlite3 --open
```

Studio listens on loopback, chooses a free port and prints a session URL. Open the complete URL if the browser does not open automatically, and keep its session token private. The explicit history file enables durable run history. Without `--history`, Studio working state is session-only; export before closing. Stop with Ctrl+C. CLI and Studio use the same execution and assessment services.

## Run from source

Use the supplied source archive, or clone the development branch. A branch may advance; preserve the commit ID when collecting evidence.

```sh
git clone --branch authzledger-v1.1.0 --single-branch https://github.com/0xFarag/0xFarag.git authzledger
cd authzledger
python3 -m venv .venv
. .venv/bin/activate
python -m pip install '.[reports]'
python -m authzledger assessment demo --out artifacts/assessment-demo
python -m authzledger studio --open
```

For the already released stable build, select tag `v1.0.0` and follow the installation document at that tag. Do not relabel or replace its wheel, evidence roots or release assets.

## Regression and build checks

Use the pinned build requirements in `pyproject.toml`. `--no-build-isolation` deliberately uses the installed build environment:

```sh
python -m pip install 'setuptools==84.0.0' 'wheel==0.48.0' 'pypdf==6.10.0'
python -m unittest discover -s tests -v
python tools/release_check.py --out artifacts/core-check
python tools/check_comparison.py --out artifacts/comparison-check
python tools/check_assessment.py --out artifacts/assessment-check
python tools/check_workflows110.py --out artifacts/workflow-check
python -m pip wheel --no-deps --no-build-isolation --wheel-dir dist .
python tools/package_release.py
python tools/release_gate110.py
```

**The final gate is expected to exit 2 for this development snapshot.** It must not be bypassed for a stable release. A green test suite does not override F01-01.

Browser acceptance requires the documented Playwright/Chromium test environment; it is a development dependency, not a product dependency. Run all six suites, not only the original Studio test:

```sh
node tests/browser_acceptance.cjs
node tests/browser_v1.cjs
node tests/browser_comparison.cjs
node tests/browser_assessments.cjs
node tests/browser_assessment_security.cjs
node tests/browser_retest_freshness.cjs
```

`PLAYWRIGHT_MODULE`, `CHROME_EXECUTABLE`, `PYTHON` and the suite artifact environment variables select the local test environment. See [the verification protocol](docs/verification-1.1.0.md) and [the release contract](docs/release-1.1.0.md) for precise measured scope, trust boundaries and publication conditions.
