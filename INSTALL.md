# Install and run

AuthzLedger 1.0 is distributed with rights reserved. See [LICENSE](LICENSE); publication does not grant a general software-use or commercial licence. These steps are for an authorised copy.

## Run from source

For the integrated **1.1.0 development branch**, use `authzledger-v1.1.0` instead of the stable branch in the clone command below, then install the assessment reporting extra:

```sh
python3 -m pip install '.[reports]'
python3 -m authzledger assessment demo --out artifacts/assessment-demo
python3 -m authzledger studio --open
```

PDF export requires the pinned ReportLab 4.4.9 extra and the bundled licensed Unicode fonts. HTML/JSON and the core runner do not require ReportLab. The supported assessment workflow and remaining production release gates are recorded in [the acceptance ledger](docs/acceptance-1.1.0.md); the stable instructions below describe the already released 1.0.0 distribution.

Requires Python 3.10 or newer. Linux / CPython 3.12 is locally verified; other platforms have not been certified in this release.

```sh
git clone --branch authzledger-v1.0.0 --single-branch https://github.com/0xFarag/0xFarag.git authzledger
cd authzledger
python3 -m authzledger studio --open
```

Alternatively, extract the source archive and open a terminal in its `authzledger` directory, then run the last command. On Windows, use `py -3` where appropriate; Windows has not been validated in this release.

The runtime uses only the Python standard library. No administrator privileges, external credentials or paid services are needed for the local demo. Studio listens on loopback, chooses a free port and prints a session URL. Open that complete URL if the browser does not open automatically. Keep the session token private. Use `--history ./authorization-history.sqlite3` for durable verified run history. Without this flag, Studio retains working sessions in memory; export before closing. Signing needs OpenSSL 3 with Ed25519 support; normal execution does not. Stop with Ctrl+C. On Linux, `bash start.sh` provides the same launch.

## Install the wheel in isolation

For a downloaded `authzledger-1.0.0-py3-none-any.whl`:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-index --no-deps /path/to/authzledger-1.0.0-py3-none-any.whl
authzledger studio --open
```

This installation does not download runtime dependencies. Your Python installation must provide `venv`.

## Run the local fixture

```sh
python3 -m authzledger demo --out artifacts/demo
python3 -m authzledger verify artifacts/demo/vulnerable/report.json
python3 -m authzledger verify artifacts/demo/fixed/report.json
python3 -m authzledger benchmark --out artifacts/corpus
```

The commands use synthetic data and loopback HTTP fixtures. The demo intentionally records failed assertions before the fixture fix; the fixed report must pass. Open `artifacts/demo/diff.html` for the comparison. The benchmark covers eight authored scenarios with 24 declared checks each.

For your own API, follow [the contract guide](docs/contract.md), use authorised test identities and review the generated scope before execution.

## Build and test

```sh
python3 -m unittest discover -s tests -v
python3 -m pip wheel --no-deps --no-build-isolation --wheel-dir dist .
```

The build needs the build-tool versions pinned in pyproject.toml. They are build requirements, not runtime dependencies. `--no-build-isolation` uses the existing build environment.

Optional browser acceptance uses `node tests/browser_acceptance.cjs` with Playwright and Chromium installed in your development environment. `PLAYWRIGHT_MODULE`, `CHROME_EXECUTABLE`, `PYTHON` and `AUTHZ_BROWSER_ARTIFACTS` override defaults. Browser test dependencies are not product dependencies.

## Three-layer intelligence and signed proof

```sh
python3 -m authzledger graph artifacts/demo/contract.json --report artifacts/demo/fixed/report.json --policy examples/authorization-policy.json --out graph.json
python3 -m authzledger explain graph.json --out explanation.json
python3 -m authzledger keygen --private operator-private.pem --public operator-public.pem
python3 -m authzledger bundle artifacts/demo/fixed/report.json --key operator-private.pem --contract artifacts/demo/contract.json --graph graph.json --out proof
python3 -m authzledger verify-bundle proof --public-key operator-public.pem
python3 tools/verify_bundle.py proof --public-key operator-public.pem
python3 -m authzledger studio --history authorization-history.sqlite3 --signing-key operator-private.pem --public-key operator-public.pem --open
```

Keep the private key outside repositories and evidence packages. Distribute the trusted public key through a separate verified channel. The embedded key is never a trust anchor. See [signatures](docs/signatures.md), [continuous assurance](docs/assurance.md) and [advisory reasoning](docs/reasoning.md).


Studio can optionally use an explicitly configured PDP: `--policy-config policy.json`. The browser selects that fixed engine with an explicit checkbox; it cannot select arbitrary PDP URLs. Retained graph snapshots ensure proof export and explanation reuse the evaluated decision rather than silently querying changed policy.
