# Install and run

This is a pre-release with rights reserved. See [LICENSE](LICENSE); publication does not grant a general software-use or commercial licence. These steps are for an authorised copy.

## Run from source

Requires Python 3.10 or newer. Linux / CPython 3.12 is locally verified; other platforms have not been certified in this release.

```sh
git clone --branch authzledger-v0.3.4 --single-branch https://github.com/0xFarag/0xFarag.git authzledger
cd authzledger
python3 -m authzledger studio --open
```

Alternatively, extract the source archive and open a terminal in its `authzledger` directory, then run the last command. On Windows, use `py -3` where appropriate; Windows has not been validated in this release.

The runtime uses only the Python standard library. No administrator privileges, external credentials or paid services are needed for the local demo. Studio listens on loopback, chooses a free port and prints a session URL. Open that complete URL if the browser does not open automatically. Keep the session token private. Export projects and results before stopping because Studio stores its working session in memory. Stop with Ctrl+C. On Linux, `bash start.sh` provides the same launch.

## Install the wheel in isolation

For a downloaded `authzledger-0.3.4-py3-none-any.whl`:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --no-index --no-deps /path/to/authzledger-0.3.4-py3-none-any.whl
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

The build needs existing `setuptools>=68` and wheel support. They are build requirements, not runtime dependencies. `--no-build-isolation` uses the existing build environment.

Optional browser acceptance uses `node tests/browser_acceptance.cjs` with Playwright and Chromium installed in your development environment. `PLAYWRIGHT_MODULE`, `CHROME_EXECUTABLE`, `PYTHON` and `AUTHZ_BROWSER_ARTIFACTS` override defaults. Browser test dependencies are not product dependencies.
