# Validation — AuthzLedger 1.0

Measured local acceptance: **233 Python tests passed** under Linux/CPython 3.12.14. The complete graph, independent local-policy, differential retest, explanation, Ed25519 package, external trusted-key verification, standalone verifier, history and dependency-closed retest workflow passed. The authored eight-scenario HTTP corpus passed.

Both Chromium 155 browser suites passed without JavaScript errors, including graph/policy drift, persistent history, signed export, protected retest preparation and a 390px viewport. The built wheel was installed in an isolated venv and executed outside the checkout through demo, graph and source-bound signed verification.

Raw records and synthetic before/after captures: [evidence/1.0.0](../evidence/1.0.0). [RELEASE.json](../RELEASE.json) contains hashes and exact scope. OPA/Ollama integration tests used loopback protocol fixtures. Remote GitHub Actions status is independently observable on the release commit; local test success does not stand in for it.

Controls, decision semantics, signature trust, stale context, corrupted history, changed credentials, graph source binding, malicious annotations, request limits and malformed inputs have targeted regression tests. This is a development-team review, not an external audit or commercial-tool superiority benchmark. Hosted infrastructure, accessibility, other platforms and customer evaluation remain open.

---

## Historical 0.3.4 evidence

# Validation — 0.3.4 release candidate

9 October 2026. These results describe the prepared distribution and its authored local fixtures. GitHub publication and remote CI results are separate from local validation.

## Verified locally

- Linux with CPython 3.12.14: all 126 existing Python tests passed.
- The 0.3.4 wheel was built without runtime dependencies, installed in a clean virtual environment and executed from outside the checkout.
- The installed CLI completed its six-case synthetic HTTP demo and verified the fixed report integrity. The comparison recorded two resolved failures.
- The installed eight-scenario corpus accepted all expected outcomes across 24 declared checks per scenario.
- The source distribution preserves the 0.3.3 authorization engine, contracts, execution limits, control semantics and evidence algorithms.

The corpus exercises owner, tenant and role boundaries, protected data in a denial response, expired credentials, missing resources and incorrect fixtures. Failed or skipped prerequisites do not count as passed denial checks. These authored fixtures do not measure general pentest coverage or superiority over another product.

- Chromium 155.0.8059.39: matrix workflow, all eight scenarios, control traces, baseline preservation, filtering, JSON/HTML/JUnit exports, comparison export and the 390 px viewport passed with no page errors. Keyboard activation also focused the selected rule editor during the release-film capture.

Raw records: [test log](../evidence/0.3.4/tests.txt), [browser acceptance](../evidence/0.3.4/browser.json), [synthetic corpus](../evidence/0.3.4/corpus.json). [RELEASE.json](../RELEASE.json) records their hashes.

## Remaining limits

Full screen-reader acceptance, additional browsers/operating systems, independent security and comparative review, and external customer validation remain open. Studio holds projects in session memory; export before closing. The OS resolver can outlast socket deadlines, so use an outer process timeout and an appropriate network boundary for CI. Report hashes support integrity checking against a retained anchor; they do not prove an uncompromised runner.

Billing, subscriptions, hosted team workspaces and licence enforcement are not implemented. The pre-release catalogue contains no paid offers. Permissions are governed by the existing LICENSE, not by repository visibility.
