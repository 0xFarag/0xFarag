# Comparison implementation verification

Date: 2026-10-10. Base: `9113c5720230e51606000359b010f867c4a23db7` on `authzledger-v1.0.0`.

This records verification of the first development increment toward 1.0.5. It does not declare the eight-capability release complete. Product metadata, legacy v1 schemas, release tag and published assets remain unchanged.

## Completed checks

| Check | Result |
|---|---|
| Complete Python suite | **279 passed**, including the existing 233-test baseline and 46 new tests |
| Comparison core | 21 tests: exact source/subset binding, profiles, transitive controls, hostile envelopes, real loopback 403 leakage |
| CLI, HTML and signed delivery | 14 tests: exit codes, offline processing, strict JSON, escaping, deterministic HTML, mismatched reports and authenticated dishonest attachments |
| Studio comparison API | 9 tests: selection/closure, offline preview, review binding, single-use race, proof export |
| Existing local reasoning transport | 2 additional deterministic tests: close-delimited response handoff, response limit, absolute deadline and cleanup |
| Real comparison demonstration | Four baseline requests, three selective-retest requests; one `resolved_check`, two `unchanged`, one `not_retested` |
| Original complete release-check workflow | Passed: original demo, graphs, policy, diff, history, corpus, signing and isolated verification |
| Wheel build and installation outside checkout | Passed; installed CLI comparison/HTML, signing and both verification paths exercised |
| Existing browser acceptance | Passed: matrix, eight-scenario lab, pinned baseline, controls, filters, exports and mobile layout |
| Existing v1 browser workflow | Passed: policy, history, graph, explanation, proof and reviewed retest |
| New comparison browser workflow | Passed: partial selection, closure preview, interrupted polling, same-job reconnection, omission status, exports, signed proof, unrelated graph isolation and mobile layout |
| Browser JavaScript errors | Zero in all three workflows |
| Source checks | JavaScript syntax, workflow YAML parsing and `git diff --check` passed |

Local browser verification used Playwright 1.64.0 and Chromium 153.0.8010.0. The browser binary came from the pinned `@sparticuz/chromium@153.0.0` development package after the standard browser CDN download failed in this environment. Browser tooling is not an AuthzLedger runtime dependency. CI installs pinned Playwright 1.64.0 with its corresponding Chromium and repeats all three browser suites.

## Meaningful failures corrected during integration

- The main package verifier initially omitted comparison attachments from its semantic payload set. It now loads and rechecks both reserved comparison files after signature/hash verification.
- HTML initially depended on JSON object-key insertion order. Summary and coverage now render in fixed order, so canonical serialization does not invalidate an otherwise identical package.
- A same-ID case in an unrelated graph could inherit an old retest annotation. Inspector annotations now require matching report root and contract digest.
- Concurrent requests could reuse a selective review after a very fast job finished. The review is now claimed and consumed atomically before dispatch; a deterministic concurrency test requires exactly one job.
- An existing local-model transport bug sometimes truncated a close-delimited body at the HTTP response handoff. Explicit exchange finalization preserves body reading, response limits and the absolute deadline. New event-gated tests fail under the old behavior and pass with the correction.

## Reproduce

```sh
python -m unittest discover -s tests -v
python tools/release_check.py --out artifacts/release-check-new
python tools/check_comparison.py --out artifacts/comparison-check-new
node tests/browser_acceptance.cjs
node tests/browser_v1.cjs
node tests/browser_comparison.cjs
```

Output directories for the two Python acceptance tools must be new. Browser tests require Playwright and Chromium; `PLAYWRIGHT_MODULE`, `CHROME_EXECUTABLE` and `PYTHON` can select installed test runtimes. The v1 browser workflow also records a local video and requires Playwright's FFmpeg component.

`tools/check_comparison.py` writes the source, original reports, exact retest contract, comparison JSON/HTML, graph, signed directory/ZIP, separate demonstration public key and machine-readable acceptance record. It stops the target before offline comparison and verification; temporary credentials and private key are not retained.

## Interpretation boundaries

`resolved_check` establishes that the same configured check now passes. Runtime identity, remote execution truth, deployment version and complete vulnerability remediation are not independently attested. The isolated standalone verifier checks signature, inventory, byte hashes and report anchors; the main verifier additionally recalculates comparison and HTML semantics. A generated demonstration key is not an independently authenticated operator identity.

The complete implementation contracts and remaining release gates are in [implementation-1.0.5.md](implementation-1.0.5.md). The actual commands, fields and Studio workflow are in [comparison-envelope-v1.md](comparison-envelope-v1.md).
