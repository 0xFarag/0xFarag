# 10 October 2026 release review

This is retained evidence for **1.1.0.dev0**, not a stable release declaration.

- `verification.json`: final 494-test run, six browser suites, five check tools and the deliberately blocked production gate; logs are retained under `logs/`.
- `source-inventory.json`: SHA-256 inventory of the tested runtime, tools, tests, fixtures, workflow and build/rights inputs. PR #3 binds the resulting commit and exact-commit remote CI separately.
- `installed-wheel.json`: final wheel hash, outside-checkout module path and executed offline verification commands.
- `assessment-demos/`: three real loopback demonstrations produced by that installed wheel; 35 HTTP requests in total. The import demonstration uses an explicitly authored Burp-format fixture.
- `selective100/`: separate 100-request baseline and 10-request retest, seven selected cases plus three fresh controls, 90 `not_retested`, signed request-category receipt and unchanged baseline bytes.
- `browser/`: final browser acceptance receipts and two screenshots from actual Studio workflows. No synthetic UI mockup is used.
- `stable-preservation-before.json`: original public v1.0.0 tag/commit and asset digests captured before the development update. The original evidence directory is unchanged.
- `distribution-inventory.json`: package exclusion and public-key checks. Final asset hashes belong to the distribution's `SHA256SUMS.txt`, outside the source archive's own inventory.

The genuine ZAP and HAR exporter evidence lives in `fixtures/imports/`; the missing compatible native Burp XML export keeps F01-01 partial and stable publication blocked.

Public keys here are intentionally generated demonstration trust anchors. For a real handover, authenticate the key separately. Main and standalone verifiers have different documented depths; neither proves truthful remote execution. The old `evidence/1.1.0-dev0/` and `evidence/1.0.0/` bytes remain historical originals.
