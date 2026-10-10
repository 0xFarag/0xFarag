# AuthzLedger 1.1.0 — Controlled findings. Verifiable evidence.

AuthzLedger 1.1.0 brings authorization testing into one local Studio and CLI workflow: import a request, define the rule, validate the controls, reduce the reproducer and verify a scoped fix.

- Native Burp raw-message import, ZAP JSON+ and HAR, with explicit mapping and offline parsing. DTD-bearing Burp XML stays rejected.
- Controlled identity and workflow tests with reviewed scope and request budgets. Protected content inside a 403 response can still establish a finding when the configured controls are valid.
- Bounded reduction with fresh controls and retained original evidence. Selective retests distinguish `fix_verified` from `not_retested`.
- JSON, HTML and PDF from one frozen snapshot, packaged with an Ed25519-signed file inventory. A standalone verifier checks integrity against a separately trusted public key.

Start with the [source](https://github.com/0xFarag/0xFarag/releases/download/v1.1.0/authzledger-1.1.0-source.zip) or [wheel](https://github.com/0xFarag/0xFarag/releases/download/v1.1.0/authzledger-1.1.0-py3-none-any.whl). Follow the [installation guide](https://github.com/0xFarag/0xFarag/blob/v1.1.0/INSTALL.md), reproduce the public local labs and inspect the [release scope and verification evidence](https://github.com/0xFarag/0xFarag/blob/v1.1.0/docs/release-1.1.0.md).

Signatures establish package integrity; they do not independently establish truthful remote execution. Supported profiles, trust boundaries and rights are documented in the tagged source. Existing 1.0.0 artifacts remain unchanged.

## Verification

The final 1.1.0 producer passed 530 Python tests with zero errors, failures or skips; all seven Chromium browser suites; five workflow checks; and the native Burp and release gates. Two pinned-tool wheel builds were byte-identical and the wheel was installed outside the checkout. JSON, HTML and PDF for 50 long-title Unicode findings were byte-identical across separate renderer processes; both bundle verifiers accepted the proofs and rejected a modified PDF. See the [retained evidence](https://github.com/0xFarag/0xFarag/blob/v1.1.0/evidence/1.1.0-final/README.md) for exact environment, hashes and limits.

Native Burp interoperability is the explicitly documented [raw-message profile addendum](https://github.com/0xFarag/0xFarag/blob/v1.1.0/docs/burp-native-import-v1.md), with original capture provenance. Native DTD-bearing Save item XML is deliberately unsupported.
