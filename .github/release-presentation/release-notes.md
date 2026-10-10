# Find the authorization gap. Prove the fix.

**AuthzLedger 1.1.0 — the local authorization testing and evidence workbench for pentesters and AppSec teams.**

Bring captured traffic into controlled experiments. Turn a finding into a smaller reproducer. Retest the fix and deliver the evidence behind it — through one Studio and CLI.

[![Watch Nasser Aldin Farag present AuthzLedger 1.1.0](https://raw.githubusercontent.com/0xFarag/0xFarag/d1fb179ed04fa28e1855c941e761e7c67ea4b45a/assets/authzledger-1.1.0/founder-film.jpg)](https://www.youtube.com/watch?v=vEaYxBpsLGw)

**[WATCH THE 52-SECOND FILM →](https://www.youtube.com/watch?v=vEaYxBpsLGw)** · **[EXPLORE THE PRODUCT →](https://github.com/0xFarag/0xFarag/blob/d1fb179ed04fa28e1855c941e761e7c67ea4b45a/AUTHZLEDGER.md)** · **[RUN THE LOCAL LAB →](https://github.com/0xFarag/0xFarag/blob/d1fb179ed04fa28e1855c941e761e7c67ea4b45a/AUTHZLEDGER.md#run-the-local-lab)**

## Eight capabilities. One evidence trail.

| Capability | What you can do |
| :--- | :--- |
| **01 · Bring your traffic** | Import native Burp raw request/response pairs, ZAP JSON+ and HAR. Review redaction and bind the source to an explicit test scope. |
| **02 · Contrast Lab** | Test BOLA/IDOR, tenant isolation and denial-data leakage with identity, owner and denial controls attached to each finding. |
| **03 · Workflow Contracts** | Exercise ordered business flows, skipped approvals, replay and idempotency. Verify the effect through independent state reads. |
| **04 · Minimal Reproducer** | Remove selected request fields through bounded, controlled experiments. Retain the original finding and evidence for every accepted reduction. |
| **05 · Source-bound retests** | Retest selected cases with fresh controls and unchanged rule bindings. Keep verified fixes and untested cases visibly distinct. |
| **06 · One Studio and CLI** | Work through a keyboard-first assessment workspace, shared matrix/graph selection, persistent Inspector and the same underlying execution services. |
| **07 · Evidence handover** | Freeze JSON, HTML and PDF from one assessment. Include reviewed standards mappings and an Ed25519-signed file inventory. |
| **08 · Change and assurance** | Explain impacted-case selection, inspect evidence relationships and run bounded assurance cycles with checked history and shared request budgets. |

## See the boundary. Keep the proof.

[![Actual AuthzLedger Studio capture, synthetic local authorization assessment](https://raw.githubusercontent.com/0xFarag/0xFarag/v1.1.0/brand/release-1.1.0/launch-landscape.png)](https://github.com/0xFarag/0xFarag/blob/d1fb179ed04fa28e1855c941e761e7c67ea4b45a/AUTHZLEDGER.md#walk-through-the-product)

The public local demonstrations show:

- **Denial-data leakage:** protected content inside a 403 can establish a finding when the identity, owner and denial controls are valid.
- **A smaller reproducer:** fresh controls verify accepted reductions while the original request and evidence remain unchanged.
- **A scoped fix:** the 100-case demonstration retests seven selected variants and three controls. All 90 omitted cases remain explicitly `not_retested`.
- **A verifiable handover:** JSON, HTML and PDF from one frozen assessment, with retained evidence and an Ed25519-signed file inventory.

**[Follow the walkthrough with real Studio screens →](https://github.com/0xFarag/0xFarag/blob/d1fb179ed04fa28e1855c941e761e7c67ea4b45a/AUTHZLEDGER.md#walk-through-the-product)**

## Download and start

Use the five assets below: **source ZIP, Python wheel, synthetic proof package, standalone verifier and SHA-256 checksums**.

**[Installation guide](https://github.com/0xFarag/0xFarag/blob/v1.1.0/INSTALL.md)** · **[Quick local lab](https://github.com/0xFarag/0xFarag/blob/d1fb179ed04fa28e1855c941e761e7c67ea4b45a/AUTHZLEDGER.md#run-the-local-lab)** · **[Verify the proof](https://github.com/0xFarag/0xFarag/blob/d1fb179ed04fa28e1855c941e761e7c67ea4b45a/AUTHZLEDGER.md#inspect-the-release)**

Python 3.10+ and `venv`; OpenSSL with Ed25519 support for signing. The local demonstrations run on synthetic loopback fixtures. PDF output uses the pinned `reports` dependency. See the installation guide for the measured environment and exact commands.

## Verified at the published commit

**88/88 acceptance scenarios · 530 Python tests · Seven Chromium browser suites.**

The [publication workflow](https://github.com/0xFarag/0xFarag/actions/runs/38080406879) passed verification, browser acceptance and publication at the unchanged product commit `a7160e13289ea0983946e03c978bc6af1841a7e6`. All five asset hashes matched the reviewed files. The checks include native Burp evidence, controlled workflows, source-bound comparison, reproducible wheel builds and installation outside the checkout.

[Acceptance ledger](https://github.com/0xFarag/0xFarag/blob/v1.1.0/docs/acceptance-1.1.0.md) · [Retained evidence](https://github.com/0xFarag/0xFarag/blob/v1.1.0/evidence/1.1.0-final/README.md) · [Native Burp profile](https://github.com/0xFarag/0xFarag/blob/v1.1.0/docs/burp-native-import-v1.md)

## Bring a pilot

**AppSec teams and pentest consultancies:** evaluate the path from captured request to developer handover and scoped retest. **Security-tooling investors:** inspect the product and discuss pilot usage, repeatability and commercial validation.

**[Contact Nasser Aldin Farag / 0xFarag →](https://www.linkedin.com/in/nasser-aldin-farag-974697412/)**

Built in Switzerland. Source-visible; proprietary rights reserved. [Rights and commercial licensing](https://github.com/0xFarag/0xFarag/blob/d1fb179ed04fa28e1855c941e761e7c67ea4b45a/AUTHZLEDGER_RIGHTS.md).

<details>
<summary>Technical scope and verification boundaries</summary>

Product footage and public labs use synthetic local data. Native Burp support is the documented raw-message profile; DTD-bearing Burp XML remains rejected. Source-bound retests require valid controls and unchanged rule bindings. Standards mappings describe assessed coverage and are not certification.

Signatures establish package integrity against a separately trusted key; they do not independently prove truthful remote execution or complete production coverage. The application verifier additionally checks supported source-bound evidence semantics. Optional local AI is advisory and does not decide findings.

The published source and five release assets are unchanged. Earlier 1.0.0 artifacts retain their original identities. Tagged installation documents record their prepublication preparation context; this public release and its verified tag are the publication record.

</details>
