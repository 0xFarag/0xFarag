![0xFarag — Web and API Security](assets/profile-header.svg)

# Nasser Aldin Farag · 0xFarag

**[AuthzLedger 1.1.0 — release, source and downloads →](https://github.com/0xFarag/0xFarag/releases/tag/v1.1.0)**

**Penetration Testing · Web & API Security · Security Engineering**  
Zürich, Switzerland

I bring more than ten years of system engineering experience and a background in web security to practical security assessment. My work follows a clear standard: understand the system, reproduce the finding, explain its impact and verify the fix.

My focus is application security, authorization testing and security automation. I build reproducible working examples that make technical reasoning and remediation inspectable.

**Open to permanent roles in penetration testing, Web/API security, AppSec and security engineering in Switzerland.** AuthzLedger is a practical engineering project supporting that focus.

[LinkedIn](https://www.linkedin.com/in/nasser-aldin-farag-974697412/) · [GitHub projects](https://github.com/0xFarag?tab=repositories) · [YouTube](https://www.youtube.com/@0xFarag) · [TryHackMe](https://tryhackme.com/p/0xFarag)

## AuthzLedger 1.1.0

**Controlled findings. Verifiable evidence.**  
Know who can do what. Prove what changed.

AuthzLedger is a local Studio and CLI for authorization testing: import native Burp raw messages, ZAP JSON+ or HAR; define access rules and test identities; validate controls; reduce a reproducer; retest selected cases; and hand over a frozen assessment with verifiable evidence.

**[Download AuthzLedger 1.1.0 →](https://github.com/0xFarag/0xFarag/releases/tag/v1.1.0)** · [Installation guide](https://github.com/0xFarag/0xFarag/blob/v1.1.0/INSTALL.md) · [Watch the 52-second release film](https://www.youtube.com/watch?v=vEaYxBpsLGw)

[Source ZIP](https://github.com/0xFarag/0xFarag/releases/download/v1.1.0/authzledger-1.1.0-source.zip) · [Installable wheel](https://github.com/0xFarag/0xFarag/releases/download/v1.1.0/authzledger-1.1.0-py3-none-any.whl) · [Synthetic proof package](https://github.com/0xFarag/0xFarag/releases/download/v1.1.0/authzledger-1.1.0-proof.zip) · [Independent verifier](https://github.com/0xFarag/0xFarag/releases/download/v1.1.0/verify_bundle.py) · [SHA-256 checksums](https://github.com/0xFarag/0xFarag/releases/download/v1.1.0/SHA256SUMS.txt)

Protected data inside a 403 response can still establish a finding when the configured controls are valid. Reduction retains original evidence; selective retests distinguish `fix_verified` from `not_retested`. JSON, HTML and PDF derive from one frozen snapshot, with an Ed25519-signed file inventory. Verification uses a separately trusted public key. Signatures establish integrity, not truthful remote execution.

**88/88 acceptance scenarios, 530 Python tests and seven Chromium browser suites.** The [release CI](https://github.com/0xFarag/0xFarag/actions/runs/38080406879) checks the frozen product commit `a7160e13289ea0983946e03c978bc6af1841a7e6` and all five published asset hashes. [Inspect the retained evidence](https://github.com/0xFarag/0xFarag/blob/v1.1.0/evidence/1.1.0-final/README.md).

The public labs and product footage use synthetic local data. Native Burp support is the documented raw-message profile; DTD-bearing Burp XML remains unsupported. Optional local AI is advisory and does not decide findings.

**Pilot partners and early-stage investors in security tooling:** [contact me on LinkedIn](https://www.linkedin.com/in/nasser-aldin-farag-974697412/) to discuss practical evaluation, repeat usage and reproducible handovers.

Source-visible; proprietary rights reserved by **Nasser Aldin Farag / 0xFarag**. [Rights and commercial licensing](AUTHZLEDGER_RIGHTS.md). Hosted team services and external customer validation remain future work.

[Release scope](https://github.com/0xFarag/0xFarag/blob/v1.1.0/docs/release-1.1.0.md) · [Burp import profile](https://github.com/0xFarag/0xFarag/blob/v1.1.0/docs/burp-native-import-v1.md) · [Development direction](AUTHZLEDGER_DIRECTION.md)

## Selected engineering work

| Project | Purpose | What to inspect |
| :--- | :--- | :--- |
| [**API Authorization Lab**](https://github.com/0xFarag/api-authorization-lab) | Make object-level authorization failures reproducible. | Local invoice API, ownership enforcement and before/after HTTP evidence. |
| [**Nmap Evidence Report**](https://github.com/0xFarag/nmap-evidence-report) | Turn scan output into usable assessment evidence. | Offline XML processing, Markdown/JSON reports and preservation of observed states. |
| [**Pentest Case Study**](https://github.com/0xFarag/pentest-case-study) | Connect a technical finding to a clear remediation decision. | Scope, impact, request/response evidence, fix and retest. |
| [**Offensive Security Labs**](https://github.com/0xFarag/offensive-security-labs) | Explore security boundaries through executable examples. | Exploit/fix pairs across OAuth, SSRF, CI and API security, with regression checks. |
| [**TryHackMe Reports**](https://github.com/0xFarag/tryhackme-writeups) | Document technical reasoning and lessons from completed rooms. | Learning retrospectives, remediation analysis and proposed retest criteria. |

The runnable labs and sample assessment use synthetic data in local environments. They are separate from client engagements. TryHackMe reports distinguish completed learning activities from proposed retests.

## Technical focus

**Web & API security** — HTTP, authentication boundaries, object-level access control, finding validation and retesting.  
**Systems** — Windows/Linux, networking, operations and system engineering.  
**Security engineering** — Python automation, structured evidence, reproducible tests and clear technical reporting.  
**Continuing development** — Active Directory security, offensive security methodology and red teaming.

## Credentials

| Credential | Issuer | Earned |
| :--- | :--- | :--- |
| **PNPT** — Practical Network Penetration Tester | TCM Security | 2024 |
| **PenTest+** | CompTIA | 2024 |
| **OPST** — OSSTMM Professional Security Tester | ISECOM | 2024 |
| **PJPT** | TCM Security | 2023 |
| **eJPT** | INE | 2023 |
| **CC** — Certified in Cybersecurity | ISC² | 2024 |
| **ICCA** — INE Certified Cloud Associate | INE | 2023 |
| **Google Cybersecurity Professional Certificate** | Google | 2023 |

## Work with me

I am seeking a permanent cybersecurity role in Switzerland, with a focus on penetration testing, Web/API security, AppSec or security engineering. I welcome technical conversations about the trade-offs, test design and evidence behind these projects.

**[Contact me on LinkedIn →](https://www.linkedin.com/in/nasser-aldin-farag-974697412/)**

## Rights and permissions

Copyright © 2026 Nasser Aldin Farag (0xFarag). All rights reserved.

All exclusive rights legally held by me in my own protectable contributions to AuthzLedger and my personal branding remain reserved to me. Publication or delivery does not itself transfer ownership or grant a general commercial licence. Commercial reuse requires a separate written agreement, subject to applicable law and permissions already validly granted. [Rights and commercial licensing](AUTHZLEDGER_RIGHTS.md).
