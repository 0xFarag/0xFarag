![0xFarag — Web and API Security](assets/profile-header.svg)

# Nasser Aldin Farag · 0xFarag

**[AuthzLedger 1.5.0 — assessment suite, source and downloads →](https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0)**

**Penetration Testing · Web & API Security · Security Engineering**  
Zürich, Switzerland

I bring more than ten years of system engineering experience and a background in web security to practical security assessment. My work follows a clear standard: understand the system, reproduce the finding, explain its impact and verify the fix.

My focus is application security, authorization testing and security automation. I build reproducible working examples that make technical reasoning and remediation inspectable.

**Open to permanent roles in penetration testing, Web/API security, AppSec and security engineering in Switzerland.** I am also the creator of AuthzLedger, an authorization testing and evidence workbench for pentesters and AppSec teams.

[LinkedIn](https://www.linkedin.com/in/nasser-aldin-farag-974697412/) · [GitHub projects](https://github.com/0xFarag?tab=repositories) · [YouTube](https://www.youtube.com/@0xFarag) · [TryHackMe](https://tryhackme.com/p/0xFarag)

## AuthzLedger 1.5.0

### From permitted scope to reproducible evidence.

**One local assessment suite for expert pentesters and AppSec teams.**

Connect permitted scope, captured traffic, discovery, controlled checks, reproducible findings, selective retests and signed handover. Studio and CLI share the same services and execution context.

**[DOWNLOAD 1.5.0 →](https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0)** · **[EXPLORE THE SUITE →](AUTHZLEDGER.md)** · **[RUN THE LOCAL DEMOS →](AUTHZLEDGER.md#run-the-150-suite)**

### Discover → Assess → Prove → Retest → Handover

| Capability | Delivered in 1.5.0 |
| :--- | :--- |
| **Engagement workspace** | Persistent assessments with explicit scope, rules-of-engagement references, credential references, expiry and budgets. |
| **Recon and inventory** | Bounded HTTP/API discovery and explicit TCP service probes; one surface catalog with retained provenance. |
| **Specialist-tool integration** | Burp raw, ZAP JSON+, HAR and OpenAPI; selected offline Nmap XML and Nuclei JSONL result adapters. Imported assertions remain hints. |
| **Controlled assessment** | Versioned authorization, business-logic and selected web checks with prerequisite controls, observable predicates and explicit evidence levels. |
| **Controlled PoCs** | Reproducible experiments, bounded Minimal Reproducer and explicitly approved static playbooks. |
| **Selective retest** | Source-bound comparisons preserve the original evidence and keep omitted work visible as `not_retested`. |
| **Reporting and handover** | JSON, HTML and PDF from one frozen snapshot; impact, remediation, coverage and an Ed25519-signed file inventory. |

**682/682 tests · 8/8 browser suites · 3 reproducible demos.** [Inspect the passing release pipeline](https://github.com/0xFarag/0xFarag/actions/runs/39477528355) · [Download the exact-commit verification receipt](https://github.com/0xFarag/0xFarag/releases/download/v1.5.0/verification.json).

The A/B/C demos use owned loopback fixtures: a 403 with protected data is confirmed only with valid controls; scoped discovery leads to a narrow configuration finding; a selective fix proof retains `not_retested`. Changing one signed report byte is rejected by both verifiers.

[Installation](https://github.com/0xFarag/0xFarag/blob/v1.5.0/INSTALL.md) · [Versioned source](https://github.com/0xFarag/0xFarag/tree/v1.5.0) · [Source ZIP](https://github.com/0xFarag/0xFarag/releases/download/v1.5.0/authzledger-1.5.0-source.zip) · [Wheel](https://github.com/0xFarag/0xFarag/releases/download/v1.5.0/authzledger-1.5.0-py3-none-any.whl) · [Proof package with JSON/HTML/PDF](https://github.com/0xFarag/0xFarag/releases/download/v1.5.0/authzledger-1.5.0-proof.zip)

The native checks cover documented predicates, not universal vulnerability coverage. Nmap/Nuclei adapters import supported results; they do not launch the scanners. [Read the exact supported scope and trust boundaries](https://github.com/0xFarag/0xFarag/blob/v1.5.0/docs/suite-1.5.0.md).

Built on the unchanged [1.1.0 authorization foundation](https://github.com/0xFarag/0xFarag/releases/tag/v1.1.0). [Watch the historical 1.1.0 film](https://www.youtube.com/watch?v=vEaYxBpsLGw); it shows that earlier release.

**AppSec teams and pentest consultancies:** [contact me on LinkedIn](https://www.linkedin.com/in/nasser-aldin-farag-974697412/) to discuss an authorized pilot and reproducible developer handover.

Built by **Nasser Aldin Farag / 0xFarag**, Switzerland. Source-visible, with proprietary rights reserved. [Commercial licensing](AUTHZLEDGER_RIGHTS.md) · [Product scope](AUTHZLEDGER.md) · [Development direction](AUTHZLEDGER_DIRECTION.md).

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
