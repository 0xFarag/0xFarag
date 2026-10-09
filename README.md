![0xFarag — Web and API Security](assets/profile-header.svg)

# Nasser Aldin Farag · 0xFarag

**Penetration Testing · Web & API Security · Security Engineering**  
Zürich, Switzerland

I bring more than ten years of system engineering experience and a background in web security to practical security assessment. My work follows a clear standard: understand the system, reproduce the finding, explain its impact and verify the fix.

My focus is application security, authorization testing and security automation. I build reproducible working examples that make technical reasoning and remediation inspectable.

**Open to permanent roles in penetration testing, Web/API security, AppSec and security engineering in Switzerland.** AuthzLedger is a practical engineering project supporting that focus.

[LinkedIn](https://www.linkedin.com/in/nasser-aldin-farag-974697412/) · [GitHub projects](https://github.com/0xFarag?tab=repositories) · [YouTube](https://www.youtube.com/@0xFarag) · [TryHackMe](https://tryhackme.com/p/0xFarag)

## AuthzLedger 0.3.4 pre-release

**Authorization Intelligence, built on evidence.**  
Know who can do what. Prove what changed.

The available v0.3.4 pre-release is a local authorization engineering workbench: explicit access expectations, controlled HTTP tests and traceable evidence.

**[Download AuthzLedger v0.3.4 →](https://github.com/0xFarag/0xFarag/releases/tag/v0.3.4)** · [Source and installation guide](https://github.com/0xFarag/0xFarag/tree/authzledger-v0.3.4)

[Source ZIP](https://github.com/0xFarag/0xFarag/releases/download/v0.3.4/authzledger-0.3.4-source.zip) · [Installable wheel](https://github.com/0xFarag/0xFarag/releases/download/v0.3.4/authzledger-0.3.4-py3-none-any.whl) · [55-second release video](https://www.youtube.com/shorts/SJrvbBdybFo) · [Release notes](https://github.com/0xFarag/0xFarag/releases/tag/v0.3.4)

The GitHub pre-release includes the source-visible distribution, downloads and wide/vertical videos. Source and test evidence are on the dedicated `authzledger-v0.3.4` branch. [GitHub verification passed](https://github.com/0xFarag/0xFarag/actions/runs/37856154307). Pre-release; all rights reserved. [Earlier 36-second product preview](https://www.youtube.com/shorts/Svr7Jhb_FNc).

A controlled local API returns HTTP 403 while leaking a protected field. The preview follows the failed body check, legitimate-access controls and the same-contract retest: 24 checks pass and one finding is recorded as resolved. Synthetic data; actual Studio captures.

AuthzLedger compiles actor/resource access matrices into checks with positive-control dependencies, traces outcomes to their rules, and keeps proposed policy changes separate from remediation results. Its local fault corpus exercises ownership, tenant and role boundaries, protected data in denial responses, invalid credentials and stale fixtures.

The current pre-release includes a local Studio, an offline OpenAPI importer, a CLI and JSON/HTML/JUnit evidence. Validation uses authored synthetic fixtures; independent customer evaluation and commercial validation are the next gates.

### Toward version 1.0

The next development stage separates **intended access**, **policy-engine decisions** and **observed application behavior**. Differences between these layers should lead to inspectable tests and evidence, with explicit control validity and change history.

The 1.0 priorities are a stable contract model, trustworthy controls, signed portable evidence with independent verification, and reproducible authorization regression workflows. These are development targets; the current release does not yet provide digital signatures, connected policy engines or continuous assurance.

[Development scope and acceptance gates](AUTHZLEDGER_DIRECTION.md)

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
