# AuthzLedger 1.1.0 — launch package

Prepared 10 October 2026 for Nasser Aldin Farag / 0xFarag.

**Status: ready drafts, not posted.** Activate the release announcements only after `v1.1.0` resolves to the verified commit, the release is neither draft nor prerelease, and the published downloads pass their checksums. This document records no social publication or completed video production.

The message: **Show the boundary. Keep the proof.**

## Release destinations

These are the intended immutable destinations. Verify each after publication; do not replace them with `/releases/latest`.

| Destination | Intended URL |
|---|---|
| Release | https://github.com/0xFarag/0xFarag/releases/tag/v1.1.0 |
| Source ZIP | https://github.com/0xFarag/0xFarag/releases/download/v1.1.0/authzledger-1.1.0-source.zip |
| Wheel | https://github.com/0xFarag/0xFarag/releases/download/v1.1.0/authzledger-1.1.0-py3-none-any.whl |
| Public proof ZIP | https://github.com/0xFarag/0xFarag/releases/download/v1.1.0/authzledger-1.1.0-proof.zip |
| Standalone verifier | https://github.com/0xFarag/0xFarag/releases/download/v1.1.0/verify_bundle.py |
| Checksums | https://github.com/0xFarag/0xFarag/releases/download/v1.1.0/SHA256SUMS.txt |

## GitHub release

**Title:** AuthzLedger 1.1.0 — Controlled findings. Verifiable evidence.

**Body:**

AuthzLedger 1.1.0 brings authorization testing into one local Studio and CLI workflow: import a request, define the rule, validate the controls, reduce the reproducer and verify a scoped fix.

- Native Burp raw-message import, ZAP JSON+ and HAR, with explicit mapping and offline parsing. DTD-bearing Burp XML stays rejected.
- Controlled identity and workflow tests with reviewed scope and request budgets. Protected content inside a 403 response can still establish a finding when the configured controls are valid.
- Bounded reduction with fresh controls and retained original evidence. Selective retests distinguish `fix_verified` from `not_retested`.
- JSON, HTML and PDF from one frozen snapshot, packaged with an Ed25519-signed file inventory. A standalone verifier checks integrity against a separately trusted public key.

Start with the [source](https://github.com/0xFarag/0xFarag/releases/download/v1.1.0/authzledger-1.1.0-source.zip) or [wheel](https://github.com/0xFarag/0xFarag/releases/download/v1.1.0/authzledger-1.1.0-py3-none-any.whl). Follow the [installation guide](https://github.com/0xFarag/0xFarag/blob/v1.1.0/INSTALL.md), reproduce the public local labs and inspect the [release scope and verification evidence](https://github.com/0xFarag/0xFarag/blob/v1.1.0/docs/release-1.1.0.md).

Signatures establish package integrity; they do not independently establish truthful remote execution. Supported profiles, trust boundaries and rights are documented in the tagged source. Existing 1.0.0 artifacts remain unchanged.

## X — German

One post; 255 characters including the literal URL and line breaks.

```text
403 kann geschützte Daten enthalten. AuthzLedger 1.1.0 verbindet Burp/ZAP/HAR-Import, kontrollierte Tests, reduzierte Reproducer und signierte Evidenz. Beim Retest bleibt sichtbar, was geprüft wurde.

https://github.com/0xFarag/0xFarag/releases/tag/v1.1.0
```

## LinkedIn — German

Ein 403 kann geschützte Daten enthalten. Für einen belastbaren Befund müssen Regel, Identität und Kontrollen zusammenpassen.

AuthzLedger 1.1.0 führt diesen Ablauf in einer lokalen Workbench zusammen: vom importierten Request über den kontrollierten Test bis zum reduzierten Reproducer und zum nachvollziehbaren Fix-Nachweis.

• Native Burp-Nachrichten, ZAP JSON+ und HAR offline importieren; Identitäten und fehlende Angaben ausdrücklich zuordnen.
• Ziel, Kontrollen und Request-Budget in Studio prüfen, bevor der Test startet.
• Freigegebene Bestandteile reduzieren und jeden akzeptierten Schritt mit frischen Kontrollen bestätigen.
• Ausgewählte Fälle erneut testen. Nicht erneut geprüfte Fälle bleiben als `not_retested` sichtbar.

JSON, HTML und PDF entstehen aus demselben eingefrorenen Stand. Das Ed25519-signierte Paket bindet die enthaltenen Dateien; der separate Verifier prüft ihre Integrität gegen einen vertrauenswürdigen öffentlichen Schlüssel.

Die lokalen Labs lassen sich reproduzieren. Importprofile, Prüfergebnisse und Grenzen liegen beim Release offen.

AuthzLedger 1.1.0 herunterladen:
https://github.com/0xFarag/0xFarag/releases/tag/v1.1.0

## Hacker News — Show HN

**Title:** Show HN: AuthzLedger 1.1.0 – Local authorization testing with signed evidence

**Submission URL:** https://github.com/0xFarag/0xFarag/releases/tag/v1.1.0

**Introduction / text-post variant:**

AuthzLedger is a local workbench for turning a selected request into a controlled authorization test, a bounded reproducer and a scoped retest.

It imports native Burp raw messages, ZAP JSON+ and HAR. You bind identities, define the rule and controls, review the exact request plan, then execute. A 403 containing protected content can be a finding; failed controls leave the result inconclusive. Reductions preserve the original evidence and must reproduce the violation with fresh controls. Omitted retest cases remain `not_retested`.

Studio and CLI share the same services and request budget. A frozen assessment produces JSON, HTML and PDF; an Ed25519 inventory binds the exported files. The standalone verifier needs Python, OpenSSL and a separately trusted public key.

The release includes public loopback labs and native-export provenance. I would value feedback on the control model, import boundaries and evidence handover.

**First comment:**

A few implementation details for reviewers:

The supported native Burp path is a complete Raw request/response pair saved from the message editor, with an explicit source origin. The retained Burp 2026.9.2 Save item XML contains a DTD and is deliberately rejected. The raw-message profile has its own acceptance addendum and provenance.

Import, rendering and verification are local. Active assessments contact the explicitly authorized target and count controls, setup, reads, reduction and cleanup against the request budget. The reducer makes a bounded claim within the approved removable units.

The standalone verifier establishes signed file integrity and report anchors. The main verifier also checks supported retained assessment semantics. Neither independently observes the remote target or authenticates an operator by itself. Demo keys are demonstration trust anchors.

The source is visible under the repository's rights-reservation licence; this is not an open-source licence. Installation, synthetic reproductions and the acceptance record are linked from the release. Please keep credentials and client data out of public issues.

## Reddit — r/netsec

**Title:** AuthzLedger 1.1.0: controlled authorization tests, scoped retests, signed evidence

**Post:**

I'm sharing AuthzLedger 1.1.0, a local authorization assessment workbench with a Studio interface and CLI.

The workflow starts with a saved Burp raw request, ZAP JSON+ export or HAR entry. You explicitly bind identities and controls, define the authorization rule and review a bounded execution plan. Findings depend on the configured predicate and valid controls, rather than the HTTP status alone.

The release adds bounded reproducer reduction, isolated workflow checks and source-bound selective retests. Original evidence is retained; omitted cases remain `not_retested`. JSON, HTML and PDF use one frozen snapshot, and an Ed25519 inventory binds the exported files. Package integrity can be checked with a standalone verifier and a separately trusted public key.

Public loopback labs, native-export provenance, tests and verification limits are included. The native Burp raw profile is separate from XML; DTD-bearing XML remains rejected. Source is visible under the repository's rights-reservation licence.

Release and reproducible labs:
https://github.com/0xFarag/0xFarag/releases/tag/v1.1.0

**First comment:**

For a focused review, start with the 403 disclosure/control counterexamples, then the selective retest. The latter keeps a scoped `fix_verified` outcome distinct from `not_retested` coverage.

For the import boundary, `tools/check_native_burp.py` checks the pinned public native capture, its provenance and controlled execution, and confirms rejection of the native DTD-bearing XML. It does not authenticate arbitrary uploaded files.

For handover, run both bundle verifiers against the same explicitly trusted public key. The standalone path checks signature, inventory and report anchors; the installed verifier adds supported semantic checks. The synthetic labs establish reproducible behavior within their declared scope, not production-wide coverage or a benchmark against other tools.

## 60-second film

**Format:** 16:9 master plus a separately framed 9:16 version. Real Studio captures and terminal output from the verified 1.1.0 build. Keep the selected finding, controls and source context readable in both crops.

**Art direction:** Navy `#071722`, Gold `#C8A66B`, pale text `#EDF5F7`. Preserve the existing mark. Use restrained movement, generous empty space and clean cuts between meaningful states. Let actual evidence supply the visual detail. Music stays below the voice; captions remain legible without sound. Use gold for emphasis, not as a substitute for a result label.

| Time | Picture and actual action | On-screen text / edit |
|---|---|---|
| 0–10s · The boundary | Open on an actual local-lab finding in **Investigate the evidence.** Show HTTP 403, the configured protected marker predicate and valid controls in the evidence view. Hold long enough to read the result. | Editorial title: **403 kann Daten preisgeben.** Persistent small label: **Synthetic local fixture**. No fabricated scanner alerts. |
| 10–30s · The workflow | Cut to **Burp raw request / response**: source origin and saved files, then **Import selected messages offline**. Show mapped identities and **Preview controlled experiment**, the exact scope authorization and the resulting finding. Continue to **Reduce selected finding** and a real accepted reduction with its request count. | Use the actual UI labels. Show source and reduced result together. Label compressed execution cuts **Edited for time**; do not imply an elapsed-time benchmark. |
| 30–45s · The handover | In **05 Handover**, choose **Freeze assessment snapshot**, then **Export signed proof package**. Cut to the real isolated standalone verification command, supplied with the recipient's separately trusted public key. Hold on the actual successful output and readable file/key context. | Editorial caption: **Ed25519 · Signatur + Dateiinventar**. Retain the displayed public-key fingerprint. Do not animate or reconstruct a success message. |
| 45–60s · The next step | Show the real retest comparison with a scoped `fix_verified` outcome and an omitted `not_retested` case. End on the original mark, version and verified GitHub release destination. | **AuthzLedger 1.1.0** / **Show the boundary. Keep the proof.** / **Download auf GitHub**. Keep the release URL visible through the final hold. |

**German voiceover — 118 words:**

**0–10s**

Ein 403 kann geschützte Daten enthalten. Für einen belastbaren Befund zählen die Regel, die Identität und gültige Kontrollen.

**10–30s**

AuthzLedger 1.1.0 bringt diesen Ablauf in eine lokale Workbench. Importiere native Burp-Nachrichten, ZAP-Exporte oder HAR-Dateien. Lege Regel und Identitäten fest, prüfe den Request-Plan und starte den freigegebenen Test. Reduziere anschließend nur ausgewählte Bestandteile; jeder akzeptierte Schritt muss den Befund mit frischen Kontrollen erneut bestätigen.

**30–45s**

Friere den geprüften Stand ein. JSON, HTML und PDF gehen in ein Ed25519-signiertes Paket. Der separate Verifier prüft Signatur und Dateiinventar gegen deinen vertrauenswürdigen öffentlichen Schlüssel.

**45–60s**

Beim Retest bleibt sichtbar, welcher Fix geprüft wurde und welche Fälle nicht erneut getestet wurden. AuthzLedger 1.1.0 auf GitHub. Lade das lokale Lab, prüfe die Evidenz und verifiziere das Paket.

The prepared captions are `brand/release-1.1.0/authzledger-1.1.0-voiceover.srt`. Their timings describe this 60-second edit; align them to the recorded voice before publishing. The storyboard and captions do not constitute a recorded video.

## Asset handoff

Use the reviewed companion brand package under `brand/release-1.1.0/`. The intended files are:

| File | Use |
|---|---|
| `launch-landscape.png` / `.svg` | 1600 × 1000 release or LinkedIn visual. |
| `launch-portrait.png` / `.svg` | 1080 × 1350 portrait feed visual. |
| `studio-source.png` | Unmodified actual Studio screenshot used by the layouts. |
| `provenance.json` | Source screenshot and build/asset provenance. |
| `authzledger-1.1.0-voiceover.srt` | Prepared German captions for the 60-second edit. |

Check the companion files and their provenance before attaching them. The artwork uses **Show the boundary. Keep the proof.** and identifies the actual Studio capture as a synthetic local fixture. Do not relabel historical 1.0 videos as 1.1 or attach a video before its real recording is reviewed.

## Evidence and activation

Product claims are supported by the [acceptance ledger](acceptance-1.1.0.md), [native exporter record](exporter-gate-1.1.0.md), [reporting profile](reporting-profile-1.1.0.md), [release record](release-1.1.0.md) and receipts for the exact candidate. Historical test counts are not reused as current results.

Publish the verified GitHub release first. Read back the immutable tag, download assets and checksums, then use the channel copy above with that same release URL. Record actual post URLs and publication times separately; an unavailable channel retains a draft. No social account access, sent post, uploaded video, independent security certification or performance benchmark is implied by this package.
