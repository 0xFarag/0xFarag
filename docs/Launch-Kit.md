# AuthzLedger · Launch-Kit für GitHub und LinkedIn

**Authorization Intelligence, built on evidence**
Redaktionelle Vorlage für Nasser Aldin Farag · Schweiz · 24. November 2026

## GitHub · Release-Ankündigung auf Englisch

**AuthzLedger Team 1.5.0.3 — evidence you can hand over**

A reviewer should be able to trace a finding back to the control that supports it. AuthzLedger Team connects the source observation, control, finding and retest in one local workspace. A case that has not been retested stays visible as `not_retested`. The recipient can verify the signed evidence package with an independently confirmed Ed25519 public key. In Team 1.5.0.3, each finding carries a signed index of its source records and control. When an experiment is linked, its revision hashes travel with the handover. Raw HTTP traffic and internal experiment notes stay with the team.

Use the workbench with your own authorised exports from Burp, ZAP, HAR, OpenAPI, Nmap XML and Nuclei JSONL. Run it on your workstation or your team’s server. The installer opens the local setup for the first administrator. Admin, Lead Pentester, Pentester, Reviewer and Read-Only permissions apply on the server.

[Download Team 1.5.0.3 and SHA256SUMS](https://github.com/0xFarag/0xFarag/releases/tag/team-1.5.0.3) · [Install on Windows, Debian, Arch or Docker](https://github.com/0xFarag/0xFarag/blob/team-1.5.0.3/packaging/team/README.md) · [Review the five roles](https://github.com/0xFarag/0xFarag/blob/team-1.5.0.3/docs/Team-Login-RBAC.md)

**Download verification.** Download the archive you need and the release’s SHA256SUMS into the same directory. On Windows, compare the command output with the matching EXE entry in SHA256SUMS. On Linux, check the files in the current directory.

Windows PowerShell:

```powershell
Get-FileHash .\AuthzLedger-Team-1.5.0.3-Windows-x64.exe -Algorithm SHA256
```

Linux:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

The release checksums identify the distributed software. The recipient’s Ed25519 verification is a separate check on a customer handover.

© Nasser Aldin Farag (0xFarag). All rights reserved.

## LinkedIn · Beitrag auf Deutsch

**Welche Fälle wurden nach dem Fix tatsächlich noch einmal geprüft?**

Beim letzten Handover zählt, ob der Reviewer den Befund bis zu seiner Quelle und zur passenden Kontrolle zurückverfolgen kann. Dafür habe ich AuthzLedger gebaut.

In der Team-Workbench lässt sich ein eigener Fall importieren, mit einer Kontrolle belegen und nach einem Fix erneut beurteilen. Offene Retests bleiben sichtbar. Der Empfänger kann die Signatur der Übergabe selbst prüfen. Pro Befund sieht er die Quellreferenzen und bei verknüpften Experimenten die Prüfsummen der einzelnen Revisionen.

Für Schweizer Pentest-Beratungen und AppSec-Teams biete ich einen 30-Tage-Pilot an: zwei benannte Nutzer, ein autorisiertes Mandat, CHF 2’400. Wenn ihr eine Übergabe plant, interessiert mich besonders, wie viel Zeit euer Reviewer heute für die Rückverfolgung braucht.

[Pilotangebot](https://authzledger.com/pilotangebot.pdf) · [Workbench und Downloads](https://authzledger.com/)

Nasser Aldin Farag · Founder & CEO, AuthzLedger
© Nasser Aldin Farag (0xFarag). All rights reserved.

## LinkedIn · English post

**After a fix, can the reviewer tell exactly which cases were retested?**

I built AuthzLedger for the person signing off the handover. They can follow the finding to its source and control, see the coverage of the retest, and check the signature on the evidence they receive. For a linked experiment, the handover identifies each revision by its hash without sharing the internal review notes.

The Team workbench runs locally or on your team’s server. If your consultancy or AppSec team has a handover coming up, I’m opening 30-day pilots for two named users on one authorised engagement. The fee is CHF 2,400. I’d like to hear how your team measures review effort today.

[Product and downloads](https://authzledger.com/) · [Pilot offer in German](https://authzledger.com/pilotangebot.pdf)

Nasser Aldin Farag · Founder & CEO, AuthzLedger
© Nasser Aldin Farag (0xFarag). All rights reserved.

## Material und Freigabe

| Verwendung | Asset |
|---|---|
| Produktlogo und Linkvorschau | [Logo](https://authzledger.com/assets/authzledger-logo.png) · [Social Card](https://authzledger.com/assets/authzledger-social.png) |
| Fachpresse und Investoren | [Investor brief, PDF](https://authzledger.com/investor-one-pager.pdf) · [bearbeitbares Markdown](https://authzledger.com/investor-one-pager.md) |
| Anfragen | [Preisseite](https://authzledger.com/abos/) · [Pilotangebot](https://authzledger.com/pilotangebot.pdf) |
| Technische Nachweise | [Stable 1.5.0](https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0) · [Team-Release](https://github.com/0xFarag/0xFarag/releases/tag/team-1.5.0.3) · [Build-Workflow](https://github.com/0xFarag/0xFarag/blob/team-1.5.0.3/.github/workflows/team-release.yml) |

Vor dem Veröffentlichen Release-Tag und Downloadlinks aufrufen. Produktivpakete und Prüfsummen müssen zum gleichen Release gehören. Pro Kanal eine Sprachfassung veröffentlichen. Zahlen zu Kunden, Einsparungen oder Umsatz erst mit einem belastbaren Nachweis in die Ankündigung übernehmen. Die private Outreach-Sequenz ist für persönliche Einzelgespräche mit fachlichem Bezug vorgesehen.

© Nasser Aldin Farag (0xFarag). All rights reserved.
