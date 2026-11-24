# AuthzLedger · Freigabenachweis vom 24. November 2026

## Stable 1.5.0

Der veröffentlichte Nachweis gehört zum Commit `03aea857e35358ddeb13d2a861b633e60c1ca873`. Am 20. Oktober 2026 liefen 682 von 682 Python-Tests erfolgreich, ohne Fehler oder übersprungene Fälle. Alle acht im Nachweis einzeln aufgeführten Browser-Suiten endeten mit Code 0. Die am 24. November erneut abgerufene Datei `verification.json` hat den SHA-256-Wert `4cb0d557238a9c46194241c78540dace69643e597e4d8b68200ff72097cd47e0`. Er stimmt mit dem veröffentlichten Verzeichnis überein.

[Stable-Nachweis](https://github.com/0xFarag/0xFarag/releases/download/v1.5.0/verification.json) · [Stable-Prüfsummen](https://github.com/0xFarag/0xFarag/releases/download/v1.5.0/SHA256SUMS.txt)

## Team 1.5.0.3

Der veröffentlichte Paketquellstand ist `06a79cfa79578c51ecc45563fd8c6af98528e74b`. Der Commit `95924fe47645109a9e1909ef4e2aa4189893fa1f` löste die Veröffentlichung für genau diesen Quellstand aus. Der GitHub-Tag verweist auf den Paketquellstand.

| Prüfung | Ergebnis |
|---|---|
| Team-Dienst | 22 Python-Tests bestanden, darunter eine Übergabe vom nativen Dienst an den Empfänger-Verifier für JSON, HTML und PDF. |
| Team-GUI | Chromium führte den angemeldeten Fall von Import und Kontrollbeobachtung über den Revisionsabgleich bis zum signierten Bericht. |
| Website | Ubuntu und Windows bestanden jeweils 204 Node-Testfälle, zwei Offline-ZIP-Tests und die ergänzenden Browsertests. |
| Distribution | Windows-EXE, Debian- und Arch-Paket sowie Docker- und OCI-Archiv bestanden die plattformspezifischen Build- und Startprüfungen. Der Windows-Build enthält keine kommerzielle Authenticode-Signatur. |
| Öffentliche Übergaben | Der ältere Team-Beleg bleibt prüfbar. Bei neuen Übergaben wird der minimale Belegindex pro Befund geprüft. Kontroll- und Revisionsreferenzen werden an die signierte Übergabe gebunden. |

[Release](https://github.com/0xFarag/0xFarag/releases/tag/team-1.5.0.3) · [Team-CI](https://github.com/0xFarag/0xFarag/actions/runs/45375131537) · [Website-CI](https://github.com/0xFarag/0xFarag/actions/runs/45375131898)

## Abgleich der Veröffentlichung

Für alle acht Release-Dateien wurden die tatsächlich heruntergeladenen Bytes und Grössen mit den GitHub-Digests abgeglichen. Alle sieben Nutzdateien stimmen zusätzlich mit dem veröffentlichten Verzeichnis `SHA256SUMS` überein. SHA-256 des Prüfsummenverzeichnisses: `2159f719950ef4deecb2b37e44dd4c53934e72b40fe3f6f82d1c412328601640`.

Vercel meldet die Produktionsdomain als verifiziert, das Deployment als bereit und die automatische TLS-Erneuerung als aktiv. Alle 220 statischen Dateien des Builds wurden über ihre öffentliche HTTPS-Adresse abgerufen und bytegenau verglichen. Das Abnahmeprotokoll enthält URL, Länge und SHA-256 je Datei. Das öffentliche Beweis-Cockpit verarbeitet Falldateien lokal. Für Pilot und Jahreslizenzen steht das persönliche Angebot zur Verfügung. Der Online-Checkout und das Zahlungsportal sind deaktiviert.

[Abnahmeprotokoll mit URLs und SHA-256-Werten](../evidence/team-1.5.0.3-production.json) · [Beweis-Cockpit](https://authzledger.com/#beweis-cockpit) · [Downloadzentrum](https://authzledger.com/downloads/#team)

© Nasser Aldin Farag (0xFarag). All rights reserved.
