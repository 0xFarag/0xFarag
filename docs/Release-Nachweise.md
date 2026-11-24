# AuthzLedger · Freigabenachweis vom 24. November 2026

## Stable 1.5.0

Der veröffentlichte Nachweis gehört zum Commit `03aea857e35358ddeb13d2a861b633e60c1ca873`. Am 20. Oktober 2026 liefen 682 von 682 Python-Tests erfolgreich, ohne Fehler oder übersprungene Fälle. Alle acht im Nachweis einzeln aufgeführten Browser-Suiten endeten mit Code 0. Die am 24. November erneut abgerufene Datei `verification.json` hat den SHA-256-Wert `4cb0d557238a9c46194241c78540dace69643e597e4d8b68200ff72097cd47e0`. Er stimmt mit dem veröffentlichten Verzeichnis überein.

[Stable-Nachweis](https://github.com/0xFarag/0xFarag/releases/download/v1.5.0/verification.json) · [Stable-Prüfsummen](https://github.com/0xFarag/0xFarag/releases/download/v1.5.0/SHA256SUMS.txt)

## Team 1.5.0.2 und Website

Der Tag `team-1.5.0.2` bezeichnet den Paketquellstand `27dcc00bb21f011b796213ae253bf1a14fc00a8a`. Der Auslösecommit `e3f1056ebd631a1a9cdac4417182b3f0617d38e1` fügte den Release-Auftrag für diesen Quellstand hinzu. Die fünf CI-Jobs für Quellpaket, Windows, Linux, Website-Abgleich und Veröffentlichung waren erfolgreich. Die Team-Prüfungen umfassen 18 Python-Tests und den vollständigen Chromium-Durchlauf der Team-Oberfläche. Die separate Website-CI bestand auf Ubuntu und Windows mit jeweils 202 Node-Testfällen, zwei Offline-ZIP-Tests und den Browserprüfungen. Auch die Paketierung der statischen Website bestand.

[Team-CI und Jobprotokolle](https://github.com/0xFarag/0xFarag/actions/runs/45369712582) · [Website-CI und Jobprotokolle](https://github.com/0xFarag/0xFarag/actions/runs/45369712618) · [Paketquellstand](https://github.com/0xFarag/0xFarag/tree/team-1.5.0.2)

## Öffentliche Downloads und Produktionsseite

Die öffentliche Release-Seite liefert acht Dateien. Für alle acht wurden die Dateilänge und der SHA-256-Wert mit den GitHub-Angaben abgeglichen. Für die sieben Nutzdateien wurde zusätzlich jeder Eintrag in `SHA256SUMS` mit den heruntergeladenen Bytes verglichen. Das Ergebnis stimmte für Windows-EXE, Debian-Paket, Arch-Paket, PKGBUILD, Quellarchiv sowie Docker- und OCI-Archiv überein. Die Windows-EXE enthält Versions- und Copyright-Metadaten. Eine kommerzielle Authenticode-Signatur ist nicht enthalten.

Unter `https://authzledger.com/` stimmten 93 abgerufene Dateien bytegenau mit dem erzeugten Website-Build überein. Die Stichprobe umfasste alle 75 lokalisierten HTML-Seiten, Startseite, Workbench, Download- und Preisübersicht, beide Cockpit-Module, den Sprachkatalog, beide kommerziellen PDFs und neun MP4-Dateien. Vercel meldete die Domain als verifiziert und die automatische Zertifikatserneuerung als aktiviert. Der öffentliche Zahlungsstatus meldete Solo- und Team-Checkout sowie das Zahlungsportal als deaktiviert. Die Website verweist auf die persönliche Lizenzofferte.

[Pakete und Prüfsummen](https://github.com/0xFarag/0xFarag/releases/tag/team-1.5.0.2) · [Beweis-Cockpit](https://authzledger.com/#beweis-cockpit) · [Preise](https://authzledger.com/abos/) · [Zahlungsstatus](https://authzledger.com/api/billing-status)

© Nasser Aldin Farag (0xFarag). All rights reserved.
