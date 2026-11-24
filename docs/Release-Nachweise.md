# Prüfnachweis · AuthzLedger Team 1.5.0.5

Der Release-Tag zeigt auf `30662554f589efaec273408701e3494939dff046`. Die öffentliche Website stammt aus dem Freigabecommit `ab27230bf2d674761f57ec7b25eee831a4d5fafb`.

| Prüfung | Ergebnis |
|---|---|
| Burp-Erweiterung | Mit JDK 21 gebaut. Registrierung und Kontextmenü über die Montoya-Schnittstellen geprüft. Die Importer aus Stable 1.5.0 und Team lasen beide exportierten HTTP-Austausche. Eine manuelle Bedienprobe in Burp Desktop ist offen. |
| Team auf Ubuntu | 44 von 45 Python-Tests bestanden. Der Windows-DPAPI-Test lief auf Windows. Der zusätzliche Chromium-Test bestand. |
| Schlüsselverwaltung auf Windows | 14 von 15 Rotationstests bestanden, darunter der native DPAPI-Test. Der POSIX-Dateimodustest lief auf Ubuntu. |
| Öffentliche Website | Alle drei Website-CI-Jobs bestanden. Der Bytevergleich aller 220 Dateien auf authzledger.com stimmt mit dem lokalen Build überein. |
| Pakete | Windows, Debian, Arch und die beiden Containerformate bestanden die Freigabeprüfungen. Alle acht Nutzdateien stimmen mit dem veröffentlichten SHA-256-Manifest überein. |

[Prüfdaten und einzelne SHA-256-Werte](../evidence/team-1.5.0.5-production.json) · [Release](https://github.com/0xFarag/0xFarag/releases/tag/team-1.5.0.5) · [Team-CI](https://github.com/0xFarag/0xFarag/actions/runs/45406141051) · [Website-CI](https://github.com/0xFarag/0xFarag/actions/runs/45406141132)

© Nasser Aldin Farag (0xFarag). All rights reserved.
