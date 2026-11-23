# AuthzLedger · Kostenfreie Offline-Prüfwerkzeuge

Das ZIP enthält zwei unabhängig nutzbare Kommandozeilenwerkzeuge mit lesbarem Quellcode. Entpacke es vollständig. Alle folgenden Befehle werden im entpackten Hauptordner ausgeführt.

## Kubernetes-Berechtigungen prüfen

Benötigt Node.js ab Version 22. Die drei Module im Ordner `rbac` laufen ohne Paketinstallation. Beispiele für die Prüfung einer Berechtigung, die Erstellung einer Prüfbasis und einen selektiven Retest stehen in [rbac/README.md](rbac/README.md).

```sh
node rbac/cli.mjs --help
```

## Eine lokale Datei prüfen

Benötigt Python ab Version 3.10. Python-Pakete sind nicht erforderlich. Verwende unter Windows bei Bedarf `py -3` anstelle von `python3`.

```sh
python3 dateipruefung.py README.md
python3 dateipruefung.py --clamav README.md
```

Der erste Aufruf liest die Datei und gibt ihre Länge, SHA-256, SHA-1 und MD5 als JSON aus. Für Integritätsvergleiche verwende SHA-256. Der zweite Aufruf nutzt zusätzlich ein bereits installiertes `clamscan` mit vorhandener lokaler Signaturdatenbank. ClamAV und seine Datenbank sind separat erhältlich. Dieses Paket installiert oder aktualisiert sie nicht. Mit `--clamav` unterscheidet der Bericht Erkennung, keine gemeldete Erkennung, fehlende Engine, unvollständige Prüfung und Fehler. Der Aufruf führt die übergebene Datei nicht aus.

Dateien bis 256 MiB können gehasht werden. Für den optionalen lokalen Scan gilt eine Grenze von 16 MiB. Der Dateipfad erscheint nicht im JSON. Ein Hashwert oder eine Prüfung ohne gemeldete Erkennung beweist keine Schadsoftwarefreiheit. Die Ergebnisse sind als `unsigned` gekennzeichnet.

| Prozesscode der Dateiprüfung | Bedeutung |
| --- | --- |
| 0 | Hash berechnet oder angeforderter Scan ohne gemeldete Erkennung beendet |
| 1 | Lokale Engine meldet eine Erkennung |
| 2 | Ungültige Eingabe, Datei nicht lesbar, Engine fehlt oder keine vollständige Scan-Aussage möglich |

## Integrität und Nutzung

Lade die zugehörige `SHA256SUMS.txt` von der Downloadseite. Unter Linux prüft `sha256sum -c SHA256SUMS.txt` das ZIP im selben Ordner. Unter Windows zeigt `Get-FileHash .\AuthzLedger-Offline-Pruefwerkzeuge.zip -Algorithm SHA256` den Vergleichswert an. Eine Prüfsumme allein bestätigt keine unabhängige Urheberschaft.

Nasser Aldin Farag (0xFarag) stellt dieses Paket zur kostenfreien lokalen Ausführung auf eigenen Daten und für ausdrücklich autorisierte Prüfungen bereit. Für weitergehende Rechte gilt die beigefügte [LICENSE](LICENSE). Das Paket enthält keinen Berechtigungsschlüssel für den AuthzLedger-Fachzugang.

© Nasser Aldin Farag (0xFarag). All rights reserved.
