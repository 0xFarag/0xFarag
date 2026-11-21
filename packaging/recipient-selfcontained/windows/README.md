# AuthzLedger Offline Recipient Verifier für Windows x64

Paketierungskandidat **1.5.0-win.1** für signierte AuthzLedger-Übergaben. Das Konsolenprogramm prüft das Ed25519-Siegel, das Dateiinventar, die SHA-256-Prüfsummen und die Bindung des Berichts. Der Empfänger braucht für das gebaute Programm weder Python noch eine separate OpenSSL-Installation. Der Build ist ohne Authenticode-Signatur vorgesehen.

Nach dem Entpacken den Fingerabdruck der EXE mit einer unabhängig bezogenen Freigabe vergleichen. Den öffentlichen Ed25519-Schlüssel des Absenders ebenfalls unabhängig bestätigen. Anschliessend in PowerShell im entpackten Verzeichnis ausführen.

```powershell
.\AuthzLedgerVerify-1.5.0-win.1-x64.exe .\uebergabe\proof --public-key .\vertrauen\absender.pem
$LASTEXITCODE
```

Exitcode 0 bestätigt die überprüften Eigenschaften der gelieferten Dateien. Exitcode 1 bedeutet, dass die Prüfung fehlgeschlagen ist. Bei einem Aufruffehler liefert die Hilfe Exitcode 2. Mit `--help`, `--version` und `--notices` lassen sich Bedienung, Buildbezeichnung und Lizenzhinweise abrufen. Ein formal gültiger Beleg beantwortet für sich allein keine Frage zum fachlichen Prüfumfang.

## Herkunft und Build

Das Paket enthält den eigenständigen Originalprüfer des Release v1.5.0 (SHA-256 `afe47e30606d61f09025fa8b2703d7446b08cc0a3093e4b82eace355bfba5303`) und eine eigene Windows-Einstiegsschicht. Diese verwendet die Ed25519- und SPKI-Implementierungen von pyca/cryptography. Die Originaldatei bleibt bytegleich. Beim Build wird in einer Arbeitskopie genau eine Zeile angepasst, damit verschachtelte Inventarpfade auf Windows dieselbe Schreibweise wie im signierten Manifest haben. Auf Windows weist die Einstiegsschicht zusätzlich Dateisystem-Reparse-Points zurück. Die Vergleichstests prüfen ein authentisches historisches Belegarchiv, eine gleich lange Ein-Byte-Manipulation, einen fremden Schlüssel, einen als vertrauenswürdig deklarierten eingebetteten Schlüssel sowie eine ungültige Signatur mit Originalprüfer und Paket.

Der Workflow läuft auf Windows Server 2022 x64. Er prüft die Originaldatei und das offizielle Belegarchiv gegen feste Prüfsummen, baut das Programm mit CPython 3.13 und PyInstaller und legt Build-Abhängigkeiten, native Testbelege, Lizenztexte sowie Dateiprüfsummen gemeinsam im Actions-Artefakt ab. Bei externer SHA-256-Bestätigung darf das Archiv offline geöffnet werden. Die konkreten Prüfergebnisse des gebauten Artefakts stehen in `windows-native-checks.json`. Ein Workflow-Entwurf ist noch keine fertige Windows-Freigabe.

[Historisches Produktrelease](https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0) · [pyca/cryptography](https://cryptography.io/) · [PyInstaller](https://pyinstaller.org/)

Die Rechte an den eigenen schutzfähigen Beiträgen bleiben Nasser Aldin Farag (0xFarag) vorbehalten. Die mitgelieferten Lizenz- und Urheberhinweise der externen Komponenten gelten jeweils für diese Komponenten.
