# AuthzLedger Empfängerprüfer für Windows x64

Paketierungsvorschau zum Release v1.5.0. Das portable Konsolenprogramm prüft eine empfangene Übergabe gegen einen separat beschafften Ed25519-Schlüssel. Der gleichwertige Installer installiert es für den aktuellen Benutzer unter dessen lokalem Programmverzeichnis. Es braucht weder Administratorrechte noch Netzwerkzugriff. Der Prüfer bewertet Signatur, vollständiges Inventar, Datei-Hashes und Bericht-Verknüpfung. Welche Tests tatsächlich stattgefunden haben und ob ein fachlicher Befund zutrifft, muss der Empfänger getrennt beurteilen.

## Prüfen

Die Vorschau setzt eine vertrauenswürdig installierte Windows-x64-Version von Python ab 3.13 und OpenSSL ab 3 voraus. Python und OpenSSL werden separat bereitgestellt. Die beiden Variablen bezeichnen die jeweiligen EXE-Dateien. Das Beispiel verwendet übliche Installationspfade. Vor der Verwendung die Pfade der eigenen Installation kontrollieren, das Paket in einen lokal schreibgeschützten Arbeitsbereich entpacken und den öffentlichen Schlüssel des Absenders unabhängig bestätigen.

~~~powershell
$env:AUTHZLEDGER_PYTHON = (& py -3.13 -c "import sys;print(sys.executable)").Trim()
$env:AUTHZLEDGER_OPENSSL = "$env:ProgramFiles\Git\usr\bin\openssl.exe"
.\AuthzLedgerVerify-x64.exe .\authzledger-proof\C-retest-proof\proof --public-key .\authzledger-proof\trusted-public.pem
$LASTEXITCODE
~~~

Für das veröffentlichte Beispiel liegt der öffentliche Demo-Schlüssel im festgehaltenen ZIP, ausserhalb des signierten Bundles. Für Kundendaten gilt der unabhängig bestätigte Kundenschlüssel. Exitcode 0 bedeutet, dass die kryptografische und strukturelle Prüfung bestanden wurde. Exitcode 1 bezeichnet ein abgelehntes Paket. Exitcode 2 bezeichnet Bedienungs- oder Abhängigkeitsfehler. Relative explizite Programmpfade werden zurückgewiesen. Ohne Umgebungsvariablen werden python.exe und openssl.exe über den vertrauenswürdigen PATH gesucht.

## Lieferumfang und Herkunft

- AuthzLedgerVerify-x64.exe ist eine portable 64-Bit-Konsolenanwendung.
- AuthzLedgerVerify-Setup.exe ist ein NSIS-Installer mit demselben x64-Payload für den aktuellen Benutzer. Entfernen über die installierten Apps oder Uninstall.exe. Bestehende Benutzerdaten bleiben im Verzeichnis.
- Der Launcher enthält die exakten Bytes des historischen Empfängerprüfers. Er startet Python im isolierten Modus, ohne Bytecode-Cache, und bindet externe OpenSSL-Aufrufe an den aufgelösten Programmpfad. Die Vorschau weist NTFS-Reparse-Points vor Dateioperationen zurück.
- Original-Release und Demo-ZIP sind unter https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0 veröffentlicht. SHA-256 des eingebetteten verify_bundle.py ist afe47e30606d61f09025fa8b2703d7446b08cc0a3093e4b82eace355bfba5303. SHA-256 des Demo-ZIP ist 54b21858a89d498ba3b5050ad85f5969068bf79bcf5a07467297b3c3d1d5e817.
- Die v1.5.0-Vorschau liefert die Empfängerprüfung. Beide EXE sind unsigniert. Freigabe für reguläre Verteilung erfordert die Authenticode-Signatur des Herausgebers, Zeitstempel, Überprüfung der finalen Dateien und separate Veröffentlichung der endgültigen Prüfsummen.
- Der Windows-Test ist zugeschnitten auf das Format des historischen Demo-C-Pakets. Für mehrfach verschachtelte Unterverzeichnisse kann der historische Prüfer auf Windows ein gültiges Paket ablehnen. NTFS-Junctions, Netzlaufwerke und gleichzeitig beschreibbare Übergabeverzeichnisse liegen ausserhalb dieser Vorschau.

## Bauen

Im Quellenordner der Vorschau führt python build_windows.py den Bau von Launcher und Installer aus. Voraussetzungen sind Go ab 1.24, NSIS 3 mit Unicode-Unterstützung und ein Python-Interpreter für das Bauskript. Die offizielle Version des historischen Python-Prüfers muss bytegleich unter src/verify_bundle.py vorliegen. Der Bau prüft dessen SHA-256. Es gibt keine Go-Moduldownloads.

Ein frisches Windows-Benutzerprofil kann die portable und installierte Variante mit python smoke_windows.py PFAD-ZUM-ORIGINAL-DEMO-ZIP prüfen. Der Test installiert den Preview-Installer nur bei anfänglich fehlendem Preview-Verzeichnis, verändert eine einzelne PDF-Datei an einem Byte und verwendet einen unabhängigen temporären Testschlüssel. Er prüft den installierten Dateiinhalt, Ablehnungen, die Deinstallation und die Erhaltung einer eigenen Testdatei.

## Rechte

ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).

Die Rechte am eigenen AuthzLedger-Code und die bestehenden Nutzungsbedingungen stehen in upstream-LICENSE und upstream-NOTICE.txt. Die Drittkomponenten tragen ihre jeweiligen Rechtehinweise in Go-LICENSE.txt und NSIS-LICENSE.txt.
