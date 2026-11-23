# AuthzLedger Recipient Studio · Preview 3

Die Desktop-Oberfläche prüft lokal über den Offline-Empfängerprüfer. Wählen Sie den unveränderten Handover-Ordner mit manifest.json und den separat bestätigten öffentlichen Schlüssel. **Verify handover** prüft Signatur, Inventar, Hashes und Berichtsanker. Mit einem MATCH ist die Integrität relativ zu diesem Schlüssel belegt. Der fachliche Befund erfordert eine separate Prüfung. Öffnen Sie nur eine abgeschlossene Übergabe, die während der Prüfung niemand bearbeitet.

## Windows x64

Das verifizierte Actions-Artefakt nach erfolgreichem Lauf herunterladen und entpacken. SHA-256 der EXE mit der zur Lieferung separat bezogenen Prüfsumme abgleichen:

```powershell
Get-FileHash .\AuthzLedgerRecipientStudio-x64.exe -Algorithm SHA256
.\AuthzLedgerRecipientStudio-x64.exe --studio
.\AuthzLedgerRecipientStudio-x64.exe C:\Evidence\handover --public-key C:\Trust\sender.pem
```

Doppelklick öffnet Studio. Die gleiche EXE enthält die CLI. Exitcode 0 steht für bestandene Prüfung, 1 für abgelehnte Belege, 2 für ungültige CLI-Syntax. Die EXE ist ohne Authenticode-Signatur gebaut. `--notices` zeigt mitgelieferte Lizenzen.

## Debian und Ubuntu mit grafischer Sitzung

Die Paketdatei und die zugehörigen Prüfsummen des gleichen Builds beziehen. Die Ausgabe von sha256sum vor der Installation mit dem unabhängig bezogenen Sollwert vergleichen:

```sh
sha256sum authzledger-verifier_1.5.0-preview3_all.deb
sudo apt install ./authzledger-verifier_1.5.0-preview3_all.deb
authzledger-studio
authzledger-verify /pfad/zur/uebergabe --public-key /pfad/zum/vertrauten-schluessel.pem
```

Im Anwendungsmenü erscheint **AuthzLedger Recipient Studio**. Das Paket ergänzt den unveränderten CLI-Prüfer aus Preview 1 um die lokale Oberfläche und die Abhängigkeit python3-tk. Zur Deinstallation dient `sudo apt remove authzledger-verifier`.

© Nasser Aldin Farag (0xFarag). All rights reserved. Mitgelieferte Drittkomponenten behalten ihre Lizenzen.
