# Bestehende ZAP-Ergebnisse im Prüflauf übernehmen

Der Import liest die bereits vorhandene Alertliste einer lokalen ZAP-Instanz über einen festen `GET /JSON/alert/view/alerts/`. ZAP arbeitet als Quelle. Der Team-Server schickt keine Anfragen an die in der Alertliste genannten Systeme.

## Betrieb

1. Eine ZAP-Instanz mit dem vorhandenen Bericht für das freigegebene Mandat bereitstellen. API-Key-Pflicht und Loopback-Bindung in ZAP beibehalten. In Team-Umgebungen ein dediziertes ZAP-Projekt mit ausschliesslich freigegebenen Beobachtungen verwenden.
2. Standardadresse aus Sicht des Team-Servers ist `http://127.0.0.1:8080`. Eine andere lokale Instanz kann die betreibende Person vor dem Serverstart über `AUTHZLEDGER_ZAP_ORIGIN` setzen. Erlaubt sind HTTP(S), eine numerische Loopback-Adresse und ein expliziter Port. Empfänger können weder über Browserparameter noch durch Redirects oder DNS-Rebinding ausgetauscht werden.
3. In einem kommerziellen Prüflauf unter **Import** die ZAP-Ergebnisübernahme wählen. Den ZAP-API-Key in das dafür vorgesehene Feld eingeben und den Import ausdrücklich auslösen. Der Key wird nur für diesen Abruf im Header `X-ZAP-API-Key` verwendet. Der Server speichert nur die projizierten Beobachtungen im Prüflauf.
4. Für jede Beobachtung werden ZAP-ID, Regel-ID, Host, Methode, reduzierter Pfad und ein gegebenenfalls ausdrücklich gelieferter Status übernommen. Fehlender Status bleibt `null`; der geschützte Marker bleibt `false`. Ein ausserhalb des Scopes liegender Host bleibt als `out_of_scope` sichtbar. Ein ZAP-Alert allein bestätigt kein Finding.

Eine leere Liste, ungültige JSON-Daten, fehlende Berechtigung und eine unerreichbare API liefern einen Fehler. Der Import ist auf 500 Alerts und 1 MiB begrenzt. Eine Antwort über der Grenze wird vollständig verworfen. Der Scope, das Budget und die spätere Bewertung laufen über denselben Importer und dieselbe Engine wie der Datei-Import.

```sh
python -m unittest qa.test_proof_zap -v
```

Der Test verwendet einen lokalen HTTP-Server mit einer vorgegebenen Antwort, prüft den exakten GET-Pfad, das Fehlerverhalten und die Bewertung einer ausserhalb des Scopes liegenden Beobachtung. Für den produktiven Abruf muss die Instanz vom Team-Server auf dessen Loopback-Interface erreichbar sein.

[OWASP ZAP API Reference](https://www.zaproxy.org/docs/api/)

© Nasser Aldin Farag (0xFarag). All rights reserved.
