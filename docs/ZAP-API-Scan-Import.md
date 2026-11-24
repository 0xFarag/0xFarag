# ZAP-API-Scan-Berichte im Team-Cockpit

© Nasser Aldin Farag (0xFarag). All rights reserved.

## Bericht übernehmen

Öffne in AuthzLedger Team das autorisierte Mandat und wähle in den Quellen den Importtyp **ZAP**. Lade den bereits vorliegenden vollständigen JSON-Bericht hoch. ZAP bezeichnet diese API-Scan-Ausgabe als `-J`. Der Import liest eine lokale Datei. Er benötigt weder eine laufende ZAP-Instanz noch Zugang zum geprüften System.

Unterstützt wird die Struktur `site[].alerts[].instances[]` des traditionellen JSON-Berichts. Jeder Eintrag erhält eine fortlaufende Datensatznummer. Für jede Instanz zeigt die GUI die Regelkennung sowie, falls vorhanden, den numerischen Risiko- und Konfidenzwert des Scanners. Der SHA-256-Wert der Originaldatei bindet den vollständigen Bericht. Der Datensatz-Fingerabdruck bindet Regelkennung und unveränderte Instanz. Pro Import gelten 1 MiB und 1’000 Instanzen. Ein identischer Import im gleichen Fall liefert dieselbe Quelle.

Eine gültige Datei mit leerer Site- oder Alert-Liste erscheint mit null Datensätzen. Daraus ergibt sich keine Aussage über geprüfte Ressourcen oder Berechtigungen. Eine Alertgruppe ohne Instanzen wird zurückgewiesen, da ihr die Datensatzbezüge fehlen.

## Vom Hinweis zum kontrollierten Befund

1. Wähle einen ZAP-Datensatz als Beobachtung für einen **Hinweis**, wenn zunächst nur die Scanner-Meldung vorliegt.
2. Importiere zur Bestätigung separat aufgezeichnete HTTP-Belege im HAR- oder Burp-Items-Format. Wähle im neuen Befund das Asset, die beobachtete Abweichung und eine unterschiedliche Kontrollbeobachtung aus dem Mandat. Trage das erwartete und beobachtete Kontrollresultat ein.
3. Unter **Verknüpfter ZAP-Hinweis** kannst du den Originalbericht und die konkrete Instanz auswählen. Beim Speichern vergleicht der Server Methode, Schema, Host, effektiven Port, Pfad und Query der Instanz mit der separat belegten Beobachtung. Verschiedene Request-Bodys sind im Bericht nicht immer vergleichbar. Die fachliche Zuordnung bleibt Aufgabe des Reviewers.
4. Der signierte Bericht weist den ZAP-Verweis zusätzlich zur Beobachtung und zur Kontrolle aus. Er enthält Quelldigest, Datensatznummer, Datensatz-Fingerabdruck und gehashte Asset-ID. Roh-URLs und Scanner-Freitext bleiben in der gespeicherten Originaldatei. Für ältere Importe kann AuthzLedger die Vergleichsdaten aus den gespeicherten Originalbytes gewinnen. Ein bestätigter Befund bleibt bis zum gesonderten Retest als `not_retested` sichtbar.

Die Signatur bestätigt die Integrität der Übergabe. Die Prüfung der fachlichen Aussage setzt Zugriff auf die zugehörigen Originalbelege voraus.

## Formatquellen und Verifikation

[ZAP API Scan](https://www.zaproxy.org/docs/docker/api-scan/) · [ZAP Traditional JSON Report](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json/)

Die Integrationsfälle in `qa/test_team_zap_scan.py` laufen über denselben Dispatcher wie der authentifizierte Team-Server. Sie prüfen Quelldigests, Dubletten, leere Berichte, Altimporte, getrennte Mandate, unterschiedliche HTTP-Ziele, Pflichtkontrollen und den signierten Verweis. Die Benutzeroberfläche wird in `qa/team-ui.cjs` über einen laufenden lokalen Team-Server geprüft.
