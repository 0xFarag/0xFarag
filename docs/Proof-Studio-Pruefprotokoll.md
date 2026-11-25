# AuthzLedger · Prüfprotokoll vom 25. November 2026

Die stabile Methode trägt weiterhin die Version 1.5.0. Die Web-Workbench wurde auf dem Website-Zweig mit Ausgangscommit `ab27230bf2d674761f57ec7b25eee831a4d5fafb` erweitert. Die folgenden Messungen stammen aus dem Entwicklungs-Checkout und einer separaten, unveränderten Arbeitskopie des Stable-Tags.

| Prüfung | Durchführung und Befund |
| --- | --- |
| Baseline | Auf Tag `v1.5.0`, Commit `03aea857e35358ddeb13d2a861b633e60c1ca873`, bestanden 682 Python-Tests. Alle acht originalen Chromium-Suiten liefen erfolgreich durch. |
| E-Mail, Session und Rollen | Login, gefälschte Identität, Fremd-Workspace, abgelaufene oder wiederverwendete Importtokens und entzogene Rechte über echte Server-Routen geprüft. Bestehende Konten bleiben nach dem Upgrade verwendbar. |
| Proof-Engine | 34 Tests im gemeinsamen Python-Lauf für Engine, API, Signatur, ZAP und Wiederherstellung bestanden. Der Zähler umfasst die Gruppen zusammen. 45 frühere Teamtests liefen separat, davon 44 erfolgreich und eine plattformbedingte Ausnahme für Windows-DPAPI unter Linux. |
| Browser | Chromium bediente die fünf Schritte, wechselte DE/EN/FR, speicherte einen Retest, signierte, exportierte und prüfte einen veränderten ZIP. Zusätzlich bestanden Prüfungen der bisherigen Team-Oberfläche, der neuen Markenbilder, der öffentlichen Sprachrouten sowie Desktop- und Mobilprüfungen der Website. |
| Synthetic Lab | Vier bestätigte 403-Beobachtungen, nachdem der Operator alle wirksamen Controls gesetzt hatte. Drei explizit ausgewählte Fälle mit separater Nachher-Quelle und belegter Marker-Abwesenheit ergaben drei `resolved_check`. Rechnung 1048 blieb `not_retested`. In der mitgelieferten Prüfkopie wurden 7 von 12 Budgeteinheiten verbraucht. |
| Integrität und Rotation | Externer öffentlicher Schlüssel und Hauptverifier akzeptierten die ursprüngliche Übergabe. Veränderte Bytes und ein falscher Schlüssel wurden abgelehnt. Der Alt-Schlüssel verifizierte das frühere Paket auch nach manueller Rotation. JSON, HTML und PDF gehen aus demselben Stand hervor. |
| Backup und Wiederherstellung | Geschützte Sicherung in ein leeres Verzeichnis wiederhergestellt, DB-Integrität geprüft, altes Paket bytegleich exportiert und über den separat bezogenen Schlüssel verifiziert. Anschliessend war eine neue Signatur möglich. |
| Integrationen | Mit Montoya kompiliertes Burp-JAR übergab zwei ausgewählte Beobachtungen über HTTP an eine lokale Teaminstanz. Das bereits verbrauchte Token lieferte 401. ZAP-Tests lasen vorhandene Alerts von einem lokalen HTTP-Testdienst. Es wurde kein externes Ziel kontaktiert. Eine interaktive Abnahme in einer installierten Burp-Desktopoberfläche steht aus. |
| Desk und Pilot | API und Chromium prüften Startfragen, Sprachgrenze, 20-Sekunden-Timeout, Providerfehler und 503 bei fehlendem Schlüssel mit simuliertem Provider. Das Pilotformular speicherte und löschte lokal, generierte den Brief in drei Sprachen und versendete keine Formularinhalte. |
| Distribution | Debian-Prüfpaket und Quellarchiv lokal reproduzierbar gebaut, Prüfsummen verglichen und den installierten Launcher aus dem ausgepackten Paket getestet. Native CI-Artefakte gelten ausschliesslich für den dort genannten Commit. Öffentlich stabil verlinkt sind die sechs vorhandenen Assets des Tags v1.5.0. |

## Nachprüfen

Im Website-Checkout die Laufzeit aus `team/requirements.txt` installieren. Die genauen Node-, Java-, Windows- und Linux-Schritte stehen im [Review-Workflow](../.github/workflows/proof-review.yml). Die [Betriebs- und Bedienanleitung](Proof-Studio-Betrieb.md) enthält Start, Login, Mandat, Abnahme und vollständige Backup-Probe.

```sh
python -m unittest discover -s qa -p 'test_proof*.py' -v
python -m unittest discover -s qa -p 'test_team*.py' -v
PYTHONPATH=. python packaging/team/launcher.py --self-test
python integrations/burp-handoff/build.py
node scripts/build-downloads.mjs
node scripts/build-locales.mjs
node --test qa/desk.cjs qa/desk-browser.cjs qa/pilot.test.mjs qa/desk-pilot-browser.cjs
node --test --test-concurrency=1 qa/proof-studio-brand.cjs qa/proof-studio-browser.cjs qa/team-ui.cjs
```

Die Signatur bestätigt die Integrität der übergebenen Bytes. Inhaltliche Aussagen zu einem Zielsystem setzen die Nachweise des verantwortlichen Prüfers voraus. Der Produktivnachweis für den kostenpflichtigen Modellzugriff und ein organisationsübergreifend erreichbares Studio mit geschütztem Dauerspeicher ist separat zu führen.

© Nasser Aldin Farag (0xFarag). All rights reserved.
