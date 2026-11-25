# AuthzLedger Handoff für Burp Suite

Das Menü **An AuthzLedger übergeben** übermittelt die im Proxy-Verlauf markierten Beobachtungen an einen bestehenden Prüflauf. Eine vollständige Antwort muss bereits im Verlauf vorliegen. Jede Zeile enthält ID, Quellhost, HTTP-Methode, reduzierten Pfad, Status, Markerentscheidung, Regel und Quelle. Die Regel lautet `authorization`, die Quelle `Burp`. Der Import führt keine Anfrage an einen Quellhost aus.

## Einrichten und übernehmen

1. Den Team-Server mit persistentem Workspace starten. In einem kommerziellen Prüflauf Scope, Rules of Engagement und Budget speichern. In Schritt **Import** ein Burp-Token ausstellen. Das Token gilt fünf Minuten, einmalig für diesen Prüflauf und die ausstellende Sitzung.
2. Das unten gebaute `authzledger-burp-handoff.jar` in **Burp → Extensions → Installed → Add → Java** laden. In der Erweiterungsliste erscheint **AuthzLedger Handoff**. Das ältere **Evidence Export** aus Team 1.5.0.5 ist ein separater XML-Exporter für vollständige Nachrichten und gehört nicht zu diesem Workflow.
3. In Burps Ziel-Scope die autorisierten Hosts festlegen. Unter **Proxy → HTTP history** bis zu 500 vollständige Einträge markieren und **An AuthzLedger übergeben** öffnen.
4. Die Workspace-URL mit dem genauen Pfad `/api/proof-import`, die erlaubten Quellhosts und das neue Token einsetzen. Für ein entferntes Team ist HTTPS erforderlich. Für den lokalen Server ist beispielsweise `http://127.0.0.1:8765/api/proof-import` zulässig. Die Empfänger-URL gegen den eigenen Team-Server prüfen. Hostliste und URL bleiben nur im Speicher der geladenen Erweiterung. Das Token wird für diesen Dialog verwendet.
5. Die Vorschau zeigt jede ausgewählte Zeile mit den Metadaten, die übermittelt werden. Einen vorliegenden geschützten Marker ausdrücklich pro Zeile ankreuzen. Ohne Auswahl bleibt der Wert `false`. Erst **OK** sendet den gesamten Stapel. Die Bestätigung enthält die angenommene Anzahl. Anschliessend die Beobachtungen und Controls im Cockpit prüfen.

Queries, Fragmente, Nutzerinformationen, Header, Cookies, Roh-Bytes und Request-/Response-Bodys erscheinen nicht im übermittelten JSON. URL-Nutzerinformationen führen zur Ablehnung. Feste Routennamen und kurze numerische IDs bleiben erhalten. Unbekannte Segmente werden mit gekürztem SHA-256 dargestellt. Diese Pseudonyme ermöglichen den Abgleich und können bei leicht erratbaren Segmenten wiedererkannt werden. Die Vorschau entscheidet, ob diese Daten für den Empfänger freigegeben sind. Der Quellhost muss in Burp, in der lokalen Allowlist und im Scope des Prüflaufs zugelassen sein. Bei einem abgelehnten Eintrag erfolgt keine Teilübertragung. Die Übergabe verwendet eine direkte Verbindung ohne Redirects oder Cookies.

Bei HTTP 401 ein frisches Token im betreffenden Prüflauf ausstellen. Nach einem Verbindungsabbruch zuerst im Cockpit prüfen, ob der Server den Stapel bereits angenommen hat. Ein Import führt ohne wirksame Controls zu keinem bestätigten Finding.

## Build und Prüfung

Voraussetzungen sind Python mit `team/requirements.txt`, ein JDK 21 einschliesslich `jdk.compiler` und die Montoya-API 2025.3 als Compile-Only-Abhängigkeit.

```sh
python integrations/burp-handoff/build.py
```

Der erste Lauf lädt die im Repository gepinnte Montoya-API von Maven Central und prüft ihre SHA-256-Prüfsumme. Für einen Offline-Build nach dem Bezug der Abhängigkeit `--api-jar /pfad/montoya-api-2025.3.jar` verwenden. Der Build erzwingt die Java-Tests, eine Übernahme über den echten lokalen Team-HTTP-Endpunkt mit einmaligem Token und den gemeinsamen Evidence-Importer. Ausgaben sind `build/authzledger-burp-handoff.jar` und die zugehörige SHA-256-Datei. Tests verwenden Montoya-Schnittstellen mit Testobjekten und einen lokalen Server. Eine interaktive Freigabe in der Burp-Desktopoberfläche ist ein eigener Prüfschritt.

[PortSwigger Montoya API](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/first-extension)

© Nasser Aldin Farag (0xFarag). All rights reserved.
