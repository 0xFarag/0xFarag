# AuthzLedger Evidence Export für Burp Suite

Die Java-Erweiterung exportiert die in **Proxy → HTTP history** markierten HTTP-Austausche als lokale Burp-XML-Datei. Jede Zeile enthält URL, Methode, HTTP-Status sowie die vollständigen Request- und Response-Bytes aus der Montoya-API. Zwei einzeln ausgewählte Exporte mit gleicher Reihenfolge und gleichem Inhalt ergeben identische XML-Bytes.

## Installation und Export

1. In Burp unter **Extensions → Installed → Add** den Typ **Java** wählen und die Release-Datei `AuthzLedger-Burp-Export-1.5.0.6.jar` laden. Ein lokaler Build heisst `authzledger-burp-export.jar`. Der Name in der Liste lautet **AuthzLedger Evidence Export**. Der Burp-Java-Prozess braucht Java 21 oder neuer und eine Montoya-API mit den Funktionen von 2025.3.
2. Im Burp-Projekt den Ziel-Scope des autorisierten Mandats konfigurieren. Eine oder mehrere vollständige Zeilen in **Proxy → HTTP history** markieren. Der Rechtsklick öffnet **Extensions → AuthzLedger Evidence Export → Export selected evidence to AuthzLedger…**. Abhängig von der Burp-Version kann das Menü direkt unter **Extensions** erscheinen.
3. Einen neuen Dateinamen in einem geschützten Mandatsordner wählen und die Verarbeitung der Originaldaten bestätigen. Der Export arbeitet im Hintergrund. Eine Meldung zeigt den Abschluss oder den ersten Fehler mit Zeilennummer an.
4. Im AuthzLedger-Team-Cockpit das Mandat wählen, beim Quellenimport **Burp Suite XML** einstellen und die XML-Datei öffnen. In der lokalen Stable-Workbench entspricht das Format dem Importprofil `burp-xml`.
5. URL, Methode und Status mit der History vergleichen. Beobachtung und Control müssen separat geprüft und zugeordnet werden. Ein Import allein ergibt den Status einer Beobachtung.

Die Grenzen liegen bei **500 Zeilen** und **1 MiB XML** einschliesslich der Base64-Daten. Fehlt eine Antwort, liegt eine URL ausserhalb des aktuellen Burp-Scopes oder wird ein Limit überschritten, schlägt der gesamte Export fehl. Die URL muss als absolute HTTP(S)-URL im ASCII-Format vorliegen. Prozentkodierte Pfade und Abfragen sowie Punycode-Hosts werden unterstützt. Der Stable-Importer prüft zusätzlich seine eigenen Profil- und Headerlimits.

## Umgang mit Originaldaten

Die exportierte Datei enthält auch Cookies, Autorisierungsheader, Parameter und Nachrichteninhalte, soweit sie in den ausgewählten Nachrichten vorhanden sind. Base64 erhält die Bytes und bietet keinen Vertraulichkeitsschutz. Bei HTTP/2 stammt die Darstellung der Nachricht von Burp. Die Erweiterung exportiert weder TLS-Daten noch einzelne HTTP/2-Frames. Sie registriert nur das Kontextmenü der Proxy-History und stellt selbst keine Netzwerkanfragen.

Der Export legt im Zielordner eine temporäre Datei an und veröffentlicht sie nach vollständigem Schreiben als neuen Hardlink. Bestehende Dateien bleiben erhalten. Das Dateisystem muss Hardlinks unterstützen, beispielsweise NTFS oder ext4. POSIX-Dateien werden mit Modus `0600` angelegt. Auf Windows gilt die ACL des ausgewählten Ordners. Ein abrupter Prozessabbruch kann eine Datei namens `.authzledger-*.tmp` im Mandatsordner zurücklassen.

## Bauen und testen

Im Repository-Root mit Python 3.10+ und einem **JDK 21**:

```sh
python integrations/burp/build.py
```

Der erste Build lädt ausschliesslich das Compile-Only-JAR der PortSwigger Montoya API 2025.3 von Maven Central. Jeder Build prüft SHA-256 `a5704ba72024a42f81fe9090dd1352f9fa856fed49636ac411adf77aca121028`. Ein vorhandenes JAR kann über `--api-jar PFAD` angegeben werden. Optional prüft `--stable-importer PFAD` zusätzlich das Modul `authzledger/imports.py` eines vertrauenswürdigen Stable-1.5.0-Checkouts.

Das Skript kompiliert die Erweiterung, testet Registrierung und Menükontext gegen die echten Montoya-Schnittstellen und prüft Scope, Limits, Binärdaten, mehrfachen Export und Überschreibschutz. Der Integrationstest übergibt das Ergebnis unverändert an den Team-Importer und vergleicht den abgeleiteten Request-Schlüssel sowie die Nachrichtenbytes. Host-Objekte kommen aus einem lokalen Test-Double. Eine Abnahme in der Burp-Desktopoberfläche erfordert einen separaten Start von Burp.

Die Ergebnisse liegen unter `integrations/burp/build/`:

- `authzledger-burp-export.jar` enthält ausschliesslich Erweiterungsklassen, Manifest und `META-INF/NOTICE.txt`.
- `authzledger-burp-export.jar.sha256` enthält den SHA-256-Wert für die Integritätsprüfung. Im Build-Ordner verifiziert unter Linux `sha256sum -c authzledger-burp-export.jar.sha256` die Datei. Auf Windows liefert `Get-FileHash authzledger-burp-export.jar -Algorithm SHA256` den Vergleichswert.

Gleiche Quellen und derselbe JDK-Compiler erzeugen durch feste ZIP-Metadaten und sortierte Einträge identische JAR-Bytes. Montoya bleibt eine von Burp bereitgestellte Abhängigkeit.

[PortSwigger-Dokumentation zur Montoya API](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/creating/first-extension) · [Versionierte API](https://repo.maven.apache.org/maven2/net/portswigger/burp/extensions/montoya-api/2025.3/)

© Nasser Aldin Farag (0xFarag). All rights reserved.
