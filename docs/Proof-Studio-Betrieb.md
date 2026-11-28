# AuthzLedger · Proof Studio betreiben

Die öffentliche Website, das Team-Studio und die signierte Übergabe haben unterschiedliche Aufgaben. Das Studio führt einen Prüflauf auf einem dauerhaften Teamdienst. Der Operator arbeitet mit Beobachtungen, die bereits in einem autorisierten Mandat erhoben wurden. Der Dienst schickt keine Prüfanfragen an die Ziele. Die stabile Referenzmethode ist 1.5.0.

## Erstes Konto und Teamdienst

Für die lokale Einzelplatzinstallation den Desktop-Launcher starten. Sprache wählen, die eigene E-Mail-Adresse angeben und das Administratorpasswort zweimal eingeben. Der Assistent öffnet den Dienst erst nach erfolgreicher lokaler Einrichtung. Der Browser verbindet sich mit einem zufälligen Port auf `127.0.0.1`. Die Passworteingabe erfolgt im Dialog. Nach dem Schliessen des Launcher-Fensters endet der Dienst.

Für den gemeinsamen Betrieb den folgenden Beispielablauf unter einem eigenen Dienstkonto auf Linux ausführen. Er setzt eine geprüfte Quellversion, Python mit den Abhängigkeiten aus `team/requirements.txt`, ein dauerhaftes lokales Dateisystem und ein vorhandenes TLS-Zertifikat für den tatsächlichen Team-Host voraus. Pfade an die Installation anpassen. Für neue Datenverzeichnisse Besitzerrechte 0700 verwenden. Die Umgebung und der Datenbestand gehören dem Dienstkonto.

```sh
umask 077
DATA_DIR=/srv/authzledger/team-data
python -m team.server --data-dir "$DATA_DIR" --bootstrap
```

Den Bootstrap einmal vor Ort ausführen. Er fragt E-Mail und Passwort interaktiv ab. Ein bestehender Erstbenutzer sperrt den Bootstrap. Es gibt keinen öffentlichen Endpunkt für die Übernahme eines neuen Systems. Die Meldung `already_initialized` verlangt die Anmeldung am bestehenden Dienst. Sie ist kein Anlass, die Datenbank zu löschen.

```sh
python -m team.server --data-dir "$DATA_DIR" --host 0.0.0.0 --port 8765 \
  --certfile /etc/authzledger/tls/fullchain.pem \
  --keyfile /etc/authzledger/tls/privkey.pem
```

Den Port ausschliesslich den freigegebenen Clients oder dem eigenen Ingress zugänglich machen. Einen einzelnen aktiven Teamdienst pro Datenverzeichnis betreiben. Bei einem Ingress die TLS-Verbindung bis zum Teamdienst erhalten. Die Dienstadresse im Browser muss zu Zertifikat und Host passen. Der Teamdienst akzeptiert Cookies mit `HttpOnly`, `Secure` und `SameSite=Strict`. Schreibzugriffe der GUI benötigen zusätzlich den CSRF-Token. Eine Sitzung endet spätestens nach acht Stunden oder 30 Minuten Inaktivität. Die Rollen und die aktive Mitgliedschaft werden bei jedem Zugriff serverseitig überprüft.

Auf der öffentlichen Vercel-Site verweist `/studio/` auf die konfigurierte Teamadresse. In der vorgesehenen Vercel-Umgebung `AUTHZLEDGER_TEAM_ORIGIN` auf den vollständigen HTTPS-Origin des bereits betriebenen Dienstes setzen, zum Beispiel `https://studio.example.org`. Benutzerdaten, Pfad, Query und Fragment sind dort unzulässig. Nach der Konfigurationsänderung das Deployment aktualisieren. `GET /api/workspace` bestätigt die Konfiguration. Die Prüfung des Dienstes erfolgt zusätzlich durch Anmeldung und erneutes Laden eines gespeicherten Prüflaufs. Die SQLite-Datei und die Schlüsseldaten gehören auf den dauerhaften Team-Speicher.

Der öffentliche Desk nutzt `POST /api/desk` auf Vercel. `XAI_API_KEY` gehört ausschliesslich in dessen serverseitige Umgebung. Nach der Konfiguration eine Starterfrage ausdrücklich senden. Für die Produktionsabnahme eine echte Antwort des angegebenen Modells `grok-4.5` überprüfen. Bei fehlendem Zugriff, einem unbekannten Modell oder Providerfehler zeigt der Desk «Der Desk ist hier gerade nicht erreichbar.» Ein erfolgreicher Produktionstest hängt vom tatsächlich eingerichteten Anbieterzugang ab.

## Mitglieder und Rollen

Als Admin im Team die Mitgliederverwaltung öffnen und die E-Mail der Person, deren Sprache und die konkrete Rolle erfassen. Neue Konten benötigen ein Passwort mit 12–256 Zeichen. Für bereits existierende Konten desselben Dienstes nur Adresse und Rolle angeben. Ein Workspace braucht mindestens einen aktiven Admin. In den Kontoeinstellungen lässt sich die Sprache ändern.

| Rolle | Dossier lesen und Paket prüfen | Erheben, Controls, Retest, signieren und exportieren | Audit lesen | Mitglieder ändern und Schlüssel rotieren |
|---|---|---|---|---|
| Admin | Ja | Ja | Ja | Ja |
| Lead Pentester | Ja | Ja | Ja | — |
| Pentester | Ja | Ja | — | — |
| Reviewer | Ja | — | Ja | — |
| Read-Only | Ja | — | — | — |

Der Server leitet die Person aus ihrer Sitzung ab und ordnet Dossiers, Importe, Entscheidungen und Archive dem Workspace zu. Bei einer Rollenänderung gilt die neue Berechtigung bereits für den nächsten Zugriff. Historische Installationen können früher angelegte Konten mit Benutzernamen enthalten. Neue E-Mail-Workspaces verwenden die Proof-API und sperren den alten Anhang-Endpunkt. Die Umstellung alter Originaldateien erfordert eine eigenständige, vereinbarte Datenmigration.

## Einen Prüflauf in der GUI abschliessen

1. **Scope.** In der angemeldeten Workbench ein Dossier anlegen. Für ein Mandat die genehmigten Hosts, die Rules of Engagement und das Budget eingeben. Die Namen müssen den importierten Hosts entsprechen. Das Budget wird auf die Prüfung importierter Beobachtungen angerechnet. Ein ausgeschöpftes Budget bleibt mit `budget_blocked` sichtbar. Im Modus Lab verwendet das Studio die reservierte Quelle `lab.authz.local` mit vier definierten Invoice-Beobachtungen. Dieses Dossier bleibt vom kommerziellen Import getrennt.
2. **Import.** Quellformat auswählen und eine gespeicherte Datei übernehmen. Die Workbench schlägt bei erkennbaren Dateiinhalten das Quellformat vor. Die Auswahl lässt sich vor dem Import ändern. Neben den unten aufgeführten acht Werkzeugen unterstützt sie HAR, OpenAPI, Nmap XML und normalisierte EDR-/SIEM-Ereignisse zu Cobalt Strike. Dateiquellen sind auf 1 MiB begrenzt. Die Ausgangsbasis eines Prüflaufs nimmt höchstens 512 Beobachtungen auf. Unsichere XML-Deklarationen und ungültige Formate werden abgelehnt. Der Server speichert die bereinigten Beweisfelder und einen Quell-Hash. Querydaten, Header, Cookies und Roh-Bodies sind keine Felder des Dossiers. Rules of Engagement und Identifikatoren frei von Zugangsdaten halten.
3. **Beweis.** Für `token`, `identity`, `owner` und `denial` die tatsächlich geprüften Controls angeben und auswerten. `identity` benötigt `token`. Sowohl `owner` als auch `denial` benötigen `identity`. Die GUI zeigt die wirksame Kette, den Quellbezug und das Ergebnis. Für `confirmed` müssen zusätzlich Scope, Budget und geschützter Marker tragen. Ein einzelner HTTP-Status oder ZAP-Alert reicht dafür nicht aus.
4. **Retest.** Die zu prüfenden Fälle ausdrücklich auswählen, die Nachher-Beobachtung übernehmen und die Controls für den Retest angeben. Im Lab sind die Fälle 1042, 1043 und 1044 ausgewählt. Mit den vier wirksamen Controls, der synthetischen Nachher-Quelle und ausreichendem Budget ergeben sich drei `resolved_check` und für 1048 einmal `not_retested`. Ein kommerzieller Retest benötigt eine passende neue Beobachtung aus derselben Art von Quelle. Ohne vergleichbaren Nachweis bleibt er `inconclusive`. Nicht bestätigte Ausgangsfälle bleiben `not_applicable`. Nach dem ersten gespeicherten Retest oder der ersten Signatur ist die Ausgangsbasis eingefroren. Weitere Retest-Runden ergänzen deren Historie.
5. **Paket.** Berichtsprache auswählen, Paket signieren und anschliessend das gespeicherte ZIP herunterladen. Die Oberfläche zeigt `keyId`, JWK und Fingerabdruck. JSON, HTML und PDF stammen aus demselben Berichtsstand. Bei der Prüfung im Dossier validiert der Dienst die Archivbytes, die Workspace-Schlüsselhistorie, die quellgebundene Semantik und den Bezug zum Evidence-Root. Die Signatur belegt die inventarisierten Bytes. Aussagen über die tatsächliche Ausführung am Ziel hängen von der Herkunft der Beobachtungen ab.

Im Audit erscheinen unter anderem Anmeldung und Abmeldung, Mitglieder- und Rollenänderungen, Import, Control-Änderung, Retest, Signatur, Export und Rotation. Die Dossierhistorie enthält Version, Zeitpunkt, ausführende User-ID und Beweisbezug. Bei gleichzeitigem Bearbeiten weist `version_conflict` auf einen inzwischen gespeicherten Stand hin. Das Dossier erneut laden, die Änderung prüfen und mit der aktuellen Version erneut entscheiden.

### Acht Werkzeuge im selben Dossier

Legen Sie die genehmigten Webhosts und Verzeichnisdomänen im Scope fest. Importieren Sie jeden gespeicherten Export in dasselbe Dossier. Im Schritt **Beweis** lassen sich Beobachtungen für denselben Host über ihre Quellen nachvollziehen. Jede Datei behält ihren eigenen SHA-256.

| Quelle | Unterstützte Eingabe | Was der Prüfer im Dossier sieht |
|---|---|---|
| BloodHound | Gruppen-JSON mit `meta.type=groups`, Version 5 oder 6, expliziter Domäne und Mitgliedern derselben SID-Domäne | Gruppen und Mitgliedschaften. Ein Mitglied, das nur in einer Mitgliederliste vorkommt, ist als Referenz gekennzeichnet. |
| Neo4j | APOC JSON Lines mit explizit deklarierten Inventarknoten und Domäne. Unterstützte Beziehungen sind `MemberOf` und `Contains`. | Quellgebundene Knoten und Beziehungen. Beide Endpunkte einer Beziehung müssen in der Datei vorhanden sein. |
| Nessus | Nessus-v2-XML (`.nessus`) | Plugin, Dienst und vom Hersteller gemeldeter Schweregrad. |
| Burp Suite | Proxy- oder Issue-XML mit unterstütztem Deklarationsformat, alternativ ausgewählte Beobachtungen über die bestehende Burp-Übergabe | Bereinigte Webbeobachtungen und ihre Herkunft. |
| OWASP ZAP | JSON-Bericht mit Sites, Alerts und Instanzen | Betroffener Host, Regel und HTTP-Methode, soweit vorhanden. |
| Nuclei | JSON Lines mit positiven HTTP-Matches | Template-Bezug und verfügbarer Hersteller-Schweregrad. |
| Nikto | XML-Bericht mit Scan- und Item-Einträgen | Host, Prüf-ID und bereinigter Ressourcenbezug. |
| sqlmap | Mehrziel-Ergebnisdatei mit den fünf Standardspalten ab `Target URL` | Pro Zeile eine Quellenmeldung. Vom Werkzeug selbst bestrittene Treffer und Zeilen ohne gemeldete Technik bleiben getrennt. |

Knoten erhalten pro Quelldatei eigene Kennungen. Übereinstimmende Domänen oder Hostnamen helfen bei der gemeinsamen Sichtung. Sie belegen für sich allein weder identische Verzeichniskonten noch einen Berechtigungsfehler. Für den ersten Durchlauf dokumentieren Sie die Zahl der Quellen, den ersten überprüften Befund und die Zeit bis zum ersten für den Empfänger lesbaren Bericht.

### Automatischer Managementbericht

Für jedes neu angelegte Dossier speichert SQLite den Bericht gemeinsam mit der jeweiligen Dossierversion. Nach Import, Änderung der Controls, Retest oder Signatur entsteht eine weitere Fassung. Alle aktiven Teammitglieder können den Bericht öffnen. Die Druckansicht eignet sich für Besprechungen, der JSON-Export für die Weiterverarbeitung.

Die Übersicht zählt die Hosts im vereinbarten Scope, die in den Quellen beobachteten Hosts, die Beobachtungen je Prüfergebnis und den letzten Retest. Eine Beobachtung zu einem Host belegt nur, dass er in den importierten Daten vorkommt. Eine Aussage zur vollständigen Prüfung dieses Hosts lässt sich daraus nicht ableiten.

Nessus und Nuclei können für Beobachtungen im Scope einen Hersteller-Schweregrad liefern. Im Schritt **Beweis** führt die Prioritätenliste von kritischen und hohen Signalen unmittelbar zur zugehörigen Beobachtung. Quelle, Regel und Prüfstatus bleiben dabei sichtbar. Ein kritisches Signal erscheint in der Priorisierung, auch wenn der Berechtigungsbefund noch offen ist. Fehlende Schweregrade erscheinen als `unknown`. Nikto-Einträge und Cobalt-Strike-bezogene Ereignisse zählen zu den importierten Beobachtungen. Der Cobalt-Import erwartet kundenseitig normalisierte EDR-/SIEM-Daten im Format `authzledger.defensive-telemetry.v1`.

Jeder Managementbericht trägt seine Version und den Status `unsigned`. Für eine signierte Kundenübergabe das ZIP im Schritt **Übergabe** erzeugen. Bei vorhandenen Installationen ist der letzte vor dem Upgrade gespeicherte Dossierstand abrufbar. Historische Versionen mit fehlendem Bericht liefern HTTP 404.

### Burp und ZAP

Für Burp im kommerziellen Dossier einen Übergabetoken erzeugen. Im Plugin die Zieladresse, den Token und die erlaubten Quellhosts konfigurieren. Nur die ausgewählten Nachrichten über **An AuthzLedger übergeben** übertragen. Der Operator entscheidet ausdrücklich über den Marker. Der Token gilt für genau einen erfolgreichen Stapel, maximal fünf Minuten, den betreffenden Prüflauf und die aktive Sitzung. Nach einer unklaren Zustellung zuerst das Dossier aktualisieren. [Burp-Anleitung](../integrations/burp-handoff/README.md)

Der ZAP-Import liest vorhandene Alerts einer administrativ definierten lokalen Instanz. Standard ist `http://127.0.0.1:8080` aus Sicht des Teamdienstes. Eine andere Loopback-Adresse vor dem Start als `AUTHZLEDGER_ZAP_ORIGIN` festlegen. Den API-Key nur ins Importfeld eingeben. Die GUI meldet fehlende Berechtigungen, leere Ergebnisse und Verbindungsfehler. Der Import behält Beobachtungen ausserhalb des Scopes als `out_of_scope`. [ZAP-Anleitung](ZAP-Ergebnisimport.md)

## Dateien und VirusTotal im Team prüfen

In der **Dateiprüfung** eine Datei bis 16 MiB auswählen oder ihren SHA-256 eingeben. Der Browser berechnet den Hash und untersucht bei einer gewählten Datei die Formatkennung und auffällige Dateinamen. Ein passender exportierter VirusTotal-v3-Dateibericht lässt sich offline auswerten. Die Hashbindung prüft den Dateibezug. Die Herkunft des importierten JSON muss der Prüfer separat beurteilen.

Für den optionalen Live-Abruf hinterlegt der Betreiber einen für diese kommerzielle Nutzung lizenzierten API-Schlüssel als `AUTHZLEDGER_VT_PREMIUM_API_KEY` in der Serverumgebung und startet den Teamdienst mit dieser Konfiguration. Der Schlüssel gehört in den Secret-Speicher des Betreibers. Die Public API ist für kommerzielle Produkte ausgeschlossen. [VirusTotal-Nutzungsbedingungen für Public und Premium API](https://docs.virustotal.com/reference/public-vs-premium-api)

Ein schreibberechtigtes Teammitglied löst die Abfrage selbst aus. Der Dienst übermittelt den SHA-256 über HTTPS an den fest hinterlegten VirusTotal-Dateibericht-Endpunkt. Bereits der Hash kann VirusTotal die Identifikation einer bekannten Datei ermöglichen. Dateiname, Dateibytes, Sitzungsdaten und Mandatskontext werden in der Anfrage ausgelassen. [VirusTotal-Dateibericht-API](https://docs.virustotal.com/reference/file-info)

Der Dateibeleg lässt sich als unsigniertes JSON exportieren. Er unterscheidet lokale Prüfung, importierte JSON-Daten, eine Anbieterantwort und deren wiederverwendete Fassung. Für Integrationen liefert `GET /api/teams/{teamId}/file-reputation/status` die Verfügbarkeit. Die bewusste Abfrage erfolgt per `POST /api/teams/{teamId}/file-reputation/lookup` mit `{"sha256":"…","consent":true}`, Sitzung und CSRF-Token. Bei einem wiederholten Abruf desselben Hashs kann der Dienst das Ergebnis im selben Team bis zu fünf Minuten wiederverwenden.

Für die Beurteilung die Zahl der meldenden Engines, das letzte Analysedatum und die Herkunft des Berichts zusammen lesen. Bei einem unbekannten Hash ist die Datei unbewertet. Null Erkennungen können auch bei neuer Schadsoftware vorkommen.

## Verifikation und Rotation

Einen öffentlichen JWK aus **Schlüsselhistorie** im authentifizierten Workspace als JSON-Objekt sichern. Der Prüfer erhält den passenden JWK oder dessen vorab vereinbarten Fingerabdruck über einen unabhängigen Vertrauenskanal. Für die Prüfung denselben öffentlich gepinnten JWK verwenden, auch wenn eine Rotation bereits einen neuen aktiven Schlüssel erzeugt hat.

```sh
python team/proof_verify.py uebergabe.zip --key freigegebener-jwk.json
```

Für ein Kundenticket lässt sich ein JSON-Prüfbeleg erzeugen. Die erwartete Workspace-ID und den öffentlichen Schlüssel vorab über einen unabhängigen Kanal bestätigen. Im Beispiel die tatsächliche ID einsetzen.

```sh
python team/proof_verify.py uebergabe.zip --key freigegebener-jwk.json --workspace WORKSPACE-ID --receipt-json
```

Nur bei Exit-Code 0 die JSON-Ausgabe übernehmen. Sie enthält den SHA-256 des vollständigen ZIP, die ID des geprüften Schlüssels, den Workspace sowie die signierten Ausgangs- und Reteststatus pro ursprünglicher ID. Der Prüfer gleicht die Anzahl pro Status mit der signierten Abdeckung ab. `not_retested` hält eine im letzten Lauf ausgelassene ID sichtbar. Ohne `--workspace` steht `workspacePinned` auf `false`.

Der Beleg ist eine lokal erzeugte Zusammenfassung. Die Signatur gehört zum Originalpaket. Wer den Beleg später überprüfen möchte, benötigt dieses Paket und den unabhängig bestätigten JWK. Für die Bewertung der fachlichen Aussagen dient die semantische Prüfung im nächsten Absatz.

Exit-Code 0 bestätigt die Signatur des Inventars und die Dokumentbytes. Ein anderes Byte oder ein fremder Schlüssel muss den Aufruf scheitern lassen. Der eigenständige Verifier benötigt Python und `cryptography`. Für die semantische Gesamtprüfung das ZIP im zugehörigen Dossier prüfen oder die API-Funktion `team.proof_packages.verify_package(archive_bytes, trusted_jwk, workspace_id)` verwenden. Für ein bereits verifiziertes Berichts-JSON lässt sich die Beweislogik zusätzlich offline wiederholen.

```sh
python -m team.proof_cli verify-semantics report.json
```

Die Rotation ist eine ausdrückliche Admin-Aktion im Paket-Schritt. Danach den neuen JWK separat bekanntgeben. Der alte öffentliche Schlüssel bleibt erhalten und vorhandene Archive bleiben bytegleich. Die Rotation widerruft den öffentlichen Vertrauensentscheid für historisch signierte Pakete nicht. Bei einem vermuteten Schlüsselverlust die betroffenen Übergaben und den Vertrauenszeitraum mit den Empfängern klären.

## Sicherung und Wiederherstellungsprobe

Die folgenden Kommandos gelten für eine einzelne Linux-Instanz. Der Sicherungsort muss bereits ein geschütztes, verschlüsseltes und für das Dienstkonto beschreibbares Sicherungsziel sein. Vor der Sicherung den Teamdienst und Desktop-Launcher geordnet beenden und sicherstellen, dass kein zweiter Prozess in das Datenverzeichnis schreibt. Die Sicherung umfasst den vollständigen Datenbestand einschliesslich SQLite-Journaldateien und der geschützten Schlüsseldatei `proof-workspaces.kek`. Der KEK gehört nie in eine Kundenübergabe. Windows schützt Schlüssel zusätzlich über das Benutzerkonto des Dienstes. Eine Datei-Kopie allein ist dort kein bestätigter Benutzer- oder Maschinenwechsel.

```sh
umask 077
DATA_DIR=/srv/authzledger/team-data
BACKUP_DIR=/mnt/verschluesseltes-backup/authzledger
BACKUP_RUN=$(mktemp -d "$BACKUP_DIR/studio-XXXXXXXX")
tar -cpf "$BACKUP_RUN/team-data.tar" -C "$DATA_DIR" .
(cd "$BACKUP_RUN" && sha256sum team-data.tar > team-data.tar.sha256)
(cd "$BACKUP_RUN" && sha256sum -c team-data.tar.sha256)
```

Die Prüfsumme dient der Erkennung von Übertragungsfehlern. Gegen eine absichtliche Änderung von Archiv und Prüfsumme zusammen hilft ein unabhängig verwahrter Prüfnachweis. Für die Probe ein leeres Verzeichnis auf geschütztem Speicher benutzen und nur ein eigenes, vertrauenswürdig verwahrtes Backup auspacken. Der Live-Datenbestand wird dabei nicht überschrieben.

```sh
RESTORE_DIR=$(mktemp -d "$BACKUP_DIR/probe-XXXXXXXX")
tar -xpf "$BACKUP_RUN/team-data.tar" -C "$RESTORE_DIR"
python - "$RESTORE_DIR" <<'PY'
from contextlib import closing
from pathlib import Path
import sqlite3
import sys

root = Path(sys.argv[1]).resolve()
with closing(sqlite3.connect((root / "team.sqlite3").as_uri() + "?mode=rw", uri=True)) as db:
    db.execute("PRAGMA foreign_keys=ON")
    if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise SystemExit("SQLite-Integritaetspruefung fehlgeschlagen")
    if db.execute("PRAGMA foreign_key_check").fetchone():
        raise SystemExit("Fremdschluesselpruefung fehlgeschlagen")
    db.execute("DELETE FROM proof_import_tokens")
    db.execute("DELETE FROM sessions")
    db.commit()
print("SQLite geprueft. Fruehere Sitzungen und Importtokens dieser Wiederherstellung verworfen.")
PY
python -m team.server --data-dir "$RESTORE_DIR" --host 127.0.0.1 --port 8766
```

Im isolierten Dienst erneut anmelden, Workspace, Rollen und Audit-Stand gegen den letzten dokumentierten Stand vergleichen. Ein bereits vor der Sicherung exportiertes Paket aus dem restaurierten Dossier erneut herunterladen und Bytegleichheit prüfen. Mit dem unabhängig verwahrten JWK verifizieren. Vor erneuter Produktivfreigabe auch den erwarteten **aktiven** Fingerabdruck abgleichen und in einem isolierten Lab-Dossier die Signatur einer neuen Übergabe prüfen. Fehlende Schlüssel oder Abweichungen zuerst klären. Der Probe-Dienst bleibt bis zum Abschluss ausschliesslich auf Loopback.

## HTTP-Schnittstellen

Die Team-API liegt auf demselben Origin wie die authentifizierte GUI. Die Pfade der Tabelle mit dem Präfix `/api/teams/{teamId}/proof` verwenden. Die Rechteprüfung geschieht auf dem Server. Die `version` in einer Mutation ist die zuvor gelesene Dossierversion.

| Methode und Unterpfad | Ein- und Ausgabe |
|---|---|
| `GET /` und `POST /` | Liste lesen oder mit `mode, hosts, roe, budget` anlegen. Im Lab genügt `{"mode":"lab"}`. |
| `GET /{id}` | Dossier mit Version, Quellen, Controls, Ergebnissen, Historie und signierten Paketen. |
| `GET /{id}/management-report` | Aktuelle aggregierte Fassung als `{filename, report}`. |
| `GET /{id}/management-report/{revision}` | Gespeicherte Fassung anhand der positiven Dossierversionsnummer abrufen. |
| `POST /{id}/import` | `version, format, content_b64` übergeben. Der Server persistiert die normalisierte Projektion. |
| `POST /{id}/controls` | `version, controls`. Alle vier Entscheidungen müssen boolesch sein. |
| `POST /{id}/retest` | `version, selected, controls`. Optional gemeinsam `format, content_b64`, im Lab alternativ `labAfter:true`. |
| `POST /{id}/sign` und `POST /{id}/export` | Mit `version, language` signieren. Mit `packageId` das eingefrorene ZIP als `archive_b64` beziehen. |
| `POST /{id}/verify` | Ein `archive_b64` anhand der Vertrauenshistorie und des Evidence-Roots prüfen. |
| `GET /keys` und `POST /rotate` | Vertrauenshistorie lesen. Admin rotiert mit leerem JSON-Objekt. |
| `POST /{id}/token` und `POST /{id}/zap` | Burp-Einmal-Token erstellen oder mit `version, apiKey` die bestehende ZAP-Ergebnisliste lesen. |

`POST /api/login` verwendet E-Mail und Passwort. `GET /api/session` liefert die aktuelle Mitgliedschaft und den CSRF-Token. Zustandsändernde Sitzungsaufrufe senden diesen als `X-CSRF-Token`. Der Burp-Endpunkt `POST /api/proof-import` nimmt ausschliesslich den gebundenen Bearer-Token sowie `{"observations":[...]}` entgegen. Cookies im Burp-Aufruf sind überflüssig und werden für diese Authentisierung zurückgewiesen.

© Nasser Aldin Farag (0xFarag). All rights reserved.
