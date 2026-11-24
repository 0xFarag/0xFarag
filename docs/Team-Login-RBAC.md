# Team-Login und Rollen in AuthzLedger

Dieses Dokument richtet sich an Betreiber und Teamleitungen einer selbst betriebenen AuthzLedger-Instanz. Das Team arbeitet mit einer gemeinsamen Datenbank. Die Mitgliedschaft im gewählten Team bestimmt, welche Fälle eine Person sehen und welche Arbeitsschritte sie ausführen kann.

## Rollenmatrix

Die Zuordnung gilt pro Team. Eine Person kann im ersten Team Reviewer und im zweiten Pentester sein. Eine Anmeldung allein verleiht keine Rechte an einem weiteren Team.

| Aktion im ausgewählten Team | Admin | Lead Pentester | Pentester | Reviewer | Read-Only |
|---|:---:|:---:|:---:|:---:|:---:|
| Berechtigte Fälle, Befunde und Retest-Stände lesen | ✓ | ✓ | ✓ | ✓ | ✓ |
| Vorhandene Übergaben verifizieren | ✓ | ✓ | ✓ | ✓ | ✓ |
| Fälle anlegen und Belege in einen Fall importieren | ✓ | ✓ | ✓ | — | — |
| Originalbytes eines Fallimports abrufen | ✓ | ✓ | ✓ | — | — |
| Befunde erfassen und Retest-Ergebnisse dokumentieren | ✓ | ✓ | ✓ | — | — |
| Signierte Übergabe freigeben | ✓ | ✓ | — | ✓ | — |
| Team-Auditprotokoll einsehen | ✓ | ✓ | — | ✓ | — |
| Mitgliedschaften und Rollen verwalten | ✓ | — | — | — | — |

Die technischen Rollenkennungen lauten `admin`, `lead_pentester`, `pentester`, `reviewer` und `read_only`. Wer bereits in mindestens einem aktiven Team Admin ist, darf ein weiteres Team anlegen und wird dort Admin. Ein Team-Admin kann sein Team umbenennen. Der letzte aktive Admin eines Teams lässt sich weder deaktivieren noch herabstufen. Admin und Lead Pentester dürfen sowohl dokumentieren als auch freigeben. Ein verbindliches Vier-Augen-Prinzip setzt einen zusätzlichen Prozess voraus. Eine neue Rolle wirkt auf den Zugriff über den Dienst. Bereits exportierte Dateien unterliegen danach dem Schutz des Empfängers.

## Erste Anmeldung

1. Die Instanz mit einem eigenen, zugriffsgeschützten Datenverzeichnis einrichten. Dienstkonto, Installationsverzeichnis und persistente Daten unterscheiden. Die Datenbank gehört ausserhalb des von einem Webserver ausgelieferten Verzeichnisses.
2. Den lokalen Bootstrap des Servers oder die Ersteinrichtung des installierten Pakets starten. Den ersten Admin und dessen Kennwort direkt am Gerät eingeben. Kennwörter gehören weder in Kommandozeilenargumente noch in Protokolle.
3. Den Dienst zunächst an der Loopback-Adresse starten. Mit dem ersten Admin über die angezeigte Adresse anmelden und die Teamverwaltung öffnen.
4. Für jede Person ein eigenes Konto mit der benötigten Teamrolle einrichten. Den Zugang mit einem zweiten Browserprofil prüfen. Erst danach reale Belege importieren.

Im installierten Linux-Paket führt die erste Zeile den einmaligen Bootstrap durch und beendet sich. Die zweite startet den Dienst mit denselben Daten lokal. Das nachfolgende Verzeichnis ist ein Beispiel. Beim regulären Standardstart verwendet der Dienst das Verzeichnis `~/.authzledger-team`.

```sh
authzledger-team --data-dir "$HOME/authzledger-daten" --bootstrap
authzledger-team --data-dir "$HOME/authzledger-daten" --host 127.0.0.1 --port 8765
```

Die lokale Adresse lautet `http://127.0.0.1:8765/`. Beim Start aus einem Quellcheckout mit installierten Abhängigkeiten entspricht `python -m team.server` dem installierten Kommando. Die Desktop-Ersteinrichtung fragt das Kennwort in zwei verdeckten Eingaben ab. Der Bootstrap ist nur bei leerem Benutzerbestand möglich. Für die Einrichtung gilt eine Kennwortlänge von 12 bis 256 Zeichen.

## Betrieb im Teamnetz

Für mehrere Arbeitsplätze betreibt das Team **eine Instanz mit einem gemeinsamen persistenten Datenverzeichnis**. Alle Mitglieder verwenden den vereinbarten HTTPS-Ursprung dieser Instanz. Separate Installationen mit separaten Datenverzeichnissen führen getrennte Fallbestände.

Die Standardbindung ist lokal. Eine Bindung an eine Netzwerkschnittstelle erfordert ein Serverzertifikat und den passenden privaten Schlüssel. Das Zertifikat muss für den verwendeten Hostnamen gelten und von den Clients als vertrauenswürdig eingestuft sein. Der Betreiber beschränkt die Erreichbarkeit auf die vorgesehenen Arbeitsplätze, beispielsweise über das Firmennetz oder ein VPN. Private Schlüssel und Datenverzeichnis bleiben unter Kontrolle des Dienstkontos. Die Optionen `--host`, `--port`, `--certfile` und `--keyfile` legen Bindung und direkten TLS-Betrieb fest. Die TLS-Untergrenze ist 1.2. Beim Einrichten von Zugriffsrechten auf einem Windows-Host müssen die NTFS-Berechtigungen des Datenverzeichnisses und der Schlüsseldateien geprüft werden. HTTPS schützt die Verbindung. Für den Schutz der Daten auf dem Datenträger ist der Betreiber verantwortlich.

Der bereits vorhandene Fachzugang auf der öffentlichen Website verwendet separat freigegebene Ed25519-Geräteschlüssel für eine begrenzte Fallauswertung. Für die Team-Instanz erfolgt die Anmeldung beim eigenen Dienst. Kubernetes-RBAC-Analysen beurteilen importierte Clusterregeln. Das Ergebnis einer solchen Analyse verändert keine Teammitgliedschaft.

Die Team-Instanz speichert hochgeladene Quelldateien samt Originalbytes in ihrer Datenbank. Beispielsweise können HAR- und Proxyberichte Cookies, Autorisierungsheader oder personenbezogene Inhalte enthalten. Vor dem Import mit dem Auftraggeber festlegen, welche Originale der Dienst aufbewahren darf und welche Daten vorab entfernt werden müssen. Die Originalbytes dürfen Admin, Lead Pentester und Pentester über den Dienst abrufen. Der Dienst protokolliert den Zugriff im jeweiligen Team. Reviewer und Read-Only sehen die freigegebenen Fall- und Belegdaten. Eine redigierte Übergabe verändert die gespeicherten Originale nicht.

## Vertrauensgrenzen

- **Browser und API.** Die Oberfläche blendet unzulässige Aktionen aus. Der Server bestimmt den Benutzer aus der gültigen Sitzung und prüft die Mitgliedschaft und erforderliche Berechtigung bei jeder geschützten Operation. Eine Fall-ID oder eine vom Browser übermittelte Team-ID genügt für den Zugriff nicht.
- **Sitzungen.** Der Browser erhält ein zufälliges Sitzungstoken in einem HttpOnly-Cookie mit SameSite=Strict. Unter TLS trägt das Cookie zusätzlich Secure. Das Backend speichert den Token-Hash. Zustandsändernde Sitzungsanfragen benötigen einen passenden CSRF-Nachweis. Die Sitzung endet nach höchstens acht Stunden oder nach 30 Minuten Inaktivität. Abmelden beendet die aktuelle Sitzung. Ein Kennwortwechsel mit dem bisherigen Kennwort beendet alle Sitzungen dieses Kontos.
- **Konten.** Der Server prüft lokale Kennwörter anhand gesalzener scrypt-Ableitungen (N = 32 768, r = 8, p = 1). Ein Bootstrap dient der ersten Einrichtung. Die laufende Verwaltung erfolgt mit einer angemeldeten Administratoridentität.
- **Belege und Übergaben.** Eine Teamfreigabe signiert das Manifest mit dem Ed25519-Schlüssel der Installation. Das Manifest enthält Team- und Fall-ID, den Berichts-Hash sowie Quell- und Retest-Referenzen. Originaldateien werden anhand der signierten Referenzen separat abgeglichen. Der Empfänger muss den öffentlichen Schlüssel unabhängig vom Paket beziehen und den erwarteten Fall und das Team kontrollieren. Für die verantwortliche Person ist das Auditprotokoll massgebend. Die Signatur bescheinigt die Integrität des Übergabestands.
- **Host und Datenbank.** Systemadministratoren mit direktem Zugriff auf Prozess, Schlüssel oder Datenbank liegen innerhalb der betrieblichen Vertrauensgrenze. Ein Team-Auditprotokoll in derselben Datenbank ist kein unabhängiger Manipulationsnachweis.

## Auditprotokoll

Admins, Lead Pentester und Reviewer erhalten die letzten 500 Ereignisse des Teams in absteigender Reihenfolge. Jeder Eintrag nennt UTC-Zeit, Akteur, Aktion, Ressource und Ergebnis. Der Dienst protokolliert erfolgreiche Teamoperationen, betroffene Kontoereignisse sowie abgelehnte Zugriffe, soweit eine Teamzuordnung vorliegt. Ein fehlgeschlagener Login ohne angemeldeten Benutzer gehört keinem Team. Der Teamverlauf allein ist deshalb keine vollständige instanzweite Anmeldeübersicht.

Die Datenbank lehnt Änderungen und Löschungen erfasster Auditereignisse über Trigger ab. Für extern aufbewahrte Prüfprotokolle, Aufbewahrungsfristen und einen Manipulationsnachweis gegenüber Hostadministratoren muss der Betreiber eigene Massnahmen vorsehen.

## Konto- und Falllebenszyklus

| Phase | Vorgehen | Kontrolle |
|---|---|---|
| Eintritt | Team, Person und Aufgabe prüfen. Nur die benötigte Rolle vergeben. | Zugang mit dem persönlichen Konto testen und ein fremdes Team als Negativkontrolle verwenden. |
| Arbeit am Fall | Pentester ordnen Belege, dokumentieren Befunde und verknüpfen den Retest mit der Quelle. | Ein Reviewer kann den Fall lesen und die Übergabe prüfen. Eine schreibgeschützte Person kann keine Falländerung speichern. |
| Rollenwechsel | Admin ändert die Mitgliedschaft. | In einer bereits geöffneten Sitzung die frühere Aktion wiederholen. Die Autorisierung muss die neue Zuordnung berücksichtigen. |
| Freigabe | Admin, Lead Pentester oder Reviewer prüft den Übergabestand und gibt ihn frei. | Eine Person mit Rolle Pentester kann dieselben Daten bearbeiten, aber keine signierte Freigabe auslösen. |
| Austritt | Zuständige Administration entzieht die Teammitgliedschaft. Offene Arbeiten einer verantwortlichen Person zuordnen. | Der Dienst verweigert den weiteren Zugriff dieses Kontos auf die Teamdaten. Andere Teammitgliedschaften separat prüfen. |
| Verlust eines Geräts | Zugang über den Betreiber sperren bzw. Mitgliedschaften entziehen. | Mit der bisherigen Sitzung eine geschützte Operation ausführen. Sie muss nach dem Entzug scheitern. |

## Sicherung, Wiederherstellung und Abnahme

Der Datenbestand liegt in `team.sqlite3`. SQLite verwendet den WAL-Modus. Eine isolierte Kopie der geöffneten Hauptdatei kann bestätigte Änderungen auslassen. Den Dienst für eine konsistente Sicherung geordnet beenden und das gesamte Datenverzeichnis kopieren oder eine geeignete SQLite-Online-Sicherung verwenden. Der private Ed25519-Schlüssel der Installation liegt in `evidence-signing.key`. Sein Fingerabdruck wird in der Datenbank gebunden. Passende Datenbank und Schlüssel zusammen sichern. Einen verlorenen gebundenen Schlüssel aus einer geprüften Sicherung wiederherstellen. Die TLS-Schlüssel liegen an den vom Betreiber angegebenen Pfaden und benötigen eine eigene geschützte Sicherung. Den Zugriff auf Sicherungen mindestens so streng wie auf den Dienst selbst begrenzen. Die Wiederherstellung zuerst mit einer getrennten Testkopie durchführen.

Vor der Freigabe für ein echtes Team prüft der Betreiber folgende Punkte an der vorgesehenen Installation.

1. Anmelden, abmelden, Sitzungsablauf und die serverseitige Ablehnung einer Anfrage ohne gültigen CSRF-Nachweis testen.
2. Je Rolle mindestens eine erlaubte und, wo möglich, eine verbotene Operation direkt an der API prüfen. Eine eigenmächtig geänderte Objekt-ID darf keinen Zugriff auf Daten eines anderen Teams eröffnen.
3. Eine Rolle bei laufender Sitzung reduzieren, die gesperrte Aktion wiederholen und die wirksame Änderung im Auditverlauf nachvollziehen.
4. Das Datenverzeichnis sichern und in einer isolierten Instanz wiederherstellen. Mit getrennten Benutzerkonten die Rollen, Fallstände und Übergaben kontrollieren.
5. Den eigenen Hostnamen, das vertrauenswürdige TLS-Zertifikat und die Cookie-Eigenschaften am zweiten Arbeitsplatz prüfen. Der Auditverlauf soll die getesteten Vorgänge erklären, ohne Kennwörter, Sitzungstoken, CSRF-Werte oder private Schlüssel preiszugeben.

© Nasser Aldin Farag (0xFarag). All rights reserved.

## Experiment und manueller Prüfnachweis

Im Fall kann ein Teammitglied mit Schreibrecht vor der Befunderfassung eine Hypothese, das erwartete Verhalten und die geplante Kontrolle zu einem Asset im Scope festhalten. Jede weitere Beurteilung verweist auf die vorherige Revision. Eine belegte Bestätigung oder Widerlegung benötigt zwei unterschiedliche Beobachtungen desselben Assets. Unklare Ergebnisse bleiben als solche sichtbar. Der interne JSON-Export des Prüfplans enthält die vollständigen Revisionen einschliesslich Freitexten. Er ist als unsigniert gekennzeichnet. Für eine signierte Kundenübergabe dient die separate Übergabefunktion im Fall.

## Signierte Kundenübergabe in drei Formaten

Im Fall wählt ein Admin, Lead Pentester oder Reviewer unter **Signierte Übergabe** die Berichtssprache und das Dateiformat. JSON enthält den signierten Quellen- und Retest-Nachweis. Bei HTML oder PDF entsteht ein ZIP mit zwei Dateien.

- `report.html` oder `report.pdf` ist der lesbare Kundenbericht. Seine SHA-256-Prüfsumme bindet jedes Byte.
- `proof.json` enthält die signierte JSON-Übergabe und eine separate Ed25519-Signatur für Format, Dateilänge, Prüfsumme, Übergabe, Fall, Team und Scope. Die PDF-Signatur wird über diese Begleitdatei geprüft.

Zur Prüfung in der Team-GUI die unveränderte ZIP-Datei im Abschnitt **Übergabe prüfen** auswählen. Jede Teamrolle kann die Verifikation gegen den Vertrauensschlüssel ihrer Installation durchführen. Die Oberfläche zeigt die geprüfte Dateiprüfsumme und den verifizierten Bericht an. Beim Versand beide Dateien zusammen übergeben und den öffentlichen Schlüssel oder seinen Fingerabdruck über einen unabhängigen Kanal bestätigen. Eine Änderung am Bericht erfordert eine neue signierte Ausgabe.

Mit dem Quellpaket kann der Empfänger die Verifikation auch rein lokal durchführen. Der Befehl gibt bei Erfolg Exitcode 0 und einen JSON-Beleg mit `valid: true` aus.

```sh
python -m team.evidence verify uebergabe.zip --trusted-key vertrauensschluessel.json
python -m team.evidence verify proof.json --document report.pdf --trusted-key vertrauensschluessel.json
```

## Minimaler Belegindex und Abgleich der Experimentrevisionen

Im Fall unter **Befunde → Minimaler Belegindex** kann jede leseberechtigte Rolle die ursprüngliche Beobachtung und die zugehörige Kontrolle nachschlagen. Pro Beobachtung stehen Format, Nummer des Datensatzes, SHA-256 der Quelldatei und Fingerabdruck des Datensatzes bereit. Ein Hinweis ohne Kontrolle enthält nur seine vorhandene Beobachtung. Der Index kann bereits vor dem Retest als unsignierte JSON-Datei gespeichert werden.

Hat der Fall einen mit diesem Befund verknüpften Prüfplan, enthält der Index dessen ID und die geordnete Liste der Revisionen mit ID, SHA-256 und Vorgängerprüfsumme. Die erste Revision ist der Plan. Ohne Verknüpfung bleibt diese Liste leer. Prüfnotizen, Zugangsdaten, HTTP-Inhalte und Benutzerkennungen sind im Index nicht enthalten.

Bei der signierten Übergabe erscheint derselbe Belegindex im JSON-Bericht und im HTML- oder PDF-Anhang. Unter **Übergabe prüfen** lässt sich nach erfolgreicher Signaturprüfung der Index eines Befunds öffnen. Wer den vollständigen, zum Übergabezeitpunkt exportierten Prüfplan separat und berechtigt erhalten hat, kann dort die Original-JSON des Plans auswählen. Der Browser berechnet die Prüfsumme jeder Revision und gleicht die gesamte Kette mit der signierten Übergabe ab. Die ausgewählte Plandatei bleibt im Browser. Fehlende, veränderte oder später hinzugekommene Revisionen ergeben keine Übereinstimmung. Frühere gültige Übergaben lassen sich weiterhin prüfen und zeigen die damals enthaltenen Informationen.
