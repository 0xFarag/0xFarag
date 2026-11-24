# Ed25519-Schlüssel der Team Workbench

Die Installation signiert Kundenübergaben mit einem Schlüssel pro Generation. Alle Teams einer Installation teilen den Signierschlüssel. Jede Übergabe enthält die signierte Team-ID. Die Prüfung in der Teamoberfläche akzeptiert nur Übergaben des ausgewählten Teams.

## Zeitpunkt und Migration

Eine Generation gilt ab ihrer Aktivierung für 90 × 24 Stunden nach der UTC-Systemuhr. Die erste danach erfolgreich ausgestellte Übergabe löst den Wechsel aus. Ist die Installation länger inaktiv, entsteht bei der nächsten Übergabe genau eine neue Generation. JSON, die signierte Dokumentbeschreibung und die dazugehörige HTML- oder PDF-Datei verwenden innerhalb einer Übergabe denselben Schlüssel. Eine Abfrage der Schlüsselhistorie löst keinen fälligen Wechsel aus.

Beim ersten Zugriff auf eine neue Installation wird ein Schlüssel erzeugt. Beim Upgrade einer Installation mit bisherigem Schlüssel muss dessen öffentlicher SHA-256-Fingerabdruck mit dem gespeicherten Pin übereinstimmen. Das ursprüngliche Aktivierungsdatum ist im alten Format nicht erfasst. Die 90 Tage beginnen deshalb bei der Migration. Der erste Export nach der Migration lässt sich mit dem bereits verteilten Schlüssel prüfen. Fehlt ein gebundener privater Schlüssel oder stimmt der Fingerabdruck nicht überein, sperrt der Dienst die Ausstellung. Ein vorhandener privater Schlüssel ohne nachweisbare Bindung wird nicht automatisch übernommen.

## Prüfung durch Team und Empfänger

Im Team zeigt die Schlüsselhistorie Aktivierung, geplanten Wechsel, Ausmusterung und SHA-256-Fingerabdruck. Den Deskriptor der Generation herunterladen, deren Fingerabdruck im Manifest der Übergabe steht. Den vollständigen Fingerabdruck über einen bereits verifizierten zweiten Kanal mit dem Auftraggeber abgleichen. Diesen Abgleich bei jeder neuen Generation wiederholen.

Die Teamprüfung wählt den zum Manifest passenden Schlüssel aus der lokal signierten Historie. Sie prüft zusätzlich den aktuellen öffentlichen Vertrauensanker im geschützten Datenverzeichnis. Selbst wenn die aktive private Datei verloren geht, bleiben bereits ausgestellte Pakete bei intakter Historie und intaktem öffentlichem Anker lokal prüfbar. Der separat bestätigte Deskriptor genügt für die unabhängige Offline-Prüfung. Für eine erwartete Mandatsbindung auch die signierte Team- und Fall-ID mit den vereinbarten Angaben abgleichen.

```sh
python -m team.evidence verify uebergabe.json --trusted-key vertrauensschluessel.json
python -m team.evidence verify uebergabe.zip --trusted-key vertrauensschluessel.json
python -m team.evidence verify proof.json --document report.pdf --trusted-key vertrauensschluessel.json
```

Der Exitcode ist bei erfolgreicher Prüfung 0. Beim ZIP werden sowohl die Übergabe als auch die konkreten Dokumentbytes geprüft. Der Einzel-Deskriptor enthält `algorithm`, `public_key` und `fingerprint`. Die authentifizierten Endpunkte `GET /api/teams/<team-id>/trust-key` und `GET /api/teams/<team-id>/trust-keys` liefern den aktiven Einzel-Deskriptor bzw. die öffentliche Historie.

## Betrieb, Sicherung und Wiederherstellung

Die SQLite-Schreibtransaktion serialisiert parallele Übergaben. Der neue Schlüssel und sein öffentlicher Anker werden zuerst im zweiten Dateislot dauerhaft geschrieben. Danach veröffentlicht dieselbe Datenbanktransaktion Fingerabdruck, Generationswechsel und die vom neuen Schlüssel signierte Historie. Bei einem Abbruch vor dem Commit bleibt der bisherige Schlüssel nutzbar. Nach dem Commit prüft der Dienst den aktiven Slot erneut und entfernt den alten privaten Slot. Wird diese Bereinigung unterbrochen, wiederholt sie sich beim nächsten erfolgreichen Schlüsselabruf oder bei der nächsten Übergabe.

Die Slots heissen `evidence-signing.key` und `evidence-signing-next.key`. Die zum Slot gehörende öffentliche Datei endet auf `.pub`. Die Datenbank enthält öffentliche Schlüssel und Metadaten. Unter POSIX liegen private Seed-Dateien mit Modus 0600 im Verzeichnis des Dienstkontos. Für ruhende Daten einschliesslich Sicherungen ist die Datenträgerverschlüsselung Sache des Betreibers. Unter Windows werden die privaten Schlüssel unter dem aktuellen Dienstkonto mit DPAPI geschützt. Das Verzeichnis benötigt restriktive NTFS-Zugriffsrechte für dieses Konto. [Microsoft dokumentiert die Bindung an Konto und Rechner.](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)

1. Vor dem Upgrade und nach einem Schlüsselwechsel den Dienst anhalten. Das gesamte Datenverzeichnis mit SQLite-, WAL- und Schlüsseldateien als konsistenten Stand verschlüsselt sichern. Den Zugriff auf Sicherungen auf die zuständigen Betreiber beschränken.
2. Die Wiederherstellung zuerst isoliert prüfen. Unter Windows benötigt sie typischerweise dasselbe Dienstkonto, sein wiederherstellbares DPAPI-Profil und denselben Rechner. Eine Kopie des Datenverzeichnisses alleine belegt die Wiederherstellbarkeit nicht.
3. Den aktuellen Fingerabdruck mit dem zuvor unabhängig bestätigten Wert vergleichen. Eine ältere Übergabe prüfen. Eine neue Übergabe in der isolierten Instanz erstellen und mit dem erwarteten öffentlichen Schlüssel prüfen. Die Testkopie danach gesichert entfernen.
4. Bei Verlust des privaten Schlüssels einen zusammenpassenden, überprüften Sicherungsstand wiederherstellen. Sicherungsstände vor der letzten Rotation können spätere Schlüssel und Falldaten auslassen. Die ausserhalb der Installation archivierten öffentlichen Deskriptoren ermöglichen die unabhängige Prüfung dieser Übergaben.

## Verdacht auf Schlüsselkompromittierung

Die planmässige Rotation lässt frühere Signaturen prüfbar. Sie widerruft einen kompromittierten Schlüssel nicht. Bei Verdacht die Ausstellung anhalten, den betroffenen Fingerabdruck festhalten und Empfänger über den verifizierten Kanal informieren. Eine neue Vertrauensbasis aus einer bereinigten Umgebung separat bestätigen. Das signierte Erstellungsdatum stammt von der Installation und ist kein unabhängiger Zeitstempel. Ob eine Signatur vor einem bestimmten Vorfall vorlag, erfordert zusätzliche zeitlich belegte Unterlagen.

## Regressionstests

`python -m unittest -v qa.test_team_rotation` prüft die Zeitgrenze, mehrere Generationen, alte JSON- und ZIP-Übergaben, Fremdteams, manipulierte Vertrauensdaten, parallele Übergaben und Prozessabbrüche vor und nach dem Commit. Der DPAPI-Test läuft auf Windows. POSIX-Dateirechte werden unter POSIX geprüft.

© Nasser Aldin Farag (0xFarag). All rights reserved.
