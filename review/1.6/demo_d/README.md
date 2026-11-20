# Demo D · Offline-Tool-Federation

Ein fester Datensatz prüft die fachliche Projektion eines Produktexports. Der Prüfer benötigt Python 3.8+ mit Standardbibliothek. Alle Befehle in diesem Abschnitt beginnen im Verzeichnis `demo_d/`.

## Referenz prüfen

```bash
python3 verify.py expected/projection.json
python3 -B -m unittest discover -s . -p test_verify.py -v
```

Der erste Befehl prüft den mitgelieferten Soll-Datensatz einschliesslich der Quelldatei-Hashes. Er liefert keine Aussage über einen AuthzLedger-Build. Die Tests prüfen auch das Verhalten des Prüfers bei verfälschten Eingaben. Exitcode 0 steht für bestanden, 1 für einen fehlgeschlagenen Nachweis und 2 für einen fehlerhaften CLI-Aufruf.

## Aktuelle Offline-Vorschau in AuthzLedger

Im Entwicklungsstand mit dem Befehl `assessment federation-preview` erzeugen CLI und Studio die Projektion direkt aus den drei Dateien. Voraussetzung für das folgende Beispiel ist ein Python-Environment, in dem dieser Entwicklungsstand installiert ist. Das Arbeitsverzeichnis ist `demo_d/`. Der Ausgabepfad muss neu sein.

```bash
python3 -m authzledger assessment federation-preview \
  --scope-service tcp://192.0.2.10:443 \
  --nmap fixtures/nmap.xml --ffuf fixtures/ffuf.json --nuclei fixtures/nuclei.jsonl \
  --out projection-cli.json
python3 verify.py projection-cli.json
```

Im Studio unter **02 Discover → Compare tool exports offline** denselben Service eintragen und die drei Dateien in den zugehörigen Feldern wählen. **Preview projection** zeigt die Beobachtungen, **Download projection JSON** liefert die Datei. Der Vergleich mit dem CLI-Export ist direkt möglich.

```bash
python3 verify.py federation-projection.json
```

Sind beide Prüfungen erfolgreich, sind CLI- und Studio-Projektion für alle Vertragsfelder semantisch gleich. Dieser Durchstich berechnet seine Ergebnisse im Arbeitsspeicher. Persistente Import-Idempotenz, Snapshot-Bindung und signierte Übergabe benötigen die gesonderten Tests am gespeicherten Assessment.

## Produktunabhängige Abnahme eines persistenten Importers

1. Einen leeren lokalen Workspace mit Scope `192.0.2.10:443/TCP` verwenden. Genau die drei Dateien aus `fixtures/` mit ihren ursprünglichen Dateinamen über die Importschnittstelle des Produkts einlesen. Der zweite Host ist ausserhalb des Scope. Beide verwendeten Adressen gehören zu Dokumentationsnetzen.
2. Graph und Import-Receipts aus diesem Lauf in **eine UTF-8-JSON-Datei** im Format `authzledger.demo-d.projection/v1` exportieren. Die Feldstruktur steht in `expected/projection.json`. Ein Übersetzer darf nach gespeicherten Identitäten referenzieren, stabile IDs ersetzen und Felder umbenennen. Er muss seine Werte aus den echten Ergebnissen beziehen. Fehlende Befunde, Quellverweise oder Kontrollen im Übersetzer zu ergänzen würde die Aussage des Tests aufheben.
3. Die drei identischen Dateien in denselben Workspace ein zweites Mal einlesen und erneut exportieren. Separate Run-IDs und Zeitpunkte bleiben im produktiven Ledger. Die beobachtbare Projektion bindet den Importbeleg einmal pro Quelle und Disposition. Sie fordert keine Unterdrückung der Zeitpunkte oder Importversuche im Ledger.

```bash
python3 verify.py /pfad/produkt-vorher.json --reimport /pfad/produkt-nachher.json
```

`--sources VERZEICHNIS` erlaubt die Hash-Prüfung einer separat bereitgestellten Kopie der drei Eingabedateien. Produkt-Commit, Aufruf, native Receipt-IDs, Quellhashes, Exporthashes und Exitcodes gehören in das Release-Gate. Der Prüfer selbst kann Herkunft eines vorgelegten JSONs, Netzwerkinaktivität des Produkts oder die interne Zahl verdeckter Duplikate nicht attestieren. Ein Laufprotokoll und Paritätstests an den nativen Services decken diese Eigenschaften separat ab.

## Verbindliche Projektion

Alle genannten Tabellen sind vollständig für diesen Fixture-Scope zu exportieren. Abweichende Zusatzfelder gehören ausserhalb dieser Projektion in das native Exportformat. Die Reihenfolge der Zeilen und Objektfelder ist frei. Objektfelder, Typen, Datensätze, Verweise und Werte werden exakt verglichen. Doppelte Schlüssel und doppelte Zeilenidentitäten sind unzulässig.

| Bereich | Identität und Darstellung |
|---|---|
| `scope.allowed_services` | TCP-Service als URI mit IP und Port. |
| `graph.assets/services/endpoints` | Eindeutige IP, `transport://address:port`, vollständige URL. Service und Endpoint enthalten den Bezug zum übergeordneten Objekt. |
| `graph.observations` | `record = source + "#" + locator`. `target` ist ein Service- oder Endpoint-Schlüssel. `asserted` enthält die unten aufgeführten Herstellermerkmale. |
| `graph.findings` | Pro Target genau die aktuell projizierte Hinweisgruppe dieser Fixture. `records` verweist auf die tragende Observation. Ein positiver Nuclei-Match bleibt auf der Obergrenze `hint` dieses Profils. |
| `receipts` | Pro Quelldatei ihr Originalname, SHA-256 aller Bytes und ein expliziter Status pro fachlichem Eingaberecord. Ein XML-Host oder ein JSON-Header ist in diesem Profil keine eigene Beobachtung. |

| Quellmaterial | Vertraglich abgebildete Semantik |
|---|---|
| `nmap.xml` | Erster Port des ersten Hosts. Der Service ist laut Quelle offen, mit Grund `syn-ack`. Der Name `https` stammt aus einer Porttabelle (`method=table`, `conf=3`). Eine erfolgreiche TLS-Verbindung ist damit unbewiesen. XML-Pfade sind einsbasiert. |
| `ffuf.json` | JSON-Pointer `/results/0` meldet eine URL im Scope, einen HTTP-Status und eine Länge. Die bereinigte synthetische Export-Fixture enthält keine Methode. `null` hält sie als unbekannt fest. `/results/1` geht ausschliesslich mit `out_of_scope` in den Beleg ein. |
| `nuclei.jsonl` | Zwei einsbasierte Zeilen enthalten Regel-ID, Matchername, boolesches Ergebnis und die Priorität des fremden Tools. Der zweite Datensatz bleibt als negative Beobachtung mit `evidence_level=null` erhalten. Ein `high` des Herstellers erzeugt kein Finding. |
| Weitere Herstellerfelder | Die gehashten Quellen bleiben bytegenau verfügbar. Der Projektionsvertrag beschränkt seine semantischen Zusagen auf die oben genannten Felder. |

Erwartet werden drei Quellen, fünf fachliche Records, vier angenommene Beobachtungen, ein Service, ein Endpoint und ein Finding-Hinweis. Ein Record bleibt ausserhalb des Scope. Kein Record erreicht `candidate` oder `confirmed`. Die Evidenzobergrenze ist profilgebunden. Das Fixture enthält synthetische Daten in drei gezielt begrenzten Herstellerformaten.

## Formatgrundlagen

- [Nmap XML output](https://nmap.org/book/output-formats-xml-output.html)
- [ffuf v2 JsonResult](https://pkg.go.dev/github.com/ffuf/ffuf/v2/pkg/output#JsonResult)
- [Nuclei v3 ResultEvent](https://pkg.go.dev/github.com/projectdiscovery/nuclei/v3/pkg/output#ResultEvent)
