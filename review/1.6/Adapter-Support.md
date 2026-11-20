# Supportmatrix der Offline-Föderation

**Der Reader verarbeitet drei begrenzte Strukturprofile.** Im gemeinsamen Golden-Datensatz entstehen aus fünf Records vier Beobachtungen, eine Hinweisgruppe und ein expliziter Scope-Ausschluss. Keine Beobachtung erreicht `candidate` oder `confirmed`. Die Matrix gilt für die Föderationserweiterung auf Commit `03aea857e35358ddeb13d2a861b633e60c1ca873`. Die bestehende Importoberfläche von 1.5.0 besitzt eigene Profile für weitere Formate.

Die Revisionsangaben gehören zu diesem Feldvertrag. CLI und Service verwenden die Selektoren `nmap`, `ffuf` und `nuclei`. Der Produktexport weist das gemeinsame Format `authzledger.demo-d.projection/v1`, den logischen Quellnamen und den Quellhash aus. Die Parser prüfen Struktur und Feldwerte. Eine im Export genannte Herstellerversion wird dabei nicht authentifiziert. Die Zuordnung zum geprüften Reader bindet dessen SHA-256. Die vollständige maschinenlesbare Feld- und Testmatrix steht in [adapter-support.json](adapter-support.json).

ffuf-Readerrevision 2 weist nichtleere Werte in den nativen Feldern `postdata` und `replayproxyurl` als `unsupported_request_context` aus. Semantische Readerrevision und gespeicherte Belegstruktur sind getrennt. Historische Receipts und Snapshots bleiben mit ihren ursprünglichen Werten verifizierbar. Beim Retain gegen Originalbytes berechnet der Service die Projektion neu. Ein inzwischen abweichender Freigabedigest scheitert mit `federation_preview_digest_mismatch`. Zum Ablegen der geänderten Sicht prüft der Operator die neue Vorschau.


| Profil und Eingabeeinheit | Feldabbildung in der Vorschau | Merkmale ausserhalb der Projektion | Evidenz und Quellverweis |
|---|---|---|---|
| **Nmap XML · Rev. 1**. Ein `port` unter `host/ports` | Eindeutiges IPv4-/IPv6-Literal, TCP und Port ergeben den Service. `state`, Grund, Servicename, Ermittlungsmethode und Herstellervertrauen bleiben separat. Fehlende optionale Werte bleiben `null`. | Hoststatus, Zeit, Hostnamen, aggregierte `extraports`, Produkt-/Versionsstrings, CPE, OS, Skriptausgaben und Stylesheets. Ein Host ohne Port erzeugt keine Beobachtung. | Höchstens `hint`. `table` belegt die Zuordnung im Portverzeichnis. Ablesbar über einen einsbasierten XML-Pfad auf Host und Port. |
| **ffuf Datei-JSON · Rev. 2**. Eine Zeile in `results[]` | URL, HTTP-Status, optionale Länge und gegebenenfalls die zugelassene Methode aus `config.method`. Ein vorhandener `host` muss zur URL passen. Fehlende Länge und Länge null Bytes bleiben unterscheidbar. | Eingabezeichenfolgen, Laufzeit, Redirect-Ziel, Wort-/Zeilenzahl, lokaler Dateiname, Befehlszeile und zusätzliche Producer-Felder. | Höchstens `hint`, keine Finding-Gruppe aus dem Status. Nullbasierter JSON-Pointer, z. B. `/results/0`. |
| **Nuclei HTTP JSONL · Rev. 1**. Ein Objekt pro nichtleerer physischer Zeile | `matched-at` bindet den Endpoint. Vorhandene Werte von `host/ip/port/scheme/url` müssen dazu passen. Template-ID, Matchername, boolesches Ergebnis und Quell-Severity bleiben getrennt. Verschiedene Basispfade desselben zulässigen Origins sind möglich. | Zusätzliche Klassifikationen, Metadaten, Zeit, Template-Inhalt, Autor, Tags und Interaktionsdetails. Bestimmte Rohdatenfelder führen zur Zurückstellung des ganzen Records. | Explizites `true` erzeugt eine Hinweisgruppe pro Endpoint, mit einer Quelle je Treffer. `false` und fehlender Status bleiben unterscheidbare Beobachtungen mit Evidenzstufe `null`. Physischer Locator, z. B. `line:2`. |

## Grenzen und Eingabefehler

| Reader | Zählung und Disposition | Grenzen und atomare Ablehnung |
|---|---|---|
| Gemeinsam | Jeder erkannte fachliche Record erhält genau einen Receipt-Eintrag. Ausgelassene Freifelder haben keine eigenen Zähler. Quellen werden über SHA-256 der unveränderten Originalbytes gebunden. | Insgesamt 2 MiB, bis 1'000 Records pro Quelle, 1–32 explizite TCP-Services. Die Service-API akzeptiert bis zu zwölf übergebene Paare für bis zu drei verschiedene Profile. Identische Wiederholungen zählen zum Bytebudget. Zwei verschiedene Dateien mit derselben Profilidentität im selben Aufruf führen zum Abbruch. |
| Nmap | Null oder mehrere eindeutige IPs eines Hosts ergeben je Port `unresolved_scope`. Bei eindeutiger Adresse ergeben Nicht-TCP-Ports `unsupported_protocol`. Ein bekannter TCP-Service ausserhalb des Filters ergibt `out_of_scope`. | UTF-8, XML-Tiefe 32, 20'000 Elemente, 64 Attribute je Element, bis 128 Zeichen je Attributname und 262'144 Zeichen je Attributwert. Zulässig ist das leere native `<!DOCTYPE nmaprun>`. Externe DTDs, deklarierte Entitäten, mehrdeutige Portcontainer, Zustände und fehlerhafte IP-Familien brechen die Vorschau ab. |
| ffuf | Ein unzulässiger Request-Kontext ergibt pro Ergebnis `unsupported_request_context`. Beispiele sind nichtleere Custom-Header, Request-Datei, Request-Body (ffuf 2.1.0: `postdata`, bisheriger Alias: `data`), SNI, Proxy, Replay-Proxy und aktiviertes Redirect-Following. Unpassender Host bleibt `unresolved_scope`. | UTF-8-JSON, Objekt mit Ergebnisarray, Tiefe 40. HTTP-Status als Ganzzahl 100–599. Länge optional als Ganzzahl von 0 bis 9'007'199'254'740'991. Eine explizite Methode muss zu GET, HEAD, POST, PUT, PATCH, DELETE oder OPTIONS gehören. Doppelte JSON-Schlüssel und ungültige Werte in einem zugelassenen Ergebniskontext brechen die Vorschau ab. |
| Nuclei | Leere Zeilen zählen zum physischen Zeilenlimit und behalten die nachfolgende Nummerierung. Fremde Protokolle ergeben `unsupported_protocol`. Nichtleere Felder `request`, `response`, `curl-command` oder `extracted-results` ergeben `unsupported_raw_record`. Widersprüchliche Ursprungsangaben ergeben `unresolved_scope`. | Bis 1'000 physische Zeilen, je nichtleerer Zeile maximal 262'144 Bytes, UTF-8-JSON, Tiefe 40. Ungültige Matcher-Typen, unzulässige Severity oder positive Meldungen ohne Template-ID brechen die Vorschau ab. |

**Scope und Retention.** Die Vorschau löst keine Namen auf. Nichtliterale Hostnamen bleiben ungeklärt. Nicht unterstützte Zielsyntax, darunter Query, Fragment oder Benutzerinformationen, wird als Disposition geführt. Der Originalwert erscheint dabei nicht im Ergebnis. Im lokal angenommenen Assessment bindet der gespeicherte Beleg HTTP-Pfade, Nmap-Grund und -Servicename sowie Nuclei-Template und -Matcher über feldgebundene Digests. Der Originaltext bleibt im Betreiberoriginal prüfbar. Digests dienen dem Abgleich und können bei erratbaren Werten durch Ausprobieren wiedererkannt werden.

## Herkunft und Prüfbelege

| Quelle | SHA-256 der Originalbytes | Anspruch |
|---|---|---|
| `demo_d/fixtures/nmap.xml` | `9885a02dc028840f7ec8dce648c40d4eab6c0028ce8a21f82f778d83e6d6bc7a` | Lokal entworfene Syntax-Fixture. Das deklarierte Versionsattribut 7.95 belegt keinen Lauf dieser Version. |
| `demo_d/fixtures/ffuf.json` | `f93742ef58a993156a6cf97a8fde40a9c96bbcde73a9c11e5a3ce8f251d69339` | Lokal entworfener, reduzierter Ergebnissatz. |
| `demo_d/fixtures/nuclei.jsonl` | `79e8030fddd5147878d2cdc9a994f4f6661654084b31dfc8a952cc143dbae70f` | Zwei lokal entworfene HTTP-Ereignisse mit positivem und negativem Matcher. |
| Vorhandene Checkout-Referenz `fixtures/adapters/nmap-7.92-publishedsample.xml` | `9ad6c819c2e29b7cb3d9aa6d1627d3f3eb11932e0013d28d9e35afd9b4f7e088` | 999 Bytes aus einem Community-Beitrag im Upstream-Issue. Nmap 7.92 / XML 1.05 laut Original. Ein IP-Host, null Portrecords. Prüft nur XML-Hülle mit nativer Leer-DTD und Stylesheet-PI. Herkunft siehe [Upstream-Issue 2371](https://github.com/nmap/nmap/issues/2371). |

Vier beigelegte native Dateien erweitern die synthetische Demo D: Ein unveränderter Apache-2.0-lizenzierter Nmap-5.51/XML-1.03-Loopback-Export liefert vier TCP-Portrecords. Die originalen ffuf-2.1.0- und Nuclei-3.3.10-Ausgabebibliotheken serialisierten eigene Beispielobjekte bei gesperrten Netzwerksockets. Die reguläre ffuf-Datei, die gesonderte ffuf-Kontextdatei und die beiden Nuclei-Ereignisse belegen die jeweils geprüften Feldvarianten. Der neue Test startet keinen Scanner. Vier zusätzliche, direkt vom Nmap-Projekt beziehbare Referenzen dokumentieren konkrete Formatgrenzen. Die 7.92-Issue-Datei bleibt ausschliesslich ein Hüllenbeleg. [Herstellerquellen, Lizenzen und Nachprüfung](vendor-proof/README.md) · [Gepinnte Provenienz](vendor-proof/provenance.json)

## Regression ausführen

Aus dem entpackten Paket prüft der erste Aufruf die unveränderten Fixtures, Matrixfelder, Kardinalitäten und den gespeicherten Produktexport. Der zweite führt zusätzlich genau den geprüften Reader aus dem angegebenen, gepatchten Checkout mit denselben lokalen Bytes aus. Er prüft auch die genannten Testreferenzen und die lokale 7.92-Referenz. Keiner der beiden Aufrufe startet einen Producer.

```sh
python3 -B test_adapter_support.py
python3 -B test_adapter_support.py --checkout /pfad/zum/gepatchten-authzledger
```
