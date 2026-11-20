# Native Formatbelege für die Offline-Föderation

Die Prüfungen betreffen die Dateiinterpretation. Der gesperrte Ausgabewriter erhält festgelegte Objekte im Arbeitsspeicher. Es werden keine Scanner, Fuzzer, Templates oder Netzwerkproben gestartet.

| Herkunft | Konkrete Aussage | Beleggrenze |
|---|---|---|
| Nmap 5.51 / XML 1.03, unveränderter lokaler Export aus python-libnmap | Alle vier TCP-Einträge ergeben die ursprünglichen Ziele, Zustände, Gründe, Dienste, Methoden und Konfidenzen. Ein auf Port 22 verkleinerter Offline-Scope schliesst drei Records aus. | Der historische Export stammt aus dem veröffentlichten Testkorpus. Die Quellversion ist im Original deklariert. |
| Nmap-Projekt, vier unveränderte Zenmap-Referenzdateien | Die Datei mit ausgewiesener Version 3.75 enthält einen geschlossenen und einen offenen TCP-Port. Acht UDP-Einträge aus einer zweiten 3.75-Datei bleiben ausgeschlossen. | Der gekennzeichnete 5.51SVN-Export mit Servicenamen `H.323/Q.931` wird atomar zurückgewiesen. Der 5.59BETA1-Export mit abweichender XML-Zeichenkodierung wird zurückgewiesen. |
| ffuf 2.1.0, originaler `output.Stdoutput.SaveFile` | Der unveränderte Writer erstellt aus zwei künstlichen HTTP-Ergebnisobjekten die native Datei-JSON. Ein zulässiger GET-Record trägt Status 200 und zwei Bytes, der zweite Record wird wegen des Scope ausgelassen. Eine separate native Datei mit `config.postdata` wird als `unsupported_request_context` protokolliert. | Das Experiment belegt das Datei-JSON-Profil für diese Werte. Ein Scannerlauf oder eine reale HTTP-Transaktion ist zur Prüfung dieser Formatabbildung nicht erfolgt. |
| Nuclei 3.3.10, originaler `output.StandardWriter.Write` | Zwei künstliche HTTP-Ereignisse mit identischem Endpunkt und gesetzter oder gelöschter Matcher-Bedingung ergeben zwei JSONL-Records. Der positive trägt einen Hinweis, der negative behält seinen eigenen Locator und keine Beweisstufe. | Gilt für die geprüfte Variante ohne eingebettete Requests/Responses. Weder die Existenz eines Befunds noch eine künftige Produzentenversion wird hierdurch belegt. |

## Originale und Nachprüfung

`provenance.json` enthält Commit, Go-Modulprüfsumme, SHA-256 der Originalbytes und bei den vier Nmap-Quelldateien die Git-Blob-ID. Der beigelegte Nmap-5.51-Export stammt aus einem Apache-2.0-lizenzierten Testkorpus. Er und die Ausgaben der beiden Go-Writer erlauben die vollständige Standardprüfung offline. Die vier zusätzlichen Nmap-Dateien aus dem Herstellerrepository sind von dort unverändert zu beziehen. Der optionale Downloader holt ausschliesslich vier fest definierte Dateien per HTTPS und prüft sie vor dem Schreiben. Die Netzwerkverbindung endet vor dem Start der eigentlichen Prüfung.

Im Verzeichnis dieses Belegs ausführen. Voraussetzung ist ein Python-Interpreter mit installiertem Kandidaten oder ein entsprechender Checkout im Python-Pfad. Der Beispielaufruf verwendet Linux und libseccomp 2. `verify.py` kann auf anderen Systemen auch ohne `offline_exec.py` mit bereits bereitgestellten Dateien ausgeführt werden.

```sh
python3 offline_exec.py "$(command -v python3)" -B verify.py
# Optional: vier zusätzliche Grenzen anhand separat bezogener Nmap-Projektdateien.
python3 fetch_nmap.py /tmp/authzledger-native-nmap-new
python3 offline_exec.py "$(command -v python3)" -B verify.py --nmap-dir /tmp/authzledger-native-nmap-new
```

Die ebenfalls enthaltene historische Snapshot-Fixture stammt vom ursprünglichen Commit `f8f840f33e88911cfcd3b9d189bc5c7ac13b17b7` vor der Korrektur des nativen ffuf-Kontextfelds. Der Vorgänger hat die native Kontextdatei als Beobachtung angenommen. Der Store-Test prüft, dass diese ursprünglichen Bytes lesbar bleiben und dass ihr alter Review-Digest eine neue, semantisch abweichende Übernahme verhindert.

## Optionale Neuserialisierung

Die drei eigenen Go-Treiber unter `writers/` rufen ausschliesslich die upstream Ausgabebibliotheken auf. `go.mod` und `go.sum` pinnen die Abhängigkeiten. Die Referenz nutzte Go 1.24.12 auf Linux/amd64. Abhängigkeiten werden nur für einen erneuten Build bezogen. Der normale Importvergleich benötigt weder Go noch Herstellerprogramme.

Für eine Neuserialisierung in einem neuen privaten Ausgabeverzeichnis die drei Treiber getrennt aus den Modulen `writers/ffuf` (Pakete `.` und `./context`) und `writers/nuclei` (Paket `.`) mit `go build -buildvcs=false -mod=readonly -o ABSOLUTER_PROGRAMMPFAD PAKET` bauen. Jeweils `python3 offline_exec.py ABSOLUTER_PROGRAMMPFAD NEUER_AUSGABEPFAD` ausführen. `go version -m ABSOLUTER_PROGRAMMPFAD` muss die Modulversion und Prüfsumme aus der Provenienzdatei ausweisen. Beide Upstream-Writer erzeugen beim Serialisieren einen aktuellen Zeitstempel. Neue Originalbytes erhalten deshalb eigene Hashes. Die hier erfassten Referenzen werden nicht überschrieben.

## Rechte und Herkunft

Für die unveränderte XML-Datei aus python-libnmap gelten die mitgelieferten Originalhinweise und Apache-2.0-Bedingungen unter `third-party/python-libnmap/`. [Originaldatei](https://github.com/savon-noir/python-libnmap/blob/f9887fc9add90e2e0b3c59671ec5ecd9bee8fcd3/libnmap/test/files/1_hosts_banner_ports.xml) · [Original-Lizenzhinweis](https://github.com/savon-noir/python-libnmap/blob/f9887fc9add90e2e0b3c59671ec5ecd9bee8fcd3/LICENCE)

Die eingecheckten ffuf-/Nuclei-Ergebnisdaten enthalten eigene künstliche Testobjekte. Weder Herstellerquellcode noch Herstellerprogramme werden mit diesen Belegen ausgeliefert. Die Go-Module führen ihre eigenen Lizenzen. Die vier Nmap-Projektdateien verbleiben an der verlinkten Originalquelle. Die Bereitstellung separat bezogener Dateien im Prüflabor gestattet keine pauschale Weiterverteilung von Nmap-Bestandteilen in einem proprietären Produkt.

[Nmap-Quelldaten](https://github.com/nmap/nmap/tree/80dd68b8d88cbc89e584941e9ba68e57247d2230/zenmap/test) · [Nmap-Lizenz am geprüften Commit](https://github.com/nmap/nmap/blob/80dd68b8d88cbc89e584941e9ba68e57247d2230/LICENSE) · [ffuf-Writer](https://github.com/ffuf/ffuf/blob/7a2756a8f367c69c261544ae83d52e86b1ca52d0/pkg/output/file_json.go) · [Nuclei-Writer](https://github.com/projectdiscovery/nuclei/blob/a7e44912f99eff51071f89d2ff180ede4ce1b49c/pkg/output/output.go)
