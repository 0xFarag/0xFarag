# ComparisonEnvelope v1 — Teilretests mit ihren Quellen vergleichen

Dieses Dokument beschreibt das **implementierte Vergleichsinkrement** auf dem Entwicklungsstand von AuthzLedger 1.0.0. Es ist kein Releasehinweis für eine fertige Version 1.0.5. Die vollständige Zielarchitektur, weitere Fähigkeiten und deren Abnahme stehen im [Implementierungsvertrag für 1.0.5](implementation-1.0.5.md).

Der neue Vergleich verbindet eine vollständige Baseline mit einem gezielten Teilretest. Er behält die Originalreports bei, ergänzt erforderliche Controls und weist jeden ausgelassenen Fall als `not_retested` aus. Er ist vollständig offline: Auswertung und Verifikation senden keine App- oder Policy-Requests und lösen keine Credentials auf.

## 1. Was der Vergleich belegt

Ein Quellcontract mit vier Fällen kann einen ausgewählten Retestfall und zwei erforderliche Controls liefern. Der aktuelle Report enthält dann drei Ergebnisse. Der vierte Fall bleibt historisch und erhält kein aktuelles Pass.

Der bisherige `evidence.compare_reports` bleibt unverändert streng: gleiche Contract-Digests und identische Toolmetadaten. Die neue Hülle schliesst die Lücke, dass ein korrekt verkleinerter Retestcontract einen anderen Digest hat. Sie berechnet aus dem vollständigen Quellcontract und der expliziten Auswahl die transitive Voraussetzungshülle und verlangt den exakt zugehörigen aktuellen Report.

Eine unverändert gültige Signatur oder ein intern konsistenter Report beweist nicht, dass ein entferntes System die behauptete Antwort tatsächlich geliefert hat. Der Vergleich belegt konfigurierte Checkübergänge unter den dokumentierten Voraussetzungen. Er attestiert weder Runtime-Identität noch Credential-Werte, aktuellen Objektbesitz, Deploymentstand oder eine fachlich bestätigte Schwachstellenbehebung.

## 2. Direkt ausführbarer lokaler Nachweis

Im Repositoryroot:

```sh
python tools/check_comparison.py --out evidence/comparison-check-local
```

Der Zielordner darf noch nicht existieren. Das Werkzeug benötigt Python, das Projekt und das für die bestehende Ed25519-Implementierung verwendete OpenSSL. Es startet ausschliesslich eine synthetische HTTP-Fixture auf `127.0.0.1` an einem freien Port.

Der Ablauf ist real, nicht aus vorgefertigten Ergebnisobjekten simuliert:

1. Vier konfigurierte HTTP-Requests erstellen die Baseline. Ein Cross-Identity-Request erhält 403, enthält aber den geschützten synthetischen Marker; die `json_absent`-Assertion schlägt fehl.
2. Die lokale Fixture wird repariert. Der ausgewählte Fall `peer-denied-owner` und seine beiden positiven Controls werden erneut geprüft: exakt drei HTTP-Requests, weiterhin 403 beim negativen Fall, jetzt ohne Marker.
3. Der HTTP-Server wird beendet. Temporäre Credential-Umgebungswerte werden entfernt bzw. frühere Werte wiederhergestellt.
4. Erst jetzt entstehen Vergleichshülle und HTML. Der ausgelassene Fall erhält `not_retested`; der korrigierte Check erhält `resolved_check`.
5. Ein temporäres Schlüsselpaar signiert das Paket. Der private Schlüssel wird nach dem Signieren entfernt. Hauptverifier und isoliert gestarteter Standalone-Verifier prüfen das Paket; zusätzlich wird das ZIP-Transportarchiv wieder ausgepackt und geprüft.

Erzeugte Dateien:

| Datei | Inhalt |
|---|---|
| `source.json`, `baseline.json` | Vollständiger Quellcontract und Originalbaseline |
| `retest-plan.json`, `retest-contract.json`, `current.json` | Auswahl mit Controls, Teilcontract und aktueller Originalreport |
| `comparison.json`, `comparison.html` | Vollständig prüfbare Hülle und abgeleitete lesbare Darstellung |
| `current-graph.json` | Graph für den tatsächlich ausgeführten Teilcontract |
| `proof/`, `proof.zip` | Signiertes Paket und identischer Inhalt als Transportarchiv |
| `trusted-public.pem` | Separat ausgegebener Demonstrations-Public-Key |
| `acceptance.json` | Requestzahlen, Coverage, Vergleichsdigest, Verifierergebnisse und Grenzen |

Erwartete Coverage: `source_cases: 4`, `selected_cases: 1`, `dependency_cases: 2`, `retested_cases: 3`, `not_retested_cases: 1`. Erwartete Transitionen: zwei `unchanged`, ein `resolved_check`, ein `not_retested`.

Das Werkzeug verwendet zufällig erzeugte temporäre Zugangsdaten, prüft deren Abwesenheit im Ergebnisverzeichnis und speichert keinen privaten Signierschlüssel. Die verwendeten synthetischen Daten sind keine echten Kundendaten. Der ausgegebene Public Key ist ein Demonstrations-Vertrauensanker; er bestätigt keine extern geprüfte Herstelleridentität.

## 3. Eigene vorhandene Reports vergleichen

Voraussetzungen:

- Die Baseline gehört exakt zum vollständigen Quellcontract.
- Der aktuelle Report gehört exakt zur mit `assurance.retest_plan` erzeugten Auswahl samt transitiven Voraussetzungen.
- Pfade, Identitätsdefinitionen, Erwartungen, Limits, Reihenfolge des normalisierten Quellcontracts und erforderliche Controls wurden nicht als vermeintlicher Fix verändert.
- Beide Reports besitzen gültige v1-Evidenceketten und unterstützte Tool-/Formatprofile.

Die folgenden Grossbuchstaben bezeichnen eigene vorhandene Dateien und IDs:

```sh
authzledger compare-retest SOURCE.json BASELINE.json CURRENT.json --case CASE_ID --out NEW_COMPARISON
authzledger verify-comparison NEW_COMPARISON/comparison.json
```

`--case` lässt sich wiederholen. Wird es weggelassen, wählt der Vergleich alle Quellfälle und erwartet einen vollständigen aktuellen Report. Leere, doppelte oder unbekannte ausgewählte IDs werden abgelehnt. Die Auswahl ist kein Ausführungsbefehl und gewährt keine Mutationserlaubnis.

`compare-retest` erzeugt `comparison.json` und `comparison.html`; vorhandene Zielordner werden nicht überschrieben. Die originalen Toolmetadaten, Evidence-Roots und Inhalte der beiden Reports bleiben erhalten. Das Einbetten verwendet kanonisch äquivalente JSON-Objekte; die ursprüngliche Dateieinrückung ist kein Teil dieser Erhaltung. Kein alter Report wird auf eine neue Toolversion umgeschrieben oder neu versiegelt.

### Exitcodes richtig interpretieren

| Befehl | Code | Bedeutung |
|---|---|---|
| `compare-retest` | 0 | Vergleich erstellt; weder Regression noch unklare/verlorene Testbarkeit gemeldet |
| `compare-retest` | 1 | Mindestens eine Regression, ohne vorrangigen Zustand für Code 2 |
| `compare-retest` | 2 | Mindestens ein `inconclusive`/`testability_lost` oder Eingabe-/Ausgabefehler |
| `verify-comparison` | 0 | Hülle aus ihren Quellen vollständig nachvollziehbar neu berechnet |
| `verify-comparison` | 2 | Verifikation oder Eingabeverarbeitung fehlgeschlagen |

**Code 0 ist kein Sicherheitszertifikat.** Ein unverändert fehlgeschlagener Check kann `unchanged` sein, und ausgelassene Fälle bleiben `not_retested`. `verify-comparison` prüft die Korrektheit der Hülle, nicht ob alle enthaltenen Checks bestehen.

## 4. Transitionen und Controlgültigkeit

| Status | Bedeutung |
|---|---|
| `regression` | Derselbe konfigurierte Check wechselt von `pass` zu `fail` |
| `resolved_check` | Derselbe konfigurierte Check wechselt von `fail` zu `pass`; kein fachlicher Remediationnachweis |
| `testability_restored` | Vorheriger Ausführungsfehler, jetzt konklusiver Pass |
| `testability_lost` | Vorher bewertbarer Check, jetzt Ausführungsfehler |
| `inconclusive` | Ungültige Controls, unklarer Intent oder unzureichende Beobachtungen |
| `unchanged` | Konklusiver Checkausgang unverändert, einschliesslich `fail → fail` |
| `not_retested` | Fall liegt ausserhalb der ausgewählten Voraussetzungshülle |

Die Controlprüfung folgt allen transitiven Voraussetzungen. Sie verlangt bestandene Controls mit eindeutiger Intent-/Beobachtungsbeziehung. Positive Controls müssen beabsichtigten Zugriff und passende positive Inhaltsassertions belegen. Negative Fälle ohne verankerten positiven Control bleiben unklar; ein Statuscode allein ist kein ausreichender positiver Nachweis.

Beispielgründe sind `control_validity_not_established`, `configured_intent_ambiguous`, `inconclusive_observation`, `current_execution_error` und `outside_selected_dependency_closure`. Jede Transition enthält die genauen Vorher-/Nachherwerte und Controlgründe beider Läufe.

## 5. Python-API und Hüllenfelder

```python
from authzledger.comparison import create_comparison, verify_comparison

envelope = create_comparison(
    source_contract,
    baseline_report,
    current_report,
    selected_ids=["peer-denied-owner"],
)
errors = verify_comparison(envelope)
```

`create_comparison` erwartet den Quellcontract als JSON-Objekt, keinen Dateipfad. Es kopiert Eingabeobjekte und verändert sie nicht. Ungültige oder nicht vergleichbare Eingaben ergeben `ComparisonError`, eine `ValueError`-Unterklasse. `verify_comparison` liefert `[]` oder eine Liste sicherer Fehlermeldungen. Es berechnet alle abgeleiteten Aussagen aus den eingebetteten Quellen neu; eine manipulierte Summary mit nachträglich korrigiertem Digest wird dadurch erkannt.

| Feld | Vertrag |
|---|---|
| `schema_version`, `kind` | `1`, `comparison-envelope` |
| `canonicalization` | `json-sort-keys-ascii-escaped-v1` |
| `source_contract` | Unverändertes Quellobjekt; für semantische Bindung normalisiert |
| `baseline_report`, `current_report` | Vollständige, unverändert eingebettete Originalobjekte |
| `selected_ids`, `dependency_ids` | Explizite Auswahl und zusätzliche transitive Voraussetzungen, in Quellreihenfolge |
| `profiles.baseline`, `profiles.current` | Explizite Report-/Checkformatregistrierung je Toolversion |
| `profiles.semantics` | `source-bound-configured-check-transitions-v1` |
| `profiles.registration` | Begrenzung: Formatprofil, keine Zertifizierung eines Executables |
| `bindings` | Digests von Originalquelle, normalisierter Quelle, Teilcontract, Reportobjekten, Originalroots und Toolobjekten |
| `bindings.credential_definitions` | `identical-source-bound-references` |
| `bindings.runtime_credentials` | `not-attested` |
| `policy` | `status: not_compared`; keine unabhängigen Policyevaluationen enthalten |
| `transitions` | Ein Eintrag je Quellfall mit Status, Gründen, Controls, Evidence und Definitiondigests |
| `coverage` | Quellfälle, gewählte Fälle, zusätzliche Controls, erneut geprüfte und ausgelassene Fälle |
| `summary` | Anzahl je Transitionstatus |
| `limitations` | Verbindliche Aussagegrenzen |
| `comparison_sha256` | Domaingebundener SHA-256-Digest der Hülle ohne dieses Feld |

Eine Transition enthält `case_id`, `status`, `before`, `after`, `reasons`, `controls`, `evidence`, `case_definition_sha256` und `identity_definition_sha256`. `after` und aktuelle Evidence/Controls sind bei `not_retested` null. Alte Ergebnisse bleiben als historische `before`-Beobachtung erhalten.

Der Digestinput ist die Bytefolge `AuthzLedger:comparison-envelope:v1\n` gefolgt von kanonischem JSON ohne `comparison_sha256`: sortierte Schlüssel, kompakte Separatoren, ASCII-Escapes, keine nicht-endlichen Zahlen, UTF-8. Dies ist kein behauptetes RFC-8785-Profil. Ein gültiger Digest ohne vertrauenswürdig gebundene Quellen bleibt nur interne Konsistenz.

### Quellenbindung und Versionsprofile

Der Quellcontract wird streng mit dem bestehenden v1-Loader normalisiert. Der Baseline-Report wird gegen alle Quellfälle gebunden. Der aktuelle Report wird gegen den exakt aus Auswahl und Closure rekonstruierten Teilcontract gebunden. Die Bindung prüft unter anderem IDs, Identity, Methode, Pfad, Voraussetzungen, Controltyp und die zulässige Checkstruktur. Der existierende Graphbinder und Graphverifier werden wiederverwendet.

Aktuell registrierte Profile:

| Berichtetes Tool | Profil |
|---|---|
| AuthzLedger 1.0.0 | `authzledger-1.0.0-report-v1-checks-v1` |
| AuthzLedger 1.0.5 | `authzledger-1.0.5-report-v1-checks-v1` |

Die 1.0.5-Registrierung gilt ausschliesslich für unveränderte v1-Report-/Checksemantik. Sie erklärt den noch nicht veröffentlichten Gesamtumfang von 1.0.5 nicht für fertig. Andere Toolmetadaten oder Versionsprofile werden abgelehnt; es gibt keinen pauschalen `1.x`-Wildcard. Policysemantik, neue Workflow-Assertions und Runtime-Attestierungen werden hiermit nicht freigegeben.

## 6. Studio: History auswählen, Teilretest planen, Proof exportieren

1. Einen vorhandenen Lauf in **History** auswählen. Die Fallauswahl zeigt die gespeicherten IDs und ihre Voraussetzungen. Zunächst sind alle Fälle gewählt; die gewünschte Teilmenge explizit auswählen.
2. **Retest** vorbereiten. Der Server verwendet ausschliesslich den gespeicherten Quellcontract und die gespeicherte Baseline. Die Vorschau zeigt gewählte Fälle, automatisch ergänzte Controls, ausgelassene IDs, Requests und Credential-Präsenz.
3. Die konkrete Zielberechtigung bestätigen und den überprüften Plan ausführen. Ein selektiver Retest führt genau einen Zyklus aus. Die Reviewfreigabe ist an Baseline, Auswahl, Teilcontract, Mutationseinstellung und Policy-/Assurancesettings gebunden, nach zehn Minuten ungültig und für diesen Retest nur einmal verwendbar.
4. Im Jobergebnis die Comparison-Tabelle ansehen. Alte/aktuelle Werte, Gründe und `not_retested` bleiben sichtbar. JSON-Hülle und lesbaren HTML-Vergleich exportieren.
5. Mit beim Studiostart konfiguriertem privaten Signierschlüssel und Public Key das Proof-Paket exportieren. Browserfelder akzeptieren keine Signingkeys oder beliebige lokalen Lesepfade. Der Server prüft, dass `comparison_envelope.current_report` genau dem signierten Report entspricht.

Die Hülle ist Bestandteil des Jobergebnisses und der Exporte. Sie wird derzeit nicht als eigenes Objekt in die History-Datenbank geschrieben. Gespeicherte Contracts und Reports erlauben eine spätere Offline-Neuberechnung; nach Schliessen einer rein flüchtigen Studiositzung müssen die zuvor exportierten Quellen verwendet werden. Die Historykette bleibt manipulationsanzeigend, keine unveränderbare externe Zeitstempelinstanz.

Die aktuelle Stopfunktion beendet keine beliebige laufende DAG-Anfrage sofort: Sie lässt den laufenden begrenzten Ausführungszyklus auslaufen und verhindert weitere Zyklen. Der spätere gemeinsame Budget-/Cancel-Kontext und der gesamte neue Studio-Workflow sind im Implementierungsvertrag geplant, nicht Teil dieses Vergleichsinkrements.

### Tatsächlich ergänzte HTTP-Endpunkte

Alle folgenden Endpunkte verwenden POST, JSON und die bestehenden lokalen Studio-Session-/Host-/Origin-Prüfungen. Die allgemeinen Bodylimits gelten weiter.

| Pfad | Relevante Eingabe | Ergebnis |
|---|---|---|
| `/api/retest/plan` | `baseline_id`, `selected_ids`; optional `allow_mutations`, `policy`, `use_server_policy`, `assurance` | Plan, Review, Credential-Präsenz und `retest` mit Source-/Baselineroot, Auswahl, Dependencies und ausgelassenen IDs |
| `/api/retest` | Vorschaucontract, `review`, `authorized: true`, passende `baseline_id`, `selected_ids` und geprüfte Settings | Job-ID; Ergebnis enthält `comparison_envelope` |
| `/api/comparison` | `source_contract`, `baseline_report`, `current_report`, optional `selected_ids` | `comparison_envelope`; vollständig offline |
| `/api/comparison/verify` | `comparison_envelope` | Verifizierte Hülle oder Fehler; vollständig offline |
| `/api/export` | `kind: comparison-envelope`, `comparison_envelope` | Abgeleitetes HTML |
| `/api/proof` | Bestehender Report-/History-/Snapshotbezug; optional `comparison_envelope` | Nach Prüfung signiertes Proof-ZIP |

`GET /api/jobs/{id}` liest den aktuellen Jobzustand. Ein Browserdisconnect ist kein Beleg, dass der Serverjob beendet wurde. Die neue Browserabnahme ist separat auszuführen; fehlender Chromium-Zugriff darf nicht als bestandener Browserflow ausgewiesen werden.

## 7. Signiertes Paket und unabhängige Prüfung

Vorhandener privater Schlüssel und aktueller Originalreport:

```sh
authzledger bundle CURRENT.json --key PRIVATE.pem --comparison NEW_COMPARISON/comparison.json --out NEW_PROOF
authzledger verify-bundle NEW_PROOF --public-key TRUSTED_PUBLIC.pem
python -I tools/verify_bundle.py NEW_PROOF --public-key TRUSTED_PUBLIC.pem
```

`bundle --comparison` bindet die reservierten Dateien `attachments/comparison.json` und `attachments/comparison.html`. Die JSON-Hülle muss semantisch gültig sein; ihr aktueller Report muss exakt dem Paketreport entsprechen. Das HTML wird aus dieser Hülle erzeugt und bei der semantischen Paketprüfung erneut verglichen. Ein frei formuliertes anderes HTML kann deshalb nicht als geprüfte Darstellung derselben Hülle unterschoben werden.

| Prüfung | Belegt | Belegt nicht |
|---|---|---|
| `verify-comparison` | Originalquellen, Closure, Formatprofile, abgeleitete Aussagen und Digest konsistent | Urheberschaft, echte Netzausführung, vertrauenswürdige Identitätsbindung |
| `verify-bundle` | Signatur gegen externen Schlüssel, Inventar, Hashes, Reportsemantik, Comparisonsemantik und abgeleitetes HTML | Echtheit eines entfernten Antwortservers oder vollständiger fachlicher Fix |
| Standalone `tools/verify_bundle.py` | Signatur, Inventar, Dateihashes und Reportanker ohne importiertes AuthzLedger-Paket | Keine Auswertung der Comparisonsemantik |

Das im Paket mitgelieferte `public.pem` ist allein kein unabhängiger Vertrauensanker. Der erwartete Public Key oder dessen authentisch übermittelter Fingerprint muss separat vorliegen. Wird das Paket über ZIP transportiert, prüfen die Verifier das ausgepackte Verzeichnis; ihnen wird keine integrierte ZIP-Extraktionsfunktion zugeschrieben.

Ein Manifest bindet die Payloaddateien, die separate Ed25519-Signatur bindet das Manifest. Manifest und Signatur werden nicht in ihre eigenen Digests aufgenommen. Eine spätere Veränderung der HTML-Datei muss die Integritätsprüfung scheitern lassen. Ein vollständiger Austausch sämtlicher Quellen mit konsistenten neuen Hashes benötigt zur Erkennung einen separat vertrauten ursprünglichen Root oder Schlüssel.

## 8. Grenzen und nächster Entwicklungsschritt

Dieses Inkrement liefert den tatsächlichen Teilvergleich, CLI, Studiointegration und signierte Übergabe. Es implementiert noch keine Burp-/ZAP-/HAR-Importer, kein vollständiges Contrast Lab, keine Workflow Contracts, keinen Minimierer und keine neuen PDF-Assessmentreports. Der gemeinsame Ausführungskontext, Identity-Attestierung und fachliche Fixstatus folgen den separaten P0-/P1-Gates im [Implementierungsvertrag](implementation-1.0.5.md).

Für die aktuelle Prüfung sind `tests/test_comparison.py`, `tests/test_studio_comparison.py`, `tests/browser_comparison.cjs` und `tools/check_comparison.py` die gezielten Einstiegspunkte. Die Browserdatei ist ein Testartefakt, kein automatisch bestandener Test. Aktuelle Testergebnisse und Einschränkungen müssen im tatsächlichen Verifikationsprotokoll stehen; diese Anleitung ersetzt es nicht.
