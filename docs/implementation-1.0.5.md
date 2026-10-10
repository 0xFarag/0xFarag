# AuthzLedger 1.0.5 — Implementierungsvertrag

Stand: 10. Oktober 2026. Eigentümer: Nasser Aldin Farag / 0xFarag.

**Produktziel:** AuthzLedger verwandelt manuelle Pentest-Entdeckungen in kontrollierte, reproduzierbare Sicherheitsnachweise mit gezieltem Fix-Nachweis. Ein Request wird übernommen, einer expliziten Sicherheitsregel zugeordnet, unter gültigen Kontrollen geprüft, auf einen kleineren Reproduktionsfall reduziert und als Finding mit Retest und signiertem Nachweis übergeben.

Dieses Dokument ist ein verbindlich ausführbarer Entwicklungsvertrag, kein Nachweis eines fertigen 1.0.5-Releases. Das erste Vergleichsinkrement ist im Entwicklungsstand implementiert; der genaue Umfang steht in Abschnitt 4 und in der [ComparisonEnvelope-Anleitung](comparison-envelope-v1.md). Version und Release bleiben bis zur vollständigen Abnahme auf 1.0.0. **Alle nachfolgend als Sollschnittstelle bezeichneten Module, API-Endpunkte und Assessment-Befehle sind geplante Erweiterungen.** Sie dürfen in Demos, Hilfe oder Marketing erst nach bestandener Abnahme als verfügbar erscheinen. Die acht vollständigen Fähigkeiten benötigen weitere Implementierung.

## 1. Reale Grundlage und feste Grenzen

Die 1.0-Basis besitzt Contract-/Report-Schema v1, einen kontrollabhängigen HTTP-DAG, lokale und explizit konfigurierte OPA-Auswertung, drei getrennte Graphebenen, signierte Pakete, Studio, CLI und lokale History. Der vorhandene Code legt folgende Erweiterungspunkte fest:

| Bestehender Ort | Tatsächliches Verhalten | Konsequenz für 1.0.5 |
|---|---|---|
| `model.load_contract`, `contract_digest` | Strikte v1-Felder; kanonisches JSON; Credential-Referenzen werden nicht aufgelöst | Neue Semantik in versionierten Sidecars; keine stillen Felder in alten Contracts |
| `engine.run`, `_execute`, `_checks` | Status, exakte JSON-Pointer, `json_absent`; DAG; kein Capture für Header-Assertions | Gemeinsamen Ausführungskontext und Observation-Sink ergänzen; v1-Resultate beibehalten |
| `engine._credentials` | Alle Credential-Umgebungsreferenzen vor App-Verkehr auflösen | In einen Resolver verlagern; CLI-Umgebungsvariablen weiterhin unterstützen |
| `assurance.retest_plan` | Auswahl plus vollständige deklarierte Voraussetzungen; neuer Teilcontract-Digest | Quellcontract und Teilcontract ausdrücklich binden |
| `evidence.compare_reports` | Gleicher Contract-Digest und identisches Toolobjekt erforderlich | Strengen Altvergleich erhalten; neue Vergleichshülle ergänzt Teil-/Versionsvergleich |
| `policy.evaluate_policy` | OPA-App-Verkehr separat; keine deployed-policy-Attestierung | PDP-Requests ebenfalls budgetieren; deklarierte Provenienz nicht als Deployment-Beweis ausgeben |
| `studio.start_job`, `/api/plan` | Ein aktiver Job; geprüfte Pläne laufen nach zehn Minuten ab; Stop zwischen Zyklen | Plan-/Freigabebindung erhalten; Stop bis in DAG und Transportaufnahme reichen |
| `signing.create_bundle` | Signiertes Inventar, strikte Namen, separate Ed25519-Signatur | Neue Dateien vollständig inventarisieren; Assessment-Semantik zusätzlich validieren |
| `tools/verify_bundle.py` | Eigenständiger kryptografischer Verifier | Kryptografische und fachliche Prüftiefe getrennt benennen |

Defaultlimits der unveränderten v1-Engine: 50 App-Requests, 5 Sekunden je Request, 64 KiB Response und Parallelität 4. Konfigurierbare Obergrenzen: 1.000 App-Requests, 60 Sekunden, 1 MiB Response und Parallelität 16. Ein neuer Gesamtzähler darf diese Grenzen enger begrenzen, niemals umgehen. Im neuen Workflow-Profil läuft die Sequenz mit Parallelität 1.

Keine zweite Engine, kein Frameworkwechsel, keine autonome Zielsuche und keine Shell-/Plugin-Hooks. Erweiterte Pentesting-Tiefe entsteht durch kontrollierte Identitäts-, Objekt-, Rollen-, Zustands- und Replay-Experimente. Race-Condition-Nachweise und allgemeine AD-/Netzwerk-Exploitation sind ausserhalb dieses Releases. Historische Reports, Signaturen, Lizenz und Rechtehinweise bleiben erhalten. Ein verkleinerter Scope ist keine Systemfreigabe.

## 2. Prioritäten und Abhängigkeitsfolge

Die IDs entsprechen der bisherigen Produktspezifikation. P1 bleibt Pflicht für den vollständigen Anspruch von 1.0.5; P0 ist die früh lieferfähige Kernvertikale.

| ID | Priorität | Fähigkeit | Benötigt | Frühester nutzbarer Nachweis |
|---|---|---|---|---|
| F05 | P0, zuerst | ComparisonEnvelope und belastbarer Retest | v1-Reports/Contracts | Vollbaseline mit Teilretest offline und ohne Umversiegelung vergleichen |
| F01 | P0 | Offline-Import und Zuordnung | Assessment-Modell, Resolver | Ein realer Burp-/ZAP-/HAR-Export wird eindeutig oder sichtbar nicht ausführbar übernommen |
| F02 | P0 | Contrast Lab | F01, ExecutionContext, Observation/Oracle | Echte BOLA von 200-Fehlerobjekt und ungültiger Kontrolle unterscheiden |
| F06 | P0 | Durchgängiges Studio | Gemeinsame Services; F01/F02/F05 | Vom Import bis zum geprüften Befund ohne Terminal |
| F07 | P0 | Assessment-Report und Proof | Finding-Modell, F05/F02 | Gleiche Befunde in JSON/HTML/PDF und signiertem Inventar |
| F03 | P1 | Workflow Contracts | F02, typisierte Extraktion, Cleanup | Fehlende Freigabe/unerlaubter Replay durch unabhängigen Zustandsread belegt |
| F04 | P1 | Minimal Reproducer | F02; isolierte Fixture, F03 bei Mutation | Jede akzeptierte Reduktion reproduziert dieselbe Verletzung |
| F08 | P1 | Graph und erklärbare Assurance | F05, F02, Änderungskatalog | Jede Auswahl ist begründet; unbekannte Abhängigkeiten sind offen sichtbar |

P0 gilt erst als abgeschlossen, wenn **F01 → F02 → Inspector → Retest → F07 → Proof** über Studio und CLI denselben fachlichen Zustand erzeugt. Ein isolierter Parser oder eine fertige Graphansicht ist keine abgeschlossene Vertikale.

## 3. Gemeinsame technische Verträge

### 3.1 Deterministische Pläne, unveränderliche Beobachtungen

Die künftig geplanten Assessment-/Experiment-/Observation-Objekte tragen `schema_id`, `schema_version: 1`, `kind` und einen typgebundenen Digest. Das bereits implementierte `ComparisonEnvelope v1` verwendet seinen ausdrücklich beschriebenen Vertrag in Abschnitt 4 und benötigt kein nachträglich ergänztes `schema_id`. Die Digest-Norm ist die bestehende Python-JSON-Kanonisierung: sortierte Schlüssel, kompakte Separatoren, ASCII-Escapes, keine nicht-endlichen Zahlen, UTF-8. Sie ist nicht als RFC-8785-Konformität bezeichnet. Unbekannte Felder, doppelte JSON-Schlüssel, ungültige Typen und nicht unterstützte Versionen werden abgelehnt. Boolesche Werte sind keine Integer.

Der Digest umfasst die typspezifische Domain und das vollständige kanonische Objekt ohne sein eigenes Digest-Feld. Bestehende v1-Digests behalten ihren bisherigen Algorithmus ohne neue Domain. Mengenartige Arrays werden nach expliziten stabilen IDs sortiert; Reihenfolgen von Workflow-Schritten, gleichnamigen Query-Parametern und HTTP-Headern bleiben erhalten. Normalisierung darf keine semantisch relevante Reihenfolge löschen. Zeit, zufällige Lauf-ID und dynamische Fixture-Werte gehören in den Laufnachweis, nicht in den Plan-Digest. Ein Schemawechsel erzeugt eine neue Version, kein stilles Umdeuten von v1.

| Sollobjekt | Pflichtinhalte | Überprüfbare Invariante |
|---|---|---|
| `AssessmentSpec v1` | Assessment-ID; Revision; Scope; Source-IDs; Identitäts-/Ressourcenbindungen; Experiment-IDs; Budgets; Capture-/Redaction-Profil; Reporting-Profil | Jede referenzierte Version/Digest auflösbar; keine Credential-Werte enthalten |
| `ImportSource v1` | Format-/Parserprofil; Original-Byte-Digest; redigierter Source-Digest; Eintrags-ID; Datenlücken; Fremdaussagen; ausführbarer Zustand | Herkunft ist getrennt von AuthzLedger-Ausführung und Finding-Status |
| `ExperimentPlan v1` | Regel; Inputquellen; Varianten; Controls; Oracle-/Normalizer-Versionen; Contract-Digests; Scope; Requestobergrenze | Derselbe normalisierte Input erzeugt dieselben Varianten, DAG-Kanten und IDs |
| `ExecutionTrace v1` | Plan-Digest; Lauf-ID; Zeit; Credential-Generationen ohne Secret; Bindungsbeobachtungen; Budget-Ledger; materialisierte Contract-/Report-Roots | Jede gesendete Anfrage besitzt vorherige Budgetreservierung und freigegebenen Planursprung |
| `ObservationRecord v1` | Lauf/Case/Attempt; Request-Projektion; Response-/Capture-Digests; Oracle-Eingaben/Ergebnis; Controls; Interpretation; Prüftiefe | Ein Ergebnis lässt sich nicht durch Anhängen an einen fremden Report umetikettieren |
| `WorkflowTrace v1` | Workflow-/Varianten-Digest; Fixture-ID; Vorzustand; geordnete Schritte; Bindungsprovenienz; Nachprüfung; Cleanup | Ein unbekannter Vorzustand oder ungültige Nachprüfung erlaubt keinen bestätigten Zustandsbefund |
| `FindingRecord v1` | Stabile Regel-/Ressourcen-ID; Kategorie; Aussage; Evidence; Kontrollen; Impact; Review; Retest-Historie; Standardreferenzen | Statuswechsel ist an neue Evidence oder explizite Reviewerentscheidung gebunden |
| `ReductionTrace v1` | Original-Finding-/Evidence-Root; entfernbare Einheiten; Versuche; Oracle-Fingerprint; akzeptierte Kette; Stopgrund | Jede akzeptierte Kante hat `reproduced`; Original bleibt unverändert |
| `ComparisonEnvelope v1` | Zwei Originalroots; Quell-/Teilcontract; Auswahl/Closure; Profil; Coverage; Klassifikationen | Originalberichte werden geprüft und verknüpft, nicht neu geschrieben |
| `AssessmentSnapshot v1` | Fixierte Finding-Versionen; Evidence-/Vergleichsrefs; Scope/Lücken; Renderer-/Katalogprofil | Alle Exportformate leiten sich aus genau diesem Snapshot ab |

IDs dienen der Zuordnung; Digests belegen Inhalte. Ein vom Import übernommener Fremdbefund erhält stets `source_assertion`, niemals durch Import `confirmed`.

### 3.2 ExecutionContext: ein Budget für alle Requests

Sollmodul `execution.py`, weiterverwendet von `engine.py`, `policy.py`, `workflows.py`, `minimize.py` und `assurance.py`. Kein Adapter darf direkt einen eigenen HTTP-Client ausserhalb dieses Kontextes öffnen.

```python
class ExecutionContext:
    def reserve(self, *, kind, operation_id, target_origin, deadline) -> Reservation: ...
    def dispatch(self, reservation, transport_call) -> ResponseCapture: ...
    def finish(self, reservation, *, outcome, elapsed_ms, response_bytes) -> None: ...
    def cancel(self, *, reason) -> None: ...
    def snapshot(self) -> BudgetLedger: ...
```

`kind` ist eine geschlossene Auswahl: `application`, `identity_control`, `object_control`, `negative_control`, `pdp`, `setup`, `state_probe`, `replay`, `reduction`, `cleanup`. Für eine Anfrage gilt genau eine primäre Zählkategorie, zusätzliche Tags erhöhen den Zähler nicht doppelt.

1. Beim Planen werden Gesamtrequests, maximale Dauer, Parallelität, erlaubte Origins und eine Cleanup-Reserve angezeigt. Ein Plan mit nicht finanzierbarer Control-/Cleanup-Hülle ist ungültig.
2. `reserve` prüft unter einem gemeinsamen Lock: Lauf offen; Deadline nicht überschritten; Origin/Rolle zulässig; Gesamtbudget und Cleanup-Reserve verfügbar; parallel offene Slots begrenzt. Die Reservierung erhält eine monotone Sequenz-ID.
3. Vor Netz-I/O wird die Reservierung unwiderruflich als `dispatched` gezählt. Verbindungsfehler zählen als Versuch. Eine noch nicht dispatchte, abgebrochene Reservierung kann freigegeben werden. Nach I/O-Beginn gibt es keine Rückerstattung.
4. OPA-Aufrufe, fehlgeschlagene Versuche, Kontrollen, Setup, unabhängige Reads und Cleanup verbrauchen dasselbe Budget. Automatische Redirects, Proxyübernahme und implizite Retries bleiben aus. Ein ausdrücklich erlaubter Retry benötigt eine neue Reservierung.
5. Ein `pdp`-Request darf ausschliesslich den separat freigegebenen OPA-Origin und dessen Entrypoint verwenden. App-Scope erlaubt keinen PDP-Verkehr und umgekehrt.
6. Normaler Stop verhindert weitere App-/PDP-Dispatches. Bereits gestartete Requests enden innerhalb ihrer Requestdeadline; blockierte DNS-Auflösung bleibt die bestehende Python-/OS-Grenze und wird nicht als hart unterbrechbar beworben. Cleanup nach Stop ist nur zulässig, wenn es im geprüften Plan ausdrücklich freigegeben ist, und nutzt ausschliesslich seine Reserve. Abgebrochener Cleanup bleibt `cleanup_pending`.
7. Assurance-Zyklen und Minimierungsversuche teilen den Kontext. Ein neues Teilcontract erhält keinen frischen Zähler. `dispatched_total <= approved_total` muss auch bei konkurrierenden Workerstarts gelten.

**Preflight ist vollständig offline:** Schema, Dateien, Scope, Credential-Präsenz und Planprüfung erzeugen keine HTTP-Anfrage. Eine optionale PDP-Prüfung ist ein eigener, sichtbar freigegebener Job mit Budget; sie darf nicht beim Öffnen von Inspector oder History erfolgen. Es wird zwischen höchstmöglicher und tatsächlich verbrauchter Requestzahl unterschieden.

### 3.3 Credential-Resolver und Identitätsbindung

Sollservice `credentials.resolve_many(refs, scope, generation)` akzeptiert zunächst `env://NAME` für CLI und `session://opaque-id` für Studio. Keine automatische Browser-/Keychain-Auslese und kein Login-Refresh im Hintergrund. Studio-Eingaben werden nur im serverseitigen Prozessspeicher gehalten, nicht in LocalStorage, History, Export oder URL. Ein Neustart erfordert erneute Eingabe. Die UI zeigt nur Referenz, vorhanden/fehlend, Generation und gebundene Identität.

Sensitive Header, Cookies sowie explizit markierte Query-/Body-Felder werden vor Persistierung redigiert und mit typisierten Referenzen ersetzt. Parser zeigen Fundstellen ohne Werte. Unklare Credential-Positionen führen zu einer zu prüfenden Zuordnung. Der Resolver validiert Header-/Feldtypen und Controlcharacters; Einträge sind origin- und identity-scoped. Ein Request an einen anderen Origin kann dieselbe Referenz nicht verwenden.

Keine exportierten Secret-Hashes: Auch ein Hash kann bei schwachen Werten Information preisgeben. Für Credential-Rotation wird eine lokale zufällige Generation verwendet. Der behauptete Benutzername aus einem Formular ist nur `declared`; `observed` verlangt einen expliziten, gültigen Identity-Control mit festgelegtem Principal-/Tenant-Feld. Rollen und Tenant werden separat attestiert. Ohne diesen Nachweis darf ein fixbezogener Identitätsvergleich nicht als gleichwertig bestätigt werden.

### 3.4 Observations, Capture und Oracles

Die bestehende `response_sha256` bindet den Responsebody, nicht sämtliche HTTP-Header oder eine echte serverseitige Signatur. Neue Header-/Zustandsaussagen brauchen deshalb ein eigenes `ObservationRecord`, das in den signierten Snapshot aufgenommen wird.

Pflichtfelder des Records:

- `plan_digest`, `execution_id`, `case_id`, `attempt_id`, `contract_digest`, `report_root`.
- `request_projection_digest` ohne Credential-Werte; `credential_ref` und Bindungsnachweise.
- `capture_profile`, `body_sha256`, `selected_headers_sha256`, Status, Body-/Header-Vollständigkeit, Inhaltsformat.
- `oracle_id`, `oracle_version`, `rule_digest`, `normalization_digest`, typisierte Eingabereferenzen und Resultat.
- `control_refs`, `controls_valid`, `interpretation`, `limitations` und `verification_level`.

Capture ist bounded. Truncation, ungültiges JSON, doppelte JSON-Keys oder fehlende notwendige Header ergeben `inconclusive`. Überzählige/doppelte Header werden nicht still zusammengeführt. Binärdaten bleiben Capture-Evidence und sind ohne definiertes Profil nicht ausführbar oder fachlich interpretierbar.

Oracles sind reine Funktionen `evaluate(rule, capture, controls, bindings) -> Decision`; kein Netz, kein `eval`, keine freie Skriptsprache. Startumfang: Statusmengen; Pointer vorhanden/abwesend; JSON-Typ; strikt gleich/ungleich; explizite Mengenbeziehungen; exakte zugelassene Headerwerte; Zustandsdifferenz. Freie Regex-Payloads sind für 1.0.5 nicht erforderlich. Zahlen/Booleans und fehlend/null bleiben unterscheidbar.

Normalisierung entfernt nur deklarierte volatile Felder. Schutzmarker, Principal-/Tenant-IDs, Zustandszähler und Oracle-Eingaben sind geschützt. Eine Normalisierung dieser Felder wird bei der Planprüfung abgelehnt.

`verification_level` unterscheidet:

- `captured_inputs_replayed`: Die erforderlichen, freigegebenen Evidencewerte liegen vor; der Offline-Verifier kann die Oracle-Funktion erneut auswerten.
- `evaluation_attested`: Der signierte Lauf enthält Ergebnis und Digests; redigierte oder nicht gespeicherte Rohwerte verhindern unabhängige Neuberechnung.
- `integrity_only`: Nur Inventar und kryptografische Bindungen wurden geprüft.

Keine dieser Stufen beweist allein, dass eine entfernte Anwendung die Antwort wirklich geliefert hat. Die Signatur belegt den signierenden Schlüssel und unveränderte Paketbytes. Synthetic-Lab-Demos sollen `captured_inputs_replayed` erreichen, weil keine echten Kundengeheimnisse gespeichert werden müssen.

### 3.5 Findings und fachlicher Status

| Dimension | Werte | Bedeutung |
|---|---|---|
| Experimentauswertung | `violation`, `satisfied`, `inconclusive`, `not_run` | Gilt nur unter dokumentierten Controls und Scope |
| Findingzustand | `candidate`, `confirmed`, `rejected`, `retest_pending`, `retest_verified` | Kein bestätigter Befund allein aus Statuscode oder Fremdimport |
| Vergleichsabdeckung | `retested`, `not_retested`, `not_comparable` | Ungeprüfte Fälle behalten ausschliesslich historische Beobachtungen |
| Fixbewertung | `violation_persists`, `fix_verified`, `testability_restored`, `inconclusive`, `not_comparable` | Fehler→Pass ist keine automatische Schwachstellenbehebung |
| Schwere | CVSS-Vektor/Score oder `not_scored` | Technische Schwere, unabhängig von Beweisqualität |
| Kundenrisiko | Begründung und Reviewer | Kontextbezogene Wirkung; keine automatische Ableitung aus CVSS |

`fix_verified` verlangt ursprüngliche bestätigte Verletzung, unveränderte fachliche Regel und Prüfgegenstand, kompatible Oracle-Semantik, gültige frische Kontrollen sowie aktuellen Nachweis, dass die Verletzung im geprüften Fall nicht mehr besteht. Erwartungsänderung oder neues Identitätsbinding ist eine fachliche Änderung, kein Fixnachweis unter unveränderten Voraussetzungen. Die generische v1-Diffkategorie `resolved` darf nicht ohne diese Prüfung übernommen werden.

## 4. F05 — Quellgebundener, versionsbewusster Teilvergleich

### Bereits implementiertes Entwicklungsinkrement

`authzledger/comparison.py` enthält zwei öffentliche Funktionen:

```python
create_comparison(source_contract, baseline_report, current_report, selected_ids=None) -> dict
verify_comparison(envelope) -> list[str]
```

`selected_ids=None` wählt alle Quellfälle. Es erfolgt kein Netz-/Credentialzugriff. Die Hülle bettet unveränderte Quellobjekte ein und verwendet `kind: comparison-envelope`, `schema_version: 1`, `canonicalization: json-sort-keys-ascii-escaped-v1`. Pflichtgruppen sind `source_contract`, `baseline_report`, `current_report`, `selected_ids`, `dependency_ids`, `profiles`, `bindings`, `policy`, `transitions`, `coverage`, `summary`, `limitations` und `comparison_sha256`. Ihr Digest ist SHA-256 über `AuthzLedger:comparison-envelope:v1\n` plus kanonisches Hüllen-JSON ohne Digestfeld.

Die Transitionzustände lauten exakt `regression`, `resolved_check`, `testability_restored`, `testability_lost`, `inconclusive`, `unchanged`, `not_retested`. **`resolved_check` bestätigt einen wieder bestandenen konfigurierten Check, keinen behobenen Sicherheitsbefund.** Aktuelle Runtime-Identität, deployte Policy, Ownership ausserhalb der Assertions und vertrauenswürdige zeitliche Reihenfolge werden ausdrücklich nicht attestiert. Policyvergleich trägt `not_compared`. Die Formatprofile für 1.0.0 und 1.0.5 registrieren v1-Report-/Checksemantik; sie zertifizieren keine unbekannte ausführbare Datei aufgrund ihres Versionsstrings.

Die tatsächlich implementierten CLI-Aufrufe lauten:

```sh
authzledger compare-retest SOURCE.json BASELINE.json CURRENT.json --case CASE_ID --out NEW_DIRECTORY
authzledger verify-comparison NEW_DIRECTORY/comparison.json
authzledger bundle CURRENT.json --key PRIVATE.pem --comparison NEW_DIRECTORY/comparison.json --out NEW_BUNDLE
```

Die grossgeschriebenen Werte sind Platzhalter für vorhandene eigene Artefakte. Mehrere `--case` wählen mehrere IDs; Voraussetzungen werden automatisch ergänzt. `compare-retest` erzeugt `comparison.json` und `comparison.html` in einem neuen Verzeichnis. Exitcode 2 bedeutet unklare/verlorene Testbarkeit, 1 Regression, 0 sonst; Eingabe-/Verifikationsfehler werden ebenfalls als Fehler ausgegeben. Exitcode 0 bescheinigt weder umfassende Sicherheit noch einen fachlichen Fix.

Studio besitzt `/api/retest/plan` mit expliziter Auswahl und Closure, an den Retest gebundene einmalige Reviewfreigaben, `/api/comparison`, `/api/comparison/verify` sowie optionale `comparison_envelope`-Bindung in `/api/proof`. CLI/Studio verwenden denselben Comparison-Kern. Vergleichshüllen stehen im Jobergebnis und Export; sie werden in diesem Inkrement **nicht zusätzlich als eigenes Objekt in der History-Datenbank persistiert**. Sie lassen sich aus den gespeicherten Originalquellen offline wieder aufbauen. Das signierte Paket bindet die reservierten Attachments `comparison.json` und `comparison.html`.

Die aktuelle Regression-/Browserverifikation ist im Testprotokoll des Entwicklungsinkrements zu belegen. Die nachstehende vollständige F05-Testmatrix enthält zusätzlich spätere P0-Integrationsgates und darf nicht insgesamt als bereits bestanden markiert werden.

### Implementierung zuerst

Der neue Vergleich arbeitet vollständig offline. Input: verifizierter Vollbaseline-Report, exakter Quellcontract, aktueller Teilreport, ausgewählte IDs und ein ausdrücklich zugelassenes Semantikprofil. Der reduzierte Contract wird aus der Auswahl und ihrer transitiven Control-Closure rekonstruiert. Ein mitgelieferter Teilcontract muss exakt dazu passen. Alte v1-Reports und deren Root-Digests werden nicht neu versiegelt oder auf eine andere Toolversion umgeschrieben.

Vor Klassifikation werden beide Reports vollständig mit `verify_report` geprüft. Beide werden gegen ihre tatsächlichen Contractfälle gebunden: IDs, Identität, Methode, Pfad, Controltyp, `requires`, Checktypen und zulässige Ergebnisstruktur. Ein gültiger Hash allein beweist nicht die behauptete Semantik.

Die Hülle enthält mindestens Originalroots, Source-Digest, Teilcontract-Digest, explizite Auswahl, zusätzlich erforderliche Controls, getestete/nicht erneut getestete IDs, Profilidentität und pro Fall Vorher-/Nachherstatus plus Klassifikation. Der Verifier berechnet die Hülle aus ihren Quellen erneut; eine selbstkonsistent umgehashte Lüge muss weiterhin scheitern.

Kompatibilität ist eine explizite, getestete Tabelle von Tool-/Report-/Oracle-Semantikpaaren. Keine Regel „alle 1.x kompatibel“. Unbekanntes Profil ist `not_comparable` bzw. Ablehnung, niemals stiller Fallback. Ein gültiger v1-Teilvergleich bestätigt lediglich konfigurierte Checks; neue fachliche Fixaussagen setzen zusätzlich das Finding-/Observation-Modell voraus.

**Zusätzliche P0-Arbeit nach dem ersten Vergleichsinkrement:** unabhängige Identitäts-/Fixture-Bindung, Policy-/Oracle-/Normalizer-Drift, Coverageereignisse für hinzugefügte/entfernte Regeln und direkte Studio-Anbindung. Die bestehende Vergleichshülle muss diese erweiterten Aussagen entweder prüfen können oder ausdrücklich nicht unterstützen.

### Abnahme- und Testmatrix F05

| ID | Test | Erwartung |
|---|---|---|
| F05-01 | 100 Baselinefälle; sieben gewählt, drei ausschliessliche Voraussetzungen | Exakt zehn aktuelle Fallresultate; 90 `not_retested`; keine Gesamtfreigabe |
| F05-02 | Baseline 1.0.0, Teilreport aus ausdrücklich zugelassenem Semantikprofil | Vergleich möglich; beide Eingabeobjekte und Roots unverändert |
| F05-03 | Transitive Voraussetzung fehlt oder fremder Fall eingeschoben | Ablehnung vor Klassifikation |
| F05-04 | Gleiche IDs, anderer Pfad/Identity/Oracle/Controltyp | Keine Vergleichbarkeit durch blosse ID-Gleichheit |
| F05-05 | Source-Digest oder Originalroot falsch; Hülle anschliessend korrekt neu gehasht | Semantischer Verifier lehnt ab |
| F05-06 | Unbekannte Toolversion oder Profil | Explizite Nichtvergleichbarkeit; keine pauschale Versionsfreigabe |
| F05-07 | Baseline-Transportfehler, aktueller Pass | Testbarkeit wiederhergestellt; kein bestätigter Fix |
| F05-08 | Voraussetzung fehlgeschlagen; abhängiger Fall nicht gesendet | `inconclusive`; Requestzähler belegt fehlenden Dispatch |
| F05-09 | Credentials rotiert, Principal-/Tenant-Bindung fehlt | Neuer Lauf möglich, fachlicher Fixvergleich unbestätigt |
| F05-10 | Normative Regel geändert statt Anwendung repariert | `not_comparable`/Regeländerung, kein Fix unter alter Regel |
| F05-11 | Manipulierte Checkstruktur oder widersprüchliche Summary bei gültigem JSON | Bericht-/Contractbindung scheitert |
| F05-12 | Comparison als Attachment plus fehlende/falsche Quellen | Hauptverifier lehnt semantische Prüfung ab; kryptografische Stufe nicht überverkaufen |

Die Tests für Identitätsattestierung, neue Oracles und Regeländerungen sind Integrationsgates der vollständigen P0-Vertikale, keine Behauptung, dass das erste Codeinkrement diese zukünftigen Daten schon besitzt.

## 5. F01 — Offline-Import, sichere Zuordnung, tiefe Werkzeugübergabe

Sollmodule `imports.py` mit separaten Parserfunktionen und `assessments.py`. Zum Start drei gepinnte Eingabeprofile: Burp HTTP-message XML mit base64/raw Nachrichten, ZAP Traditional JSON **with requests and responses**, HAR 1.2. Nicht jeder beliebige ZAP-Report enthält ausführbare Requests. Fremdbefunde ohne vollständige Nachricht bleiben externe Referenzen.

`parse_import(raw_bytes, format_profile, limits) -> ImportBatch` ist rein und offline. Default: 10 MiB Gesamtdatei, maximal 500 Einträge, 1 MiB je decodiertem Body, JSON-Tiefe 64 und höchstens 100 Header pro Nachricht. Decodegrenzen gelten zusätzlich zur codierten Eingabegrenze. DTD/Entities, XML-Expansion, externe Schemas, URL-Nachladen, Archive und verschachtelte Multipart-Parser sind nicht zulässig. Die Runtime erhält keine Parser-Option, mit der externe Entities aktiviert werden können.

`map_import(batch, identity_bindings, resource_bindings, scope, rule) -> AssessmentRevision` erstellt zunächst eine Vorschau. Es extrahiert den Origin, lässt aber keinen importierten Host die explizite Scopefreigabe ersetzen. Sensitive Daten werden vor Speicherung redigiert. Nur unterstützte HTTP-/JSON-Nachrichten werden nach Contract v1 kompiliert. Doppelte Header, ambiguous framing, nicht unterstütztes Encoding, Binärbody und verloren gegangene Queryreihenfolge sind sichtbare `execution_blockers`. Solche Nachrichten bleiben als Quelle auswählbar; es gibt keine stille „Reparatur“.

Die Mapping-UI fragt genau nach den für den Nachweis nötigen Bindungen: Testidentität, Ressource/Owner/Tenant, Schutzmarker, Regel, Controls und Targetscope. Vorhandene Bindungen können wiederverwendet werden; jeder Import behält seinen eindeutigen Source-Verweis. Rollen werden nicht aus Tokenstrings geraten.

| ID | Test | Erwartung |
|---|---|---|
| F01-01 | Je ein versioniertes reales Burp-, ZAP- und HAR-Fixture | Methode, Origin, Pfad, Body, Header und Herkunft nachvollziehbar |
| F01-02 | HTTP-Client/DNS während Import durch Fail-fast-Stub ersetzt | Import löst null Netzwerkaufrufe aus |
| F01-03 | DTD/XXE, Entitybomb, tiefe JSON-Struktur und Base64-Übergrösse | Begrenzter Abbruch ohne externe Reads oder Resourceexhaustion |
| F01-04 | Unvollständige Request-/Response-Nachricht | Sichtbare Lücke; keine erfundene Response oder bestätigtes Finding |
| F01-05 | Token in Header, Cookie, Query, JSON-Feld und Fehlertext | Keine Werte in Logs, History, Export oder Browserpersistenz |
| F01-06 | Doppelte Header/Querynamen oder Raw-HTTP-Sonderfall | Reihenfolge bleibt erhalten oder Ausführung explizit blockiert |
| F01-07 | Script-/HTML-Payload als Name oder Body | Studio und Report rendern als Text, nie als aktives Markup |
| F01-08 | ZAP-Fremdfinding mit hohem Risiko, ohne eigenen Test | `source_assertion`; keine automatische AuthzLedger-Bestätigung |
| F01-09 | Wiederholter Import identischer Datei | Stabile normalisierte Source-/Casezuordnung; keine Duplikatfindings |
| F01-10 | Quelle enthält anderen Origin als freigegebener Scope | Offline sichtbar; ausgehender Request verweigert |

## 6. F02 — Contrast Lab: eine explizite Hypothese, kontrollierte Varianten

Sollmodule `experiments.py`, `observations.py`, `oracles.py`. Bestehende v1-Checks werden für abbildbare Regeln weiterverwendet. Zusätzliche fachliche Oracles erzeugen Sidecars und keine inkompatiblen Felder im v1-Report.

`compile_experiment(assessment_revision, rule, variant_selection) -> ExperimentPlan` übernimmt ausschliesslich explizite Werte für Identity, Tenant, Objekt, Aktion, freigegebene Route, Query oder JSON-Feld. Default ist genau eine veränderte Dimension. Mehrdimensionale Varianten werden vollständig aufgelistet und vor Ausführung ausgewählt; keine versteckte kartesische Expansion. Default höchstens 24 Varianten, zusätzlich Gesamtrequestlimit. Stable-IDs ergeben sich aus normalisiertem Regel-/Varianteninhalt, nicht aus Arraypositionen.

Beispielregel: `forbid_field_equal(/protected_marker, marker_for_object_A)` für Actor B beim Lesen von Objekt A. Owner-Read belegt Objekt und Marker; Identity-Controls binden A und B; eine bekannte Negativkontrolle bestätigt die erwartete Denial-Semantik. Alle Aussagen verweisen auf die jeweils nötigen Kontrollen.

Der Evaluator trennt `status_deviation` von der eigentlichen Verletzung. Ein 200-Fehlerobjekt ohne geschützte Daten ist kein BOLA-Beweis. Ein 403 mit dem **konkreten geschützten Marker** kann `denial_data_disclosure` bestätigen. Ein beliebiges Feld namens `secret` oder eine grössere Antwort allein reicht nicht. Bei allgemeiner Statusabweichung ohne fachlichen Beleg bleibt ein überprüfbarer Kandidat statt bestätigtem Impact.

Rezepte sind versionierte Versuchsvorlagen: BOLA/IDOR; Tenantisolation; funktionsbezogener Rollenwechsel; Property-Level Read/Write; Leakage in Denials; Rechteentzug; kontrollierter Cache-Isolationstest. Ursache und Beobachtung sind getrennt: ein fremder Marker belegt Leakage, nicht automatisch einen Cachefehler.

| ID | Test | Erwartung |
|---|---|---|
| F02-01 | Gleicher Input mit unterschiedlicher Dictionaryreihenfolge | Identischer Plan-Digest und identische Fall-IDs |
| F02-02 | 200 + Fehlerobjekt ohne Objekt-/Tenantmarker | Kein bestätigtes BOLA; nachvollziehbarer Oracle-Ausgang |
| F02-03 | 403 + exakt geschützter Marker; alle Kontrollen gültig | Bestätigte Denial-Datenpreisgabe mit Captureprovenienz |
| F02-04 | Derselbe Leak, Identity- oder Owner-Control ungültig | `inconclusive`; ungültige Voraussetzung prominent |
| F02-05 | Token B stammt tatsächlich von A | Bindung schlägt fehl; kein vermeintlicher Cross-Tenant-Befund |
| F02-06 | Marker fehlt wegen Truncation/Parsefehler | Keine behauptete Abwesenheit; `inconclusive` |
| F02-07 | Normalizer soll geschützten Marker entfernen | Plan wird abgelehnt |
| F02-08 | Verborgene mehrdimensionale Expansion würde Limit überschreiten | Plan nicht ausführbar; exakte Requestobergrenze sichtbar |
| F02-09 | 16 parallele Starts, nur drei verbleibende Budgetplätze, OPA aktiv | Höchstens drei neue Dispatches insgesamt, inklusive PDP |
| F02-10 | App-/PDP-Timeout, 302-Redirect, komprimierte unerlaubte Response | Präziser unklarer/error-Zustand; keine stillen Folgezugriffe |
| F02-11 | Header-Oracle gegen fehlende/mehrfache Header | Definierte typisierte Auswertung; kein stiller Join |
| F02-12 | CLI und Studio führen denselben Plan aus | Gleiche fachliche Outputs nach Herausnahme laufabhängiger Metadaten |

## 7. F03 — Workflow Contracts: Zustandsfehler und Replay beweisen

Sollmodul `workflows.py`. Höchstens zwölf logische Schritte pro Variante, acht explizit gewählte Varianten, sequenziell. Jeder Versuch erhält ein frisches Testobjekt oder einen unabhängig bestätigten Reset. Ein HTTP-Erfolg ist kein Nachweis einer fachlichen Zustandsänderung.

Ein `WorkflowPlan` enthält `precondition`, `setup`, geordnete `steps`, `postcondition`, `cleanup`, `fixture_isolation` und typisierte Bindungen. Jeder Step referenziert eine bereits freigegebene Operation und eine bestimmte Identität. Varianten: einen freigegebenen Schritt auslassen; Identität an einem bestimmten Übergang wechseln; einen ausdrücklich zugelassenen Schritt wiederholen. Keine willkürliche Graph-/Exploitkettenplanung.

`extract(capture, selector, expected_type) -> BoundValue` akzeptiert nur JSON-Pointer und einzelne freigegebene Responseheader. `BoundValue` enthält Source-Step, Observation-Digest, Selector, Typ, Sensitivität und Value-/Commitment-Referenz. Fehlend ist nicht null; Integer ist nicht Bool. Erlaubte Zielpositionen sind deklarierte JSON-Felder, Querywerte, einzelne codierte Pfadsegmente oder freigegebene Header. Werte dürfen niemals Scheme, Host, Port oder freie URL bestimmen. Eine nach Bindung entstehende Route wird erneut gegen Scope und Mutationfreigabe geprüft.

Die Engine materialisiert normalisierte v1-Teilcontracts. `WorkflowTrace` verbindet Plan, BoundValues, materialisierte Digests, Reportroots und Ausführungsreihenfolge. Dynamische Objektwerte ändern den Ausführungsnachweis, nicht den abstrakten Plan. Mutierende Schritte benötigen eine konkrete Freigabe; HTTP GET allein beweist keine Harmlosigkeit.

Für Idempotenz gilt: Vorzustand `(operation_id, effect_count)`, erster Abschluss, expliziter zweiter Abschluss mit definiertem Idempotency-Key, unabhängiger Read von `effect_count`. Nur ein verbotener weiterer fachlicher Effekt erfüllt die Verletzung. Zwei 200-Antworten reichen nicht.

| ID | Test | Erwartung |
|---|---|---|
| F03-01 | Sichere Fixture: Create → Skip approval → Complete → Read | Abschluss verhindert; kein Finding |
| F03-02 | Verletzliche Fixture, gleiche Variante | Vorzustand und verbotener Nachzustand belegen bestätigte Verletzung |
| F03-03 | Gleicher Request zweimal erfolgreich, Effektzähler bleibt einmalig | Kein Idempotenz-Finding |
| F03-04 | Effektzähler erhöht sich beim zweiten Abschluss erneut | Replayverletzung bestätigt, sofern Control-/Fixturebindung gültig |
| F03-05 | Fehlender Pointer, falscher Typ, null statt ID oder duplizierter JSON-Key | Abhängige Schritte nicht dispatchen; `inconclusive` |
| F03-06 | Extraktion liefert fremde URL oder Pfadsegment mit Slash/Traversal | Keine Originerweiterung; sichere codierte Position oder Ablehnung |
| F03-07 | Reset fehlgeschlagen oder Fixture bereits benutzt | Folgevariante gestoppt; kein vermischter Nachweis |
| F03-08 | Budget vor Mutation reicht nicht mehr für notwendige Nachprüfung und Cleanup | Mutation wird nicht begonnen |
| F03-09 | Stop nach bereits gesendeter Mutation | Ausgeführte Wirkung und offene Cleanup-Arbeit sichtbar; kein Rollbackversprechen |
| F03-10 | Alle zwölf Schritte plus maximale acht Varianten | Bounded Trace, korrektes Gesamtbudget und stabile Reihenfolge |

## 8. F04 — Minimal Reproducer: reproduzierte Reduktion statt plausibler Kürzung

Sollmodul `minimize.py`. Input ist ein bestätigtes Finding mit stabiler Fixture und exakt benanntem Interestingness-Oracle. Entfernt werden nur freigegebene Header, Query-Vorkommen und JSON-Felder. Die Einheiten werden stabil adressiert: Headername + Vorkommen, Queryname + Vorkommen, JSON-Pointer. Authentifizierung, Identitybinding, Host, Schutzmarker, Controls und notwendiger Setup-/State-Probe sind geschützt. 1.0.5 minimiert keine beliebigen Workflow-Schritte.

`minimize(finding, plan, removable_units, context) -> ReductionTrace` verwendet eine deterministische ddmin-artige Teilmengenreduktion und abschliessend Einzelentfernung. Jeder Kandidat läuft mit frischen gültigen Controls und geeigneter Fixture; bei Mutation ist F03-Isolation Voraussetzung. Mehrere Versuche dürfen kein überlebendes Zwischenzustandsobjekt teilen.

Interestingness ist tri-state:

- `reproduced`: dieselbe verletzte Regel, dasselbe beabsichtigte Subject-/Resourcebinding, gleicher Oracle-Fingerprint und gültige Controls.
- `not_reproduced`: gültige Kontrollen, der fachliche Verstoss tritt in diesem Versuch nicht auf.
- `inconclusive`: Kontrollen, Fixture, Transport, Extraktion oder Budget erlauben keine Aussage.

Nur `reproduced` darf den akzeptierten Kandidaten ersetzen. `inconclusive` ist kein negativer Beleg. Default Zusatzbudget: höchstens 40 Requests einschliesslich aller erneuten Controls/Setup/PDP, begrenzt durch das verbleibende Gesamtbudget. Bei Budgetende bleiben Original, letzte bestätigte Reduktion und Stopgrund verfügbar.

`1_minimal: true` ist nur zulässig, wenn jede verbleibende einzeln entfernbare Einheit am finalen Kandidaten vollständig und konklusiv geprüft wurde und jede Entfernung `not_reproduced` ergab. Es bedeutet nicht global kürzester Request. Bei Flakiness oder unbekanntem Ausgangszustand ist die Minimalität nicht bestätigt. Der Export zeigt „reduziert, Minimalität nicht bestätigt“, soweit dieses Gate nicht erfüllt ist.

| ID | Test | Erwartung |
|---|---|---|
| F04-01 | Deterministischer Request mit drei irrelevanten und zwei nötigen Feldern | Irrelevante Felder entfallen; gleiche Verletzung erneut belegt |
| F04-02 | Kontrollausfall erst nach Entfernen eines Feldes | Kandidat nicht akzeptiert; `inconclusive` |
| F04-03 | Reduktion erzeugt anderen Bug/anderen Schutzmarker | Interestingness nicht erfüllt |
| F04-04 | Budget reicht nur für Teilreduktion | Letzte bestätigte Variante; `1_minimal: false`; exakter Stopgrund |
| F04-05 | Abschliessende Einzelentfernungsprüfung unvollständig | Kein 1-Minimalitätsanspruch |
| F04-06 | Doppelte Querynamen und verschachtelte JSON-Felder | Exakt gewähltes Vorkommen entfernt; keine semantische Umsortierung |
| F04-07 | Entfernbare Auswahl umfasst Credential oder Controlbindung | Plan abgelehnt |
| F04-08 | Originalfinding und Originalreport nach Reduktion byteweise verglichen | Identisch; neue Evidence referenziert Originalroot |
| F04-09 | Ein Kandidat reproduziert nur sporadisch | Instabilität sichtbar; keine verlässliche Minimalität behauptet |
| F04-10 | Exportierter Reproducer in frischer Labfixture mit neuen Secrets | Gleicher Plan/gleiche Regel; Credentials ausschliesslich als Referenzen |

## 9. F06 — Studio: ein Arbeitsobjekt von Import bis Proof

Die vorhandene lokale Vanilla-Oberfläche wird schrittweise in `state`, `api`, `views`, `inspector` und `commands` zerlegt. Keine Frontendruntime ist dafür erforderlich. Assets bleiben lokal. Die bestehende Loopbackbindung, Sessiontoken, Host-/Origin-Prüfung, CSP sowie Body-/Workerlimits bleiben erhalten.

### Zustand und gemeinsame Auswahl

Ein zentraler `AssessmentState` hält `assessment_id`, Revision, Scope-Digest, Plan-Digest, Auswahl `{entity_type, stable_id}`, aktiven Job, aktuell angezeigten Snapshot und Inspectorzustand. Matrix, Graph, Findings, History und Retest verwenden dieselbe Auswahl. Eine historische Ansicht ist ein eingefrorener Snapshot; sie löst keine frischen HTTP-/PDP-Requests aus.

Der Server liefert Revisionsnummer und Content-Digest. Schreib-/Plananfragen müssen die erwartete Revision angeben; Konflikt ergibt HTTP 409 mit der neuen Revision. Veraltete Fetchantworten dürfen neuere Revision/Auswahl nicht überschreiben. Ausführung bindet exakt die geprüfte Revision, Scope, Plan, Budgets, Captureprofil und erlaubte Mutationen. Eine beliebige Änderung macht die Freigabe ungültig.

### Durchgängiger Bedienablauf

| Schritt | Hauptansicht und Aktion | Persistenter Inspector | Ergebnis/Gate |
|---|---|---|---|
| 1. Import | Datei oder exportierte Nachricht übernehmen | Quelle, Parserprofil, Datenauslassungen, redigierte Secretpositionen | Ausführbare Operation oder expliziter Blocker |
| 2. Zuordnen | Bestehende Identitäten/Objekte wählen; Regel/Marker definieren | Deklarierte vs. beobachtete Bindungen, Scope | Vollständiges Assessment ohne erfundene Werte |
| 3. Contrast Lab | Rezept/Dimensionen wählen; konkrete Varianten sehen | Oracle, Controls, DAG, Budgetobergrenze | Deterministischer Plan; konkrete Ausführungsfreigabe |
| 4. Ausführen | Ein Job mit sichtbarem Fortschritt/Stop | Dispatch-/Controlstatus, offene Voraussetzungen | Beobachtungen; unklare Fälle bleiben unklar |
| 5. Untersuchen | Matrix oder Graph; Ergebnis wählen | Regel → Binding → Controls → Observation → Interpretation → Grenzen | Bestätigtes Finding oder begründeter Kandidat |
| 6. Reduzieren | Freigegebene Elemente markieren; Budget prüfen | Akzeptierte Kürzungen und je eigene Evidence | Separater Reproducer; Original bleibt erreichbar |
| 7. Retest | Baseline/ausgewählte Findings; Abhängigkeiten ansehen | Auswahlgrund, Closure, Drift, `not_retested` | Vergleichshülle und falls belegbar Fixnachweis |
| 8. Report | Scope, Reviewer, Impact, Standardrefs prüfen | Jede Berichtsaussage führt zu ihren Quellen | Unveränderlicher AssessmentSnapshot; JSON/HTML/PDF |
| 9. Proof | Extern gespeicherten Public-Key-Fingerprint prüfen; Paket erzeugen/verifizieren | Inventar, Signatur, semantische Prüftiefe | Signiertes Paket und explizites Verifikationsergebnis |

Der Inspector beantwortet stets: Welche Regel? Welche Identität/Ressource? Welche Kontrollen? Welche Beobachtung? Was bleibt unklar? Was wurde beim Retest wirklich geprüft? Herkunft und Unsicherheit sind am Ergebnis sichtbar, nicht hinter einem allgemeinen Disclaimer versteckt.

### Tastatur, Jobs und Bedienqualität

`Ctrl/Cmd+K` öffnet eine lokale Befehlspalette für die aktuelle Auswahl: Source öffnen, Experiment planen, Controls anzeigen, Finding öffnen, Reduzierung planen, Retest planen, Report/Proof öffnen. Kein Shortcut löst unbemerkt eine neue Ausführung aus. `Esc` schliesst Dialoge und gibt Fokus zurück; Suchfelder unterdrücken globale Einzeltastenkürzel. Sichtbarer Fokus, semantische Buttons, Screenreaderlabels und Status zusätzlich zu Farbe sind Pflicht.

Die visuelle Umsetzung verwendet die bestehende Navy-/Gold-Marke mit klarer Hierarchie: stabile 48-Pixel-Kontextzeile, kompakte Navigation, Arbeitsbereich und 360-Pixel-Inspector ab ausreichend grosser Breite. Bei engeren Fenstern wird der Inspector als zugängliches Drawer geöffnet; wichtige Aktionen bleiben erreichbar. Ein 4-/8-Pixel-Abstandsraster, konsistente Typografiestufen, zurückhaltende Trennlinien und Statussymbole ergänzen Klartext. Kein Dauerleuchten und keine dekorative Graphanimation. Interaktionsanimationen bleiben kurz und respektieren `prefers-reduced-motion`. Die Komponenten teilen sich CSS-Tokens für Farbe, Fokus, Radius, Abstand und Typografie; neue Ansichten erhalten keine eigenständige Designsprache.

Jobs: `queued → running → cancelling → cancelled|complete|error`. Der Browserzustand `disconnected` ist keine Serverbestätigung. Reconnect fragt denselben Job erneut ab. Neue Initiierung verwendet einen Idempotency-Key, sodass ein Doppelklick keinen zweiten Lauf startet. Stop zeigt die noch laufenden Requests und die vorab freigegebene Cleanup-Regel. Nicht gestartete Fälle erhalten `not_run` im neuen Trace; ein v1-Report bildet dies ohne Schemabruch als `inconclusive` mit Grund ab.

### Soll-API und gemeinsame Services

Die Tabelle beschreibt neue Schnittstellen, keine bereits nutzbaren Endpunkte. Bestehende `/api/run`, `/api/retest`, `/api/proof` bleiben kompatibel; sie werden intern auf gemeinsame Services umgestellt, sobald deren Regressionstests bestanden sind.

| Methode/Pfad | Gemeinsamer Service | Netzwirkung |
|---|---|---|
| `POST /api/v1/assessments/imports` | `parse_import` | Keine |
| `POST /api/v1/assessments` | `create_assessment` | Keine |
| `PATCH /api/v1/assessments/{id}` | `revise_assessment(expected_revision)` | Keine |
| `POST /api/v1/assessments/{id}/plans` | `compile_experiment` / `compile_workflow` | Keine |
| `POST /api/v1/assessments/{id}/runs` | `execute_plan(plan_digest, grant, idempotency_key)` | Nur freigegebener Plan |
| `GET /api/v1/jobs/{id}` | `read_job` | Keine Zielzugriffe |
| `POST /api/v1/jobs/{id}/cancel` | `cancel_job` | Keine neuen Appanfragen; Cleanup nur gemäss Plan |
| `GET /api/v1/assessments/{id}/entities/{entity_id}` | `inspect_entity(snapshot_digest)` | Keine |
| `POST /api/v1/assessments/{id}/reduction-plans` | `plan_reduction` | Keine |
| `POST /api/v1/assessments/{id}/reductions` | `execute_reduction(plan_digest, grant)` | Bounded Requests |
| `POST /api/v1/assessments/{id}/retest-plans` | `plan_retest` | Keine |
| `POST /api/v1/assessments/{id}/comparisons` | `compare_assessment` | Keine |
| `POST /api/v1/assessments/{id}/snapshots` | `freeze_assessment` | Keine |
| `POST /api/v1/assessments/{id}/exports` | `render_assessment(snapshot_digest, formats)` | Keine |
| `POST /api/v1/assessments/{id}/proofs` | `create_assessment_bundle` | Keine |
| `POST /api/v1/proofs/verify` | `verify_assessment_bundle` | Keine |

GET-Endpunkte sind nebenwirkungsfrei. API-Fehler haben stabile Codes, sichere Nachricht und Fieldpfad; keine Roh-Ausnahme mit Token-/Bodyinhalt. Dateien kommen über begrenzten Upload, serverseitig verwaltete IDs oder etablierte Konfiguration, niemals über frei wählbare Lesepfade aus dem Browser. Private Signingkeys werden nicht in die Browser-UI geladen.

Geplante CLI-Gruppe `assessment`: `import`, `plan`, `run`, `inspect`, `minimize`, `retest`, `report`, `bundle`, `verify`. Diese Namen sind bis Implementierung keine ausführbare Anleitung. CLI und API rufen dieselben Services auf. Plan-/Inspect-/Compare-/Verify-Befehle sind offline. Netzwerkaktionen verlangen den exakten geprüften Plan plus explizite Freigabe; Outputpfade werden nicht still überschrieben.

| ID | Test | Erwartung |
|---|---|---|
| F06-01 | Vollständiger Fixture-Ablauf nur mit Tastatur | Import bis Proof erreichbar; Fokus geht nicht verloren |
| F06-02 | Matrixauswahl → Graph → History → Inspector | Gleiche stabile Entität; sichtbare Snapshot-/Zeitbindung |
| F06-03 | Ältere API-Antwort trifft nach neuer Revision ein | Neuer Zustand bleibt erhalten |
| F06-04 | Plan/Scope/Budget nach Freigabe verändert | Ausführung abgelehnt, neue Vorschau erforderlich |
| F06-05 | Netzwerk zum Studio während laufendem Job unterbrochen | `disconnected`, keine falsche Behauptung „beendet“ |
| F06-06 | Doppeltes Startsignal/Reload mit gleichem Idempotency-Key | Ein Job, ein Ledger, keine doppelte Ausführung |
| F06-07 | Stop während Control/Mutation | Keine weiteren ungeplanten Dispatches; Cleanup und offene Arbeit sichtbar |
| F06-08 | Historischer Inspector mit OPA-Konfiguration | Null neue Ziel-/PDP-Requests |
| F06-09 | Markup in importiertem Label/Response | Keine Scriptausführung; CSP bleibt wirksam |
| F06-10 | Secrets, private Keypfade, rohe Exceptions im Job | Nicht in Browserstorage, Historie, URL oder Fehlerantwort |
| F06-11 | 1.000 Fälle auf dokumentierter Referenzhardware; 20 wiederholte lokale Interaktionen | P95 Auswahl-/Filterreaktion ≤ 250 ms; Inputfeedback ≤ 100 ms, ohne laufende Netzzeit; grosse Listen begrenzt rendern |
| F06-12 | Alte Studiofunktionen und CLI-v1-Fixtures | Fachlich unveränderte Resultate; kein erzwungener neuer Workflow |

## 10. F07 — Assessment-Reporting und signiertes Proof-Paket

Sollmodule `assessments.py`, `assessment_reports.py`, Erweiterungen in `signing.py`. `freeze_assessment` erzeugt einen unveränderlichen Snapshot mit Finding- und Evidenceversionen. `render_assessment(snapshot, profile)` gibt HTML, PDF und kanonisches JSON aus demselben Viewmodel aus. Unterschiede dürfen Layout, Sprache und Seitenumbrüche betreffen, nicht Findings, Status, Scope oder Evidence-IDs.

Pflichtinhalt: Executive Summary; Scope/Zeitraum/Limitierungen; Methodik und geprüfte Regeln; Coverage einschliesslich `not_retested`; Findings mit Erwartung/Beobachtung/Voraussetzungen/Reproduktion/Impact/Massnahme; Controls; Reteststatus; Original-/aktueller Evidencebezug; Signerfingerprint und Anweisung zur unabhängigen Prüfung. Technische Schwere, Beweisqualität und Kundenrisiko bleiben getrennte Felder.

Standards werden als **gepinntes Zuordnungsprofil** geführt: ASVS 5.0.0, WSTG 4.2, API Security Top 10 2023, CVSS 4.0. Ein Mapping enthält Standard-ID, Version, Bezugstyp `supports|partially_covers|related`, Begründung und konkrete Evidence. Anforderungen werden nur dann als geprüft dargestellt, wenn der konkrete Test sie abdeckt. Kein pauschales ASVS-Zertifikat aus einzelnen Authorizationtests. CVSS verwendet nachvollziehbaren Vektor und validierte Metriken; kein KI-generierter Score ohne belegte Auswahl. Der Versionskatalog und offizielle Definitionen werden während Implementierung geprüft und lokal gepinnt; Quellenlinks stehen am Ende.

HTML bleibt self-contained und escaped, ohne entfernte Assets. PDF wird lokal aus demselben Viewmodel mit ReportLab als separat paketiertem Reports-Extra erzeugt. Die getestete Version, Paket-Hashes, eingebetteten Unicode-Fonts und deren Lizenzen werden im Implementierungslock festgehalten. Layoutparameter, Metadaten und Zeitwerte stammen aus dem Snapshot, damit dieselben Inputs reproduzierbar rendern. Der CLI-Kern bleibt dependency-arm; ein fehlender PDF-Renderer ist ein sichtbarer Exportblocker, kein stiller HTML-Ersatz. Die erste Rendererprüfung deckt Fonts, Unicode, lange URLs und Druckumbruch ab. Für den 1.0.5-Abnahmestand muss PDF in der dokumentierten Installation funktionieren.

### Paketbau ohne Selbstreferenz

1. Alle Originalreports, Contracts, Observation-/Finding-/Comparison-Dateien und der AssessmentSnapshot stehen fest.
2. JSON/HTML/PDF werden erzeugt. Berichte referenzieren Snapshot-ID und Evidence-Digests; sie enthalten **nicht** ihren zukünftigen eigenen Datei- oder Manifest-Digest.
3. Ein Attachmentindex benennt die vorhandenen Dateien, ohne sich selbst zu hashen. Das bestehende Bundlemanifest inventarisiert alle Payloadbytes einschliesslich der drei Berichtsdateien und des Attachmentindex.
4. Das Manifest wird kanonisiert und signiert. `manifest.json` und `signature.base64` werden nicht in ihr eigenes Inhaltsinventar aufgenommen.
5. Der Hauptverifier prüft Inventar/Signatur, Originalreportsemantik, Quelle-Teilcontractbindung, Observation-/Control-/Finding-Referenzen, Snapshotkonsistenz und zulässige Reteststatus.
6. Der Standalone-Verifier prüft Signatur und Inventar gegen einen **extern vertrauten** Public Key. Wenn er neue Assessmentsemantik nicht implementiert, lautet die Prüfstufe ausdrücklich `integrity_only`; ein im Paket liegender Schlüssel allein ist kein Vertrauensanker.

Originale Evidence wird nie überschrieben. Ein korrigierter Bericht erhält eine neue Snapshotversion und ein neues Paket. Eine nachträgliche PDF-Annotation ändert die signierten Bytes und muss die Integritätsprüfung scheitern lassen.

| ID | Test | Erwartung |
|---|---|---|
| F07-01 | Dasselbe Snapshot-Viewmodel in JSON, HTML, PDF | Identische sortierte Finding-IDs, Status, CVSS-Vektoren und Evidence-Refs |
| F07-02 | Manipulierte PDF-/HTML-Datei nach Signatur | Standalone-Integritätsprüfung schlägt fehl |
| F07-03 | Signiertes, aber fachlich falsches Findingattachment | Hauptverifier lehnt ab; Signatur allein genügt nicht |
| F07-04 | Finding referenziert fremden Case-/Reportroot | Unauflösbare oder widersprüchliche Provenienz wird abgelehnt |
| F07-05 | Explizit nur drei ASVS-Anforderungen teilweise geprüft | Teilcoverage und Lücken sichtbar, keine globale Konformitätsbehauptung |
| F07-06 | Ungültiger CVSS-4-Vektor oder widersprüchlicher Score | Kein Export als validierter Score |
| F07-07 | Lange Findingtitel, Unicode, 50 Findings und lange URLs | Keine abgeschnittenen Inhalte; Seiten visuell geprüft |
| F07-08 | Fremdes HTML und lokale/remote URLs im Responsebody | Statischer Text; Renderer greift keine fremden Ressourcen ab |
| F07-09 | Paketkey ausgetauscht, Signature formal passend | Prüfung mit extern vertrautem Schlüssel scheitert |
| F07-10 | Redaction verhindert Re-Oracle-Auswertung | Prüftiefe `evaluation_attested`, keine falsche unabhängige Neuberechnung |
| F07-11 | Report manifestiert sich selbst oder circular Evidence-Referenz | Schema-/Paketprüfung lehnt zyklische Digestdefinition ab |
| F07-12 | Alte Evidence-v1-Pakete | Weiterhin mit ihrer bisherigen Prüftiefe verifizierbar |

## 11. F08 — Erklärbare Graphänderungen und begrenzte Assurance

Die Ebenen Intent, Policyentscheidung und Beobachtung bleiben getrennt. Neue Graphnebenknoten repräsentieren Regel, Experiment, Kontrolle, Observation, Finding und Retest; die v1-Graphstruktur wird nicht still umgedeutet. Der Inspector zeigt die Kantenkette bis zum Originalnachweis. Eine geschlossene Beweiskette wird nicht mit tatsächlicher Produktionsvollständigkeit verwechselt.

Ein `ChangeSet` bindet alte/neue Digests von Regel, Case, Identitybinding, Fixture, Policy, Oracle, Normalizer und expliziter Impactzuordnung. `plan_impacted_retest` bildet zunächst die betroffenen Knoten, dann die transitiv abhängigen Tests, anschliessend die vollständige prerequisite-Closure. Jede Aufnahme erhält `reason_code` und `source_refs`, etwa `changed_rule`, `changed_policy_binding`, `dependent_on_changed_fixture`, `required_control`.

Nicht zuordenbare Änderung führt standardmässig zum Volltest des vereinbarten Scopes. Falls das Budget ihn nicht erlaubt, wird der Auftrag blockiert oder nach erneuter, sichtbarer Begrenzung als eingeschränkter Test ausgeführt. Er wird nicht automatisch auf eine beliebige grüne Teilmenge verkleinert. Eine Git-Dateiänderung ohne explizite Impactabbildung ist keine zuverlässige Authorization-Abhängigkeit.

Assurance bleibt endlich: explizite Zyklenzahl, Intervall, Höchstdauer und gemeinsames Requestbudget. Jeder Zyklus prüft aktuelle Credential-/Fixturegültigkeit; Historyintegritätsfehler, Scope-Drift, Kontrollfehler oder Stop halten betroffene Arbeit an. Ein alter Pass wird in der UI als „historisch, am … beobachtet“ angezeigt, niemals als aktueller Pass.

| ID | Test | Erwartung |
|---|---|---|
| F08-01 | Bekannte Regeländerung mit expliziten Abhängigkeiten | Alle modelliert betroffenen Tests plus Controls gewählt |
| F08-02 | Unbekannte Änderung/fehlende Impactzuordnung | Volltestvorschlag mit Begründung, kein Vollständigkeitsversprechen für Teilmenge |
| F08-03 | Graphvorschlag enthält falsche/zyklische Kante | Schema-/Provenienzprüfung verhindert Ausgabe als gültiger Plan |
| F08-04 | Policyentscheidung ändert sich, Intent bleibt gleich | Policy-Drift getrennt von beobachteter Regression |
| F08-05 | 90 ungeprüfte Kanten bei zehnfacher Teilprüfung | 90 `not_retested` mit historischem Datum |
| F08-06 | Assurance erreicht globales Budget zwischen zwei Zyklen | Kein Budgetreset, kein weiterer Dispatch |
| F08-07 | Manipulierte History oder veraltete Fixturebindung | Fail-closed; kein aktueller Assurance-Pass |
| F08-08 | Derselbe ChangeSet und Scope | Deterministische Auswahl und Erklärung |
| F08-09 | Volltest und selektiver Test auf modellierten Impactfixtures | Gleiche Befunde für betroffene modellierte Beziehungen |
| F08-10 | Daten-/Codeabhängigkeit ausserhalb des Modells | Begrenzung explizit; keine garantierte globale Impactanalyse |

## 12. Drei Demonstrationen als überprüfbare Beweise

Diese Demonstrationen sind Abnahmeszenarien, noch keine vorhandenen zusätzlichen CLI-Befehle. Sie laufen auf einer isolierten lokalen Fixture mit synthetischen Daten und drei fest eingebauten Modi: `vulnerable`, `fixed`, `invalid_controls`. Der Serverseed, Profile, Eingaben und erwarteten Outputs werden mitgeliefert. Eine reale Zeitmessung beginnt erst nach implementiertem, dokumentiertem Setup.

### Demo A: Burp → Finding → reduzierter Reproducer

**Frage:** Wie schnell wird aus einer manuellen Entdeckung ein Nachweis, den ein Entwickler ohne erneutes Zusammensuchen reproduzieren kann?

1. Einen echten Burp-XML-Export eines Tenant-A-Invoice-Requests importieren; die UI zeigt den Quellenhash und redigierte Credentialpositionen.
2. Vorbereitete Testidentitäten A/B auswählen, Objekt A und synthetischen Marker binden; BOLA-Rezept mit drei Kontrollen und einer Cross-Tenant-Variante ansehen.
3. `vulnerable` ausführen. Inspector zeigt: A/Objekt-Control gültig, B-Identity-Control gültig, Negativkontrolle gültig, B erhält Marker A. Ein bestätigtes Finding entsteht.
4. Zwei irrelevante Queryfelder und ein optionaler Header für Reduktion freigeben. Jede angenommene Entfernung besitzt ihren eigenen reproduzierten Oraclebeleg.
5. Reproducer in frischer Fixture ausführen; Originalfinding bleibt identisch. Bericht und signiertes Paket erstellen.

**Sollartefakte:** redigierte Importsource, ExperimentPlan, zwei Identitätsbindungen, originale und reduzierte Reports/Observations, ReductionTrace, Finding, AssessmentSnapshot, HTML/PDF/JSON und signiertes Inventar. **Beweis für Mehrwert:** eine durchgängige Auswahl und wiederverwendbare Bindungen; Anzahl manueller Bearbeitungsschritte und Requests werden gemessen. „1-minimal“ nur bei abgeschlossenem Gate.

### Demo B: 403-Leakage und ehrliche Control-Validität

1. Dieselbe Regel gegen `vulnerable` ausführen: Status 403, Body enthält Marker A. Gültige Controls erlauben `denial_data_disclosure`.
2. Gegen `fixed` ausführen: weiterhin 403, der Marker fehlt; bei frischen Controls ist die Regel in diesem Versuch erfüllt.
3. Mit abgelaufener B-Session oder fehlendem Ownerobjekt wiederholen: UI zeigt `inconclusive`, ungültige Kontrolle und keinen behaupteten Fix.
4. Gegen einen 200-Fehlerobjektfall prüfen: keine geschützten Inhalte, daher kein bestätigtes BOLA aus dem Statuscode allein.

**Solloutput:** drei klar getrennte fachliche Ausgänge plus 200-Gegenbeispiel; jede Aussage führt zu Regel, Kontrollen, Marker und Capture. **Beweis für Mehrwert:** Ein komplexer Denialfall wird korrekt bewertet, und unzureichende Versuchsbedingungen werden zuverlässig erkennbar. Eine reduzierte Fehlerquote darf erst nach dem Fixturevergleich behauptet werden.

### Demo C: kleiner Retest, ehrliche Coverage, unabhängiges Paket

1. Vollbaseline mit 100 Fällen erstellen; sieben fachlich relevante Fälle auswählen. Ihre Vereinigung benötigt genau drei zusätzliche, nicht bereits gewählte Controls.
2. Gegen die reparierte lokale Fixture exakt zehn Cases erneut ausführen. Die Oberfläche zeigt zehn aktuelle Fallresultate und 90 `not_retested` samt historischen Zeiten.
3. Originalbaseline, Teilreport, Quellcontract, Selection/Closure und ComparisonEnvelope exportieren; Originalroots bleiben unverändert.
4. Assessmentberichte erstellen und inventarisiert signieren. Standalone-Verifier in einer separaten lokalen Umgebung mit separat bereitgestelltem Public Key ausführen; Prüftiefe sichtbar anzeigen.
5. Ein Byte in der PDF ändern: Signatur-/Inventarprüfung muss scheitern. Vergleichshülle mit weggelassener Voraussetzung neu hashen/signieren: fachliche Prüfung muss unabhängig davon scheitern.

**Beweis für Mehrwert:** 90 Prozent weniger **App-Testfälle** in dieser konstruierten Fixture; zusätzliche PDP-, Setup- oder Kontrollrequests werden separat vollständig gezählt. Dies ist kein allgemeiner Kundeneffizienzclaim. Die Demonstration zeigt gleichzeitig korrekte Einsparung, Grenzen und Manipulationserkennung.

### Messung und öffentliche Darstellung

Jede Demo veröffentlicht Fixtureversion, Commit, Seed, Requestledger, geprüfte Ergebnisse und bekannte Grenzen. Videos folgen dem tatsächlichen UI-Ablauf; Wartezeitkürzungen werden gekennzeichnet. Keine gefälschten Konsolenausgaben und keine unimplementierten Buttons als fertige Funktion präsentieren.

Primäre Metriken: aktive Operatorzeit; Zahl manueller Dateneingaben/-wechsel; vollständige Requests nach Kategorie; Zeit bis zum bestätigten Finding; Zeit bis zur Entwicklerreproduktion; korrekte Klassifikation sicher/verletzt/unklar; Verifikationsfehler bei Mutationsfixtures. Pilotziel: maximal zehn Minuten bis zum ersten Lab-Finding und mindestens 50 Prozent weniger manuelle Bearbeitungsschritte gegenüber einer dokumentierten manuellen Baseline. **Unverifizierte Ziele, keine bisher gemessenen Ergebnisse.**

## 13. Sofort ausführbare Implementierungsfolge

### Inkrement A: ComparisonEnvelope zuerst

1. v1-Goldenreports unverändert als Fixtures sichern; Vollbaseline/Teilretestfehler reproduzieren.
2. Neuen Vergleich mit strikter Quellenbindung, dependency-Closure und explizitem Semantikprofil implementieren. `compare_reports` nicht aufweichen.
3. Offline-Verifier implementieren, der aus Originalquellen neu berechnet. F05-01 bis F05-08 und F05-11 abdecken, soweit auf v1-Ebene darstellbar.
4. CLI und signierte Attachmentbindung ergänzen; Tests gegen falsche Roots/Quellen und selbstkonsistent manipulierte Hülle.
5. Bestehende Gesamtsuite, gezielte Negativtests, Packaging und CLI-Smoke ausführen. Das Ergebnis ist ein überprüfbares erstes Inkrement, noch kein gesamtes 1.0.5.

### Inkrement B: P0-Datenkern und sichere Ausführung

1. `AssessmentSpec`, `ImportSource`, `ExperimentPlan`, `ObservationRecord` und `FindingRecord` strikt definieren; Freeze nur nach Testfixtures.
2. ExecutionContext und Resolver in den bestehenden App-/PDP-Pfad integrieren. Zuerst globales Budget/Cancel/Secret-Tests, dann neue fachliche Oracles.
3. Burp-Import als ersten kompletten Pfad erstellen; danach ZAP/HAR gegen reale Profile. Unsupported-Fälle bleiben explizit blockiert.
4. Contrast-Rezept BOLA/Tenantisolation und Denial-Leak implementieren. Sichere, verletzliche und unklare Fixture laufen durch denselben Service.

### Inkrement C: P0 vollständig durch Studio und Reporting

1. Studiozustand/Inspector parallel gegen eingefrorene Servicefixtures bauen; erst danach an echte Dienste anschliessen.
2. Planfreigabe, Idempotency-Key, Revisionen und Job-Reconnect mit negativem Browserflow abnehmen.
3. AssessmentSnapshot, HTML/JSON und gepinnte PDF-Erzeugung implementieren. Report-/Evidencegleichheit und Paketbindung prüfen.
4. Vergleichsdienst als Retestpfad integrieren. Frische Identity-/Fixture-Bindung sowie Regel-/Oracle-Drift als fachliche Gates ergänzen.
5. **P0-Auslieferungsgate:** F01/F02/F05/F06/F07 komplett; Import → kontrolliertes Finding → Inspector → Retest → drei Reports → verifiziertes Proof-Paket in CLI und Studio.

### Inkrement D: vollständige 1.0.5-Pflichtfähigkeiten

1. Typisierte Extraktion und isolierte Workflowfixture, dann Freigabe-/Replayrezepte.
2. Minimierer mit tri-state Interestingness, akzeptierter Beweiskette und striktem Minimalitätsgate.
3. Erklärbarer ChangeSet-/Retestplaner und gemeinsame Assurancebudgets.
4. Alle drei Demos reproduzierbar durchführen; gemessene Zeit-/Requestwerte statt Zielwerte dokumentieren.
5. Upgrade-/Rollbackprobe, Offlineinstallation, Browserabnahme und Releasepakete prüfen. Erst danach Versionsmetadaten/Changelog/Release veröffentlichen.

### Arbeitspakete ohne Blockierketten

| Verantwortungsbereich | Startauftrag | Freigabe für nächste Arbeit |
|---|---|---|
| Core | A: Vergleich + Negativfixtures | Quellenbindung/Compatibilityprofil stabil |
| Integration | B: Parserprofile + rote/sichere/unklare Fixtures | Offlineimport und Secretredaction geprüft |
| Execution | Gemeinsamer Budget-/Cancel-/Observation-Pfad | Keine ungezählten Requests, v1-Regression grün |
| Studio | Gemeinsamer Zustand und Inspector gegen Fixtures | Echte P0-Services und Revisionsvertrag vorhanden |
| Reporting/QA | Snapshot-/Viewmodelcontract, Renderer-Spike, Testmatrix | Finden/Retest/Proof konsistent |

Bei nur einer Engineeringkapazität bleibt dieselbe Reihenfolge bestehen; nicht fünf Parallelprojekte eröffnen. Harte Blockaden: unbekannter Semantikvergleich, unbudgetierter Transport, Secretleck, falscher Fixstatus, verlorene Controlabhängigkeit oder nicht prüfbare Berichtsaussage. Kosmetik blockiert diese Korrekturen nicht.

## 14. Releasegates und Nachweisführung

Jeder Testfall erhält im Implementierungs-PR eine Zuordnung `Test-ID → Testfunktion → Fixture → Ergebnisartefakt`. Eine neue Fähigkeit ist erst fertig, wenn Loader, Service, CLI, Studio, Evidence und Negativfälle denselben Zustand tragen. Die bereits vorhandenen 233 Tests sind eine Baseline, keine Aussage über den heutigen Arbeitsbaum; aktuelle Ergebnisse stehen im jeweiligen Testprotokoll.

- **G1 Integrität:** Golden-v1-Artefakte unverändert lesbar; keine verlorene Signatur-/Historykompatibilität.
- **G2 Vergleich:** Ganze/partielle Baselines, ungültige Controls, Versionspaare, falsche Quellen und `not_retested` geprüft.
- **G3 Ausführung:** Alle Requestarten budgetiert; Cancel-/Concurrent-start-Rennen; Scope-/Redirect-/Proxygrenzen erhalten.
- **G4 Secrets/Capture:** Tokenfixtures finden keine Secrets in Export/History/Logs; Redaktionsgrenzen und Prüftiefe korrekt.
- **G5 Fachlichkeit:** Sichere, verletzliche und unklare Oracles; keine Statuscode-only-BOLA; kein error→pass-Fix.
- **G6 Studio:** Tastatur, Fokus, Reconnect, Planrevision, Inspector und vollständiger P0-Ablauf bestanden.
- **G7 Reports/Proof:** HTML/PDF/JSON gleichwertig; PDF gerendert geprüft; manipulierte Dateien und semantisch falsche Attachments abgelehnt.
- **G8 P1:** Workflowisolation, Replayeffekt, Minimierungsbelege und begrenzte Assurance vollständig.
- **G9 Distribution:** Dokumentierte Installation, Offlineverifikation, vorhandene CLI/Studio-Flows, upgrade/rollback und Lizenzhinweise geprüft.

Ergebnisse werden als `planned`, `in_progress`, `blocked` oder `verified` geführt. Ein Test, der nur einen Mock bestätigt, belegt keine echte Browser-/Transportintegration. Nach ausreichend konkreter Verifikation wird nicht durch zusätzliche redundante Tests verzögert.

Die gewünschte Produktnummer 1.0.5 bleibt der Auftrag. Da neue öffentliche Fähigkeiten hinzukommen, darf der Release nicht pauschal als strikt SemVer-konformes reines Patchupdate beworben werden. Inkompatible Änderungen werden nicht versteckt; das v1-Fundament bleibt unverändert nutzbar.

## 15. Primärquellen für gepinnte Implementierungsprofile

Diese Links dienen der Implementierung und Katalogpflege. Sie begründen keine behauptete Produktzertifizierung oder vollständige Testabdeckung.

- OWASP ASVS: <https://owasp.org/www-project-application-security-verification-standard/> — Profilversion 5.0.0.
- OWASP WSTG: <https://owasp.org/www-project-web-security-testing-guide/v42/> — Profilversion 4.2.
- OWASP API Security Top 10: <https://owasp.org/API-Security/editions/2023/en/0x00-header/> — Edition 2023.
- FIRST CVSS: <https://www.first.org/cvss/v4.0/specification-document> — Version 4.0.
- PortSwigger Burp HTTP messages: <https://portswigger.net/burp/documentation/desktop/tools/message-editor> — Parserfixtures aus echten Exporten pinnen.
- ZAP Traditional JSON with Requests and Responses: <https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json-plus/> — genau dieses Exportprofil.
- HAR 1.2, ursprünglicher Spezifikationsautor: <https://www.softwareishard.com/blog/har-12-spec/> — gepinntes 1.2-Format; nur unterstützte Felder ausführen.

Alle externen Formatdetails werden vor Adapterfreigabe gegen die jeweilige offizielle Dokumentation und reale Exportfixtures geprüft. Abweichende Varianten erhalten ein neues Parserprofil oder einen sichtbaren Blocker.
