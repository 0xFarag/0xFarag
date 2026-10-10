# AuthzLedger 1.1.0 — Verifikation des Entwicklungsstands

Stand: 10. Oktober 2026. **Aktueller Producer: `1.1.0.dev0`. Kein produktionsreifer 1.1.0-Release erklärt.** Dieses Protokoll hält ausgeführte Prüfungen und verbleibende Freigaben auseinander. Die Produktionsveröffentlichung bleibt gesperrt; ein Entwicklungsbranch beziehungsweise Draft-PR ersetzt dieses Gate nicht.

## Ausgangspunkt und unveränderte Originale

| Bezug | Commit / Bedeutung |
|---|---|
| Stabiles Release `v1.0.0` | `c0d4446a17ca15fb4e8a71f20f6b02c1a364e90c` |
| Nachfolgende Rechtehinweise auf `authzledger-v1.0.0` | `9113c5720230e51606000359b010f867c4a23db7` |
| ComparisonEnvelope-Entwicklungsstand und unmittelbarer Elterncommit dieser Arbeit | `a794c6581a603d1ca54972f0cc2edbeee95284d2` |
| Endgültiger geprüfter Entwicklungscommit / Tree | Commit dieses Protokolls; das geprüfte Codeinventar liegt in `evidence/1.1.0-dev0/source-inventory.json`. Git-Commit und Tree werden zusätzlich im Draft-PR und dessen CI verankert. |

Die Entwicklung erfolgt auf dem bestehenden v1-Contract-/Report-/Graph-/Signaturfundament. Originale Reports behalten ihre tatsächliche Toolversion und Evidence-Roots. Vergleichshüllen binden beide Quellen; sie versiegeln frühere Reports nicht neu. Dieses Entwicklungsprotokoll erklärt keine Änderung oder Ersetzung des stabilen Tags und seiner Artefakte.

Explizit registriert sind die Reportprofile `1.0.0`, `1.0.5`, `1.1.0` und `1.1.0.dev0`. Diese Einträge beschreiben geprüfte v1-Formatsemantik, keine pauschale Freigabe weiterer Versionen und keinen Nachweis, dass ein behaupteter Versionsstring eine bestimmte ausführbare Datei identifiziert. `1.1.0.dev1`, `1.1.1` und fremde Toolnamen sind nicht automatisch kompatibel.

## Abnahmestand

**87 der 88 Vertragsszenarien sind verifiziert. F01-01 ist teilweise verifiziert und bleibt das Releasegate.** Alle Zeilen, konkreten Testnamen und Nachweisgrenzen stehen im [Abnahmeledger](acceptance-1.1.0.md).

Der echte HAR-Nachweis ist abgeschlossen: Playwright **1.64.0** schrieb mit Chromium **153.0.8010.0** einen unveränderten HAR aus zwei tatsächlichen lokalen HTTP-Requests. Originaldatei und Producerbeleg liegen unter `fixtures/imports/chromium-real.har` und `fixtures/imports/chromium-real.provenance.json`. SHA-256 der bewusst öffentlichen, credentialfreien Fixture:

`6024bbad4bfdae631ec115389765f4c7470e1adcf77547e1b48ee1e0922311ba`

Das ist ein Playwright-HAR und kein manueller DevTools-Export. Burp und ZAP sind bislang anhand synthetischer Formatfixtures geprüft. Echte Exporte mit installierter Toolversion fehlen. DTD-haltige Burp-XML-Dateien werden weiterhin ausdrücklich blockiert; eine sicher kompatible Exportprozedur ist noch nicht abgenommen. Ein selbst geschriebenes XML darf diese Lücke nicht verdecken.

**Einziger noch offener fachlicher Freigabeschritt:** Aus installierten, dokumentierten Burp-/ZAP-Versionen je einen echten Export der öffentlichen Loopback-Fixture erzeugen, unverändert mit Herkunftsbeleg aufnehmen und durch Import, Mapping und kontrollierten Lauf prüfen. Dabei die DTD-Unvereinbarkeit mit einem ausdrücklich überprüften Export-/Parserprofil lösen; Schutz vor externen Entities oder stiller Requeständerung nicht abschalten. Erst danach kann F01-01 vollständig als verifiziert gelten.

## Ausgeführte Nachweise

| Prüfung | Tatsächliches Ergebnis | Beleg |
|---|---|---|
| Neue Studio-HTTP-Integration | 18 Tests bestanden: gemeinsame Services, Kontrollgültigkeit, Review-/Credentialbindung, Idempotenz, Cancel, offline Inspector, Retest, Bericht/Proof und Assurance | `tests/test_studio_assessments.py` |
| Assessment-CLI | Acht Vertikaltests bestanden; Offlineplanung, exakter Freigabedigest, reale Ausführung/Reduktion/Retest/Reporting, Mehrzyklus-Assurance mit dauerhaftem History-Reopen und Exitcodes | `tests/test_assessment_cli.py` |
| Kombinierte Workflow-Assurance | 15 Tests bestanden; echte Mehrzyklusläufe, globale Budgets, frische Fixtures, korrupte/veraltete History, Stop und Wiederöffnung einer dateibasierten History | `tests/test_workflow_assurance.py` |
| Assessment-Reporting | 27 Tests bestanden; Snapshot-/Finding-/Vergleichsbindung, Rendererparität, manipulierte und neu signierte falsche Artefakte, Assurance-Pakete | `tests/test_assessment_reports.py` |
| Bestehender vollständiger Intelligence-Workflow | Erfolgreich: drei Graphebenen, Policy, Diff, Evidence, Signatur, Standalone-Prüfung, History, Retest und Fault-Corpus | `artifacts/release110-check/acceptance.json` |
| Alle automatisierten Tests des endgültigen Entwicklungsstands | **492 Tests bestanden, keine Fehler oder übersprungenen Tests; 82,435 Sekunden, CPython 3.12.14 / Linux x86_64.** | Finaler Root-Lauf |
| Finales Wheel nach sämtlichen Änderungen | Finales Wheel ausserhalb des Checkouts installiert: drei Demos, zwei Assurance-Zyklen mit History-Reopen, JSON/HTML/PDF und beide Paketverifier bestanden. | Finaler Root-Lauf |

Der finale Gesamtlauf steht in `artifacts/unit-110-final.log`; sein Hash und die Laufumgebung sind in `evidence/1.1.0-dev0/unit-tests.json` fixiert. `evidence/1.1.0-dev0/installed-wheel.json` bindet den tatsächlich installierten Wheel-Hash und die erfolgreich ausgeführten Prüfungen. Die zusätzliche Security-Suite enthält 14 Tests, darunter Credential-Reflection bis SQLite, History und Report.

## Sechs bestandene Browser-Suiten

| Suite | Beobachteter Ablauf | Receipt |
|---|---|---|
| `tests/browser_acceptance.cjs` | Bestehende Matrix, acht Szenarien, Controls, Baseline, Filter und Exporte; 390-Pixel-Ansicht | `artifacts/browser/acceptance.json` |
| `tests/browser_v1.cjs` | Drei Graphebenen, separate Policy-/Intent-Drift, History, Erklärung, signierter Graph-/Report-Export | `artifacts/browser-v1/acceptance.json` |
| `tests/browser_comparison.cjs` | Geschlossener Teilretest, laufender Pollingabbruch, Wiederaufnahme desselben Jobs, `not_retested`, unabhängig geprüftes Paket | `artifacts/browser-comparison/acceptance.json` |
| `tests/browser_assessments.cjs` | Import bis signiertem Proof vollständig über Tab/Enter/Space und Texteingabe; Inspector-/Historykontext, Minimal Reproducer, Retest, Workflow, endliche Assurance, veraltete Preview und Reconnect eines tatsächlich laufenden Jobs | `artifacts/browser-assessments/acceptance.json` |
| `tests/browser_assessment_security.cjs` | Feindlicher Import/Titel/Response ohne XSS; acht Secret-Canaries gegen APIs, DOM, History-SQLite/WAL, Exporte, Logs, Storage und URLs geprüft | `artifacts/browser-assessment-security/acceptance.json` |
| `tests/browser_retest_freshness.cjs` | Reale 100-Fall-Baseline, zehn aktuelle Fälle, 90 ausgelassene Fälle mit historischen Zeitangaben und unverändertem Baseline-Root | `artifacts/browser-retest-freshness/acceptance.json` |

Alle Receipts melden bestanden und keine JavaScript-Seitenfehler. Beim Tastaturtest wird ausschliesslich die native Dateiauswahl durch eine offengelegte Fixture-Injektion ersetzt; der Produktablauf verwendet keine geskripteten Klicks oder Fokuswechsel. Beim blockierten laufenden `/me`-Control zeigt der Reconnect genau einen Job und insgesamt vier Requests.

Die gemessene Oberfläche verarbeitet 1.000 Fälle mit begrenzter Darstellung von 100 Zeilen. Nach 20 Interaktionen: P95 Auswahl/Filter **19,7 ms**, Inputfeedback **2,1 ms**, ohne Netzzeit. Referenz: HeadlessChrome 153, Linux x86_64, neun logische CPUs. Quelle: `artifacts/browser-assessments/performance.json`. Das ist eine Messung dieser Umgebung, keine allgemeine Leistungsgarantie.

## Reproduzierbare Demonstrationen und Zähler

Die drei Assessment-Demonstrationen erzeugten zusammen **35 echte Loopback-Requests**:

- Import → bestätigtes Finding → Reproducer: drei ausdrücklich freigegebene unnötige Einheiten entfernt, zwölf Reduktionsrequests, `1-minimal within approved units`.
- Geschützter Marker trotz 403 → `denial_data_disclosure`; ungültige Controls → `inconclusive`; 200-Fehlerobjekt ohne Schutzinhalt → `rejected`.
- Fünf Baselinefälle → vier ausgewählte Fälle samt Controls; ein Finding erhält `fix_verified`, das ausgelassene Finding bleibt `not_retested`. HTML, PDF und JSON sind im signierten Paket gebunden. Der temporäre private Schlüssel wird entfernt.

Beleg: `artifacts/assessment110-final/results.json`; kompakte Kopie: `evidence/1.1.0-dev0/assessment-demos.json`. Diese kleine Demo ist vom nachfolgenden 100-Fall-Nachweis zu unterscheiden. Die importierte Burp-Formatdatei ist ausdrücklich synthetisch; sie schliesst das echte Exportergate nicht.

Die separate Workflow-Demonstration erzeugte **41 Requests**. Sie zeigt ausgelassene Freigabe, sichere Gegenprobe, Replay über unabhängig gelesenen Effektzähler, ungültige Controls ohne Setup sowie mutierende Reduktion mit frischer Fixture. Die Reduktion benötigt zwölf Requests; alle Testobjekte werden bereinigt. Nach Abschalten des Fixture-Servers werden Trace und Reduktion erneut offline geprüft. Beleg: `artifacts/workflow110-final/acceptance.json`, kompakte Kopie `evidence/1.1.0-dev0/workflow-demo.json`.

Der grosse Retestnachweis besteht separat: **100 → zehn aktuelle Fälle + 90 `not_retested`**. Der Service-Test deckt sieben gewählte Fälle plus drei Controls ab; die Browserfixture verwendet eine Auswahl plus neun Voraussetzungen und prüft die Darstellung aller historischen Fälle. Ihre Coverage ist nicht als gleiche Auswahlgeometrie ausgegeben.

Der im Browserreceipt dokumentierte Original- und Vergleichs-Baseline-Root ist identisch:

`cb01c5078bafc5771fc49edff162c333464abe122560bfdfefc342abf45704b0`

Baselinezeit: `2026-10-10T14:39:17.861Z`; aktuelle Zeit: `2026-10-10T14:39:18.493Z`. Diese lokalen Reportzeiten sind keine vertrauenswürdige externe Zeitattestierung. Die 90 Prozent weniger App-Testfälle gelten für diese konstruierte Fixture; zusätzliche Requestkategorien werden vollständig gezählt. Ein allgemeiner Kundeneffizienz- oder Zeitgewinnclaim wird daraus nicht abgeleitet.

## PDF- und Assurance-Nachweise

| Artefakt | Ausgeführte Prüfung | SHA-256 |
|---|---|---|
| `artifacts/report-qa/fifty-findings.pdf` | 50 Findings, lange Unicode-Titel und URLs; 72 A4-Seiten gerendert und in vier Kontaktbögen visuell geprüft; alle IDs/Evidence-Refs extrahiert; Snapshot gültig und PDF bytegleich erneut gerendert | `58d25d8b0d808e5046bce0f725bdc7518f8450b4a7046680c2984406c867c8fc` |
| `artifacts/report-qa/assurance.pdf` | Echter Lauf mit zwei Zyklen und zwölf Requests; fünf Seiten visuell geprüft; Snapshot gültig und PDF bytegleich erneut gerendert | `216b746f7ee70f3918957f66de6af8ec95e2f3b741f57451a9394c8c518eaccc` |

Receipts: `artifacts/report-qa/receipt.json` und `artifacts/report-qa/assurance-receipt.json`. Rendererprofil: ReportLab **4.4.9**, eingebettete DejaVu-Fonts **2.37**. Das [Reportingprofil](reporting-profile-1.1.0.md) dokumentiert Versionen, Lizenzen, Standards und Prüftiefe.

Der Workflow-Assurance-Service verlangt einen expliziten `HistoryStore`. Dauerhafte, dateibasiert konfigurierte History ist nach Schliessen und Wiederöffnen geprüft. Studio ohne konfigurierte `--history` verwendet hingegen ausdrücklich **session-only** History. Reconnect innerhalb eines laufenden Studio-Prozesses belegt keine Persistenz über dessen Neustart. Snapshots und unabhängig verwahrte Proof-Pakete sind separate Artefakte.

## Vertrauensgrenzen

- Ed25519 und Dateiinventar belegen unveränderte Paketbytes relativ zu einem **separat vertrauten** Public Key. Ein selbst mitgelieferter Schlüssel identifiziert nicht automatisch den Autor.
- Der Standalone-Verifier prüft Signatur, Inventar, Hashes und Reportanker. Der Hauptverifier ergänzt die jeweiligen Contract-, Vergleichs-, Finding-, Snapshot-, Trace- und Rendererprüfungen. Keine Stufe beweist allein die Wahrheit einer entfernten Ausführung.
- `captured_inputs_replayed` erlaubt die erneute reine Oracleauswertung über ausgewählte Werte. Die Projektion aus dem nicht gespeicherten Rohbody bleibt laufseitig attestiert. `evaluation_attested` enthält keine unabhängige Rekonstruktion redigierter Werte.
- Ungültige Controls verhindern bestätigte Findings. Eine unklare Baseline wird bei später entdecktem Leak nicht als erwiesene Regression umgedeutet. `resolved_check`, wiederhergestellte Testbarkeit und fachlich gebundener `fix_verified` bleiben getrennt.
- Bekannte reflektierte Laufzeit-Credentials werden entfernt und machen betroffene Oraclebeobachtungen unklar. Beliebige unbekannte Strings können nicht allein durch Mustererkennung garantiert als Geheimnis erkannt werden; `safe_values` ist nur für ausdrücklich freigegebene öffentliche Evidencewerte vorgesehen.
- Standardszuordnungen sind versionierte, evidenzgebundene Teilzuordnungen. ASVS-, WSTG- oder API-Top-10-Referenzen sind kein Konformitätszertifikat. CVSS-Vektoren werden geprüft; ein nicht berechneter beziehungsweise nicht bewerteter Score bleibt `not_scored`.

## Erneut ausführbare Prüfungen

Alle Ausgabeverzeichnisse müssen neu sein. Die Demonstrationen verwenden ausschliesslich eigene synthetische Loopback-Ziele.

```sh
python3 -m pip install '.[reports]' 'pypdf==6.10.0'
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
python3 tools/release_check.py --out artifacts/final-core-check
python3 tools/check_comparison.py --out artifacts/final-comparison-check
python3 tools/check_assessment.py --out artifacts/final-assessment-check
python3 tools/check_workflows110.py --out artifacts/final-workflow-check
```

Nach Installation des dokumentierten Playwright-/Chromium-Testprofils:

```sh
node tests/browser_acceptance.cjs
node tests/browser_v1.cjs
node tests/browser_comparison.cjs
node tests/browser_assessments.cjs
node tests/browser_assessment_security.cjs
node tests/browser_retest_freshness.cjs
```

Paketprüfung nach beendetem Fixture-Server:

```sh
python3 -m authzledger assessment verify artifacts/final-assessment-check/03-selective-retest-proof/snapshot.json
python3 -m authzledger verify-bundle artifacts/final-assessment-check/proof --public-key artifacts/final-assessment-check/trusted-public.pem
python3 -I tools/verify_bundle.py artifacts/final-assessment-check/proof --public-key artifacts/final-assessment-check/trusted-public.pem
```

Für reale Übergaben ersetzt ein unabhängig authentifizierter Public Key den lokal erzeugten Demo-Vertrauensanker. Die CI-Datei `.github/workflows/tests.yml` beschreibt den Wheelbau sowie die Installation und CLI-/Evidenceprüfung ausserhalb des Checkouts; diese definierte Prüfung ist nicht mit einem bereits ausgeführten finalen CI-Lauf gleichzusetzen.

## Finaler lokaler Buildnachweis

| Feld | Status |
|---|---|
| Gesamtzahl Tests / erfolgreich / Fehler / übersprungen | 492 / 492 erfolgreich / 0 Fehler / 0 übersprungen |
| Pythonversion, Betriebssystem, Zeitpunkt, Laufzeit und Log | CPython 3.12.14; Linux x86_64; 2026-10-10T14:50:33Z; 82,435 s; `artifacts/unit-110-final.log` |
| Geprüfter Commit und Tree | Commit dieses Protokolls; geprüftes Codeinventar als separates SHA-256-Verzeichnis, CI bindet den Git-Commit |
| Wheeldatei und SHA-256 | `authzledger-1.1.0.dev0-py3-none-any.whl`; `a5351f857bd1f82bfcbe0514bd1b093b4fbf9a86742bd46552a9bf75d4f44bd9` |
| Externe Installationsumgebung und importierter Modulpfad | Eigenes venv ausserhalb des Repositories; Import aus `installed110-venv/lib/python3.12/site-packages/authzledger`, gebündelte Fonts und Studio-Assets vorhanden |
| Installierte CLI, Demo, Haupt- und Standalone-Verifier | Bestanden: 35 Demo-Requests + zwölf Assurance-Requests, History nach Reopen gültig, alle drei Reportformate, Hauptverifier und Standalone mit `python -I` |
| CI-Lauf / veröffentlichter Entwicklungsstand | Remote-CI folgt auf dem exakten Entwicklungscommit; Ergebnisse werden im Draft-PR geführt. Kein Produktionsrelease. |

`python3 tools/release_gate110.py` muss den aktuellen Entwicklungsstand absichtlich ablehnen: Version `1.1.0.dev0` und unvollständiges Exportergate erfüllen keine Produktionsfreigabe. Erst nach Schliessen von F01-01, einer expliziten Version `1.1.0` und erneut bestandenen Prüfungen auf demselben finalen Commit ist der in [release-1.1.0.md](release-1.1.0.md) beschriebene Releaseablauf freigabefähig.
