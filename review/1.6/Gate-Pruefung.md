# Formale Prüfung eines Release-Dossiers

Der Release-Reviewer prüft mit `check_release_gate.py` die Signatur eines Dossiers, sämtliche deklarierten Datei-Hashes und die vollständige Zuordnung zu S16-01 bis S16-18. Der Prüfer liest lokale Dateien. Er startet als einzigen Unterprozess OpenSSL für die Ed25519-Prüfung. Er führt keine Produkttests aus, interpretiert die Ergebnisse der Rohbelege fachlich nicht und erteilt keine Veröffentlichungsfreigabe.

## Wer die vertrauenswürdigen Eingaben festlegt

Die prüfende Person oder ein geschützter CI-Job legt den erwarteten vollständigen Git-Commit, den öffentlichen Review-Schlüssel, seinen SHA-256-Fingerabdruck und die Version dieses Prüfers unabhängig vom Einreicher fest. Der Zielcommit kommt aus der autorisierten Repository-/CI-Auswahl für den tatsächlichen Kandidaten. Der Schlüssel und sein Fingerabdruck stammen aus einer getrennt verwalteten Trust-Konfiguration. Der Fingerabdruck bezieht sich auf den DER-kodierten SubjectPublicKeyInfo. Das Dossier liefert keines dieser Argumente. In CI müssen die Argumente und der Prüfer aus geschützten Dateien oder Einstellungen des Reviewers kommen. Eine vom Einreicher erzeugte Kommandozeile oder ein von ihm gelieferter Prüfbericht ist kein unabhängiger Nachweis.

Der Prüfer und die neben ihm liegende `release-gate.json` kommen aus dem geprüften Engineering-Kit. Dieser Stand bindet die exakten Vertragsbytes an SHA-256 `19d646e2f8814a107e388205041453cafd255af27b0c8b9dc192fbd9f61db3d8`. Der Kandidat muss von der 1.5.0-Basis abweichen. Ob der extern angegebene Commit im Repository existiert und welcher Build darauf lief, verifiziert der Reviewer anhand der zugehörigen CI- und Repository-Belege. Ein Dossier auf einem für den Einreicher beschreibbaren oder laufend synchronisierten Pfad zunächst in einen gegen Änderungen geschützten Snapshot übernehmen.

## Ausführung

Benötigt werden Python ab 3.10 unter Linux beziehungsweise POSIX mit `dir_fd` und `O_NOFOLLOW` sowie OpenSSL mit Ed25519 und `pkeyutl -rawin`. Unter Windows eignet sich WSL mit einem lokalen Linux-Dateisystem. Die Shell-Variablen in diesem Aufruf müssen zuvor im unabhängigen Review-Kontext belegt sein.

```sh
python3 -I /pfad/zum/engineering-kit/check_release_gate.py /pfad/zum/dossier \
  --expected-commit "$REVIEWED_COMMIT" \
  --trusted-key "$REVIEWER_PUBLIC_KEY_FILE" \
  --key-sha256 "$PINNED_ED25519_SPKI_SHA256"
```

| Ergebnis | Bedeutung |
|---|---|
| Exit 0, `formal_dossier=verified` | 18 vollständige, als bestanden deklarierte Entscheidungsbelege, gültige Signatur, gleiche Version/Commit und geprüfte Dateihashes. |
| Exit 1, `formal_dossier=rejected` | Fehler bei Eingabedaten, Vertrauensanker, Struktur, Version, Commit, Belegen oder Signatur. Das JSON nennt den ersten festgestellten Grund. |
| Exit 2 | Fehlerhafte CLI-Argumente. Argparse erklärt den Aufruf über stderr. |

Das Ergebnis enthält immer `publication_authorized=false`, sofern ein maschinenlesbares Prüfergebnis vorliegt. Auch beim Erfolg bleibt `semantic_validation=not_performed`. Ein inhaltlich falscher, korrekt signierter Prüfbericht kann formal bestehen. Der verantwortliche Reviewer kontrolliert deshalb jedes Kriterium, die Gegenprobe, Testumgebung und Artefaktherkunft sowie die tatsächlichen CI-/Buildbindungen separat.

## Dossiervertrag

Ein von extern vertrauenswürdigem Schlüssel signiertes Attest bindet die **genauen Bytes** der Entscheidungsdatei und der Gate-Spezifikation. `gate-attestation.ed25519` enthält die rohe Ed25519-Signatur der unveränderten UTF-8-Datei `gate-attestation.json` als 64 Bytes. Die Signatur liegt ausserhalb des JSON. Der öffentliche PEM-Schlüssel liegt ausserhalb des Dossiers. Reviewer und Einreicher können über unabhängige Transportwege kommunizieren.

| Datei | Genau erwartete Felder |
|---|---|
| `gate-attestation.json` | `schema="authzledger.gate-attestation/v1"`, `target_release="1.6.0"`, `target_commit`, `contract_sha256`, `decisions_sha256`. |
| `gate-decisions.json` | `schema="authzledger.gate-decisions/v1"`, `target_release`, `target_commit`, `criteria`, `artifacts`. |
| Eine Zeile in `criteria` | `id`, `decision="passed"`, `path`, `sha256`. Die 18 IDs und ihre Belegpfade entsprechen bytegenau dem Feld `evidence_path` des mitgelieferten Gate-Vertrags. |
| Jeder dieser 18 Belege | `schema="authzledger.criterion-receipt/v1"`, `id`, `target_release`, `target_commit`, `positive="passed"`, `negative_control="passed"`, `reviewer`, `environment`, `reproduction` und `artifacts`. Die drei Textfelder sind nichtleere Beschreibungen. Die letzte Liste enthält mindestens einen zugehörigen deklarierten Rohbelegpfad. Die negative Kontrolle hat bestanden, wenn der erwartete Gegenfall tatsächlich erkannt wurde. |
| Eine Zeile im zentralen `artifacts`-Inventar | `path` unter `artifacts/` und `sha256` über die vollständigen ursprünglichen Bytes. Ein Rohartefakt darf für mehrere Kriterien referenziert werden. Sein Pfad wird im Inventar genau einmal deklariert. |

Der Dossierautor legt Testergebnisse, Logfiles und weitere Rohbelege unverändert unter `artifacts/` ab und erfasst pro Kriterium den nachvollziehbaren Prüfkontext. Er schreibt erst die Kriteriumsbelege, dann die Entscheidungen mit Beleg- und Artefakthashes, anschliessend das Attest mit dem Entscheidungen-Hash. Der autorisierte Unterzeichner signiert die exakten Attestbytes über den organisationsüblichen Ed25519-Signaturprozess. Jede spätere Änderung erfordert neue abgeleitete Hashes und eine neue Signatur. Eine private Schlüsseldatei gehört niemals ins Dossier.

Leere Dateien, unbekannte Felder, fehlende oder zusätzliche Dateien, Duplikate, widersprüchliche Commits, fehlgeschlagene oder übersprungene Gegenproben sowie abweichende Gross-/Kleinschreibung bei kollidierenden Pfaden werden zurückgewiesen. Alle Prüfeingänge sind reguläre Dateien. Symbolische Links, Hardlinks, Geräte, Pipes und Pfadausbrüche sind unzulässig. Die Grenzen liegen bei 400 Einträgen einschliesslich Verzeichnissen, 512 MiB pro Dossier, 64 MiB pro Rohbeleg und 512 KiB pro JSON-Steuerdatei. Ein grösserer Rohbeleg kann in dokumentierte Teile innerhalb dieses Inventars unterteilt werden.

## Selbsttest

Im ausgepackten Kit startet der folgende Aufruf die isolierten Schema-, Signatur- und Gegenproben. Das positive Testdossier und seine temporären Schlüssel werden im Test erzeugt und anschliessend entfernt. Die Tests erzeugen kein Attest für AuthzLedger 1.6.0.

```sh
python3 -B -m unittest discover -s . -p test_check_release_gate.py -v
```
