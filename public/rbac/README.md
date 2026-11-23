# AuthzLedger · Kubernetes-RBAC offline prüfen

Die CLI beantwortet für einen gespeicherten Kubernetes-RBAC-Export, welche Rolle und Bindung eine konkrete Anfrage abdecken. Sie liest lokale UTF-8-JSON-Dateien und schreibt ihr Ergebnis als JSON auf die Standardausgabe. Zum Betrieb reichen Node.js ab Version 22 und die drei Dateien `cli.mjs`, `model.mjs` und `retest.mjs` im selben Ordner.

## Eine Berechtigung prüfen

Speichere das folgende Beispiel als `vorher.json`. Es erlaubt der fiktiven Benutzerin Alex über die Rolle `reader` das Lesen von Pods im Namespace `ops`.

```json
[
  {
    "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
    "metadata": {"name":"reader","namespace":"ops"},
    "rules": [{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]
  },
  {
    "apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
    "metadata": {"name":"readers","namespace":"ops"},
    "subjects": [{"kind":"User","apiGroup":"rbac.authorization.k8s.io","name":"alex"}],
    "roleRef": {"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"reader"}
  }
]
```

Diese Prüfanfrage gehört in `frage.json`. Benutzer- und Gruppennamen sind schreibungsabhängig. Ein leerer `apiGroup` bezeichnet die Kubernetes-Core-API.

```json
{"kind":"User","name":"alex","groups":[],"namespace":"ops","verb":"get","apiGroup":"","resource":"pods"}
```

```sh
node cli.mjs check vorher.json frage.json
```

Im Beispiel lautet `result.status` auf `granted_in_snapshot`. Unter `matches` stehen die Rolle, ihre Bindung und die Regelnummer. Ein vollständiger Export ohne entsprechende Regel ergibt `no_grant_in_snapshot`. Fehlende relevante Rollenbelege oder gekennzeichnete Folgeseiten können zu `indeterminate` führen. Das gilt auch für passende namensraumgebundene Regeln, wenn der Ressourcentyp dem Offline-Profil nicht als namensraumgebunden bekannt ist.

## Änderungen nachprüfen

Speichere die Fragen für den Vergleich als Liste in `fragen.json`. Das Beispiel verwendet zwei Fälle.

```json
[
  {"kind":"User","name":"alex","groups":[],"namespace":"ops","verb":"get","apiGroup":"","resource":"pods"},
  {"kind":"User","name":"jordan","groups":[],"namespace":"ops","verb":"get","apiGroup":"","resource":"pods"}
]
```

Erzeuge die Prüfbasis. Lege `nachher.json` für dieses Beispiel als Kopie von `vorher.json` an und ändere in der ersten Rolle `"verbs":["get"]` zu `"verbs":["list"]`. Bewahre `vorher.json` bytegenau auf.

```sh
node cli.mjs baseline vorher.json fragen.json > basis.json
node cli.mjs retest basis.json vorher.json nachher.json 1 > retest.json
```

Fall 1 wechselt von `granted_in_snapshot` zu `no_grant_in_snapshot`. Das Ergebnis lautet `snapshot_decision_changed`. Fall 2 bleibt unter `not_retested` mit seinem ursprünglichen Ergebnis sichtbar. Das Feld `after` bleibt dort `null`, die Coverage ergibt `total: 2`, `retested: 1` und `not_retested: 1`. Für alle Fälle entfällt das letzte Argument. Eine Auswahl wie `1,3` nutzt einsbasierte Fallnummern. `none` wählt keinen Fall aus.

| Status im Retest | Bedeutung |
| --- | --- |
| snapshot_decision_changed | Die Auswertung der beiden Richtliniendateien liefert unterschiedliche Berechtigungsentscheidungen. |
| snapshot_evidence_changed | Die Entscheidung bleibt gleich, ihr konkreter Regel- oder Bindungsnachweis hat sich geändert. |
| snapshot_result_repeated | Die Entscheidung und der erfasste Nachweis stimmen überein. |
| indeterminate | Mindestens eine Entscheidung ist unbestimmt oder der Nachweis für den Vergleich gleicher Entscheidungen ist unvollständig (mehr als 500 Regelverweise). |
| not_retested | Es liegt nur das historische Ergebnis vor. |

Das Flag `identical_source_bytes` zeigt, ob beide Richtliniendateien bytegleich waren. Die CLI berechnet die Ergebnisse der Prüfbasis am Original erneut und prüft dessen SHA-256. Der Export ist als `unsigned` gekennzeichnet. Für einen nachweisbaren Ursprung der Prüfbasis bewahre deren Digest über einen vertrauenswürdigen separaten Kanal auf. Eine selbst erstellte, konsistente Basis belegt keine Urheberschaft.

## Geltungsbereich

- Das Format unterstützt RBAC-v1-Objekte der Typen `Role`, `ClusterRole`, `RoleBinding` und `ClusterRoleBinding`, als Einzelobjekt, JSON-Array oder unterstützte Kubernetes-Liste. Pro Datei gelten 2 MiB, pro Policy bis zu 1’000 Objekte, pro Prüfbasis 1 bis 32 eindeutige Fragen.
- Trage die Gruppen des Subjekts ausdrücklich unter `groups` ein. Für einen ServiceAccount umfasst die Anfrage `kind: "ServiceAccount"`, `name` und `subjectNamespace`. Der abzufragende Ressourcen-Namespace steht unabhängig davon unter `namespace`. Für clusterweite Anfragen ist dieser leer. Bestimme den Scope von API-Ressourcen und CRDs aus der zum Export gehörenden API-Discovery.
- Das Profil wertet Ressourcenanfragen aus. Weitere Authorizer, Admission Controller, tatsächliche Authentifizierung, dynamische Gruppen und eine erfolgreiche Laufzeitanfrage benötigen eigene Belege. Der Export enthält Subjektnamen und gegebenenfalls Namensräume und Ressourcenbezüge. Prüfe diese Angaben vor einer Übergabe.
- Erfolgreiche Auswertungen haben Prozesscode 0, auch bei fehlender Berechtigung oder unbestimmtem Ergebnis. Beschädigte Dateien und ungültige Fallauswahlen führen zu Code 2. Die Shell-Umleitung `>` ersetzt eine bestehende Zieldatei. Verwende neue Ausgabepfade und bewahre die Originale auf.

© Nasser Aldin Farag (0xFarag). All rights reserved.
