# AuthzLedger 1.6.0 – öffentlicher Prüfstand

Diese Belege gelten für den [Quellcommit bb34603](https://github.com/0xFarag/0xFarag/commit/bb34603a99ba96b6fb23ae9f09d332b335a98b3d). Der Git-Tree lautet `aedd13378b49dfc651e4771c5d8b0ba836147eb1`. Der stabile öffentliche Stand ist [v1.5.0](https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0). Für 1.6.0 ist das Release-Gate offen.

| Prüfung auf bb34603 | Ergebnis |
|---|---|
| Historische Python-Tests | 523 von 682 bestanden, 159 ausstehend |
| Neue Python-Tests | 51 von 51 bestanden |
| Historische Browsersuiten | 1 von 8 bestanden, 7 ausstehend |
| Neue Browsersuiten | 2 von 2 bestanden |
| Zusätzliche Vertrags- und Verifierprüfungen | 34 von 34 bestanden |
| Wheel ausserhalb des Checkouts | Zwei byteidentische Builds, 45 ausgewählte Tests der Installation bestanden |

Die 45 am installierten Wheel ausgeführten Tests überschneiden sich mit der Quellprüfung. Die [GitHub-Actions-Quellprüfung](https://github.com/0xFarag/0xFarag/actions/runs/44828742578) deckt Offline-Import, Belegverträge und die reproduzierbare Demo D ab.

| Beleg | Inhalt |
|---|---|
| [Abnahmestand](gate-status.json) | Alle 18 Kriterien, technische Nachweise und formelle Freigabe. 12 sind technisch belegt, 5 teilweise und 1 offen. Formell attestiert sind 0. |
| [Demos A–D](demos.json) | A prüft archivierte Controls offline. B bindet native Headerbeobachtung, HAR und passiven ZAP-Export. C weist einen geprüften Fix und ein offenes Retest-Element aus. Beide Package-Verifier erkennen eine Ein-Byte-Änderung. D erhält Quellenherkunft und Evidence-Level der drei Importprofile. |
| [Regression](regression.json) | Getrennte Zähler für frühere und neue Tests, Auslassungen und historische Referenz |
| [Distribution](distribution.json) | Wheel-Digest, Installationsprüfung und Bytevergleich historischer Fixtures und Belege |
| [Adapterprofile](adapter-formats.json) | Herkunft und Grenzen der ausgewählten Nmap-, ffuf- und Nuclei-Beispiele |
| [Speicherprüfung](storage.json) | Parallelstart, Rollback, Wiederholung und Markerprüfung |
| [GitHub Actions](github-actions.json) | Provider-Ergebnisse der drei Workflow-Läufe auf dem Zielcommit |

Die Demos verwenden Testdaten. Eine erfolgreiche Demo-Paketsignatur bestätigt das Inventar unter dem jeweiligen Demo-Schlüssel. Die Freigabe durch den Release-Inhaber sowie der vollständige historische Regressionslauf am Zielcommit stehen aus.

[Bezahlter Pilot für Teams und Consultancies](PILOT.md)
