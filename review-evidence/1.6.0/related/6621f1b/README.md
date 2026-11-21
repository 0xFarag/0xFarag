# Offline-Prüfung der Scope-Korrektur

Der Korrekturstand aus [PR #5](https://github.com/0xFarag/0xFarag/pull/5) bestand 111 gezielt ausgewählte Regressionstests. Die 416 bereits in Git versionierten Dateien unter `release/` und `evidence/` stimmen Byte für Byte mit dem Stand von v1.5.0 überein. Die im Repository archivierten Source- und Wheel-Pakete der Version 0.3.4 entsprechen zusätzlich dem historischen SHA-256-Manifest.

| Beleg | Stand |
| --- | --- |
| Geprüfter Quellstand | `6621f1b76b3b641ae1f25a195d50cad677d96091` |
| Historische Vergleichsbasis | `03aea857e35358ddeb13d2a861b633e60c1ca873` |
| Geprüfte Eigenschaften | Offline-Import, HTML/JUnit, Abhängigkeiten von Controls, Evidence, lokale Historie, Wissenszuordnung, signierte Übergabe und Vergleichspakete |
| Prüftiefe | 111 bestehende Tests, 18 Aufrufe des eigenständigen Verifiers aus der Auswahl. Jeder Test und jeder historische Dateihash steht in [regression.json](regression.json). |
| Browser | Zwei Prozesse gestartet. Chromium brach vor der ersten Browser-Assertion bei der Socket-Erstellung ab. Der Installationsversuch der vorgesehenen Playwright Headless Shell erhielt HTTP 403. [Browserprotokoll](browsers.json) |
| Releaseentscheidung | Offen. Diese Ergänzung gilt für den bezeichneten Korrekturstand. Der veröffentlichte Gate-Bericht zu PR #4 behält seinen eigenen Geltungsbereich. |

## Nachvollziehen

Unter Linux die unten genannten Archivdateien aus den beiden exakten GitHub-Commits herunterladen. Das Kandidatenarchiv in ein frisches Verzeichnis entpacken. Python 3.12, OpenSSL und die Abhängigkeiten der lokalen Tests bereitstellen. Die folgenden Befehle laufen im Arbeitsverzeichnis mit den beiden Archiven und dem mitgelieferten Prüfskript.

```sh
base=03aea857e35358ddeb13d2a861b633e60c1ca873
candidate=6621f1b76b3b641ae1f25a195d50cad677d96091
curl -fsSL "https://codeload.github.com/0xFarag/0xFarag/tar.gz/$base" -o baseline.tar.gz
curl -fsSL "https://codeload.github.com/0xFarag/0xFarag/tar.gz/$candidate" -o candidate.tar.gz
mkdir candidate
tar -xzf candidate.tar.gz -C candidate --strip-components=1
(cd candidate && python ../verify.py ../baseline.tar.gz ../candidate.tar.gz ../local-regression.json)
```

Das Skript gleicht vor den Tests jede getrackte reguläre Kandidatendatei mit dem Archiv ab. Ein Python-Audit-Hook im Elternprozess verweigert Netzwerkzugriffe und begrenzt Subprozesse auf lokale OpenSSL-Schlüsseloperationen sowie den isolierten, eigenständigen Paket-Verifier. Externe Release-Downloads und Installer liegen ausserhalb des Dateivergleichs.

ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
