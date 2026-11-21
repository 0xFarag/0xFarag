# AuthzLedger · Debian-Empfängerprüfer

**Paketierungsvorschau, 21. November 2026.** Das Debian-Paket enthält den eigenständig nutzbaren Offline-Prüfer des veröffentlichten AuthzLedger-Releases v1.5.0. Die CLI prüft mit einem vom Empfänger vorgegebenen Ed25519-Public-Key die Signatur, das Inventar, die aufgeführten Datei-Hashes und die Verknüpfung zum Bericht. Die fachliche Wahrheit der im Bericht beschriebenen Ausführung erfordert eigene Belege. Der unveränderte Originalprüfer und das Demoarchiv stammen aus dem [stabilen Release](https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0).

## Ausprobieren ohne Systeminstallation

Debian mit Python ab 3.10, OpenSSL ab 3.0 und dpkg-deb. Die folgenden Befehle entpacken die Vorschau nur in das Unterverzeichnis `pruefer` und starten die Hilfe.

```sh
dpkg-deb -x ./authzledger-verifier_1.5.0-0~preview1_all.deb ./pruefer
./pruefer/usr/bin/authzledger-verify --help
```

Für das historische Beispiel das Originalarchiv `authzledger-1.5.0-proof.zip` aus dem stabilen Release entpacken und aus dem übergeordneten Verzeichnis starten:

```sh
./pruefer/usr/bin/authzledger-verify \
  authzledger-proof/C-retest-proof/proof \
  --public-key authzledger-proof/trusted-public.pem
```

Im Kundenmandat muss der Empfänger den erwarteten öffentlichen Schlüssel über einen unabhängig bestätigten Kanal erhalten. Für den Paketierungstest ist der historische Demo-Schlüssel über den separat veröffentlichten SHA-256-Wert des GitHub-Release-Archivs festgelegt. Er liegt im Archiv ausserhalb des signierten Bundles. Diese Zuordnung dient ausschliesslich dem bekannten Testfall.

## Bau und Prüfung

`build_verifier_deb.py` prüft die SHA-256-Werte beider Originaldateien vor dem Bau. Zum Nachbauen `verify_bundle.py` und das historische Proof-ZIP in ein Verzeichnis `upstream` legen und `python3 build_verifier_deb.py upstream ausgabe` ausführen. Zwei unabhängige Bauvorgänge in derselben Debian-Umgebung erzeugten bytegleiche Pakete.

| Test unter Debian 13.7 amd64 | Exitcode |
|---|---:|
| Unverändertes historisches Demo-C-Paket mit externem Demo-Prüfschlüssel | 0 |
| Ein Byte am PDF-Anhang verändert, Länge gleich | 1 |
| Unverändertes Paket mit anderem öffentlichem Schlüssel | 1 |

Das Debian-Paket trägt keine Herausgebersignatur. Zusätzlich zum entpackten Aufruf wurde das Paket in einem eigenen Debian-13.7-amd64-Systembaum mit eigener dpkg-Datenbank installiert. Die Abhängigkeiten stammen aus den signierten Debian-Paketquellen. Im netzwerkisolierten Prüflauf lieferte der installierte Befehl dieselben drei erwarteten Exitcodes. Nach der Entfernung mit dpkg fehlten Launcher und Programmdatei, während die Referenzbelege erhalten blieben. Die abschliessende dpkg-Prüfung meldete keine Probleme. Der Test lief im Linux-Namespace auf einem geteilten Kernel. Ein Upgrade von einer früheren Debian-Ausgabe, eine separate Desktop-VM und ein signiertes Distributionsinventar stehen aus. Das Paket ist der Empfängerprüfer; die vollständige Studio-/CLI-Suite und der Windows-Installer bleiben eigene Vertriebsziele. Die Dateien `verification.json` und `SHA256SUMS` dokumentieren Testumgebung, Ausgaben und Transportprüfsummen.

ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
