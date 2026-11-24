# AuthzLedger Team 1.5.0.4

Team ist ein separat versionierter Arbeitsbereich für die gemeinsame defensive Befundprüfung. Die Pakete enthalten denselben Python-Dienst und dieselbe Weboberfläche. Die lokalen Daten liegen standardmässig unter `~/.authzledger-team`. Produktbedingungen und Hinweise zu Drittmaterial stehen in `LICENSE` und `NOTICE.txt`.

## Neu in 1.5.0.4

Die neue Burp-Erweiterung exportiert ausgewählte HTTP-Belege für einen Fall. Team übernimmt ausserdem Berichte aus abgeschlossenen ZAP API Scans. Die Anleitung zur Ed25519-Schlüsselrotation erläutert den Wechsel des Signierschlüssels und die Prüfung früherer Übergaben.

[Schlüsselrotation und Verifikation](https://github.com/0xFarag/0xFarag/blob/team-1.5.0.4/docs/Key-Rotation.md) · [Bericht aus ZAP API Scan importieren](https://github.com/0xFarag/0xFarag/blob/team-1.5.0.4/docs/ZAP-API-Scan-Import.md)

## Integrität

Die Release-Seite führt für jede Datei einen SHA-256-Wert in `SHA256SUMS`. Unter Linux können Sie alle heruntergeladenen Pakete mit `sha256sum --ignore-missing -c SHA256SUMS` prüfen. Unter Windows berechnet `Get-FileHash .\AuthzLedger-Team-1.5.0.4-Windows-x64.exe -Algorithm SHA256` die Prüfsumme. Diese Prüfsummen dienen dem Abgleich mit der Veröffentlichung. Der Windows-Build enthält keine kommerzielle Authenticode-Signatur.

Über **Anleitungen** im Startfenster lassen sich die lokal installierten Leitfäden zu Burp, ZAP, Schlüsselrotation und Teamrollen lesen. Die mitgelieferten Drittanbieterhinweise stehen unter `THIRD-PARTY.md`. Im Windows- und Linux-Startfenster öffnet «Lizenz und Drittanbieterhinweise» die für das jeweilige Paket bereitgestellten Texte.

## Windows x64

Starten Sie `AuthzLedger-Team-1.5.0.4-Windows-x64.exe`. Das Desktopfenster führt beim ersten Start durch die Einrichtung des Administratorkontos. Anschliessend öffnet es den Arbeitsbereich in Ihrem Standardbrowser. Solange das Fenster geöffnet bleibt, läuft der Dienst auf einer privaten Loopback-Adresse. Schliessen Sie das Fenster, um ihn zu beenden.

## Burp Suite

1. Laden Sie `AuthzLedger-Burp-Export-1.5.0.4.jar` und `SHA256SUMS` vom gleichen Release. Vergleichen Sie die Prüfsumme der JAR-Datei mit der zugehörigen Zeile im Manifest.
2. Öffnen Sie in Burp **Extensions → Installed → Add**. Wählen Sie **Java**, wählen Sie die JAR-Datei und laden Sie die Erweiterung. Verwenden Sie eine Burp-Installation mit Java 21 oder neuer.
3. Markieren Sie unter **Proxy → HTTP history** vollständige Request-/Response-Paare innerhalb des freigegebenen Burp-Scopes. Wählen Sie im Kontextmenü **Export selected evidence to AuthzLedger…** und speichern Sie die XML-Datei an einem geschützten Ort.
4. Öffnen Sie den zugehörigen Fall in AuthzLedger Team und importieren Sie die Datei als **Burp Suite XML**. Exportdateien können Anmeldedaten und personenbezogene Inhalte enthalten. Kontrollieren Sie die Auswahl vor der Weitergabe.

[Quellcode, Build und Tests der Erweiterung](https://github.com/0xFarag/0xFarag/tree/team-1.5.0.4/integrations/burp)

## Debian oder Ubuntu

Installieren Sie mit `sudo apt install ./authzledger-team_1.5.0.4-1_all.deb`. Das Anwendungsmenü enthält anschliessend **AuthzLedger Team**. Alternativ startet `authzledger-team-desktop` das Fenster. Das Paket verwendet die vom Betriebssystem gepflegten Python-, Tk-, ReportLab- und Kryptografiepakete.

## Arch Linux

Installieren Sie mit `sudo pacman -U ./authzledger-team-1.5.0.4-1-any.pkg.tar.zst`. Für einen eigenen Build legen Sie `PKGBUILD` und `authzledger-team-1.5.0.4.tar.gz` zusammen in ein leeres Verzeichnis und führen als normaler Nutzer `makepkg -s` aus. Die Prüfsumme des Quellarchivs ist im Baurezept hinterlegt.

## Docker (Linux amd64)

Laden Sie das Docker-Archiv mit `docker load -i authzledger-team-1.5.0.4-linux-amd64.docker.tar.gz`. Das zusätzliche OCI-Archiv lässt sich mit OCI-kompatiblen Werkzeugen wie Skopeo importieren. Das mehrstufig gebaute Image enthält die Anwendung, ihre Python-Laufzeit und die eingebettete PDF-Schrift. Es läuft unter UID 10001 und speichert die Teamdaten in `/data`.

```sh
docker volume create authzledger-team-data
docker run --rm -it -v authzledger-team-data:/data authzledger-team:1.5.0.4 --bootstrap
```

Für die Portweiterleitung benötigt der Dienst ein TLS-Zertifikat mit passendem Hostnamen und einen für UID 10001 lesbaren Schlüssel. Mounten Sie den vorbereiteten Zertifikatsordner schreibgeschützt. Das Beispiel veröffentlicht den Port auf der Loopback-Adresse des Docker-Hosts.

```sh
docker run --rm --name authzledger-team \
  -v authzledger-team-data:/data \
  -v "$PWD/tls:/tls:ro" \
  -p 127.0.0.1:8765:8765 authzledger-team:1.5.0.4 \
  --host 0.0.0.0 --port 8765 --certfile /tls/cert.pem --keyfile /tls/key.pem
```

Öffnen Sie die HTTPS-Adresse, deren Hostname im Zertifikat steht. Vor einem Rechnertausch oder Update den Dienst sauber beenden und das vollständige Datenverzeichnis einschliesslich der Schlüssel geschützt sichern.

## Quellarchiv

Der Server unterstützt Python 3.10 und höher. In einem virtuellen Python-Umfeld installieren Sie die Abhängigkeiten aus `team/requirements.txt`. Für das Desktopfenster ist eine Python-Installation mit Tk erforderlich. `python -m team.server --bootstrap` erstellt das erste Konto. `python -m team.server` startet den Dienst.

## Erster Prüflauf

Nach der Anmeldung einen Fall mit genehmigtem Scope anlegen und einen freigegebenen Export importieren. Aus der Fallansicht können berechtigte Rollen die Übergabe ausstellen. Für den Empfänger den öffentlichen Schlüssel über einen unabhängig bestätigten Kanal bereitstellen. Den privaten Signierschlüssel beim Team belassen.

© Nasser Aldin Farag (0xFarag). All rights reserved.
