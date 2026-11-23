# AuthzLedger Team – Drittanbieterhinweise

Der Quellcode von AuthzLedger und die Hinweise des Projekts werden als `LICENSE` und `NOTICE.txt` mitgeliefert. Die Lizenztexte externer Komponenten gelten für die jeweiligen Komponenten.

**Windows.** Die EXE bündelt eine Python-Laufzeit, Tcl/Tk für das Desktopfenster, die Kryptografiebibliothek und den PyInstaller-Bootloader. Unter «Lizenz und Drittanbieterhinweise» im Startfenster lassen sich die mitgelieferten Texte lesen. Unter `third-party/` stehen die beim Erstellen des Pakets aus den installierten Distributionen übernommenen Lizenztexte und die Versionsübersicht. Die Übersicht kennzeichnet auch eingesetzte Build-Werkzeuge.

**Docker.** Die Projekttexte und die beim Build erfassten Python-Lizenzen liegen unter `/usr/share/doc/authzledger-team/`. Für die Komponenten des Debian-Basisimages gelten deren Paketinformationen und die im Image verfügbaren Copyright-Dateien.

**Debian und Arch Linux.** Python, Tk und die Kryptografiebibliothek werden als Systempakete installiert. Debian stellt die verfügbaren Texte unter `/usr/share/doc/<Paket>/copyright` bereit. Unter Arch weisen `pacman -Qi` und die Paketdateiliste auf die Lizenz und die mitgelieferten Texte hin. Die Hinweise zum AuthzLedger-Paket stehen unter `/usr/share/doc/authzledger-team/`.

**Quellarchiv.** Die Datei `team/requirements.txt` legt die Python-Kryptografiebibliothek fest. Der Quellstand des Projekts und das Baurezept liefern die Anwendung ohne vorinstallierte Python-Laufzeit.

Upstream-Projekte: [Python](https://www.python.org/psf/license/), [Tcl/Tk](https://www.tcl-lang.org/software/tcltk/license.html), [cryptography](https://github.com/pyca/cryptography), [PyInstaller](https://github.com/pyinstaller/pyinstaller).
