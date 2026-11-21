# AuthzLedger · Empfängerprüfer für Arch Linux

© Nasser Aldin Farag (0xFarag). All rights reserved.

Unter Arch Linux die offiziellen Pakete base-devel, python (ab 3.10) und openssl (ab 3.0) bereitstellen. Als normaler Benutzer das entpackte Verzeichnis öffnen und die mitgelieferten lokalen Quellen sowie das Rezept prüfen.

```sh
makepkg --verifysource
makepkg --cleanbuild
sudo pacman -U ./authzledger-verifier-1.5.0pre1-1-any.pkg.tar.zst
authzledger-verify --help
authzledger-verify ./proof --public-key ./vertrauen/mandat.pem
```

Der Paketname folgt dem Standard für die Kompression mit zstd. Bei anderer lokaler Konfiguration zeigt `makepkg --packagelist` den tatsächlichen Namen. Den erwarteten öffentlichen Schlüssel getrennt über einen vertrauenswürdigen Kanal bestätigen. Zum Entfernen `sudo pacman -R authzledger-verifier` verwenden. Das Rezept installiert nur die Empfängerprüfung. Die vollständige Workbench ist eine eigene Distribution. Zu diesem Rezept gehören die beigefügten Rechtehinweise.
