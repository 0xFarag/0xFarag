# AuthzLedger · Öffentliche Website

<img src="public/assets/authzledger-logo.png" alt="AuthzLedger" width="96" height="96">

Dieser Zweig enthält die Produktwebsite und den eigenständig installierbaren AuthzLedger-Teamdienst. Vercel baut die Download-Dateien und Sprachseiten und veröffentlicht `dist/`. Die öffentliche Website und das historische Lab sind unabhängig von den privaten Fällen und Benutzerdaten der Teaminstallation.

Der [Teamdienst](team/) speichert Benutzer, Teamzugehörigkeiten und Belege lokal in SQLite. Die [Rollenspezifikation](docs/Team-Login-RBAC.md) und die [Installationsanleitung](packaging/team/README.md) beschreiben Anmeldung, Betrieb und Paketprüfung. Die Pakete der Team-Edition haben einen eigenen Release-Tag. Die Versionsnachweise der stabilen Workbench 1.5.0 bleiben getrennt.

Das stabile Produkt liegt im [Release v1.5.0](https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0). Die Freigabe des Produktes hat einen separaten Versions- und Signaturprozess. Die Projektadresse ist authzledger.com.

## Lokal ansehen

```sh
node scripts/build-downloads.mjs
node scripts/build-locales.mjs
python -m http.server 8000 --bind 127.0.0.1 --directory dist
```

## Rechte

ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).

Für eigene geschützte Beiträge gelten die Bedingungen in [LICENSE](LICENSE). Hinweise zu Drittmaterial stehen in [NOTICE.txt](NOTICE.txt).
