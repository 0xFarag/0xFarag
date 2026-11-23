# Fachzugang für ausgewählte Pentester

Nasser Aldin Farag (0xFarag) entscheidet über jeden Fachzugang. Die Freigabe gilt für genau einen öffentlichen Geräteschlüssel bis zum festgelegten UTC-Zeitpunkt. Das Protokoll authentifiziert die Kontrolle über den zugehörigen privaten Schlüssel. Die fachliche Eignung und die Identität der Person prüft der Betreiber bei der Auswahl.

## Schlüssel freigeben

1. Der Bewerber erzeugt auf seinem Gerät unter `/fachzugang/` ein Ed25519-Schlüsselpaar. Für die Prüfung benötigt der Betreiber nur die drei öffentlichen JWK-Felder `kty`, `crv`, `x` und den angezeigten Fingerabdruck. Der private Schlüssel bleibt auf dem Gerät.
2. Nasser gleicht den Fingerabdruck über einen bereits bekannten Kontakt mit dem Bewerber ab und entscheidet über die Freigabe und deren Laufzeit. Ein Antrag und ein bezahltes Abo verleihen für sich allein keinen Zugang.
3. Im aktiven Vercel-Projekt die Produktionsvariable `AUTHZ_PRO_APPROVALS` bearbeiten. Sie enthält ein JSON-Array. Die vorhandenen Freigaben beibehalten, die drei geprüften öffentlichen Felder übernehmen und den Eintrag um `expiresAt` (UTC-Unixzeit in Sekunden) ergänzen. Beispielstruktur mit Platzhaltern:

   ```json
   [
     {
       "jwk": {"kty":"OKP","crv":"Ed25519","x":"<öffentliche JWK-Koordinate>"},
       "expiresAt": 0
     }
   ]
   ```

   Der Wert `0` ist abgelaufen. Das Beispiel gewährt keinen Zugang. Eine fehlende Variable, ein leeres Array, eine ungültige Liste oder ein doppelter Schlüssel sperrt die Fachprüfung. Die Liste fasst höchstens 128 Einträge und 32 KiB. Schlüssel und Inhaberzuordnung gehören in die vom Betreiber geführte Zugriffsliste. Die Produktionsvariable enthält ausschliesslich die öffentlichen Schlüssel und deren Ablaufzeit.
4. Mit der aktualisierten Produktionskonfiguration bereitstellen und die Domain prüfen. Der Bewerber kann über sein hinterlegtes Gerät mit einer leeren Fallliste die Freigabe testen. Eine erfolgreiche Antwort enthält `approved` und die Ablaufzeit. Zum Widerruf den entsprechenden Eintrag entfernen und die aktualisierte Konfiguration erneut bereitstellen. Änderungen an Umgebungsvariablen greifen bei Vercel mit dem neuen Deployment. Bei Geräteverlust den alten Schlüssel widerrufen und den Ersatz separat auswählen.

Der Server akzeptiert standardmässig nur die Origin `https://authzledger.com`. Für eine getrennte Testbereitstellung setzt `AUTHZ_PRO_ORIGIN` eine einzelne kanonische HTTPS-Origin ohne Pfad. Host und Origin müssen übereinstimmen. Nur geprüfte Berechtigungen für die jeweilige Umgebung hinterlegen. Dieses Verzeichnis steuert die neue Fachprüfung. Bereits ausgelieferte Dateien lassen sich dadurch nicht zurückrufen.

## Protokoll

`POST /api/pro-review` verlangt einen gleichursprünglichen JSON-Aufruf mit den vier Feldern `kid`, `issuedAt`, `cases` und `signature`. Maximal 32 Fälle und 8192 Bytes je Anfrage. Pro Fall werden ausschliesslich folgende Werte akzeptiert.

| Feld | Zulässige Werte |
| --- | --- |
| scope | in_scope, out_of_scope, unknown |
| controls | passed, failed, missing |
| binding | matched, ambiguous, missing |
| retest | not_retested, inconclusive, still_present, change_observed |

`kid` ist die ungepolsterte Base64url-Codierung von SHA-256 über die 32 Rohbytes des öffentlichen Schlüssels. `issuedAt` ist die UTC-Unixzeit in Sekunden. Der Server toleriert eine Abweichung von höchstens 60 Sekunden. Für die Signatur gilt dieser exakt serialisierte UTF-8-Inhalt. Es wird die durch `JSON.stringify` erzeugte kompakte Arraydarstellung verwendet.

```js
const rows = cases.map(c => [c.scope, c.controls, c.binding, c.retest]);
const message = JSON.stringify([
  'authzledger.pro-review.v1', 'POST', '/api/pro-review',
  location.origin, kid, issuedAt, rows
]);
```

Die Ed25519-Signatur umfasst 64 Bytes und wird ungepolstert base64url-codiert übertragen. Der Server hält keine Sitzung. Ein erneut übermittelter gültiger Request innerhalb des Zeitfensters kann dieselbe Auswertung abrufen. Er verändert keinen Zustand. Operationen mit Schreibwirkung benötigen einen eigenen Replay-Schutz. Jede Antwort trägt `no-store`.

## Auswertung

Die erste zutreffende Regel entscheidet pro Fall. `index` bezeichnet die Position des Falls ab 1. Die ursprüngliche Reihenfolge bleibt erhalten.

| Bedingung | decision |
| --- | --- |
| Ausserhalb des Mandats | excluded |
| Scope offen | clarify_scope |
| Controls fehlen oder sind fehlgeschlagen | check_controls |
| Quellenbezug fehlt oder ist mehrdeutig | bind_source |
| Kein Retest | schedule_retest |
| Retest ohne eindeutiges Ergebnis | review_inconclusive |
| Weiterhin beobachtet | review_open |
| Änderung beobachtet | review_change |

`total` zählt alle übergebenen Fälle. `eligible` zählt Fälle mit erklärtem Scope-Bezug, bestandenen Controls und passender Quelle. `conclusive` zählt daraus die als weiterhin vorhanden oder verändert gemeldeten Fälle. `notRetested` zählt alle als nicht erneut geprüft gemeldeten Fälle. Diese Werte beruhen auf den vier Angaben je Fall. Eine fachliche Bestätigung setzt die Prüfung der tatsächlichen Belege voraus. Eine leere Fallliste dient als persönlicher Zugangstest.

Die API verarbeitet keine Belegdateien, Zieladressen, Pfade, Kundennamen oder Zugangsdaten. Unbekannte Felder werden verworfen und die gesamte Anfrage wird abgelehnt. Fehlende oder abgelaufene Rechte und ungültige Signaturen ergeben dieselbe Antwort `403 access_denied`. Ungültiges JSON oder falsche Felder ergeben `400`. Mengen- und Grössenüberschreitungen ergeben `413`, nicht unterstützte Medientypen `415`. Ohne gültige Freigabekonfiguration bleibt die Prüfung bei `403`.

© Nasser Aldin Farag (0xFarag). All rights reserved.
