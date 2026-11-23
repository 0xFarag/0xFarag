# Stripe-Betrieb für AuthzLedger

© Nasser Aldin Farag (0xFarag). All rights reserved.

## Händler und Auszahlung

Die Website legt Checkout Sessions direkt im Schweizer Stripe-Händlerkonto an, dessen Konto-ID zu ihrem serverseitigen API-Schlüssel gehört. Die Sitzung verwendet weder Stripe Connect Transfers noch Plattformgebühren. Stripe führt das Händlerguthaben und zahlt aus gemäss den im Dashboard hinterlegten Bankdaten, Kontoprüfungen und Auszahlungsbedingungen. Das AuthzLedger-Backend liest keine IBAN.

Ohne Konfiguration bleiben Checkout und Kundenportal geschlossen. Ein API-Status oder eine Rückkehr zur Website ist kein Zahlungseingang. Abgeschlossene Abos und Zahlungen sind im richtigen Stripe-Dashboard anhand der Subscription und der zugehörigen bezahlten Rechnung zu prüfen. Die Anwendung legt beim Öffnen der Kasse eine Zahlungssitzung an. Sie erteilt keine Softwarelizenz und löst keine Folgeaktion anhand eines undokumentierten Browserzustands aus.

## Dashboard einrichten

1. Das neue AuthzLedger-Konto im Schweizer Stripe-Dashboard auswählen. Der Inhaber schliesst die Identitätsprüfung ab, hinterlegt sein Auszahlungskonto und prüft die Firmenangaben. Die Auszahlungsvorschau im Dashboard muss das beabsichtigte Bankkonto zeigen. Persönliche Bankdaten und Geheimnisse ausschliesslich in den authentifizierten Anbieteroberflächen eingeben.
2. Im ausgewählten Test- oder Livemodus zwei **aktive** Produkte mit je einem wiederkehrenden lizenzierten Stückpreis anlegen. Solo kostet CHF 1’200 pro Jahr, Team CHF 4’800 pro Jahr. Ein Stück, ein Jahr, reguläre Dezimalpreise ohne Mengenstaffel oder Umrechnung. Vertraglich vereinbarte Pilotgutschriften vor dem Abschluss über die individuelle Anschlussrechnung bearbeiten.
3. In den öffentlichen Geschäftsdaten die Zahlungs-/Abonnementbedingungen, Datenschutzseite, Rechnungsangaben und Supportkontakt pflegen. Der Checkout verlangt Zustimmung zu den hinterlegten Bedingungen. Steuerverhalten der Preise, gegebenenfalls erforderliche Steuerregistrierungen, Zahlungsmittel und die Anzeige der jährlichen Verlängerung im Testmodus abstimmen. Beim Einsatz von Stripe Tax die Preisbasis und den letzten angezeigten Gesamtbetrag prüfen.
4. Im Kundenportal Rechnungsverlauf, Zahlungsmittel und Kündigungsbedingungen passend zu den abgeschlossenen Verträgen konfigurieren. Login-Link aktivieren. Die ID dieser Portal-Konfiguration ins Projekt übernehmen. Die Website liest den Login-Link bei Stripe mit dem Schlüssel des bestätigten Kontos. Die E-Mail-/Code-Prüfung übernimmt Stripe. Ein Konto mit offenem Auszahlungsschritt darf seinen bestehenden Kunden das Portal weiterhin anbieten.

## Vercel-Projekt konfigurieren

Die integrierten Systemvariablen von Vercel bereitstellen, damit `VERCEL_ENV` zuverlässig zwischen Production und Preview unterscheidet. Alle unten aufgeführten Werte im richtigen Deployment-Environment setzen und anschliessend neu bereitstellen. Einen geheimen API-Schlüssel als Sensitive Environment Variable anlegen. Falls ein eingeschränkter Schlüssel zum Einsatz kommt, braucht er die von Stripe vorausgesetzten Rechte für das Lesen des eigenen Kontos, der Preise, Produkte und Portal-Konfiguration sowie das Anlegen einer Checkout Session im Abo-Modus. Den eingeschränkten Schlüssel mit derselben Operation im Testkonto prüfen.

| Umgebungsvariable | Wert oder Zweck |
|---|---|
| `AUTHZ_BILLING_MODE` | `test` auf der Testwebsite oder `live` in Production. Entfernen deaktiviert beide Zahlungswege nach dem nächsten Deployment. |
| `AUTHZ_BILLING_TEST_ORIGIN` | Nur für Test, vollständiger fester HTTPS-Origin einer kontrollierten Preview-Domain ohne Pfad und abschliessenden Slash. |
| `STRIPE_MERCHANT_ACCOUNT_ID` | Bestätigte Konto-ID des eigenen Schweizer Händlers, beginnend mit `acct_`. |
| `STRIPE_SECRET_KEY` | Privater Schlüssel im gleichen Konto und Modus. |
| `STRIPE_PUBLISHABLE_KEY` | Öffentlicher Schlüssel aus demselben Schlüsselpaar/Konto und Modus. Erst nach erfolgreichem Preis-/Kontocheck im Status sichtbar. |
| `STRIPE_PRICE_SOLO`, `STRIPE_PRICE_TEAM` | Unterschiedliche Preis-IDs der zwei Jahresabos, beginnend mit `price_`. |
| `STRIPE_PORTAL_CONFIGURATION` | Portal-Konfigurations-ID im selben Modus, beginnend mit `bpc_`. |
| `STRIPE_AUTOMATIC_TAX` | `true` aktiviert Stripe Tax für Checkout. Ohne `true` erstellt dieser Checkout keine automatische Steuerberechnung. Die steuerliche Behandlung vor Aktivierung festlegen. |

Die Livefunktion ist auf `authzledger.com` und `www.authzledger.com` in Production beschränkt. Testmodus funktioniert ausschliesslich auf der bewusst angegebenen separaten Testdomain ausserhalb von Production. Der Kundenbereich speichert keine Konten oder Passwörter. Die Zuordnung der Portal-Sitzung zu einem Abrechnungskunden führt Stripe aus.

## Freigabe und Betrieb

- `node --test qa/billing-api.cjs` prüft die Funktionen gegen simulierte Stripe-Antworten. Mit echten Testschlüsseln danach Solo und Team, Rechnungsadresse, Währung, Steueranzeige, jährliche Wiederholung, Abbruch, erforderliche Bestätigung und den Rücksprung prüfen. Einen Testkunden zur E-Mail-/Code-Anmeldung im Kundenportal verwenden, soweit die Sandbox dies zulässt.
- Testzahlungen nur im Stripe-Testmodus. Keine Testkartendaten im Livebetrieb verwenden. Eine bestätigte Freigabe umfasst getrennt den Händlerstatus, die öffentliche Preis- und Steueranzeige, den Kundenportalumfang, die Abwicklung der Lizenzleistung und die produktive Kaufbereitschaft.
- Die Versionsbindung lautet `2026-11-18.endive` mit `ui_mode=embedded_page`. Geheimnisse und Sitzungsantworten nicht protokollieren. Stripe.js kommuniziert bei der Bezahlung direkt mit Stripe.
- Im Vercel-Projekt für `POST /api/create-checkout` ein verteiltes IP-Limit im WAF mit wirksamer Blockieraktion konfigurieren. Eine Ausgangseinstellung sind 10 Versuche pro Minute je IP. Auf legitime Nutzer hinter gemeinsamem NAT abstimmen. Wirkung am Projekt prüfen. Der lokale Zähler (10 Anfragen pro Minute/IP/warmer Funktionsinstanz) läuft nur ergänzend und kann von einer anderen Instanz oder einem Kaltstart zurückgesetzt werden. Der Herkunftscheck hindert fremde Browserseiten an der Nutzung, er authentifiziert keinen anonymen Käufer. Ein kryptografisch zufälliger Request-Identifier pro Kaufabsicht macht Wiederholungen innerhalb des Stripe-Idempotenzfensters sicher. Bewusste neue Kaufvorgänge erhalten eine neue ID.
- Bei falscher Zuordnung, Störung oder fehlender Bereitschaft gibt der Checkout eine neutrale Fehlermeldung zurück. Bei einer Rückbuchung, Kündigung oder fehlgeschlagenen Verlängerung den Abostatus im Stripe-Dashboard prüfen. Eine künftige automatische Lizenzfreischaltung benötigt eine eigene authentifizierte Verarbeitung verifizierter Zahlungsereignisse und die Zuordnung zum Lizenzvertrag.

[Embedded Checkout](https://docs.stripe.com/checkout/embedded/quickstart) · [Checkout Sessions](https://docs.stripe.com/api/checkout/sessions/create) · [Kundenportal](https://docs.stripe.com/customer-management/activate-no-code-customer-portal) · [Idempotenz](https://docs.stripe.com/api/idempotent_requests) · [Vercel WAF](https://vercel.com/docs/vercel-firewall/vercel-waf/rate-limiting)
