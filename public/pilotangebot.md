# AuthzLedger Pilotangebot

**30 Tage · CHF 2’400 einmalig · zwei benannte Nutzer · ein autorisiertes Mandat**

Mit Ihrem Reviewer prüfen Sie, ob Ihr Team einen korrigierten Berechtigungsbefund bis zur ursprünglichen Beobachtung zurückverfolgen kann. Am Ende verifiziert der Empfänger die Übergabe auf seinem eigenen Gerät und kann nachgeprüfte und offene Fälle benennen.

## Im Pilot enthalten

Der Pilot verwendet die kommerzielle Basis AuthzLedger 1.5.0. Ihr Team vereinbart einen konkreten Übergabefall, bearbeitet ihn lokal und prüft eine ausgewählte Korrektur. Für die Abnahme erhalten Sie den Berichtssnapshot, das zugehörige signierte Inventar und eine Liste der nachgeprüften und offenen Fälle. Die separate technische Vorschau auf 1.6 dient der Erprobung.

## Abnahmekriterien

- **Kontrollen.** Der Reviewer kann einen bestätigten Befund auf die ursprüngliche Beobachtung und die zugehörigen gültigen Kontrollen zurückführen. Gelingt das nicht, bleibt die Bestätigung offen.
- **Retest.** Eine nachgeprüfte ID verweist auf Ausgangsbefund und Ergebnis. Der Reviewer identifiziert einen ausgelassenen Fall am Status `not_retested`.
- **Übergabe.** Der Empfänger bestätigt den öffentlichen Schlüssel über einen zweiten Kanal und prüft die Ed25519-Signatur und das Dateiinventar. Er hält die Annahme des Originals und die Zurückweisung einer eigens veränderten Testkopie fest. Die Signatur belegt die Integrität der Übergabe. Die fachliche Beurteilung stützt sich auf die Kontrollen.

## Beispiel für eine Abnahme

Im öffentlichen Demofall liegen zwei ursprüngliche Befunde vor. Der Empfänger wählt den nachgeprüften Befund, liest den Status und gleicht seine ID mit dem ursprünglichen Prüfprotokoll ab. Anschliessend öffnet er den zweiten Befund und hält fest, dass dessen Korrektur offen bleibt. So können beide Seiten denselben Fall besprechen, auch wenn sie unterschiedliche Werkzeuge einsetzen.

[Öffentliches Retest-Protokoll aus Demo C](https://authzledger.com/proof/v1.5.0/receipt.json)

## So arbeiten wir zusammen

| Zeitpunkt | Beitrag Ihres Teams | Arbeitsergebnis |
|---|---|---|
| Vor dem Start | Zwei Nutzer, zuständigen Reviewer, freigegebenen Fall und Ausgangsdaten benennen. Scope, Ausführungsbudget, Anfangs- und Enddatum gemeinsam festhalten. | Schriftlicher Auftrag und ein vereinbarter Vergleichsfall. |
| Erster Arbeitstag | Bereinigte Beispieldaten auf einem freigegebenen Gerät öffnen. Einen früheren Übergabeaufwand in Minuten dokumentieren. | Erste gemeinsam geprüfte Beispielübergabe als Arbeitsziel. |
| Im Pilot | Eine Korrektur nachprüfen. Beleg, offene Fälle und Rückfragen erfassen. Den öffentlichen Schlüssel unabhängig bestätigen. | Berichtssnapshot mit Befund-IDs, Prüfstatus und signiertem Inventar. |
| Spätestens Tag 30 | Der Empfänger prüft das Paket lokal. Gleiche Fallmenge und Reviewzeit vergleichen. | Gemeinsames Abnahmeprotokoll mit Resultat je Kriterium und Folgeentscheidung. |

## Offerte und Anschluss

Der Richtpreis beträgt CHF 2’400 einmalig, exklusive allfälliger MWST. Starttermin, Fristbeginn, Ansprechpartner, Supportfenster und Zahlungsmodalitäten werden in Ihrer persönlichen Offerte vereinbart. Bitte nennen Sie einen anonymisierten Fall und einen Wunschtermin. Produktivdaten und Zugangsdaten werden für die Anfrage nicht benötigt.

Die Jahreslizenzen kosten CHF 1’200 für Solo und CHF 4’800 für Team. Bei einem qualifizierten Jahresabschluss innert der vereinbarten 30-Tage-Frist werden einmalig CHF 1’200 angerechnet. Bei Team ergibt dies CHF 3’600 auf der ersten Jahresrechnung. Der Pilot endet nach der vereinbarten Laufzeit. Ein Jahresvertrag bedarf eines separaten Abschlusses.

[20-minütiges Erstgespräch mit Nasser Aldin Farag anfragen](https://www.linkedin.com/in/nasser-aldin-farag-974697412/)

[Release und Prüfbelege für AuthzLedger 1.5.0](https://github.com/0xFarag/0xFarag/releases/tag/v1.5.0)

Nasser Aldin Farag (0xFarag) · Founder & CEO · Schweiz · 23. November 2026

© Nasser Aldin Farag (0xFarag). Alle Rechte an den eigenen schutzfähigen Beiträgen vorbehalten. Rechte Dritter bleiben gewahrt.
