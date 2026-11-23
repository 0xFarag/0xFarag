# Review saved tool evidence in AuthzLedger

In Studio, open **Assessment → Scope to proof → Surface → Compare tool exports offline**. Enter the literal IP and TCP port covered by your assessment. Select the saved reports, preview the projection and open an observation to see its original file hash and locator. To add the reviewed evidence to a persistent assessment, grant the matching TCP service in its scope, then choose **Retain reviewed evidence**. The frozen assessment's surface index includes both accepted observations and omissions.

| Input | Fields available in the offline inventory |
| --- | --- |
| Nmap XML | TCP service, reported port state and provenance |
| ffuf JSON | Recorded response status, optional content length and method |
| Nuclei HTTP JSONL | Reported template match and scanner severity |
| Nikto XML | Numeric test ID and reported IP/port, at service level |
| Nessus XML v2 (e.g. a Tenable Nessus **.nessus** export) | Plugin ID and original severity 0–4, for a reported TCP service |
| Gobuster directory results, UTF-8 text | HTTP status and optional response size. Absolute literal HTTP(S) URLs can be joined to a service. Relative results and hostnames retain an unresolved disposition. |
| feroxbuster response JSONL | HTTP status, reported method and content length. Metadata records have a separate disposition. |

**Scope and evidence.** The inventory reads saved files, with a 2 MiB combined input limit and 1,000 records per profile. It makes no target requests or DNS lookups. A service-level observation does not identify an application endpoint. Nessus plugin output, Nikto description text and feroxbuster response bodies are omitted. Scanner records have a ceiling of **hint**. Confirmed authorization findings continue to require validated controls. The local source files remain the authority for their contents. The retained endpoint path is a digest. A guessed string can be checked against that digest.

To try the four added scanner profiles, run the following from the candidate checkout. The example files are synthetic.

```sh
python -m authzledger assessment federation-preview \
  --scope-service tcp://192.0.2.10:443 \
  --nikto fixtures/offline-tools/nikto.xml \
  --nessus fixtures/offline-tools/nessus.nessus \
  --gobuster fixtures/offline-tools/gobuster.txt \
  --feroxbuster fixtures/offline-tools/feroxbuster.jsonl
```

Burp XML and raw HTTP request/response pairs, ZAP JSON+ and HAR use **Surface → Import offline**. OpenAPI uses the existing contract import. Original tool functionality and upstream licenses remain with their respective publishers.

## Defensive event records

In Studio, open **Investigate → Review defensive telemetry from a Cobalt Strike exercise**. An operator supplies normalized detection, containment and review events from their EDR/SIEM. The expected exchange schema is `authzledger.defensive-telemetry.v1`, with `source` equal to `cobalt-strike` and an `events` array. Each row contains exactly `record_id`, `asset`, `observed_at` (UTC) and `event_type`. The full input contract has a 512 KiB limit, at most 4,096 events and requires unique record IDs. [Synthetic example](../fixtures/offline-tools/telemetry.json)

```sh
python -m authzledger assessment telemetry-summary fixtures/offline-tools/telemetry.json
```

The summary counts event types, records each original JSON pointer, hashes the asset and record identifiers, and binds the original bytes by SHA-256. It is unsigned. A normalized event records a source assertion. For a comparison bound to a particular retest, use the existing [retrospective control-evidence workflow](blue-evidence.md) with the original retest bytes and matching context. Native Cobalt Strike logs and commercial scanner services are outside these import profiles.

© Nasser Aldin Farag (0xFarag). All rights reserved.
