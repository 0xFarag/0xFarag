# Saved detection evidence

Compare one source-bound retest result with one operator-supplied event/alert export. Studio and CLI call the same local function. The result is an unsigned derivative for incident-response handover. It carries the original retest statuses and both input hashes. It makes no change to the assessment, its evidence levels or its signed package. A production detection claim still requires independent review of the export and its provenance.

## Try the saved example

```sh
python -m authzledger assessment blue-evidence \
  examples/blue-evidence/mixed-c-result.json \
  examples/blue-evidence/control-lab.json --out blue-evidence.json
```

With Studio open, choose **Investigate → Compare saved detection evidence**. Select the retest result and the saved signals, then compare. Studio displays each sample status and downloads the same JSON. Input files stay local to the Studio installation. The CLI writes to stdout by default and exclusively creates a named output file.

The example retest is a byte-for-byte copy of the public mixed-C artifact with SHA-256 `e88fa8b182ad1d7b3477516c1432e24a919d1882a4221bf2cb8e25265cff4bd8`. One finding was retested and marked `fix_verified`. The second remains `not_retested`. The four named samples in `control-lab.json` are synthetic and exercise each status independently.

| Status | Evidence in this sample |
| --- | --- |
| observed | At least one qualifying event has an alert referencing that exact event ID and expected rule. |
| telemetry_only | A qualifying event exists. Its expected alert is absent from this export. |
| unavailable | Both event and alert lists are empty. |
| incomparable | Records exist, but no event has the required source, assessment, scope, finding and timestamp. Includes an alert with no qualifying event. |

## Operator export contract

Use UTF-8 JSON. Set `schema` to `authzledger.control-signals.v1` and `dataset` to `operator-supplied-signals`. The example's `authzledger.website-lab.v1` identifies the published synthetic profile. Choose opaque, non-sensitive IDs. The input label records the operator's declaration. It does not authenticate the origin of the events.

| Field | Meaning |
| --- | --- |
| anchor_sha256 | SHA-256 of the exact retained retest JSON file. Reformatting changes it. |
| expectation.assessment, scope, finding | Assessment ID, scope digest and selected finding ID from the retest. |
| expectation.source, rule | Operator-declared telemetry source and rule ID. |
| expectation.from_utc, until_utc | Inclusive event start and exclusive end, with explicit UTC offset. The operator selects this window for the telemetry pipeline. |
| controls | Map of 1–32 named samples. Each has arrays of events and alerts, each capped at 4,096 entries. |
| events[] | Required fields are event ID (`event`), `assessment`, `scope`, `finding`, `source` and event timestamp (`at`). Event IDs must be unique within a sample. |
| alerts[] | `event` references an event in that sample. `rule` identifies the observed rule. This profile does not establish when the alert fired. |

Each file may be up to 512 KiB. Duplicate JSON keys or ambiguous source finding IDs cause an error. Source retests must provide an assessment ID, scope digest, snapshot digest and finding transitions. The reader checks the known source status vocabulary and each baseline finding digest. A retested row must carry a current finding digest. An omitted row must carry none. The output field `source_assertions_verified: false` distinguishes copied assertions from independent proof. A correctly shaped and rehashed forgery is outside the integrity guarantee of this unsigned comparison. Each output lists the accepted event IDs, linked alert event IDs and input counts. Other export fields are outside this profile and are omitted from the derivative. Verify the original signed handover separately using its trusted verification key. Collecting telemetry, querying a SIEM and dispatching alerts are outside this offline comparison.

ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
