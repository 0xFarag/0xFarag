# F01-01: Native exporter acceptance

Review date: 10 October 2026. Status: **native evidence present for all three producers under the explicit F01 addendum; final release gates remain separate**.

The acceptance contract, including the [native Burp profile addendum](burp-native-import-v1.md), requires an actual versioned export from Burp, ZAP and a HAR producer, with traceable HTTP fields and provenance. A handwritten format fixture, an official example copied into a file, or a filename containing a tool version does not satisfy this gate.

| Producer/profile | Actual evidence | Status |
|---|---|---|
| Playwright 1.64.0 / Chromium 153.0.8010.0 / HAR 1.2 | `fixtures/imports/chromium-real.har` and matching provenance; two real public loopback requests | Verified browser-produced HAR; not a manual DevTools export |
| ZAP 2.17.0 / Report Generation 0.43.0 / `traditional-json-plus` | `fixtures/imports/zap-real.json`, matching provenance and separate controlled execution | Verified native exporter component |
| Burp Community 2026.9.2 / `burp-http-pair-v1` | `fixtures/imports/burp-native-v1/`: unchanged native Raw request/response files, UI receipts, provenance and controlled execution | Verified native message export under the explicit addendum |
| Burp Community 2026.9.2 / native Save item XML | Unchanged `burp-native-v1/burp-http-messages.xml` containing a DTD | Correctly rejected with `xml_declarations_forbidden`; negative fixture only |

## Reproduce the verified ZAP component

The recorded binary was acquired from the [official ZAP 2.17.0 release](https://github.com/zaproxy/zaproxy/releases/tag/v2.17.0). The Linux package's published and observed SHA-256 is `efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a`. The checked runtime was OpenJDK 17.0.20. A pinned historical tool version is used for format reproducibility, not represented as universally current or suitable for other deployments.

```sh
curl --fail --location --output ZAP_2.17.0_Linux.tar.gz \
  https://github.com/zaproxy/zaproxy/releases/download/v2.17.0/ZAP_2.17.0_Linux.tar.gz
sha256sum ZAP_2.17.0_Linux.tar.gz
tar -xzf ZAP_2.17.0_Linux.tar.gz
python3 tools/capture_zap_fixture.py \
  --zap-dir ./ZAP_2.17.0 \
  --archive ./ZAP_2.17.0_Linux.tar.gz \
  --output ./new-zap-capture
python3 -m unittest discover -s tests -p test_imports.py -q
```

Compare the digest with the independently opened official release before extraction. The capture harness also refuses a mismatching archive and any existing capture output. Its temporary ZAP process uses loopback binding, a generated API key, `-silent` and `-notel`. It disables passive scanner rules, enables native rule 10021, makes one public fixture request, waits for passive scanning and calls the official [Report Generation API](https://www.zaproxy.org/docs/desktop/addons/report-generation/api/) using [Traditional JSON with Requests and Responses](https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json-plus/). No active scan, spider, external target or manually added alert is used.

The original report is read without modification. Explicit mapping supplies fresh identity references, principal/owner/denial controls, the protected marker and a four-request budget. The separate execution has four dispatched requests and a confirmed synthetic marker disclosure; its source references bind the parsed native entry. Native ZAP assertions retain `not_verified` status.

Each reproduction has its own timestamps, ephemeral port and hashes. It must create a new provenance sidecar, not replace the historical fixture's contents or digest. Startup diagnostics about unused Firefox integration remain in the native report and in the provenance summary; this acceptance does not assert that every installed ZAP add-on works.

## Burp: verified native raw-message path

PortSwigger documents **Copy to file** separately from **Save item** in its [message editor documentation](https://portswigger.net/burp/documentation/desktop/tools/message-editor). The [F01 addendum](burp-native-import-v1.md) explicitly adds the complete native Raw request/response pair as `burp-http-pair-v1`. It does not reinterpret a modified XML file as a native export, relax the original DTD prohibition or retroactively rewrite historical acceptance records.

The pinned official Burp Community **2026.9.2** JAR has SHA-256 `3571f8cadbfd65b0b090d2753735c40b76ad7fdde0b927df2b22ec46ea09693a`. The isolated temporary project used an owned, public synthetic loopback fixture. The observed message-editor action was **Save selected text to file** in the Raw tab with **no selection**, which saved each complete message. The native request and response bytes equal the corresponding base64 messages in the independently retained native XML. The XML itself was neither modified nor accepted by the importer.

| Retained original | SHA-256 |
|---|---|
| `burp-request.http` | `494b9be5fc48c4f8faf23bf2f01d1647e473fbe81831d74143d6368c8c5cbedb` |
| `burp-response.http` | `552123446e70539dd222b275c733b451ccc4dac7a76702888c750cb44a5ecd61` |
| `burp-http-messages.xml` — rejected | `1f4157ec2e306dc11c9192e7f0efcf9425b92b53af4b8526b322025d488cd67d` |

`burp-real.provenance.json` binds the distribution, native files, screenshots and capture harness. The UI receipt retains the actual menu label and absence of selection. The source origin is explicit operator metadata; the parser never infers TLS from a Host header. Import then applies the same bounded redaction and mapping rules as the other profiles.

The fixture records **one native capture request and four separately counted controlled requests**. The latter use fresh identity, owner and denial controls and produce a confirmed synthetic marker disclosure. The execution retains its imported source ID and passes semantic verification. Scanner assertions and imported responses themselves are not promoted to verified findings.

Check the retained original evidence offline:

```sh
python3 tools/check_native_burp.py
python3 -m unittest discover -s tests -p test_imports.py -q
```

To collect a separate reproduction with the pinned official JAR, use a **new directory**:

```sh
python3 tools/capture_burp_fixture.py \
  --burp-jar /path/to/burpsuite_community_v2026.9.2.jar \
  --out /new/burp-capture --wait-seconds 1200
```

The harness prints the owned origin and completion protocol. Make exactly the requested native capture, save the complete request and response with no text selected, preserve the actual UI receipts and finish the documented completion record. The harness then performs the separate controlled execution. New ports and timestamps produce new hashes and provenance; do not overwrite this pinned historical capture. `check_native_burp.py` intentionally checks the retained reviewed fixture, rather than accepting arbitrary new provenance as equivalent.

The original `burp-xml` parser still accepts only the supported DTD-free `<items>` profile. The native **Save item** export from this pinned installation contains a DOCTYPE and fails before XML parsing. A successful negative XML test alone is not positive native acceptance; the separately demonstrated raw-message profile supplies that path. Other Burp versions and export modes are not certified by this fixture.

## Required provenance and release decision

Every actual export needs the native file, its SHA-256, capture time with offset, tool/edition/version, exporter/profile and relevant add-on versions, distribution source/digest, native export action/settings, owned origin, observed HTTP request count, public-data declaration, reproduction command and verification artifacts. Derived mapping and execution evidence must remain separate from the unchanged native source. Raw-byte digests in this repository are appropriate only for deliberately public fixtures; live imports retain the secret-free projection hashing contract.

The Burp and ZAP sidecars supply those applicable fields and bind separate controlled executions. The HAR sidecar supplies its browser/exporter fields. Each producer has its own native evidence; none is inferred from another tool.

The release target is **1.1.0**. Native evidence closes the previously missing Burp component only within the explicit addendum and pinned profile. The full acceptance ledger, frozen-source test results, isolated wheel checks and exact-commit CI still govern stable publication. Historical `1.1.0.dev0` receipts and their original partial-gate statements remain unchanged; they are not the final candidate receipt. No claim of universal Burp interoperability follows from this acceptance.
