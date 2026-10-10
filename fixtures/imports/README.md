# Offline import fixtures

The three original format fixtures below are authored and synthetic; they are not claimed to be captured exports from installed third-party tools. Every credential and private marker in them is a public test canary. `chromium-real.har` and `zap-real.json` are separately identified as actual browser/tool exports.

* `burp-http-messages.xml`: HTTP-message XML `<items>` with base64 request/response. Only the no-DTD profile is accepted. Exports with a DOCTYPE are explicitly rejected under the import contract.
* `zap-traditional-json-plus.json`: ZAP Traditional JSON Report with Requests and Responses, using the official `site` / `alerts` / `instances` and `request-header` fields.
* `har-1.2.json`: HAR 1.2 `log.entries` profile.

Pinned format references:

* https://portswigger.net/burp/documentation/desktop/tools/message-editor
* https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json-plus/
* https://www.softwareishard.com/blog/har-12-spec/

No parser connects to any imported URL. Source digests bind the redacted normalized projection only. Input credentials, response bodies, scanner descriptions and raw errors are not retained.

## Mapping and supported bounds

`parse_import(raw_bytes, format_profile, limits=None)` is offline. The parser accepts at most 10 MiB, 500 entries, 1 MiB per decoded body, 100 headers and JSON/XML depth 64; callers may only reduce these limits. Echo filtering has an additional bounded redaction budget. Duplicate JSON keys, non-finite values, DTDs, entity declarations and invalid base64 fail closed. Duplicate HTTP headers/query names, unsupported bodies, mismatched framing and incomplete messages remain visible execution blockers. No compressed or multipart message decoding is performed.

Request header values outside the safe content-negotiation allowlist become required binding slots. Transport headers are omitted with explicit gaps. Every query value and JSON string is conservatively redacted. Credential-labelled or token-shaped path segments are redacted; ordinary path identifiers remain visible. Known request credentials echoed in other retained request fields are removed across the complete batch. This is not a claim that arbitrary unlabeled application data can be classified as secret automatically: the operator must review ordinary paths, field names and declared public literals before use. Response bodies, response headers and scanner descriptions are never retained.

`resolve_imported_entry(entry, mappings)` accepts a slot-ID map with `{"literal": scalar}` or `{"omit": true}`. Literals are an explicit operator declaration of public data. Credential-labelled query/JSON fields may only be omitted; credential path/header slots cannot be replaced with literals. Header credentials are separately mapped to scoped identity references. Replacements create a new entry ID, retain source/parent IDs and record the safe mapping operations; original source entries are unchanged. Partial mappings retain blockers. Structural blockers are never silently cleared. JSON array members can be replaced but not removed.

Example for a benign redacted query or JSON value:

```json
{"slot-1": {"literal": "invoice-A"}, "slot-2": {"omit": true}}
```

The authored fixtures establish parser regression behavior, not interoperability certification against installed Burp/ZAP releases. A genuine ZAP 2.17.0 JSON+ export is now verified below. Genuine compatible Burp export acceptance remains unverified. Burp exports containing a DOCTYPE are rejected, never silently rewritten.

## Actual Chromium / Playwright HAR capture

`chromium-real.har` is the unmodified HAR emitted by Playwright 1.64.0 while Chromium 153.0.8010.0 performed two HTTP requests against a temporary, owned loopback server. Its content is public lab data authored for this repository. It contains no authentication, cookies or external website requests. This closes the **browser-produced HAR parser fixture** gap; it does not constitute a manual Chrome DevTools export or Burp/ZAP interoperability certification.

`chromium-real.provenance.json` records the exporter/browser versions, HAR creator, two observed requests, loopback origin, reproduction command and fixture byte digest. The digest is permitted here because this specific authored capture intentionally contains no credentials; the production importer still hashes only redacted normalized projections. The capture script does not rewrite the HAR after the exporter flushes it.

Reproduce from the repository root with already installed tooling:

```sh
PLAYWRIGHT_MODULE=/path/to/node_modules/playwright CHROME_EXECUTABLE=/path/to/chromium node tools/capture_har_fixture.cjs
python3 -m unittest discover -s tests -p test_imports.py -q
```

The actual export exposed a compatibility defect that the handcrafted fixture did not: browser `Origin`/`Referer` values and an ordinary invoice ID had been classified as known credentials, which incorrectly redacted the target origin and object path. Those header values are still omitted into explicit binding/omission slots, and JSON strings are still conservatively redacted for mapping. Only credential-classified values participate in cross-field credential-echo removal. Regression tests retain credential-echo checks for Authorization, Cookie, query tokens and sensitive JSON fields.

## Precise Burp / ZAP acceptance boundary

PortSwigger's current report documentation says its XML output contains an internal DTD:

* https://portswigger.net/burp/documentation/desktop/running-scans/reporting/report-settings

Its HTTP-item export release documentation describes the XML DTD and base64 attributes:

* https://portswigger.net/burp/releases/professional-1-4-04

The current message-editor documentation describes **Save item** as XML request/response export:

* https://portswigger.net/burp/documentation/desktop/tools/message-editor

The implementation contract prohibits every DTD. Therefore any DTD-bearing export is rejected with `xml_declarations_forbidden`; no internal-DTD allowlist or silent stripping is applied. The supported profile is DTD-free `<items>` HTTP-message XML. Direct compatibility with a current installed Burp **Save item** export is not demonstrated. The product must not claim universal or one-click Burp export compatibility until a contract-compliant export path is verified.

The ZAP parser field names follow the official **Traditional JSON Report with Requests and Responses** example:

* https://www.zaproxy.org/docs/desktop/addons/report-generation/report-traditional-json-plus/

The authored ZAP fixture remains explicitly synthetic. The separate native fixture below verifies one installed, pinned exporter profile; it does not certify all ZAP versions, profiles or scanners.

## Actual ZAP 2.17.0 JSON+ export

`zap-real.json` contains the unchanged bytes emitted by ZAP **2.17.0**, Report Generation **0.43.0**, using native `reports.generate` with `traditional-json-plus`. The downloaded Linux distribution matched SHA-256 `efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a` from the official release. ZAP ran with `-silent -notel`, an isolated temporary home and a keyed API bound to loopback. One actual GET to an owned, credential-free local fixture produced passive rule 10021's native missing-header alert. No custom alert or report JSON was fabricated.

The export SHA-256 is `f5212d5dbbf7e12439002656b4888741a9bf0af58bbba1aa28b9436c071bfe87`. `zap-real.provenance.json` binds producer/add-on versions, distribution source, original bytes, observed requests and the separate execution artifact. The native report contains an unrelated Firefox client-integration startup error and driver warnings; those diagnostics remain visible. The checked path is core HTTP → passive rule → report generation, not ZAP browser automation.

After import, the User-Agent slot was explicitly omitted and new lab identity references, identity probe, owner control, denial control, protected marker and four-request budget were supplied through `compile_imported_experiment`. `zap-real.execution.json` records the actual four-request controlled run. Its source ID equals the parsed native entry ID, its finding is `confirmed`/`denial_data_disclosure`, and `verify_execution` returns no errors. The ZAP missing-header assertion itself remains `not_verified`; it is not converted into an AuthzLedger finding.

Reproduce into a **new directory** (the harness refuses overwrites):

```sh
python3 tools/capture_zap_fixture.py \
  --zap-dir /path/to/ZAP_2.17.0 \
  --archive /path/to/ZAP_2.17.0_Linux.tar.gz \
  --output /new/capture/directory
python3 -m unittest discover -s tests -p test_imports.py -q
```

Ports and timestamps legitimately differ between captures; a new capture has its own hashes and provenance. The script never rewrites the native report. Raw-byte fixture hashes are used only because this capture intentionally contains public lab data and no credentials; production import digests still cover the redacted normalized projection only.

The native report's upstream-generated scanner descriptions are from ZAP, under [Apache-2.0](https://github.com/zaproxy/zap-extensions/blob/main/LICENSE). The authored lab data and capture harness use the repository licence. F01-01 remains **partial** until its genuine compatible Burp component is verified; see [exporter gate](../../docs/exporter-gate-1.1.0.md).
