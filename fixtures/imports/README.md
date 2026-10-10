# Offline import fixtures

The three original format fixtures below are authored and synthetic; they are not claimed to be captured exports from installed third-party tools. Every credential and private marker in them is a public test canary. `chromium-real.har` is separately identified as an actual browser/exporter capture.

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

The authored fixtures establish parser regression behavior, not interoperability certification against installed Burp/ZAP releases. Genuine Burp and ZAP export acceptance remains unverified. Burp exports containing a DOCTYPE are rejected, never silently rewritten.

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

No actual report emitted by an installed, version-pinned ZAP instance has been accepted in this environment. The authored ZAP fixture remains explicitly synthetic.
