# F01-01: Native exporter acceptance

Review date: 10 October 2026. Status: **partial; production release blocked**.

The acceptance contract requires an actual versioned export from Burp, ZAP and a HAR producer, with traceable HTTP fields and provenance. A handwritten format fixture, an official example copied into a file, or a filename containing a tool version does not satisfy this gate.

| Producer/profile | Actual evidence | Status |
|---|---|---|
| Playwright 1.64.0 / Chromium 153.0.8010.0 / HAR 1.2 | `fixtures/imports/chromium-real.har` and matching provenance; two real public loopback requests | Verified browser-produced HAR; not a manual DevTools export |
| ZAP 2.17.0 / Report Generation 0.43.0 / `traditional-json-plus` | `fixtures/imports/zap-real.json`, matching provenance and separate controlled execution | Verified native exporter component |
| Burp / HTTP-message XML | Only explicitly synthetic `burp-http-messages.xml` is available | Genuine compatible native export missing |

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

## Burp: exact remaining blocker

PortSwigger documents **Save item** as a native XML request/response export in its [message editor documentation](https://portswigger.net/burp/documentation/desktop/tools/message-editor). Its [HTTP-item XML export release documentation](https://portswigger.net/burp/releases/professional-1-4-04) describes a DTD with base64 attributes. The current [XML issue report documentation](https://portswigger.net/burp/documentation/desktop/running-scans/reporting/report-settings) also describes an internal DTD; issue reports and HTTP-item exports are different formats.

The binding [1.0.5 implementation contract](implementation-1.0.5.md), F01, excludes **DTDs and entities**. The implementation accordingly returns `xml_declarations_forbidden` before XML parsing. It accepts the documented DTD-free `<items>` profile only. No native, installed-version Burp procedure producing that supported profile has been demonstrated here. The environment did not contain an installed Burp instance; official documentation alone cannot supply the missing export or prove such an option exists.

The next concrete Burp action is:

1. Record the installed Burp edition and exact version, acquisition source and installer/JAR digest. Use an isolated temporary project containing only the public local lab; no customer traffic or credentials.
2. Capture one request and its response against that lab. Use the native **Save item(s)** XML action with base64 message encoding. Preserve the complete output exactly as emitted; record a screenshot or export receipt, export settings and hash.
3. Inspect whether the native output contains a DOCTYPE. A DTD-bearing original must fail the existing importer. It may be preserved as an additional **negative** interoperability fixture, never relabelled as accepted.
4. A genuinely supported native DTD-free option, if the installed tool offers one, must be demonstrated with a second unchanged export. Run import, explicit mapping and a budgeted controlled execution; record the resulting source and execution digests.
5. If the native exporter cannot emit a contract-compatible profile, the frozen contract and native exporter remain incompatible. Supporting a reviewed inert-DTD profile would require an explicit contract change, a separate parser design and hostile-input tests; it is not an implementation shortcut authorised by this gate. No blanket DTD allowance, regex stripping, reconstructed XML or relabelling of a derived file is acceptable.

No Burp download, installation or export is claimed by this review. The DTD rejection was not relaxed. A successful negative test alone cannot close F01-01.

## Required provenance and release decision

Every actual export needs the native file, its SHA-256, capture time with offset, tool/edition/version, exporter/profile and relevant add-on versions, distribution source/digest, native export action/settings, owned origin, observed HTTP request count, public-data declaration, reproduction command and verification artifacts. Derived mapping and execution evidence must remain separate from the unchanged native source. Raw-byte digests in this repository are appropriate only for deliberately public fixtures; live imports retain the secret-free projection hashing contract.

The ZAP sidecar supplies those applicable fields and binds its separate controlled execution. The HAR sidecar supplies the browser/exporter fields. Neither establishes a Burp export by analogy.

The correct target version remains **1.1.0** for the F01–F08 feature release. `1.1.5` is not a remedy for an open feature acceptance gate. Until the missing Burp component is verified, retain the development version, keep F01-01 partial and do not publish a stable release. A transparent development update may describe exactly the verified components without claiming 88/88 acceptance or full Burp interoperability.
