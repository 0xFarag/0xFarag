# Native Burp message import — F01 addendum v1

Effective: 10 October 2026. Target: AuthzLedger 1.1.0.

## Explicit change to the native interoperability acceptance

F01 originally named three input profiles, including Burp HTTP-message XML.
The later exporter runbook required a positive native DTD-free XML capture.
This addendum expands that requirement with a separate native Burp path:
**complete Raw request and response messages saved using Copy to file**.
It does not represent a derived XML file as a native export or claim that a
DTD-bearing Save item XML file is supported.

The original `burp-xml` profile remains available for its supported DTD-free
`<items>` format. Every DOCTYPE or ENTITY declaration is still rejected before
XML parsing. There is no DTD stripping, inert-DTD exception, external resolver,
XML-to-HTTP conversion or source-file rewrite in the new path.

For the Burp portion of **F01-01**, positive acceptance now requires an unchanged
native Copy-to-file request/response pair from a pinned Burp installation,
explicit source-origin metadata, provenance of the native action, bounded
offline import, explicit mapping and a separate controlled execution. Existing
ZAP and HAR acceptance requirements are unchanged. Original acceptance records
remain historical records; they are not retroactively relabelled.

PortSwigger documents [Copy to file separately from Save item](https://portswigger.net/burp/documentation/desktop/tools/message-editor).
Copy to file writes the current message, or selected bytes if a selection
exists. This profile therefore requires **no text selection** in the Raw tab.
Save the complete request and complete response in separate files. An export
receipt must identify the action actually used.

In the observed Burp Community 2026.9.2 interface, the corresponding menu label
is **Save selected text to file**. With no selection, the complete message is
saved. The UI screenshots and `observed_ui_label` in the capture receipt retain
that exact label; the harness uses the documented Copy-to-file action name as
its completion protocol identifier.

## Input and trust boundary

The versioned profile is `burp-http-pair-v1`. Its input is a native HTTP/1.0 or
HTTP/1.1 request, an optional separate response and an explicitly supplied
origin such as `https://api.example.test:8443`. The origin contains only scheme,
host and optional port. It is transport metadata, not permission to contact a
target. TLS is never guessed from a Host header or port number.

Both files share the 10 MiB input budget. Existing per-message, body and header
bounds, credential redaction and explicit mapping rules still apply. Unsupported
request lines, ambiguous framing, duplicate headers and origin/Host conflicts
block execution. Missing response bytes remain a visible gap with no invented
status. Imported responses are unverified observations, never confirmed findings.

The parser does not authenticate the application that wrote an arbitrary file.
The request/response pairing and source origin are operator-supplied metadata.
Source references say `explicit_operator_binding`; provenance comes from the
separate controlled native-export acceptance, not a filename or HTTP contents.

Stored import digests continue to bind only the redacted normalized projection.
Raw-byte hashes are retained for the deliberately public, credential-free
acceptance fixture only. No customer traffic or private credentials belong in
the repository or release proofs.

## CLI and Studio

The Python interface is:

```python
parse_import(request_bytes, "burp-http-pair-v1",
             source_origin="https://api.example.test",
             response_bytes=response_bytes)
```

The CLI adds source-origin and optional response-file arguments to the existing
assessment import command:

```sh
authzledger assessment import burp-request.http --format burp-http-pair-v1 \
  --source-origin https://api.example.test --response burp-response.http \
  --out new-import.json
```

Studio provides the same origin and separate file
inputs. Its raw profile transports exact bytes as base64; it does not pass
binary files through a UTF-8 text decoder. An explicit import action lets the
operator select both files before parsing. Existing XML, ZAP and HAR flows retain
their original behavior. The Studio file pair is limited to 2 MiB to fit within
the server's bounded JSON transport; the CLI uses the 10 MiB parser budget.

Import itself performs no network operations. The existing review, target scope,
identity binding, controls and total request budget apply before execution.

## Native acceptance procedure

`tools/capture_burp_fixture.py` verifies the pinned official Burp JAR, starts an
owned public loopback fixture and prints the exact source URL. In Burp Community,
make one request to that URL, then use native Copy to file for the request and
response. Preserve screenshots of the action and save the files unchanged.

Only after the native files and UI receipt exist does the harness import them,
compile an explicit assessment and dispatch four separately counted controlled
requests. It records the native file hashes, source projection, execution and
observed counts. A captured native XML export, when available, is independently
tested as its actual format; a DTD rejection is a negative interoperability
result, not positive XML acceptance.

Release acceptance requires the resulting native files and provenance to be
present and checked. This document alone does not close F01-01.
