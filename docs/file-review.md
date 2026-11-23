# Review a local file

```sh
python -m authzledger file-review FILE
python -m authzledger file-review FILE --clamav
```

The JSON result records the byte count, SHA-256, SHA-1 and MD5. Use SHA-256 to bind the review to the file. SHA-1 and MD5 permit matching legacy inventories. File contents, filenames and scanner output are omitted from the report. The command never executes the file or submits it to a remote service.

With `--clamav`, AuthzLedger uses an installed `clamscan` executable on the operator’s PATH and the signature databases already on that machine. AuthzLedger sends the fingerprinted file bytes to its standard input. ClamAV may use private temporary files during scanning. AuthzLedger removes its temporary directory on completion or timeout. Source files are read-only. No signature download, daemon, quarantine or automatic remediation is enabled.

| Engine status | Meaning | Command exit |
| --- | --- | --- |
| `not_requested` | Fingerprints computed without a scan. | 0 |
| `no_detection_reported` | The recorded ClamAV version reported no match and a complete single-file summary for the supplied bytes. | 0 |
| `detection_reported` | The local signatures or heuristics produced a detection. | 1 |
| `unavailable` | A local scanner executable was unavailable. | 2 |
| `incomplete` | Empty or oversized input for scanning, timeout, encrypted content, a reported limit, warning or incomplete summary. | 2 |
| `error` | The scanner failed, for example while loading its local databases. | 2 |

Regular files up to 256 MiB are fingerprinted. Live byte-count or metadata changes during reading invalidate the review. The scan ceiling is 16 MiB per input, 64 MiB total decoded data, 256 embedded files and eight nested levels. ClamAV's internal scan-time budget is 30 seconds. The overall process limit is 75 seconds. ClamAV version and local signatures, format support and parser limits affect detection coverage. Some unsupported content can pass through without a warning. A no-detection result provides no general safety verdict. The result is unsigned.

© Nasser Aldin Farag (0xFarag). All rights reserved.
