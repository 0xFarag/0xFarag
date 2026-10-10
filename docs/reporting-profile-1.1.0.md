# AuthzLedger 1.1.0: assessment reporting profile

This document describes implemented reporting services, not a promise of complete standards compliance. The module is `authzledger.assessment_reports`; CLI and Studio use the same functions. Original v1 reports, contract digests and evidence roots are retained without re-sealing.

## Installed renderer

```sh
python3 -m pip install '.[reports]'
```

The core package remains dependency-free. The `reports` extra pins `reportlab==4.4.9`. Missing ReportLab or another ReportLab version is an explicit PDF export/semantic-verification error; HTML is never substituted for PDF. HTML/JSON export and packages without a PDF do not need the extra. OpenSSL remains the existing Ed25519 implementation.

The profile is `assessment-html-pdf-v1-reportlab-4.4.9-dejavu-2.37`. It fixes A4 pages, margins, typography, PDF invariant metadata, and the bundled fonts. The renderer makes no network requests and executes no HTML from assessment content. Exported HTML is escaped, self-contained and uses `default-src 'none'`; sources and long URLs are inert text. PDF text is escaped before entering ReportLab's paragraph parser. Missing font glyphs block export explicitly instead of replacing evidence text with invisible boxes. This font profile supports the tested Latin, Greek and Cyrillic repertoire; it is not a claim of universal script shaping or CJK support. Reports are not PDF/UA-certified.

| Artifact | SHA-256 |
|---|---|
| ReportLab `reportlab-4.4.9-py3-none-any.whl` | `68e2d103ae8041a37714e8896ec9b79a1c1e911d68c3bd2ea17546568cf17bfd` |
| ReportLab `reportlab-4.4.9.tar.gz` | `7cf487764294ee791a4781f5a157bebce262a666ae4bbb87786760a9676c9378` |
| `fonts/DejaVuSans.ttf` | `ae7b7855e115a5966d8b1b3f80f254ccc117ec86f9965e202ee2940453837280` |
| `fonts/DejaVuSans-Bold.ttf` | `5c1247acef7f2b8522a31742c76d6adcb5569bacc0be7ceaa4dc39dd252ce895` |
| `fonts/LICENSE-DejaVu.txt` | `e180b3d65bf650dffffd71dd21b6180767b469a18dd87e1d8552be69bb9ecdf0` |

ReportLab archive hashes are the publisher's PyPI file hashes, checked on 2026-10-10. Font hashes are computed from the actual bundled files and enforced before PDF rendering. DejaVu's redistribution notice ships alongside the fonts; the fonts do not acquire AuthzLedger's proprietary license. ReportLab's transitive dependencies are resolved by the package manager; the table is not a claim of a complete transitive supply-chain lock. The exact-render profile was exercised on Python 3.12/Linux. A different renderer producing different bytes is rejected rather than silently classified as equivalent.

## Public services

```python
freeze_assessment(executions, metadata, comparisons=None,
                  *, workflows=None, reductions=None, assurances=None) -> dict
verify_assessment(snapshot) -> list[str]
render_assessment_json(snapshot) -> str
render_assessment_html(snapshot) -> str
render_assessment_pdf(snapshot) -> bytes
assessment_attachments(snapshot, formats=("json", "html", "pdf")) -> dict[str, bytes]
export_assessment(snapshot, out, formats=("json", "html", "pdf")) -> dict[str, Path]
create_assessment_bundle(snapshot, out, key,
                         formats=("json", "html", "pdf")) -> dict
validate_cvss_vector(vector) -> dict
reporting_catalog() -> dict
```

All functions are offline. Export destinations must be new, symlink-free directories with an existing parent. Files use exclusive creation and mode 0600; failed writes remove the partial new directory. Rendering and validation finish before export writes begin. `assessment_attachments` always includes `assessment.json` even when a caller requests only HTML or PDF, because a visual export needs its retained semantic source.

`freeze_assessment` accepts up to 100 experiment executions, 100 workflow traces and 100 reduction traces, up to 100 comparisons, and at most 500 distinct experiment finding IDs. An optional `assurances` list accepts up to 100 finite workflow-assurance results. Its verified cycle traces are included in the 100-workflow limit, with exact duplicates removed. The entire canonical snapshot is limited to 16 MiB. At least an experiment execution or workflow trace is required. Workflow-only snapshots are supported. For packaging, a retained executed v1 report must exist as an anchor.

## Snapshot contract

`AssessmentSnapshot v1` has exactly these fields, reconstructed during verification:

- `schema_id: authzledger.assessment-snapshot`, `schema_version: 1`, `kind: assessment-snapshot`.
- `renderer_profile`, `catalog_profile`, `metadata`.
- Original `executions`, `workflows`, `reductions` and `comparisons`.
- Derived `findings`, `workflow_findings`, `summary`, `coverage`, `standards`, `limitations`.
- `snapshot_digest`.
- Optional `assurances`, present only when nonempty. Existing snapshots without assurance keep exactly the same object shape and rendering.

The digest is SHA-256 of `AuthzLedger:assessment-snapshot:v1\n` plus sorted-key, compact, ASCII-escaped, finite JSON excluding only `snapshot_digest`. This is the documented Python canonicalization profile, not an RFC 8785 claim. Unknown fields, extra digest references or changed derived statements fail full reconstruction, even if an attacker recomputes the snapshot digest. File-level parsers must reject duplicate keys before calling the object API; the package parser already does so.

Metadata accepts `assessment_id`, `title`, `reviewer`, `executive_summary`, `scope` (list of strings), `period` (text), `limitations` (list of strings), and `finding_annotations` (map keyed by a retained experiment finding ID). Missing editorial fields receive explicit neutral defaults, never inferred business assertions. Metadata is operator-authored and must not contain credentials.

Annotations accept `impact`, `remediation`, `business_risk`, `cvss_vector` and `standard_refs`. They cannot override computed status, controls, oracle result, case ID, evidence or report root. The original finding record is retained under `record`; editorial fields are separate. `source` binds the exact source execution/report/contract. `versions` retains all supplied versions of a stable finding, sorted by execution and finding digest. A reused finding ID with a different origin, rule digest, resource, case or identity definition is rejected; it cannot hide a confirmed finding behind a safe result from another target.

`status` on the assessment row is a separately reconstructed lifecycle: `confirmed`, `candidate`, `rejected`, `retest_pending` or `retest_verified`. Original `record.status` is never rewritten. Current evidence is selected through explicit verified experiment-comparison edges, not execution argument order. Without such an ordering, a confirmed historical record stays open. A unique terminal, verified fix gives `retest_verified`; an inconclusive, omitted or conflicting terminal retest gives `retest_pending` when a confirmed finding existed. Comparison cycles are rejected. Several incomparable terminal branches do not establish one current fix. Summary counts use this lifecycle, consistently in all three formats.

Each finding reference must resolve to an observation in its own verified execution, with matching case and report root. Full `verify_execution` repeats contract/graph/control/observation/finding reconstruction. A foreign but correctly hashed observation cannot be transplanted into the report.

A `ComparisonEnvelope v1` is verified directly and must reference a retained baseline execution. An `experiment-comparison` additionally requires **both** original baseline and current executions. `compare_executions` recomputes its complete content, including scoped `fix_verified` or `not_retested` transitions. Rehashing a false fix classification does not make it acceptable. The human report keeps the configured-check transition and the finding-level fix assessment separate.

Workflow traces are checked with `verify_workflow`. Their derived findings preserve variant identity, interpretation, valid controls, cleanup status and every materialized step report root. The report explicitly states `evaluation_attested` because state values are not retained. Reduction traces are checked with `verify_reduction`; their original experiment/workflow digest must be present in the snapshot. The report shows the original and accepted evidence, attempt count, stopping reason and conditional one-minimal result. Reduction does not replace the original evidence.

Finite workflow assurance results are checked with `verify_workflow_assurance`; the original outer object, schedule, shared budget ledger and cycle history anchors are retained under `assurances`. Each original cycle trace also appears exactly once in `workflows`, so ordinary workflow finding/report verification is reused. HTML and PDF show the bounded cycle count, stop reason, shared request usage and chained history references. Tampered history references fail reconstruction even after rehashing the outer assurance result. The snapshot does not imply continuous observation between cycles or after the approved finite schedule.

## One semantic source, three formats

`assessment.json` is the canonical complete snapshot. Both visual formats use one ordered `_sections` view derived from that snapshot. Every export displays the same finding IDs, statuses, oracle verification levels, CVSS vectors, original roots and retest references. Layout and whitespace may differ; evidence claims may not.

Content includes executive summary, scope, reviewer, period, method, explicit coverage limitations, experiment and workflow findings, expected checks, control references, observations, reproduction instructions, impact, remediation, business risk, reduction results, selective retest classifications, standards references and verification instructions. The signer fingerprint is in the signed package manifest, which the report explicitly references; an unsigned standalone report does not invent a signer.

Reproduction instructions use retained scoped contracts and credential references. Credential values and response bodies are not fetched by reporting. `captured_inputs_replayed` means that approved oracle projections are re-evaluated offline. Their relationship to unavailable raw response bytes remains signer-attested. Neither that level nor a signature proves a remote server really returned the data.

## Pinned standards and CVSS

The catalog profile is `owasp-asvs-5.0.0-wstg-4.2-api-2023-cvss-4.0-v1`. Its explicit requirement subset is ASVS V8 authorization (8.1.1-8.1.4, 8.2.1-8.2.4, 8.3.1-8.3.3, 8.4.1-8.4.2), WSTG authorization ATHZ-01 through ATHZ-04 and business logic BUSL-01 through BUSL-09, and API1:2023 through API10:2023. Unlisted requirements are rejected rather than silently treated as supported.

Every standards mapping requires exact standard/version/ID, `supports|partially_covers|related`, a reviewer rationale and evidence references belonging to that finding. It represents the reviewer’s scoped relationship assertion. A syntactically valid mapping is not automatic proof of an entire standard requirement or global compliance. No mappings are assigned automatically from a status code or vulnerability label.

CVSS 4.0 validation covers all base, threat, environmental and supplemental metric names and case-sensitive values, mandatory base metrics, exact specification order and duplicate rejection. Metric syntax alone does not establish a justified severity. This implementation stores an analyst vector as `not_scored` with `score: null`; it does **not** calculate or publish a numerical CVSS score. Submitted score fields are rejected. This avoids unsupported precision and keeps business risk separate from technical severity.

Official sources checked during implementation:

- ASVS 5.0.0 release: <https://github.com/OWASP/ASVS/tree/v5.0.0>.
- Exact ASVS authorization catalog: <https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/en/0x17-V8-Authorization.md>.
- WSTG 4.2 authorization: <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/>.
- WSTG 4.2 business logic: <https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/>.
- API Security Top 10 2023: <https://api-security.owasp.org/editions/2023/en/0x11-t10/>.
- FIRST CVSS 4.0, especially vector table 23: <https://www.first.org/cvss/v4.0/specification-document>.
- ReportLab release files and hashes: <https://pypi.org/project/reportlab/4.4.9/#files>.

Only identifiers and original mapping metadata are included; the product does not reproduce the standards' requirement texts.

## Signed package semantics

Reserved paths are `attachments/assessment.json`, `attachments/assessment.html` and `attachments/assessment.pdf`. A visual assessment attachment without its snapshot is rejected. The main verifier reconstructs the entire snapshot, matches the package’s anchored v1 report exactly (the unique terminal compared execution, otherwise a deterministic retained report), then regenerates each present visual export and compares exact bytes. The snapshot export itself must have canonical bytes.

No exported report includes its own future file hash or package manifest hash. The existing EvidenceBundle v1 manifest inventories the already-rendered payloads and is signed only after those bytes exist. Old bundles retain their previous semantics. Existing original reports and roots are not migrated.

The independent standalone verifier checks the external trusted Ed25519 key, signature, exact inventory, byte counts and payload hashes. It intentionally does not repeat new assessment semantics. A deliberately dishonest PDF re-signed by a real key holder can therefore pass that integrity-only check; it is rejected by the main verifier's exact-render check. A missing/mismatched PDF renderer fails that semantic verification explicitly rather than downgrading silently.

## Verification evidence

`tests/test_assessment_reports.py` exercises real local HTTP evidence, strict snapshot reconstruction, metadata/status separation, foreign evidence rejection, scoped standards mappings, complete CVSS vector grammar, HTML injection, offline rendering, deterministic PDF bytes, text-level export parity, missing glyph failure, exclusive exports, independent key verification, re-signed false PDF rejection, reconstructed fix comparisons, workflow-only snapshots, original-bound reduction traces, and a real two-cycle assurance run with twelve globally budgeted requests and a signed proof binding its history anchors.

A 50-finding real HTTP fixture exercises long Unicode titles, Greek characters, long URLs and all evidence references. The rendered PDF had 72 A4 pages. All pages were rasterized and visually reviewed as four contact sheets; no clipped or overlapping content was observed. The complete finding IDs and observation references were also extracted from the PDF and compared with the snapshot.

Local reproducible QA artifacts (intentionally excluded from the source distribution):

- `artifacts/report-qa/fifty-findings.pdf` and `fifty-findings.html`.
- `artifacts/report-qa/snapshot.json`.
- `artifacts/report-qa/page-01.png` through `page-72.png`.
- `artifacts/report-qa/contact-1.png` through `contact-4.png`.

The finite-assurance fixture also produces a five-page PDF containing two independently
controlled workflow cycles, twelve requests in one budget ledger, both cleanup results
and the chained history anchors. All five pages were rasterized and visually reviewed.
`artifacts/report-qa/assurance-snapshot.json`, `assurance.pdf`, `assurance.html`,
`assurance-page-1.png` through `assurance-page-5.png` and `assurance-receipt.json`
retain that local review. Both QA snapshots pass semantic verification and reproduce
their PDF bytes exactly; the optional assurance support leaves the 72-page fixture
unchanged.

Run the focused automated suite with:

```sh
python3 -m unittest discover -s tests -p test_assessment_reports.py -v
```

The four PDF-dependent tests explicitly skip when the optional renderer is absent. A release claiming PDF support must install the reports extra and run them without skips. Layout review is a release gate in addition to text extraction; a passing text assertion alone does not establish readable layout.
