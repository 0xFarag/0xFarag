# AuthzLedger 1.1.0 — release execution order

Review date: **10 October 2026, Europe/Zurich**. Owner: **Nasser Aldin Farag / 0xFarag**.

The current producer remains **1.1.0.dev0**. The intended stable version is **1.1.0** because this delivery adds the eight contracted capability areas to 1.0.0. **1.1.5 is not a substitute for an incomplete acceptance gate**: no stable 1.1.0 baseline and separately bounded patch scope have been established.

This runbook is executable preparation, not a record that a stable release has happened. Current results are recorded separately under `evidence/1.1.0-release-review/`. The binding ledger remains `docs/acceptance-1.1.0.md`.

## Priority 1 — close the exporter evidence gap

1. Preserve the existing genuine HAR and all historical evidence bytes.
2. Use genuine, versioned ZAP and Burp installations against the public loopback fixture. Preserve native export bytes. Record the exact product and exporter versions, installation digest where available, capture method, command or UI actions, public fixture revision, time, file length and SHA-256.
3. Exercise **import → explicit principal/resource/control mapping → a bounded controlled execution**. A format-only parser test is insufficient. Capture originals must not contain operator credentials, private targets or customer data.
4. Keep every DTD/entity input rejected under the binding import contract. Native Burp XML containing a DTD is a **compatibility blocker**, even if a particular declaration appears benign. Removing a DTD, relabelling a HAR as Burp XML, authoring an XML fixture or weakening the parser does not supply the missing native export evidence.
5. Only mark **F01-01 `Verifiziert`** when the complete scenario actually passes. If no native compatible Burp procedure can be demonstrated, retain its partial status, the development version and the stable-publication block. An altered supported profile requires an explicit, separately reviewed contract change; this runbook grants none.

See `docs/exporter-gate-1.1.0.md` for the exporter-specific outcome and reproduction procedure. No remaining step has a guaranteed duration; a deadline cannot substitute for evidence.

## Priority 2 — freeze and verify the intended release

Perform these steps only after F01-01 is closed. Keep the released `v1.0.0` tag at `c0d4446a17ca15fb4e8a71f20f6b02c1a364e90c`, its asset hashes and `evidence/1.0.0/` unchanged. Work exclusively on `authzledger-v1.1.0`; the repository's profile branch `main` is unrelated.

1. Set both `pyproject.toml` and `authzledger/__init__.py` to **1.1.0**. Update `RELEASE.json`, `RELEASE_NOTES.md`, `CHANGELOG.md`, `INSTALL.md` and `docs/release-1.1.0.md` to the measured final state. Remove development labels only where they describe the new release. Retain historical receipt/version labels.
2. Review the complete diff, rights notices and inventory. Commit the candidate. Use a clean checkout of that exact commit for final verification. Record its commit, tree and runtime-source hashes in external receipts, avoiding a self-referential commit-hash claim inside its own commit.
3. Run the pinned tools on Linux/CPython 3.12. Use new output directories; never overwrite an old proof root. These commands use the project interpreter and the documented browser overrides:

```sh
python -m pip install '.[reports]' 'pypdf==6.10.0'
python -m unittest discover -s tests -v
python tools/release_check.py --out artifacts/release-final/core
python tools/check_comparison.py --out artifacts/release-final/comparison
python tools/check_assessment.py --out artifacts/release-final/assessment
python tools/check_workflows110.py --out artifacts/release-final/workflows
python tools/check_selective100.py --out artifacts/release-final/selective100
node tests/browser_acceptance.cjs
node tests/browser_v1.cjs
node tests/browser_comparison.cjs
node tests/browser_assessments.cjs
node tests/browser_assessment_security.cjs
node tests/browser_retest_freshness.cjs
python tools/release_gate110.py
```

4. Build the wheel with the build tools pinned in `pyproject.toml`. Install it in a new virtual environment **outside the checkout**, clear `PYTHONPATH`, and confirm the imported module is in that environment's `site-packages`. Run `authzledger assessment demo`, snapshot verification and both bundle verifiers after the fixture stops. PDF verification needs the pinned reports extra. `tools/verify_bundle.py` remains standalone and is invoked with `python -I`.
5. Run `python tools/package_release.py`. Verify `dist/SHA256SUMS.txt`, inspect source/wheel inventories and confirm no private keys or local assessment databases are present. Preserve the separate licensed-font notices. A demo public key is a local demonstration trust anchor, not an authenticated author identity.
6. Push the exact candidate to `authzledger-v1.1.0` without force. Require the **verify** and **browser** jobs to pass on its exact SHA. A passing run for an older commit does not approve a later one. Stop for any secret leak, unbudgeted request, falsely confirmed finding/fix, overwritten original or unverifiable report.

## Priority 3 — publish assets, then channel announcements

The GitHub CLI commands below require an authenticated owner session. They are instructions, not evidence of successful dispatch.

```sh
gh workflow run tests.yml --repo 0xFarag/0xFarag \
  --ref authzledger-v1.1.0 -f publish_110=true
gh run list --repo 0xFarag/0xFarag --workflow tests.yml --limit 5
```

Select the **workflow_dispatch** run for the verified SHA, inspect its jobs and wait for completion. Its `publish110` job repeats the version/ledger gate and creates `v1.1.0`. Before dispatch, confirm neither that tag nor release already exists; if either exists, inspect it and stop instead of replacing it. Do not merge into the 1.0.0 product branch to trigger its separate legacy publisher.

After publication:

1. Read back the release, verify the tag resolves to the candidate commit and `isDraft=false`, `isPrerelease=false`. Download the published assets and verify checksums and advertised filenames. Inspect the install path and each documentation link.
2. Verify that the stable 1.0.0 tag, original evidence inventory and original asset digests still match the preflight record.
3. Use the **stable** GitHub body and social copy in `docs/launch-1.1.0.md` only now. Publish the GitHub release first, then the landing statement, LinkedIn main post and X post/thread, all with the same verified release URL. Use a short LinkedIn variant as an alternative, not an additional duplicate launch post.
4. Publish a video description only for a recording of this actual 1.1 workflow with inspected outputs. Existing 1.0/0.3.4 videos do not document 1.1. Avoid simulated UI or invented terminal output. Keep the existing Navy/Gold identity.
5. Read back each published URL and record the exact account, timestamp and result. If a channel cannot be reached, retain its ready draft and label it **not posted**. Do not imply all channels are live.

## Three demonstrations and what they prove

| Demonstration | Run / retained evidence | Claim boundary |
|---|---|---|
| Request → reproducer | `tools/check_assessment.py`; `01-import-to-reproducer` outputs and `results.json` | Three approved irrelevant units removed; fresh valid controls; original retained. Authored Burp-format demo input does not close the genuine-exporter gate. |
| 403 leakage vs controls | Same assessment check; `02-denial-and-controls` outputs and receipt | Protected content can contradict an HTTP denial. Invalid controls remain inconclusive. A 200 error object alone does not prove unauthorized access. |
| Selective fix + independent package | Assessment proof plus `tools/check_selective100.py` | Distinguish the small five-to-four assessment demo from the contractual 100-to-ten case fixture. Retained unselected cases stay `not_retested`; neither demonstrates universal time savings. |

The standalone verifier checks signature, byte inventory and anchors relative to a separately trusted public key. The installed verifier also checks the supported semantic relationships. Neither proves that a remote server was honestly observed, that every authorization path was tested or that a standards mapping establishes compliance.

Copyright © 2026 Nasser Aldin Farag / 0xFarag. Existing `LICENSE` and `NOTICE.txt` apply; third-party font notices remain separate.
