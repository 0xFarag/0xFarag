# AuthzLedger 1.1.0 — controlled findings, reproducible proof

**Release target. Publication remains blocked while the acceptance ledger contains open or partial scenarios. The current development producer is `1.1.0.dev0`; stable 1.0.0 remains unchanged.**

The 10 October release review adds a genuine ZAP 2.17.0 / Report Generation 0.43.0 Traditional JSON+ capture, its original-byte provenance and a four-request controlled execution. The genuine HAR remains retained. **F01-01 is still partial because a genuine, contract-compatible Burp export has not been demonstrated.** DTD rejection is unchanged. See [the exporter gate record](exporter-gate-1.1.0.md), [the exact release runbook](release-runbook-1.1.0.md) and [prepared channel copy](launch-1.1.0.md).

AuthzLedger turns a selected request into an explicit rule, valid controls, a reproducible finding, a smaller reproducer and a source-bound fix assessment. The local Studio workflow and CLI use the same existing execution engine and shared request budget.

The integrated scope includes offline Burp XML, ZAP JSON-plus and HAR import; controlled authorization contrast; isolated workflow transitions, replay and idempotency; bounded request reduction; source-bound selective comparisons; an assessment workspace with Inspector and command palette; consistent HTML/PDF/JSON reporting; signed file inventories; and explainable change-based retest selection.

## Immediate completion and publication sequence

1. Finish each explicitly open/partial case in `docs/acceptance-1.1.0.md`. Keep the fixture provenance and actual test names. In particular, authored import files cannot count as genuine exporter captures.
2. Freeze the code. Run the complete unit suite, six browser suites, `tools/release_check.py`, `tools/check_comparison.py`, `tools/check_assessment.py` and `tools/check_workflows110.py`. Inspect actual results and report renderings; preserve exact commit and artifact hashes.
3. Build the wheel, install it outside the checkout, run the assessment demo and both verifiers there. The reports extra must include the pinned renderer and licensed fonts. Verify source ZIP and wheel inventory; exclude keys and local assessment data.
4. Once all 88 cases are verified, set package/runtime version to exactly `1.1.0`, update the release record and rerun the checks on that commit. `python tools/release_gate110.py` must pass. A development version deliberately fails.
5. Push the exact reviewed commit to `authzledger-v1.1.0`; require both CI jobs to pass. The existing stable branch and old Evidence-Roots are not rewritten.
6. Run the verification workflow on that branch with `publish_110=true`. Its publication stage repeats the contract/version gate, builds the source, wheel, proof ZIP, standalone verifier and checksums, then atomically creates `v1.1.0` on the verified commit. Existing tags/assets are never replaced. A tag left by an interrupted publication requires inspection; it is never silently retargeted or reused.

These are execution gates, not a multi-quarter roadmap. The working implementation, commands, contract and demonstrations already exist in this branch. Remaining evidence gaps have explicit owners and scenarios; they must not be hidden behind a release label.

## Demonstrate value with verifiable outcomes

- **Request to reproducer:** import, bind two principals and object/control markers, confirm the violation and remove selected irrelevant fields while retaining each accepted proof. Show request counts and the original alongside the reduced case.
- **403 does not mean safe:** expose a protected marker in a denial, then invalidate a control. Show the confirmed-to-inconclusive distinction. Include the 200 error-object counterexample.
- **Selective fix, honest coverage:** retain a full baseline, execute only selected variants plus controls, show `fix_verified` next to `not_retested`, stop the fixture and verify the signed report inventory independently.

The synthetic labs are reproducible, and screenshots/recordings must show actual runs. Active operator time is measured separately from request reduction. No unsupported speedup, commercial-tool superiority, OSCE certification or guaranteed adoption claim is made.

## Installation and evidence boundaries

Python 3.10+; the measured environment is Linux/CPython 3.12. PDF uses the `reports` extra (`reportlab==4.4.9`) and bundled DejaVu fonts. Signing requires OpenSSL with Ed25519 support. The core remains dependency-free and local.

The default oracle mode retains an evaluation attestation. Explicit public selected inputs can be replayed against their predicate, but their derivation from the discarded raw response is not independently reconstructed. The standalone verifier establishes signature and byte integrity; the main verifier adds source-bound semantics. Neither proves remote execution truth or universal standards compliance. Unsupported import framing and DTDs remain blocked.

All existing proprietary rights and the rights-reservation licence remain in force. See `LICENSE`, `NOTICE.txt` and the separate font licences.
