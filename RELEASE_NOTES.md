# AuthzLedger 0.3.4 pre-release

A local authorization engineering workbench: explicit access policy, controlled HTTP tests and inspectable retest evidence.

## Distribution

Version 0.3.4 is published in `0xFarag/0xFarag`, with source on the dedicated `authzledger-v0.3.4` branch. The GitHub pre-release includes a source ZIP, installable wheel, SHA-256 checksums, the 55-second walkthrough in wide and vertical formats, and English/German subtitle files. The public profile links to the tool. A separate AuthzLedger repository has not been created.

## Get started

For an authorised copy, extract the source ZIP and run `python3 -m authzledger studio --open` from its `authzledger` directory. Python 3.10+ is required; Linux / CPython 3.12 is verified. The runtime uses the Python standard library. See INSTALL.md for isolated wheel installation and the local demo.

## Included

Permission matrix, local Studio, offline OpenAPI import, positive controls, response assertions, CLI execution, JSON/HTML/JUnit evidence and same-contract comparison. The 0.3.4 distribution adds public-facing installation and contribution guidance, the repository verification workflow and a portable browser acceptance script. It removes internal subscription-price proposals from the distribution. The core authorization and evidence algorithms are unchanged from 0.3.3.

## Verified

126 Python tests; isolated wheel installation and local demo; the eight-scenario synthetic corpus with 24 declared checks per scenario; actual Chromium 155 workflow, exports and 390 px layout. See RELEASE.json and evidence/0.3.4 for records and limits. Remote GitHub Actions results are not claimed by local checks.

## Rights and limits

Pre-release, all rights reserved. This is a source-visible preview, not an open-source licence or a general grant of use or redistribution rights. The existing LICENSE applies. Billing is disabled. Independent security review, full accessibility, wider platform coverage and customer validation remain open.

Use only authorised targets and dedicated test identities. The bundled demo is entirely local and synthetic.
