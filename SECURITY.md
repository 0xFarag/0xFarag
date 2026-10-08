# Security policy

Report potential credential disclosure, request-scope escapes, unsafe report rendering, unbounded execution or evidence-verification bypasses privately before publishing technical details.

## Private reporting

For this pre-release, report issues to Nasser Aldin Farag through the agreed private project contact. If a private channel has not been established, request one using the contact information linked from [0xFarag's profile](https://github.com/0xFarag). Do not publish exploit details, credentials or sensitive reproduction material in a public issue.

Include:

- The affected AuthzLedger version or commit and Python version.
- A minimal contract and local fixture using synthetic data.
- Reproduction steps, expected behaviour and observed behaviour.
- The security boundary affected and any known workaround.

Do not include real credentials, customer data or private target details. Use a local reproduction where possible. Redact operational metadata before sharing report files.

## Scope

Security-sensitive components include contract validation, target and path handling, credential resolution, execution limits, report generation and evidence verification. A passing authorization contract is not a complete assessment of the tested application; see the [security model](docs/security-model.md).

Report against the current development branch where practical and identify older affected releases. This project does not promise a response deadline or a maintenance window for previous releases.

