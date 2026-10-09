# AuthzLedger 1.0

**Authorization Intelligence, built on evidence.**

**Know who can do what. Prove what changed.**

Version 1.0 extends the v0.3.4 authorization workbench into a three-layer evidence workflow: explicit intent, independently supplied policy decisions and controlled application observations. Each configured relationship keeps its provenance, prerequisite controls and evidence binding.

## Included

- Living Authorization Graph with stable relationships, source fingerprints and explicit unknown states.
- Differential intelligence for policy, intent and context drift; behavioral regressions, escalation candidates and coverage changes. Changed credentials or weakened prerequisites cannot masquerade as remediation.
- The existing positive/negative control DAG, access-matrix compiler, offline OpenAPI importer and bounded HTTP runner.
- Independent local policy-as-code rules and an explicitly scoped OPA HTTP adapter.
- Durable, tamper-evident SQLite run history with retained contracts, reports and graphs.
- Finite continuous assurance with fresh credential checks, aggregate App/PDP request budgets and conservative stop conditions.
- Dependency-complete selective retest plans, plus authenticated local Studio jobs.
- Evidence-grounded explanations; optional local Ollama annotations are advisory and never decide findings or CI outcomes.
- Ed25519 signed evidence manifests, externally trusted-key verification and an independent standalone verifier.
- Studio graph, policy, history, retest and signed-proof workflows, with corresponding CLI commands.

## Start

Extract the source archive and run `python3 -m authzledger studio --history authorization-history.sqlite3 --open`, or install the wheel in a virtual environment. Python 3.10+ is required; the verified release environment is Linux/CPython 3.12. Signing requires OpenSSL 3 with Ed25519 support. The core has no Python runtime dependencies.

Use **Run eight-scenario lab** for actual loopback HTTP tests on synthetic data. CLI: `python3 -m authzledger demo --out artifacts/demo`. See INSTALL.md and the guides under docs/ for graph construction, policy inputs, signed proof and assurance.

## Verification and boundaries

The release is gated on unit/adversarial/local HTTP tests, the complete graph-to-signed-proof workflow, the authored eight-scenario corpus and installation outside the checkout. Local browser acceptance covers the preserved workflows and new Studio features. Exact measured results are recorded in RELEASE.json and evidence/1.0.0. Remote GitHub Actions results must be inspected separately.

The corpus is an authored local test set, not an independent commercial-tool comparison. OPA and Ollama protocol tests use local test servers; they do not certify external deployments or a particular model. Signatures verify content and key possession, not truthful execution, operator identity or trusted time. Local history is not immutable external storage. Continuous assurance covers configured checks and bounded observation windows. Hosted multi-user Retest-as-a-Service is a future commercial deployment; this release provides local retest execution jobs.

The existing rights-reservation LICENSE remains in force. Billing is disabled. Independent security review, other platforms/browsers, full accessibility and external customer validation remain open.
