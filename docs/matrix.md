# Access matrix and controlled test generation

The v0.3 matrix compiles an explicit actor × resource policy into GET checks. It is an authorization testing workflow, not an autonomous penetration-testing platform.

## Working in Studio

1. Start `bash start.sh`. **Access matrix** is the default workspace.
2. Use **Run eight-scenario lab** for a self-contained demonstration. The Evidence view lets you select a scenario, then a result cell to inspect its prerequisites. The temporary API stops when the corpus finishes.
3. For your own staging API, set the target, configure actors and exact resources, and assign **Allow**, **Deny** or **Unknown** to each cell. Role/tenant labels describe the context; they never determine permissions automatically.
4. Each actor references a distinct environment variable holding the complete Authorization header. Set actual credentials in the terminal before starting Studio. The matrix does not accept credential values.
5. Every resource needs a positive JSON response assertion, for example `/id` equals the string `invoice-1`. More assertions can be edited under resource configuration or in the project JSON. Incorrect/weak assertions can still produce misleading controls; choose identifiers that genuinely establish the expected object.
6. **Validate coverage** identifies unknown rules and missing actor/resource controls. Generation is blocked until all declared relationships are reviewable. This is coverage of the supplied matrix, not complete application coverage.
7. **Generate checks & review scope** opens the exact request plan. Review it and affirm authorization before execution. No target request is sent during import or generation.
8. Export the project, reports and trace manifest before closing. Storage is session memory; exports may contain private target paths, labels and fixture assertions.

## Controls

An allow cell becomes a GET check requiring HTTP 200 and the configured resource JSON assertions. A deny cell requires:

- A passing allow check using the same actor, demonstrating permitted access with its credentials.
- A passing allow check against the same resource, demonstrating an accessible fixture.
- Then HTTP 403/404, as explicitly configured, and absence of the protected JSON pointers.

The compiler prefers the actor's own resource and the resource's declared owner for controls, then stable ID ordering. These are control-selection preferences, not inferred permissions. Authentication failures (401) are not accepted as a matrix denial. If a control fails, the dependent denial is **inconclusive** and its request is not sent. This cannot establish that credentials remain valid for every endpoint, nor eliminate changes occurring between requests.

## Trace and integrity

The compiler exports the normalized project, executable contract and trace manifest with their SHA-256 digests. The manifest maps each relationship to its exact case and controls. `matrix/explain` verifies report integrity and binds the contract digest, target, name, case set, identities, methods, paths and prerequisites before showing the trace. A content hash is not a signature or independent execution attestation.

## Policy evolution

Load a previous matrix under **Review a policy change**, or run:

```sh
python3 -m authzledger policy-diff before.json after.json --out proposed-migration.json
```

Changes to decisions, actor bindings, fixture mappings and selected controls remain explicit. Added/removed relationships remain in the comparison and coverage totals. Changes of target or request budget are flagged. The result is a **proposed policy migration requiring review**, not a finding-resolution report. It does not grant approval or alter the strict same-contract retest comparator.

## CLI

```sh
python3 -m authzledger matrix examples/tenant-matrix.json --out artifacts/compiled-matrix
python3 -m authzledger plan artifacts/compiled-matrix/contract.json
python3 -m authzledger benchmark --out artifacts/corpus
```

The compiler refuses an existing output directory. Compilation does not send requests. The benchmark uses only an ephemeral loopback API and randomly generated temporary credentials, removed afterwards.

## Boundaries

Up to 30 actors × 30 resources, within the explicit request budget; GET, JSON responses, HTTP 200 positive controls, 403/404 denials, Authorization environment references. No fixture creation, live endpoint discovery, OAuth login, cookie-session orchestration, arbitrary policy language, conditional permission inference, hosted team service or attack-path exploitation. Use the existing explicit contract/OpenAPI workflow for methods and assertions outside this narrower matrix interface. Unknown/conditional decisions must remain unresolved until an engineer supplies an appropriate explicit test contract.

Browser JSON imports reject integer values outside ±9,007,199,254,740,991 to prevent silent numeric rounding. Prefer string identifiers, or the CLI for exact larger integer assertions.
