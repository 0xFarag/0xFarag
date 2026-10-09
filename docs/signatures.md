# Signed evidence packages

AuthzLedger 1.0 adds externally verifiable Ed25519 evidence packages. A package
binds a sealed report, its contract digest, its report-chain root, explicit
attachments and the signing key's SHA-256 fingerprint to one detached signature.
Python has no additional package dependencies; signing and verification require
the `openssl` executable with Ed25519 support (OpenSSL 1.1.1 or newer).

**Trust is supplied by the verifier.** Obtain the public key from an independently
controlled channel or approved key inventory. `public.pem` inside a package is a
convenience copy, never a trust anchor. Both verifiers require an external public
key and reject a key path inside the package.

## Local API

```python
from pathlib import Path
from authzledger.signing import generate_keypair, create_bundle, verify_bundle

# Parent directories already exist. Existing destinations are never overwritten.
generate_keypair(Path("keys/private.pem"), Path("keys/public.pem"))

# report is an existing valid sealed AuthzLedger report dictionary.
manifest = create_bundle(
    report, Path("artifacts/signed-run"), Path("keys/private.pem"),
    attachments={"contract.json": Path("authorization.json")},
)
errors = verify_bundle(Path("artifacts/signed-run"), Path("keys/public.pem"))
if errors:
    raise ValueError("; ".join(errors))
```

The private key is created with mode `0600`. Keep it outside evidence directories
and source control. New bundle directories have mode `0700`, with payload files
mode `0600`; distribute through a controlled artifact channel. Attachment names
are safe relative names under `attachments/`; values are bytes or regular file
paths. Private signing-key copies and recognised private-key PEM material are
rejected. Review all attachments for credentials and sensitive application data:
the format performs no general-purpose secret discovery or automatic redaction.

## Independent verification

The standalone verifier can be copied to a separate machine without installing
AuthzLedger or importing its modules:

```sh
python3 tools/verify_bundle.py artifacts/signed-run --public-key keys/public.pem
```

Exit `0` means the Ed25519 signature, exact file inventory, byte sizes, SHA-256
digests, JSON structure, signing-key fingerprint and signed report anchors verify.
Exit `1` means verification failed. The script performs no outbound requests.

The main `authzledger.signing.verify_bundle` API additionally calls AuthzLedger's
report verifier: report shape, outcome/assertion consistency, summary, internal
hash-chain records, declared prerequisites and dependency cycles must also pass.
Reserved `contract.json`, `graph.json` and `explanation.json` attachments receive
additional source checks during both creation and main verification. A graph
requires its exact retained contract, and is reconstructed against that contract
and the signed report. This rejects locally rehashed graphs whose observations
or evidence records contradict the retained report. An explanation requires the
retained graph; its deterministic content is reconstructed offline, its graph
and contract digests must match, and every AI citation must refer to an existing
graph edge. AI metadata must retain `advisory_only: true`, `claims_verified:
false` and `untrusted: true` on notes. Verification never calls a model or PDP.
Other attachment names are opaque bytes with integrity checks only.
The independent script deliberately does not reimplement those application
semantics. An authentic but semantically contradictory output from a key-holding
runner can pass its cryptographic check and fail the main verifier.

## Protocol

| File | Binding |
| --- | --- |
| `manifest.json` | Exact canonical UTF-8 JSON; all manifest fields are signed. |
| `signature.base64` | Detached 64-byte Ed25519 signature, canonical base64 plus one newline. |
| `report.json` | Sealed finite JSON report; SHA-256 and byte size appear in the manifest. |
| `public.pem` | Public convenience copy; hashed by the manifest and matched against the trusted key. |
| `attachments/*` | Explicit payload files; each has an exact byte size and SHA-256 digest. |

The manifest contains exactly `schema`, `schema_version`, `domain`, `algorithm`,
`signer`, `report` and `files`. The schema identifier is
`https://authzledger.dev/schemas/evidence-bundle-v1`; it is an identifier and is
never fetched. `domain` is `AuthzLedger.EvidenceBundle`, `schema_version` is `1`
and `algorithm` is `Ed25519`. The public-key fingerprint is SHA-256 of the
Ed25519 SubjectPublicKeyInfo DER encoding, not PEM formatting. File records are
sorted by path, and each contains exactly `path`, `size` and `sha256`.

Canonical JSON uses sorted object keys, no insignificant whitespace,
`ensure_ascii=False`, separators `,` and `:`, finite numbers and UTF-8 encoding.
It is this version's Python JSON representation, not an assertion of RFC 8785
interoperability. Duplicate keys, unsupported fields and alternative manifest
formatting are rejected. Implementations must reproduce these exact bytes.

The signed message is the UTF-8 domain separator
`AuthzLedger:EvidenceBundle:Ed25519:v1` followed by a newline and the exact
canonical `manifest.json` bytes. The manifest records `report.root_sha256` and
`report.contract_sha256`; both must match the hashed report payload.

Verification rejects path traversal, absolute paths, backslashes, symlinks,
special files, duplicate file records, missing files, extra files and extra
directories. Names use ASCII letters, digits, `.`, `_` and `-` in relative path
segments, with at most 16 segments and 512 characters. Limits are 1,024 payload
files, 64 MiB per attachment, 16 MiB for a report, 64 KiB for a key, 1 MiB for the
manifest and 256 MiB total payload bytes. Verification checks declared limits
before reading payloads, and actual reads are bounded.

## What verification proves

A retained, independently trusted public key makes dishonest resealing
detectable: changing a report and recomputing its local hash chain cannot
recreate the package signature. Altering the manifest to match the rewritten
report also fails signature verification.

A valid signature proves unchanged authenticated bytes and possession of the
corresponding private key at signing time. It does not prove that HTTP requests
occurred, that the runner was honest, that testing was authorised or that
unconfigured access boundaries are secure. A compromised runner with access to
the private key can sign fabricated evidence. Protect the runner and private key,
and retain trusted public-key fingerprints outside the artifact channel.

This local format provides no trusted timestamp, key revocation service, HSM
integration, certificate identity, automatic rotation or encrypted storage.
Rotate keys through the external trust inventory and keep historical key
fingerprints with the runs they are permitted to authenticate.
