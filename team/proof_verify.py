"""Independently verify the exact signed handover bytes with an externally pinned key.
© Nasser Aldin Farag (0xFarag). All rights reserved.
"""
import argparse
import base64
import hashlib
import io
import json
import re
from collections import Counter
from pathlib import Path
from zipfile import BadZipFile, ZIP_STORED, ZipFile, ZipInfo

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RIGHTS = "© Nasser Aldin Farag (0xFarag). All rights reserved."
SCHEMA = "authzledger.proof.inventory.v1"
DOCUMENTS = ("report.json", "report.html", "report.pdf")
FILES = (*DOCUMENTS, "inventory.json", "signature.ed25519")
MAX_BYTES = 8 * 1024 * 1024


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def public_descriptor(raw):
    fingerprint = digest(raw)
    kid = "ed25519-" + fingerprint
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": encode64(raw), "kid": kid}
    return {"keyId": kid, "jwk": jwk, "fingerprint": fingerprint[:16]}


def pinned_raw(jwk):
    if not isinstance(jwk, dict) or not isinstance(jwk.get("x"), str) or len(jwk["x"]) != 43:
        raise ValueError("Invalid pinned public JWK")
    try:
        raw = base64.b64decode(jwk["x"] + "=", altchars=b"-_", validate=True)
    except (UnicodeError, ValueError):
        raise ValueError("Invalid pinned public JWK") from None
    if public_descriptor(raw)["jwk"] != jwk:
        raise ValueError("The external trust anchor must be the exported public Ed25519 JWK")
    return raw


def archive_bytes(parts):
    """Canonical uncompressed container also detects changes to headers and trailing bytes."""
    output = io.BytesIO()
    with ZipFile(output, "w", compression=ZIP_STORED, allowZip64=False) as archive:
        for name in FILES:
            info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, parts[name], compress_type=ZIP_STORED)
    return output.getvalue()


def canonical_object(raw):
    value = json.loads(raw.decode("utf-8"))
    # Reject duplicate keys, alternate serializations, unused suffixes and non-finite numbers.
    if not isinstance(value, dict) or canonical(value) != raw:
        raise ValueError("Expected a canonical JSON object")
    return value


def document_inventory(parts):
    return [{"name": name, "sha256": digest(parts[name]), "bytes": len(parts[name])} for name in DOCUMENTS]


def _contents(data):
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_BYTES:
        raise ValueError("Invalid archive size")
    try:
        with ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if tuple(entry.filename for entry in entries) != FILES or any(
                entry.compress_type != ZIP_STORED or entry.flag_bits or entry.file_size != entry.compress_size
                for entry in entries
            ) or sum(entry.file_size for entry in entries) > len(data):
                raise ValueError("Unexpected archive layout")
            parts = {name: archive.read(name) for name in FILES}
        if archive_bytes(parts) != data:
            raise ValueError("Archive bytes differ from the canonical container")
        return parts
    except (BadZipFile, OSError, EOFError, RuntimeError, KeyError, UnicodeError) as exc:
        raise ValueError("Invalid archive framing") from exc


def inventory_key_id(data):
    """Untrusted selector for lookup in a separate, trusted workspace keyring."""
    parts = _contents(data)
    if len(parts["inventory.json"]) > 4096:
        raise ValueError("Invalid inventory size")
    try:
        kid = canonical_object(parts["inventory.json"]).get("keyId")
    except RecursionError as exc:
        raise ValueError("Invalid inventory") from exc
    if not isinstance(kid, str) or not re.fullmatch(r"ed25519-[a-f0-9]{64}", kid):
        raise ValueError("Invalid inventory key selector")
    return kid


def verify_bytes(data, trusted_jwk, workspace=None):
    """Check inventory signature, key identity, exact document bytes and archive framing."""
    raw = pinned_raw(trusted_jwk)
    try:
        parts = _contents(data)
        if len(parts["inventory.json"]) > 4096:
            raise ValueError("Invalid inventory size")
        inventory = canonical_object(parts["inventory.json"])
        Ed25519PublicKey.from_public_bytes(raw).verify(parts["signature.ed25519"], parts["inventory.json"])
        desc = public_descriptor(raw)
        if inventory.get("schema") != SCHEMA or inventory.get("rights") != RIGHTS:
            raise ValueError("Unknown inventory")
        if any(inventory.get(k) != v for k, v in desc.items()) or inventory.get("files") != document_inventory(parts):
            raise ValueError("Untrusted key or damaged document")
        report = canonical_object(parts["report.json"])
        if (report.get("keyId") != desc["keyId"] or report.get("fingerprint") != desc["fingerprint"]
                or report.get("publicKey") != trusted_jwk or report.get("rights") != RIGHTS
                or report.get("workspace") != inventory.get("workspace") or not isinstance(report.get("workspace"), str)
                or (workspace is not None and report["workspace"] != workspace)):
            raise ValueError("Report identity mismatch")
        return report
    except (BadZipFile, InvalidSignature, OSError, EOFError, RuntimeError, KeyError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid signed archive") from exc


def _report_rows(report, field):
    rows = report.get(field)
    if not isinstance(rows, list) or not rows:
        raise ValueError(f"Missing signed {field}")
    indexed = {}
    for row in rows:
        if not isinstance(row, dict) or any(
            not isinstance(row.get(key), str) or not row[key] for key in ("id", "status")
        ):
            raise ValueError(f"Invalid row in signed {field}")
        if row["id"] in indexed:
            raise ValueError(f"Duplicate ID in signed {field}")
        indexed[row["id"]] = row["status"]
    return indexed


def _recipient_receipt(data, report, workspace_pinned):
    """Project verified report claims. This does not independently replay observations."""
    baseline = _report_rows(report, "findings")
    retests = _report_rows(report, "retests")
    if baseline.keys() != retests.keys():
        raise ValueError("Signed retest IDs differ from baseline IDs")
    counts = Counter(retests.values())
    counts.setdefault("not_retested", 0)
    # Canonical comparison also distinguishes integer counts from JSON booleans.
    if canonical(report.get("coverage")) != canonical(counts):
        raise ValueError("Signed coverage differs from per-ID retest statuses")
    return {
        "schema": "authzledger.proof.recipient-receipt.v1",
        "verification": "archive_integrity_and_pinned_key_signature",
        "archiveSha256": digest(data),
        "keyId": report["keyId"],
        "workspace": report["workspace"],
        "workspacePinned": workspace_pinned,
        "reportedCoverage": dict(counts),
        "reportedFindings": [
            {"id": ident, "baselineStatus": status, "retestStatus": retests[ident]}
            for ident, status in baseline.items()
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--key", type=Path, required=True, help="Public JWK pinned independently of this package")
    parser.add_argument("--workspace", help="Require the exact independently expected workspace ID")
    parser.add_argument("--receipt-json", action="store_true",
                        help="Print a JSON receipt with the archive digest and signed per-ID statuses")
    opts = parser.parse_args()
    try:
        if opts.archive.stat().st_size > MAX_BYTES or opts.key.stat().st_size > 4096:
            raise ValueError("File exceeds size limit")
        data = opts.archive.read_bytes()
        report = verify_bytes(data, json.loads(opts.key.read_bytes()), opts.workspace)
        if opts.receipt_json:
            receipt = _recipient_receipt(data, report, opts.workspace is not None)
            print(json.dumps(receipt, sort_keys=True, allow_nan=False))
            return
    except (OSError, ValueError) as exc:
        parser.exit(1, f"INVALID — {exc}\n")
    print(f"VALID — Ed25519 and all inventory bytes verified. keyId={report['keyId']}")
    print("This verifies the package bytes, not an execution on a remote system.")
    print(RIGHTS)


if __name__ == "__main__":
    main()
