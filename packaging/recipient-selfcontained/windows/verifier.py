# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Offline recipient verifier and native handover viewer."""
import os
from pathlib import Path
import stat
import sys

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import receipt_portable as receipt

VERSION = "AuthzLedger Offline Recipient Verifier - Studio preview 3"


def public_key(pem):
    try:
        key = serialization.load_pem_public_key(pem)
    except UnsupportedAlgorithm as exc:
        raise ValueError("unsupported public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("only Ed25519 public keys are accepted")
    return key


def public_der(pem):
    return public_key(pem).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def verify_signature(message, key, signature):
    try:
        public_key(key).verify(signature, receipt.SIGNING_DOMAIN + message)
    except InvalidSignature as exc:
        raise ValueError("invalid Ed25519 signature") from exc
    return b""


def reject_reparse_points(path):
    original_path_check(path)
    if ".." in path.parts:
        raise ValueError("parent traversal components are not accepted")
    for component in (path, *path.parents):
        try:
            attrs = component.lstat().st_file_attributes
        except FileNotFoundError:
            continue
        if attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("reparse points are not accepted")


original_path_check = receipt._no_symlink_components


def main(argv):
    if argv in ([], ["--studio"], ["--studio-smoke"]):
        from evidence_studio import launch
        command = [sys.executable]
        if not getattr(sys, "frozen", False):
            command.append(str(Path(__file__).resolve()))
        return launch(command, smoke=argv == ["--studio-smoke"])
    if argv == ["--version"]:
        print(VERSION)
        return 0
    if argv == ["--notices"]:
        notices = Path(__file__).with_name("THIRD_PARTY_NOTICES.txt")
        sys.stdout.buffer.write(notices.read_bytes())
        return 0
    # The pinned upstream parser, limits, inventory and anchors are retained. Only
    # DER conversion and Ed25519 verification switch to the in-process backend.
    receipt._public_der = public_der
    receipt._signature = verify_signature
    if os.name == "nt":
        receipt._no_symlink_components = reject_reparse_points
    return receipt.main(argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
