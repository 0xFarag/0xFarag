#!/usr/bin/env python3
"""Standalone AuthzLedger Ed25519 verifier: Python standard library + OpenSSL.

This script has no AuthzLedger imports. It verifies signature, hashes, inventory,
JSON structure and report anchor binding. Use the installed main verifier for
report outcome/dependency semantics and internal hash-chain validation.
"""
from __future__ import annotations

import base64

import binascii

import hashlib

import json

import os

from pathlib import Path

import re

import shutil

import stat

import subprocess

import tempfile

from typing import Any, Mapping

SCHEMA = "https://authzledger.dev/schemas/evidence-bundle-v1"

SIGNING_DOMAIN = b"AuthzLedger:EvidenceBundle:Ed25519:v1\n"

MAX_FILE_BYTES = 64 * 1024 * 1024

MAX_REPORT_BYTES = 16 * 1024 * 1024

MAX_TOTAL_BYTES = 256 * 1024 * 1024

MAX_MANIFEST_BYTES = 1024 * 1024

MAX_KEY_BYTES = 64 * 1024

MAX_FILES = 1024

_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

_PRIVATE_PEM = re.compile(rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")

_ED25519_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")

def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("expected finite UTF-8 JSON data") from exc

def _json(raw: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("non-finite JSON number")

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=constant)
        _canonical(value)  # Also rejects overflow such as 1e999 and lone surrogates.
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("invalid or excessively nested UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value

def _safe_name(name: Any) -> str:
    if not isinstance(name, str) or len(name) > 512:
        raise ValueError("invalid bundle file path")
    parts = name.split("/")
    if len(parts) > 16 or any(
        part in (".", "..") or not _SEGMENT.fullmatch(part) for part in parts
    ):
        raise ValueError("unsafe bundle file path")
    return name

def _no_symlink_components(path: Path) -> None:
    for component in (path, *path.parents):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("symlinks are not accepted")

def _read_regular(path: Path, limit: int) -> bytes:
    _no_symlink_components(path)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("expected a regular file")
        if info.st_size > limit:
            raise ValueError("file exceeds size limit")
        raw = handle.read(limit + 1)
        if len(raw) > limit:
            raise ValueError("file exceeds size limit")
        return raw

def _write_new(path: Path, raw: bytes, mode: int = 0o600) -> None:
    _no_symlink_components(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(descriptor, "wb") as handle:
        os.fchmod(handle.fileno(), mode)
        handle.write(raw)

def _openssl(arguments: list[str]) -> bytes:
    try:
        result = subprocess.run(["openssl", *arguments], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=15, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("OpenSSL 1.1.1 or newer with Ed25519 support is required") from exc
    if result.returncode:
        raise ValueError("OpenSSL key or signature operation failed")
    return result.stdout

def _public_der(public_key: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="authzledger-key-") as temp:
        key = Path(temp) / "public.pem"
        _write_new(key, public_key)
        der = _openssl(["pkey", "-pubin", "-in", str(key), "-pubout", "-outform", "DER"])
    if len(der) != 44 or not der.startswith(_ED25519_DER_PREFIX):
        raise ValueError("only Ed25519 public keys are accepted")
    return der

def _signature(message: bytes, key: bytes, signature: bytes | None = None) -> bytes:
    with tempfile.TemporaryDirectory(prefix="authzledger-sign-") as temp:
        root = Path(temp)
        key_path, message_path = root / "key.pem", root / "message"
        _write_new(key_path, key)
        _write_new(message_path, SIGNING_DOMAIN + message)
        arguments = ["pkeyutl", "-rawin", "-inkey", str(key_path), "-in", str(message_path)]
        if signature is None:
            signed = _openssl([*arguments, "-sign", "-passin", "pass:"])
            if len(signed) != 64:
                raise ValueError("invalid Ed25519 signature length")
            return signed
        signature_path = root / "signature"
        _write_new(signature_path, signature)
        _openssl([*arguments, "-verify", "-pubin", "-sigfile", str(signature_path)])
        return b""

def _manifest_shape(manifest: dict) -> dict[str, dict]:
    if set(manifest) != {"schema", "schema_version", "domain", "algorithm", "signer", "report", "files"}:
        raise ValueError("unexpected or missing manifest fields")
    if (manifest["schema"] != SCHEMA or type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1 or manifest["domain"] != "AuthzLedger.EvidenceBundle"
            or manifest["algorithm"] != "Ed25519"):
        raise ValueError("unsupported manifest schema, domain or algorithm")
    signer = manifest["signer"]
    if (not isinstance(signer, dict) or set(signer) != {"public_key_sha256"}
            or not isinstance(signer["public_key_sha256"], str)
            or not _SHA256.fullmatch(signer["public_key_sha256"])):
        raise ValueError("invalid signing public key fingerprint")
    report = manifest["report"]
    if (not isinstance(report, dict) or set(report) != {"path", "root_sha256", "contract_sha256"}
            or report["path"] != "report.json" or any(
                not isinstance(report[field], str) or not _SHA256.fullmatch(report[field])
                for field in ("root_sha256", "contract_sha256"))):
        raise ValueError("invalid report anchor")
    files = manifest["files"]
    if not isinstance(files, list) or not 2 <= len(files) <= MAX_FILES:
        raise ValueError("invalid manifest file count")
    records = {}
    for record in files:
        if not isinstance(record, dict) or set(record) != {"path", "size", "sha256"}:
            raise ValueError("invalid manifest file record")
        name = _safe_name(record["path"])
        if name not in ("report.json", "public.pem") and not name.startswith("attachments/"):
            raise ValueError("unexpected bundle payload path")
        if name in records:
            raise ValueError("duplicate manifest file path")
        limit = MAX_REPORT_BYTES if name == "report.json" else MAX_KEY_BYTES if name == "public.pem" else MAX_FILE_BYTES
        if type(record["size"]) is not int or not 0 <= record["size"] <= limit:
            raise ValueError("invalid file size or file exceeds size limit")
        if not isinstance(record["sha256"], str) or not _SHA256.fullmatch(record["sha256"]):
            raise ValueError("invalid file digest")
        records[name] = record
    if not {"report.json", "public.pem"} <= records.keys():
        raise ValueError("missing report or public key record")
    if list(records) != sorted(records):
        raise ValueError("manifest file records must be sorted by path")
    if sum(record["size"] for record in records.values()) > MAX_TOTAL_BYTES:
        raise ValueError("bundle exceeds total size limit")
    return records

def _inventory(root: Path, names: set[str]) -> None:
    _no_symlink_components(root)
    if not root.is_dir():
        raise ValueError("evidence package must be a directory")
    expected_directories = set()
    for name in names:
        expected_directories.update(str(parent) for parent in Path(name).parents if str(parent) != ".")
    found = set()
    found_directories = set()
    pending = [root]
    # Streaming scandir avoids first allocating an attacker-sized directory list.
    while pending:
        directory = pending.pop()
        _no_symlink_components(directory)
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                info = entry.stat(follow_symlinks=False)
                name = path.relative_to(root).as_posix()
                _safe_name(name)
                if stat.S_ISLNK(info.st_mode):
                    raise ValueError("symlinks are not accepted in bundles")
                if stat.S_ISDIR(info.st_mode):
                    if name not in expected_directories:
                        raise ValueError("unexpected bundle directory")
                    found_directories.add(name)
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode):
                    if name not in names:
                        raise ValueError("missing or extra bundle files")
                    found.add(name)
                else:
                    raise ValueError("non-regular bundle file")
    if found != names:
        raise ValueError("missing or extra bundle files")
    if found_directories != expected_directories:
        raise ValueError("missing or extra bundle directories")

def _verify_cryptographic(bundle_path: str | Path, public_key: str | Path) -> dict:
    root = Path(bundle_path).absolute()
    _no_symlink_components(root)
    trusted_path = Path(public_key).absolute()
    _no_symlink_components(trusted_path)
    # An attacker-controlled embedded key must never become its own trust anchor.
    if trusted_path == root or root in trusted_path.parents:
        raise ValueError("trusted public key must be supplied from outside the bundle")
    trusted = _read_regular(trusted_path, MAX_KEY_BYTES)
    trusted_der = _public_der(trusted)
    manifest_raw = _read_regular(root / "manifest.json", MAX_MANIFEST_BYTES)
    manifest = _json(manifest_raw)
    records = _manifest_shape(manifest)
    if manifest_raw != _canonical(manifest):
        raise ValueError("manifest must use exact canonical JSON bytes")
    if manifest["signer"]["public_key_sha256"] != hashlib.sha256(trusted_der).hexdigest():
        raise ValueError("trusted public key fingerprint mismatch")
    _inventory(root, set(records) | {"manifest.json", "signature.base64"})
    signature_raw = _read_regular(root / "signature.base64", 128)
    try:
        signature = base64.b64decode(signature_raw.rstrip(b"\n"), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("invalid detached signature encoding") from exc
    if len(signature) != 64 or signature_raw != base64.b64encode(signature) + b"\n":
        raise ValueError("invalid detached Ed25519 signature")
    try:
        _signature(manifest_raw, trusted, signature)
    except ValueError as exc:
        raise ValueError("detached signature verification failed") from exc
    payloads = {}
    for name, record in records.items():
        raw = _read_regular(root / name, record["size"])
        if len(raw) != record["size"] or hashlib.sha256(raw).hexdigest() != record["sha256"]:
            raise ValueError("bundle file size or hash mismatch: " + name)
        if _PRIVATE_PEM.search(raw):
            raise ValueError("private key material is present in bundle")
        if name in ("report.json", "public.pem"):
            payloads[name] = raw
    if _public_der(payloads["public.pem"]) != trusted_der:
        raise ValueError("embedded public key differs from trusted public key")
    report = _json(payloads["report.json"])
    if (not isinstance(report.get("evidence"), dict)
            or report["evidence"].get("root_sha256") != manifest["report"]["root_sha256"]
            or report.get("contract_sha256") != manifest["report"]["contract_sha256"]):
        raise ValueError("report anchors do not match signed manifest")
    return report

def verify_bundle(bundle_path: str | Path, public_key: str | Path) -> list[str]:
    """Cryptographic and structural verification against an external trusted key."""
    try:
        _verify_cryptographic(bundle_path, public_key)
        return []
    except (ValueError, OSError, TypeError, RecursionError) as exc:
        return [str(exc) or "bundle verification failed"]


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", help="Evidence package directory")
    parser.add_argument("--public-key", required=True, help="External independently trusted Ed25519 public key")
    args = parser.parse_args(argv)
    errors = verify_bundle(args.bundle, args.public_key)
    if errors:
        for error in errors:
            print("FAILED: " + error, file=sys.stderr)
        return 1
    print("VERIFIED: Ed25519 signature, exact inventory, file hashes and report anchors.")
    print("Report assertion/dependency semantics and execution truth are not established by this standalone verifier.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
