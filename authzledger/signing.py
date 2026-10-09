"""Externally anchored Ed25519 evidence packages using the OpenSSL executable.

Signatures establish unchanged bytes and possession of the trusted signing key.
They do not prove execution, permission to test, or an honest runner.
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

from .evidence import verify_report


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


def _public_from_private(private_key: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="authzledger-key-") as temp:
        key = Path(temp) / "private.pem"
        _write_new(key, private_key)
        public = _openssl(["pkey", "-in", str(key), "-pubout", "-passin", "pass:"])
    _public_der(public)
    return public


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


def generate_keypair(private_path: str | Path, public_path: str | Path) -> None:
    """Create a new Ed25519 keypair without overwriting either destination.

    The private file is created with mode 0600. Its parent must already exist.
    Encrypted private keys and signing daemons are outside this local format.
    """
    private, public = Path(private_path).absolute(), Path(public_path).absolute()
    for path in (private, public):
        _no_symlink_components(path)
        if path.exists():
            raise ValueError("key destination already exists")
    if private == public:
        raise ValueError("private and public key destinations must differ")
    private_key = _openssl(["genpkey", "-algorithm", "ED25519"])
    public_key = _public_from_private(private_key)
    _write_new(private, private_key, 0o600)
    try:
        _write_new(public, public_key, 0o644)
    except BaseException:
        private.unlink()
        raise


def _file_record(name: str, raw: bytes) -> dict:
    return {"path": name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _attachment_semantics(report: dict, contents: Mapping[str, bytes]) -> None:
    """Reconstruct reserved intelligence attachments from their retained sources.

    Other attachment names remain opaque integrity-bound bytes. Never contact a
    policy endpoint or model while verifying an existing package.
    """
    contract_name, graph_name = "attachments/contract.json", "attachments/graph.json"
    explanation_name = "attachments/explanation.json"
    if graph_name in contents and contract_name not in contents:
        raise ValueError("graph.json requires a retained contract.json attachment")
    if explanation_name in contents and graph_name not in contents:
        raise ValueError("explanation.json requires a retained graph.json attachment")
    documents = {}
    for name in (contract_name, graph_name, explanation_name):
        if name in contents:
            if len(contents[name]) > MAX_REPORT_BYTES:
                raise ValueError("reserved intelligence attachment exceeds size limit")
            documents[name] = _json(contents[name])
    if contract_name in documents:
        from .model import load_contract
        from .intelligence import build_graph
        contract = load_contract(documents[contract_name], allow_mutations=True)
        # Build without a policy to repeat all contract/report assertion binding.
        build_graph(contract, report)
    if graph_name in documents:
        from .intelligence import verify_graph
        graph = documents[graph_name]
        errors = verify_graph(graph, contract, report)
        if errors:
            raise ValueError("invalid retained graph attachment: " + "; ".join(errors))
    if explanation_name not in documents:
        return
    from .reasoning import explain_graph
    explanation = documents[explanation_name]
    expected = explain_graph(graph)  # Offline deterministic explanation only.
    if set(explanation) != set(expected):
        raise ValueError("unexpected or missing explanation fields")
    if type(explanation.get("schema_version")) is not int:
        raise ValueError("invalid explanation schema version")
    for name, value in expected.items():
        if name != "ai" and _canonical(explanation[name]) != _canonical(value):
            raise ValueError("explanation does not match its retained graph: " + name)
    ai = explanation["ai"]
    required = {"status", "advisory_only", "source", "model", "notes", "claims_verified"}
    if (not isinstance(ai, dict) or not required <= set(ai)
            or set(ai) - required - {"edges_shared", "edges_omitted", "error"}
            or ai.get("status") not in ("disabled", "generated", "error")
            or ai.get("advisory_only") is not True or ai.get("claims_verified") is not False
            or ai.get("source") not in (None, "local-ollama")
            or ai.get("model") is not None and (
                not isinstance(ai["model"], str) or not 1 <= len(ai["model"]) <= 128)):
        raise ValueError("AI explanation metadata must remain explicitly advisory")
    notes = ai["notes"]
    if (not isinstance(notes, list) or len(notes) > 16
            or ai["status"] != "generated" and notes):
        raise ValueError("invalid advisory explanation notes")
    edges = {edge["id"] for edge in graph["edges"]}
    seen = set()
    for note in notes:
        if (not isinstance(note, dict) or set(note) != {"edge_id", "text", "citations", "untrusted"}
                or not isinstance(note.get("edge_id"), str) or note["edge_id"] not in edges
                or note["edge_id"] in seen or note.get("untrusted") is not True):
            raise ValueError("invalid or ungrounded advisory explanation note")
        citations = note["citations"]
        if (not isinstance(citations, list) or not 1 <= len(citations) <= 8
                or any(not isinstance(item, str) or item not in edges for item in citations)
                or note["edge_id"] not in citations):
            raise ValueError("advisory explanation cites an absent graph edge")
        text = note["text"]
        if (not isinstance(text, str) or not 1 <= len(text.strip()) <= 1200
                or any(ord(char) < 32 and char not in "\n\t" for char in text)
                or any(char in text for char in "<>")):
            raise ValueError("invalid advisory explanation text")
        seen.add(note["edge_id"])
    for field in ("edges_shared", "edges_omitted"):
        if field in ai and (type(ai[field]) is not int or not 0 <= ai[field] <= len(edges)):
            raise ValueError("invalid advisory explanation coverage")
    if "error" in ai and (ai["status"] != "error" or not isinstance(ai["error"], str)
                           or not re.fullmatch(r"[a-z_]{1,64}", ai["error"])):
        raise ValueError("invalid advisory explanation error category")


def create_bundle(report: dict, out: str | Path, private_key: str | Path,
                  attachments: Mapping[str, bytes | str | Path] | None = None) -> dict:
    """Sign a valid sealed report and explicit, bounded attachments into a new directory.

    Attachment keys are relative names under ``attachments/``; values are bytes
    or regular source-file paths. The destination must not exist. No implicit
    directory copying, credential collection, or outbound requests occur.
    """
    report_raw = _canonical(report)
    if len(report_raw) > MAX_REPORT_BYTES:
        raise ValueError("report exceeds size limit")
    report = _json(report_raw)
    errors = verify_report(report)
    if errors:
        raise ValueError("cannot sign invalid sealed report: " + "; ".join(errors))
    destination = Path(out).absolute()
    _no_symlink_components(destination)
    if destination.exists():
        raise ValueError("bundle destination already exists")
    key_path = Path(private_key).absolute()
    private = _read_regular(key_path, MAX_KEY_BYTES)
    public = _public_from_private(private)
    contents = {"report.json": report_raw, "public.pem": public}
    total_bytes = sum(map(len, contents.values()))
    if attachments is not None and not isinstance(attachments, Mapping):
        raise ValueError("attachments must be a mapping of names to bytes or paths")
    if attachments is not None and len(attachments) + 2 > MAX_FILES:
        raise ValueError("too many bundle files")
    for name, source in (attachments or {}).items():
        name = "attachments/" + _safe_name(name)
        if isinstance(source, bytes):
            raw = source
        elif isinstance(source, (str, Path)):
            source_path = Path(source).absolute()
            if source_path == key_path:
                raise ValueError("private signing key cannot be attached")
            raw = _read_regular(source_path, MAX_FILE_BYTES)
        else:
            raise ValueError("attachment must be bytes or a regular file path")
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError("attachment exceeds size limit")
        if raw == private or _PRIVATE_PEM.search(raw):
            raise ValueError("private key material cannot be attached")
        total_bytes += len(raw)
        if total_bytes > MAX_TOTAL_BYTES:
            raise ValueError("bundle exceeds total size limit")
        contents[name] = raw
    if _PRIVATE_PEM.search(report_raw):
        raise ValueError("private key material cannot be included in a report")
    _attachment_semantics(report, contents)
    manifest = {
        "schema": SCHEMA, "schema_version": 1, "domain": "AuthzLedger.EvidenceBundle",
        "algorithm": "Ed25519",
        "signer": {"public_key_sha256": hashlib.sha256(_public_der(public)).hexdigest()},
        "report": {"path": "report.json", "root_sha256": report["evidence"]["root_sha256"],
                   "contract_sha256": report["contract_sha256"]},
        "files": [_file_record(name, raw) for name, raw in sorted(contents.items())],
    }
    manifest_raw = _canonical(manifest)
    if len(manifest_raw) > MAX_MANIFEST_BYTES:
        raise ValueError("manifest exceeds size limit")
    signature_raw = base64.b64encode(_signature(manifest_raw, private)) + b"\n"
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    try:
        for name, raw in contents.items():
            path = destination / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _write_new(path, raw)
        _write_new(destination / "manifest.json", manifest_raw)
        _write_new(destination / "signature.base64", signature_raw)
    except BaseException:
        shutil.rmtree(destination)
        raise
    return manifest


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


def _verify_cryptographic(bundle_path: str | Path, public_key: str | Path) -> tuple[dict, dict]:
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
        if name in ("report.json", "public.pem", "attachments/contract.json",
                    "attachments/graph.json", "attachments/explanation.json"):
            payloads[name] = raw
    if _public_der(payloads["public.pem"]) != trusted_der:
        raise ValueError("embedded public key differs from trusted public key")
    report = _json(payloads["report.json"])
    if (not isinstance(report.get("evidence"), dict)
            or report["evidence"].get("root_sha256") != manifest["report"]["root_sha256"]
            or report.get("contract_sha256") != manifest["report"]["contract_sha256"]):
        raise ValueError("report anchors do not match signed manifest")
    return report, payloads


def verify_bundle(bundle_path: str | Path, public_key: str | Path) -> list[str]:
    """Validate signature, exact inventory, byte hashes and sealed report semantics.

    ``public_key`` is mandatory and must be independently trusted and outside the
    bundle. Invalid input returns errors, never a successful partial verification.
    """
    try:
        report, payloads = _verify_cryptographic(bundle_path, public_key)
        errors = ["invalid sealed report: " + error for error in verify_report(report)]
        if not errors:
            _attachment_semantics(report, payloads)
        return errors
    except (ValueError, OSError, TypeError, RecursionError) as exc:
        return [str(exc) or "bundle verification failed"]
