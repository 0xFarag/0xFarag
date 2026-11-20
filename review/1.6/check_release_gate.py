#!/usr/bin/env python3
"""Read-only AuthzLedger 1.6 formal dossier verification (Python 3.10+, POSIX)."""
import argparse
import base64
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

CONTRACT = Path(__file__).with_name("release-gate.json")
CONTRACT_HASH = "19d646e2f8814a107e388205041453cafd255af27b0c8b9dc192fbd9f61db3d8"
RELEASE = "1.6.0"
DECISIONS = "gate-decisions.json"
ATTESTATION = "gate-attestation.json"
SIGNATURE = "gate-attestation.ed25519"
MAX_FILES = 400
MAX_TOTAL = 512 * 1024 * 1024
JSON_LIMIT = 512 * 1024
LOG_LIMIT = 64 * 1024 * 1024
SPKI_ED25519 = bytes.fromhex("302a300506032b6570032100")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def exact(value, *keys):
    require(isinstance(value, dict) and set(value) == set(keys), "unexpected or missing object fields")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(data):
    def distinct(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("invalid JSON number")

    return json.loads(data.decode("utf-8"), object_pairs_hook=distinct, parse_constant=invalid)


def is_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def safe_path(name):
    require(isinstance(name, str) and 0 < len(name) <= 250, "invalid relative path")
    parts = name.split("/")
    require(len(parts) <= 12 and all(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,95}", p)
                                     for p in parts), "invalid relative path")
    return parts


class Inventory:
    """Open only rooted regular files without following links. Every file must be declared."""
    def __init__(self, root_fd):
        self.root_fd = root_fd
        self.total = 0
        self.files = set()
        self.signatures = {}
        self.dirs = set()
        self.read = set()
        self.scan(root_fd, "")

    def scan(self, fd, parent):
        with os.scandir(fd) as entries:
            for entry in entries:
                name = entry.name
                rel = f"{parent}/{name}" if parent else name
                safe_path(rel)
                require(len(self.files) + len(self.dirs) < MAX_FILES, "too many dossier entries")
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    self.dirs.add(rel)
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    try:
                        self.scan(child, rel)
                    finally:
                        os.close(child)
                else:
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "linked or special dossier file")
                    self.files.add(rel)
                    self.signatures[rel] = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                    self.total += info.st_size
                    require(self.total <= MAX_TOTAL, "dossier exceeds size bound")

    def consume(self, name, limit=JSON_LIMIT, hash_only=False):
        parts = safe_path(name)
        require(name in self.files and name not in self.read, "missing or duplicate evidence path: " + name)
        with ExitStack() as stack:
            parent = self.root_fd
            for part in parts[:-1]:
                parent = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                stack.callback(os.close, parent)
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            file = stack.enter_context(os.fdopen(fd, "rb"))
            initial = os.fstat(fd)
            require(self.signatures[name] == (initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns),
                    "evidence changed after inventory: " + name)
            require(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1 and 0 < initial.st_size <= limit,
                    "invalid evidence file type or size: " + name)
            size, digest, data = 0, hashlib.sha256(), bytearray()
            for block in iter(lambda: file.read(65536), b""):
                size += len(block)
                require(size <= limit, "evidence exceeds size bound")
                if hash_only:
                    digest.update(block)
                else:
                    data.extend(block)
            final = os.fstat(fd)
            require((size, initial.st_mtime_ns, initial.st_ctime_ns) ==
                    (initial.st_size, final.st_mtime_ns, final.st_ctime_ns), "evidence changed while reading")
        self.read.add(name)
        return digest.hexdigest() if hash_only else bytes(data)

    def complete(self):
        require(self.files == self.read, "undeclared evidence files")
        allowed_dirs = {str(p) for f in self.read for p in Path(f).parents if str(p) != "."}
        require(self.dirs == allowed_dirs, "undeclared evidence directories")
        final_inventory = Inventory(self.root_fd)
        require(self.dirs == final_inventory.dirs and self.signatures == final_inventory.signatures,
                "dossier changed during verification")
        paths = self.files | self.dirs
        require(len({p.casefold() for p in paths}) == len(paths), "case-ambiguous dossier path")


def verify_signature(att, signature, pem, pinned):
    require(is_digest(pinned), "invalid external key fingerprint")
    match = re.fullmatch(rb"-----BEGIN PUBLIC KEY-----\r?\n([a-zA-Z0-9+/=\r\n]+?)\r?\n-----END PUBLIC KEY-----\r?\n?", pem)
    require(match is not None, "expected one public SPKI PEM")
    der = base64.b64decode(b"".join(match.group(1).splitlines()), validate=True)
    require(len(der) == 44 and der.startswith(SPKI_ED25519) and sha(der) == pinned, "wrong Ed25519 trust anchor")
    require(len(signature) == 64, "invalid detached signature size")
    with tempfile.TemporaryDirectory(prefix="authz-gate-") as name:
        folder = Path(name)
        for filename, data in [("attest", att), ("sig", signature), ("public", pem)]:
            (folder / filename).write_bytes(data)
        result = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-rawin", "-inkey", "public",
                                 "-sigfile", "sig", "-in", "attest"], cwd=folder, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=10, check=False)
    require(result.returncode == 0, "invalid Ed25519 gate attestation")


def check(dossier, expected_commit, key_path, fingerprint):
    contract_bytes = CONTRACT.read_bytes()
    require(sha(contract_bytes) == CONTRACT_HASH, "unexpected release contract")
    contract = json_bytes(contract_bytes)
    required = {c["id"]: c["evidence_path"] for c in contract["required_criteria"] if c["required"] is True}
    require(len(required) == 18 and re.fullmatch(r"[a-f0-9]{40}", expected_commit) is not None
            and expected_commit not in {contract["baseline_commit"], "0" * 40}, "invalid 1.6 target commit")
    require(hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd, "POSIX rooted file access required")
    root = dossier.resolve(strict=True)
    key_real = key_path.resolve(strict=True)
    require(not key_real.is_relative_to(root) and key_real.is_file() and 0 < key_real.stat().st_size <= 2048,
            "trusted key must be a separate regular PEM file outside the dossier")
    with key_real.open("rb") as keyfile:
        pem = keyfile.read(2049)
    require(not dossier.is_symlink(), "symlink dossier root")
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        inventory = Inventory(root_fd)
        att_bytes = inventory.consume(ATTESTATION)
        signature = inventory.consume(SIGNATURE, 64)
        verify_signature(att_bytes, signature, pem, fingerprint)
        att = json_bytes(att_bytes)
        exact(att, "schema", "target_release", "target_commit", "contract_sha256", "decisions_sha256")
        require(att["schema"] == "authzledger.gate-attestation/v1" and att["target_release"] == RELEASE
                and att["target_commit"] == expected_commit and att["contract_sha256"] == CONTRACT_HASH,
                "attestation target or contract mismatch")
        raw = inventory.consume(DECISIONS)
        require(att["decisions_sha256"] == sha(raw), "signed decision digest mismatch")
        decisions = json_bytes(raw)
        exact(decisions, "schema", "target_release", "target_commit", "criteria", "artifacts")
        require(decisions["schema"] == "authzledger.gate-decisions/v1" and decisions["target_release"] == RELEASE
                and decisions["target_commit"] == expected_commit, "decision target mismatch")
        rows, artifacts = decisions["criteria"], decisions["artifacts"]
        require(type(rows) is list and len(rows) == len(required), "expected all 18 criterion decisions")
        require(type(artifacts) is list and 0 < len(artifacts) <= MAX_FILES, "invalid raw artifact list")
        declared, referenced, seen = set(), set(), set()
        for item in artifacts:
            exact(item, "path", "sha256")
            path = item["path"]
            safe_path(path)
            require(path.startswith("artifacts/") and path not in declared and is_digest(item["sha256"]),
                    "invalid raw artifact declaration")
            require(inventory.consume(path, LOG_LIMIT, hash_only=True) == item["sha256"], "raw artifact hash mismatch")
            declared.add(path)
        for row in rows:
            exact(row, "id", "decision", "path", "sha256")
            cid, path = row["id"], row["path"]
            require(isinstance(cid, str) and cid in required and cid not in seen and row["decision"] == "passed"
                    and path == required[cid] and is_digest(row["sha256"]), "unexpected, duplicate or unpassed criterion")
            receipt = inventory.consume(path)
            require(row["sha256"] == sha(receipt), "criterion receipt hash mismatch")
            record = json_bytes(receipt)
            exact(record, "schema", "id", "target_release", "target_commit", "positive", "negative_control",
                  "reviewer", "environment", "reproduction", "artifacts")
            require(record["schema"] == "authzledger.criterion-receipt/v1" and record["id"] == cid
                    and record["target_commit"] == expected_commit and record["target_release"] == RELEASE
                    and record["positive"] == record["negative_control"] == "passed", "invalid criterion receipt")
            require(all(isinstance(record[k], str) and 0 < len(record[k].strip()) <= 4096
                        for k in ("reviewer", "environment", "reproduction")), "missing criterion metadata")
            refs = record["artifacts"]
            require(type(refs) is list and 0 < len(refs) <= len(declared)
                    and all(isinstance(p, str) and p in declared for p in refs) and len(set(refs)) == len(refs),
                    "invalid criterion artifact references")
            seen.add(cid)
            referenced.update(refs)
        require(seen == set(required) and referenced == declared, "incomplete criteria or orphaned artifacts")
        inventory.complete()
    finally:
        os.close(root_fd)
    return {"schema":"authzledger.formal-gate-check/v1", "formal_dossier":"verified",
            "target_release":RELEASE, "target_commit":expected_commit, "criteria_verified":len(seen),
            "artifacts_verified":len(declared), "signer_spki_sha256":fingerprint,
            "contract_sha256":CONTRACT_HASH, "signed_decisions_sha256":sha(raw),
            "semantic_validation":"not_performed", "publication_authorized":False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dossier", type=Path)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--trusted-key", required=True, type=Path)
    parser.add_argument("--key-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        result = check(args.dossier, args.expected_commit, args.trusted_key, args.key_sha256)
    except (OSError, ValueError, TypeError, KeyError, RecursionError, subprocess.TimeoutExpired) as error:
        print(json.dumps({"schema":"authzledger.formal-gate-check/v1","formal_dossier":"rejected",
                          "reason":str(error),"publication_authorized":False}, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
