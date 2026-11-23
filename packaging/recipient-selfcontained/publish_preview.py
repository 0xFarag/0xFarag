# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Publish only the two tested offline recipient artefacts, as a separate prerelease."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile

REPO = "0xFarag/0xFarag"
TAG = "recipient-studio-1.5.0-preview.3"
WIN = "AuthzLedger-Recipient-Studio-Preview3-Windows-x64.zip"
DEB = "authzledger-verifier_1.5.0-preview3_all.deb"
RIGHTS = "© Nasser Aldin Farag (0xFarag). All rights reserved."


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check_assets(path, manifest, expected):
    if {p.name for p in path.iterdir()} != expected | {manifest}:
        raise ValueError(f"unexpected payload in {path}")
    digests = {}
    for line in (path / manifest).read_text(encoding="utf-8-sig").splitlines():
        digest, name = line.split("  ", 1)
        if name not in expected or name in digests or not re.fullmatch("[0-9a-f]{64}", digest):
            raise ValueError("invalid manifest inventory")
        if sha(path / name) != digest:
            raise ValueError("tested package checksum mismatch: " + name)
        digests[name] = digest
    if digests.keys() != expected:
        raise ValueError("incomplete tested inventory")


def gh(*args):
    return subprocess.check_output(["gh", *args])


def api(path, *args):
    return json.loads(gh("api", f"repos/{REPO}/{path}", *args))


def list_all(path):
    return [item for page in api(path, "--paginate", "--slurp") for item in page]


def check_tag(commit, required):
    refs = api(f"git/matching-refs/tags/{TAG}")
    exact = next((ref for ref in refs if ref["ref"] == f"refs/tags/{TAG}"), None)
    if exact is None:
        if required:
            raise ValueError("published tag does not exist")
    elif exact["object"]["type"] != "commit" or exact["object"]["sha"] != commit:
        raise ValueError("tag exists with a different source")


def main():
    commit = os.environ["GITHUB_SHA"]
    if (os.environ["GITHUB_REPOSITORY"] != REPO or not re.fullmatch(r"[a-f0-9]{40}", commit)
            or os.environ["GITHUB_REF"] != "refs/heads/release/recipient-studio-preview-20261123"):
        raise ValueError("unexpected publishing source")
    tested = Path(sys.argv[1])
    windows, debian = tested / "windows", tested / "debian"
    exe = "AuthzLedgerRecipientStudio-x64.exe"
    files = {exe, "THIRD_PARTY_NOTICES.txt", "LICENSE.AuthzLedger.txt", "NOTICE.AuthzLedger.txt",
             "INSTALL-Studio.md", "build-dependencies.txt", "windows-native-checks.json"}
    check_assets(windows, "SHA256SUMS", files)
    check_assets(debian, "SHA256SUMS.txt", {DEB, "INSTALL-Studio.md"})
    receipt = json.loads((windows / "windows-native-checks.json").read_text())
    if (receipt["commit"] != commit or receipt["binary_sha256"] != sha(windows / exe)
            or receipt["github_run_id"] != os.environ["GITHUB_RUN_ID"]):
        raise ValueError("Windows binary not bound to this build receipt")
    with tempfile.TemporaryDirectory() as temp:
        out = Path(temp)
        with zipfile.ZipFile(out / WIN, "x") as package:
            for file in sorted(windows.iterdir()):
                info = zipfile.ZipInfo(file.name, (2026, 11, 23, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                package.writestr(info, file.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
        payload = {WIN: out / WIN, DEB: debian / DEB, "INSTALL-Studio.md": debian / "INSTALL-Studio.md"}
        manifest = out / "SHA256SUMS.txt"
        manifest.write_text("".join(f"{sha(path)}  {name}\n" for name,path in sorted(payload.items())))
        payload[manifest.name] = manifest
        hashes = {name: sha(path) for name, path in payload.items()}
        check_tag(commit, required=False)
        matches = [r for r in list_all("releases") if r["tag_name"] == TAG]
        if len(matches) > 1:
            raise ValueError("ambiguous existing release")
        desc = ("Offline recipient Studio and CLI. Windows x64 portable EXE (unsigned) and Debian desktop package. "
                "Use an independently obtained trusted Ed25519 public key. This standalone recipient preview "
                "does not establish the status of the assessment suite.\n\n"
                f"Source commit: {commit}\n\n{RIGHTS}")
        if matches:
            release = matches[0]
            if not release["prerelease"] or release["target_commitish"] != commit:
                raise ValueError("existing release has incompatible target or status")
        else:
            release = api("releases", "--method", "POST", "-f", f"tag_name={TAG}", "-f", f"target_commitish={commit}",
                          "-f", "name=AuthzLedger Recipient Studio · Preview 3", "-f", f"body={desc}", "-F", "draft=true",
                          "-F", "prerelease=true", "-f", "make_latest=false")
        release_id = release["id"]
        def inventory():
            items = list_all(f"releases/{release_id}/assets")
            names = [r["name"] for r in items]
            if len(set(names)) != len(names) or set(names) - hashes.keys():
                raise ValueError("unexpected existing release inventory")
            for asset in items:
                if (asset["state"] != "uploaded" or asset["digest"] != "sha256:" + hashes[asset["name"]]
                        or asset["size"] != payload[asset["name"]].stat().st_size):
                    raise ValueError("existing release asset does not match tested bytes")
            return set(names)
        present = inventory()
        missing = sorted(hashes.keys() - present)
        if missing and not release["draft"]:
            raise ValueError("published release is incomplete; refusing to modify it")
        for name in missing:
            gh("release", "upload", TAG, str(payload[name]), "--repo", REPO)
        if inventory() != hashes.keys():
            raise ValueError("incomplete draft")
        if release["draft"]:
            api(f"releases/{release_id}", "--method", "PATCH", "-F", "draft=false", "-F", "prerelease=true",
                "-f", "make_latest=false")
        final = api(f"releases/{release_id}")
        if final["draft"] or not final["prerelease"] or inventory() != hashes.keys():
            raise ValueError("public preview reconciliation failed")
        check_tag(commit, required=True)
        print(final["html_url"])


if __name__ == "__main__":
    main()
