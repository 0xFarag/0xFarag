"""Gather installed-license texts plus audited source notices for linked native code."""
from hashlib import sha256
from importlib import metadata
import io
import json
from pathlib import Path, PurePosixPath
import re
import sys
import tarfile
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
DIST_NAMES = ("cryptography", "cffi", "pycparser", "pyinstaller", "pyinstaller-hooks-contrib",
              "pefile", "pywin32-ctypes", "altgraph", "packaging", "setuptools")
LICENSE_NAME = re.compile(r"^(?:copying|copyright|licen[cs]e|notice|authors|acknowledgements)(?:$|[.\-_])", re.I)


def bundled_texts(component, url):
    if urlsplit(url).hostname not in {"github.com", "static.crates.io"}:
        raise ValueError(f"unexpected distribution host for {component['name']}")
    checksum = next(h["content"] for h in component["hashes"] if h["alg"] == "SHA-256")
    with urlopen(Request(url, headers={"User-Agent": "AuthzLedger-license-collector"}), timeout=60) as resp:
        raw = resp.read(150_000_001)
    if len(raw) > 150_000_000 or sha256(raw).hexdigest() != checksum:
        raise ValueError(f"source archive checksum mismatch for {component['name']}")
    result = []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if member.isfile() and len(path.parts) <= 3 and LICENSE_NAME.match(path.name) and member.size < 2_000_000:
                result.append((member.name, archive.extractfile(member).read().decode("utf-8", "replace")))
    if not result:
        raise RuntimeError(f"source license missing for {component['name']} {component['version']}")
    return result


def build():
    chunks = []
    def append(label, text):
        chunks.append(f"\n{'=' * 72}\n{label}\n{'=' * 72}\n{text}\n")
    for name in ("LICENSE.AuthzLedger.txt", "NOTICE.AuthzLedger.txt"):
        append(name, (HERE / name).read_text(encoding="utf-8"))
    append("Windows packaging changes", "Recipient build 1.5.0-win.1 adds an in-process pyca/cryptography backend.\n"
           "Original upstream recipient file is unchanged. Third-party copyrights and license grants apply.")
    append("CPython and its bundled components", Path(sys.base_prefix, "LICENSE.txt").read_text(encoding="utf-8"))
    for name in DIST_NAMES:
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        notices = [p for p in dist.files or () if LICENSE_NAME.match(p.name) and
                   (len(p.parts) <= 3 or "licenses" in p.parts) and dist.locate_file(p).is_file()]
        for p in notices:
            append(f"{name} {dist.version} · {p}", dist.locate_file(p).read_text(encoding="utf-8", errors="replace"))
        if name in ("pyinstaller", "cryptography") and not notices:
            raise RuntimeError(f"{name} license missing")
    crypto = metadata.distribution("cryptography")
    sboms = [p for p in crypto.files if str(p).endswith(".json") and "sboms" in p.parts]
    if not sboms:
        raise ValueError("cryptography wheel lacks a software bill of materials")
    count_openssl = 0
    for sbom in sboms:
        raw = crypto.locate_file(sbom).read_text(encoding="utf-8")
        append(f"pyca/cryptography {crypto.version} · {sbom.name}", raw)
        for c in json.loads(raw)["components"]:
            name, version = c["name"], c["version"]
            if name == "openssl" and not c.get("purl", "").startswith("pkg:cargo/"):
                url = next(ref["url"] for ref in c["externalReferences"] if ref["type"] == "distribution")
                count_openssl += 1
            elif c.get("bom-ref", "").startswith("registry+https://github.com/rust-lang/crates.io-index"):
                url = f"https://static.crates.io/crates/{name}/{name}-{version}.crate"
            else:
                continue
            for path, content in bundled_texts(c, url):
                append(f"{name} {version} · {path}", content)
    if not count_openssl:
        raise ValueError("linked OpenSSL distribution missing from the wheel SBOM")
    (HERE / "THIRD_PARTY_NOTICES.txt").write_text("".join(chunks), encoding="utf-8")


if __name__ == "__main__":
    build()
