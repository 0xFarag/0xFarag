"""Build the offline source download. © Nasser Aldin Farag (0xFarag). All rights reserved."""
import argparse
import hashlib
import io
import os
from pathlib import Path
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "public" / "downloads" / "pruefwerkzeuge"
NAME = "AuthzLedger-Offline-Pruefwerkzeuge.zip"

MEMBERS = {
    "LICENSE": "LICENSE",
    "README.md": "tools/pruefwerkzeuge/README.md",
    "dateipruefung.py": "tools/pruefwerkzeuge/dateipruefung.py",
    "file_review.py": "tools/pruefwerkzeuge/file_review.py",
    **{f"rbac/{name}": f"public/rbac/{name}" for name in ("cli.mjs", "retest.mjs", "model.mjs", "README.md")},
}


def archive():
    target = io.BytesIO()
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as archive_file:
        archive_file.comment = "© Nasser Aldin Farag (0xFarag). All rights reserved.".encode("utf-8")
        for name, source in sorted(MEMBERS.items()):
            # All members are text. Preserve committed LF bytes even with Git autocrlf on Windows.
            content = (ROOT / source).read_bytes().replace(b"\r\n", b"\n")
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED
            archive_file.writestr(info, content)
    return target.getvalue()


def install(path, content):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temp:
        temporary = Path(temp.name)
        try:
            temp.write(content)
        except BaseException:
            temp.close()
            temporary.unlink(missing_ok=True)
            raise
    try:
        temporary.chmod(0o644)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Compare the committed files to a clean in-memory build")
    args = parser.parse_args()
    content = archive()
    sha = hashlib.sha256(content).hexdigest()
    files = {NAME: content, "SHA256SUMS.txt": f"{sha}  {NAME}\n".encode("ascii")}
    if not args.check:
        OUT.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        target = OUT / name
        if args.check:
            if not target.is_file() or target.read_bytes() != data:
                raise SystemExit(f"Stale or missing download: {name}")
        else:
            install(target, data)
    print(f"{sha}  {NAME} ({len(content)} bytes)")


if __name__ == "__main__":
    main()
