# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Build the passive Burp extension and check its output with the repository importer."""
import argparse
import base64
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from urllib.request import urlopen
import xml.etree.ElementTree as ET
import zipfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE / "build"
API_SHA = "a5704ba72024a42f81fe9090dd1352f9fa856fed49636ac411adf77aca121028"
API_URL = ("https://repo.maven.apache.org/maven2/net/portswigger/burp/extensions/"
           "montoya-api/2025.3/montoya-api-2025.3.jar")
JAR_NAME = "authzledger-burp-export.jar"
PACKAGE = "ch.zeroxfarag.authzledger.burp"


def compile_api(file):
    if file is None:
        file = BUILD / "montoya-api-2025.3.jar"
        if not file.is_file():
            with urlopen(API_URL, timeout=40) as response:
                data = response.read(1024 * 1024)
            if hashlib.sha256(data).hexdigest() != API_SHA:
                raise ValueError("Unexpected Montoya dependency digest")
            file.write_bytes(data)
    if hashlib.sha256(file.read_bytes()).hexdigest() != API_SHA:
        raise ValueError(f"Montoya API must match SHA-256 {API_SHA}")
    return file.resolve()


def compile_java(java, classpath, dest, src):
    dest.mkdir()
    subprocess.run([java, "-m", "jdk.compiler/com.sun.tools.javac.Main",
                    "-source", "21", "-target", "21", "-encoding", "UTF-8", "-g:none",
                    "-proc:none", "-cp", classpath, "-d", str(dest),
                    *map(str, sorted(src.glob("*.java")))], check=True)


def verify_import(path, stable_importer):
    sys.path.insert(0, str(ROOT))
    from team.evidence_formats import parse_records, sha, canonical
    raw = path.read_bytes()
    tree = ET.fromstring(raw)
    entries = tree.findall("item")
    rows = parse_records("burp", raw)
    if len(rows) != 2 or len(entries) != 2:
        raise AssertionError("Missing captured exchange")
    request = (b"POST /a?x=1&y=2 HTTP/1.1\r\nHost: evidence.example.test\r\n"
               b"Content-Length: 3\r\n\r\n\x00\xffx")
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n\xfe\x00"
    source_key = sha(canonical(["POST", "https", "evidence.example.test", 443,
                                "/a", "x=1&y=2", sha(b"\x00\xffx")]))
    for entry, row in zip(entries, rows):
        if row.get("kind") != "http_exchange" or row.get("status_code") != 200 or row.get("request_key") != source_key:
            raise AssertionError("Importer metadata mismatch")
        for field, expected in (("request", request), ("response", response)):
            elem = entry.find(field)
            if elem.get("base64") != "true" or base64.b64decode(elem.text, validate=True) != expected:
                raise AssertionError(f"{field} bytes changed")
    if stable_importer:
        from importlib.util import module_from_spec, spec_from_file_location
        spec = spec_from_file_location("authzledger_stable_imports", stable_importer.resolve())
        stable = module_from_spec(spec)
        spec.loader.exec_module(stable)
        batch = stable.parse_import(raw, "burp-xml")
        if len(batch["entries"]) != 2 or any(item["method"] != "POST" for item in batch["entries"]):
            raise AssertionError("Stable Burp adapter contract failed")
        print("Stable burp-xml adapter accepted both exchanges.")
    print("Native team Burp import accepted both captured exchanges and derived the expected request key.")


def make_jar(classes, target):
    manifest = (b"Manifest-Version: 1.0\r\nImplementation-Title: AuthzLedger Evidence Export\r\n"
                b"Implementation-Vendor: Nasser Aldin Farag (0xFarag)\r\n\r\n")
    content = {"META-INF/MANIFEST.MF": manifest, "META-INF/NOTICE.txt": (HERE / "NOTICE.txt").read_text(encoding="utf-8").encode("utf-8")}
    content.update((file.relative_to(classes).as_posix(), file.read_bytes()) for file in classes.rglob("*.class"))
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_STORED) as jar:
        for name in sorted(content):
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            jar.writestr(info, content[name])


def main():
    args = argparse.ArgumentParser(description=__doc__)
    args.add_argument("--api-jar", type=Path, help="pre-downloaded, hash-verified Montoya API JAR")
    args.add_argument("--stable-importer", type=Path, help="also test against a trusted 1.5.0 authzledger/imports.py checkout")
    options = args.parse_args()
    BUILD.mkdir(exist_ok=True)
    dependency = compile_api(options.api_jar)
    java = shutil.which("java")
    if not java:
        raise RuntimeError("Install a JDK 21 with jdk.compiler and put java on PATH")
    with tempfile.TemporaryDirectory(dir=BUILD) as working:
        working = Path(working)
        classes, tests, sample = (working / name for name in ("classes", "tests", "sample"))
        sample.mkdir()
        compile_java(java, str(dependency), classes, HERE / "src")
        classpath = os.pathsep.join(map(str, (classes, dependency)))
        compile_java(java, classpath, tests, HERE / "tests")
        subprocess.run([java, "-ea", "-Djava.awt.headless=true", "-cp",
                        os.pathsep.join([classpath, str(tests)]), PACKAGE + ".ExportTest", str(sample)], check=True)
        verify_import(sample / "export.xml", options.stable_importer)
        make_jar(classes, working / JAR_NAME)
        output = BUILD / JAR_NAME
        (working / JAR_NAME).replace(output)
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        (BUILD / (JAR_NAME + ".sha256")).write_bytes(f"{digest}  {JAR_NAME}\n".encode("ascii"))
        print(f"{output}\nSHA-256 {digest}")


if __name__ == "__main__":
    main()
