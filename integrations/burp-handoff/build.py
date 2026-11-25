# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Build and test the metadata-only handoff; Burp supplies the Montoya API."""
import argparse
import hashlib
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import secrets
import threading
import sys
import tempfile

HERE = Path(__file__).resolve().parent
legacy = runpy.run_path(str(HERE.parent / "burp" / "build.py"))
OUT = HERE / "build"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--api-jar", type=Path)
    args = parser.parse_args()
    OUT.mkdir(exist_ok=True)
    api = args.api_jar or OUT / "montoya-api-2025.3.jar"
    if not api.exists() and not args.api_jar:
        from urllib.request import urlopen
        with urlopen(legacy["API_URL"], timeout=30) as response:
            content = response.read(1024 * 1024)
        if hashlib.sha256(content).hexdigest() != legacy["API_SHA"]:
            raise ValueError("Montoya dependency digest mismatch")
        api.write_bytes(content)
    api = legacy["compile_api"](api)
    java = shutil.which("java")
    if not java:
        raise RuntimeError("JDK 21 required")
    with tempfile.TemporaryDirectory(dir=OUT) as name:
        temp = Path(name)
        classes, tests = temp / "classes", temp / "tests"
        legacy["compile_java"](java, str(api), classes, HERE / "src")
        classpath = os.pathsep.join(map(str, (classes, api)))
        legacy["compile_java"](java, classpath, tests, HERE / "tests")
        sys.path.insert(0, str(HERE.parents[1]))
        from team.server import bootstrap, dispatch, make_server
        directory = temp / "workspace"
        account = "operator@example.test"
        password = secrets.token_urlsafe(24)
        bootstrap(directory, account, password, "Integration fixture")
        session, cookie = dispatch(directory, "POST", "/api/login", {"email": account, "password": password})
        auth = {"token": cookie, "csrf": session["csrf"]}
        base = "/api/teams/" + session["teams"][0]["id"] + "/proof"
        scope = {"hosts": ["engagement.example.test"], "mode": "commercial", "roe": "Offline fixture", "budget": 2}
        created, _ = dispatch(directory, "POST", base, scope, **auth)
        run_url = base + "/" + created["run"]["id"]
        grant, _ = dispatch(directory, "POST", run_url + "/token", {}, **auth)
        with make_server(directory, port=0) as server:
            worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
            worker.start()
            try:
                subprocess.run([java, "-ea", "-Djava.awt.headless=true", "-cp", classpath + os.pathsep + str(tests),
                                "ch.zeroxfarag.authzledger.handoff.HandoffTest", str(temp / "two.json"),
                                "http://127.0.0.1:" + str(server.server_port) + "/api/proof-import"], check=True,
                               env=dict(os.environ, WORKBENCH_FIXTURE_TOKEN=grant["token"]))
                updated, _ = dispatch(directory, "GET", run_url, **auth)
                imported = updated["run"]["sources"][0]["observations"]
                assert len(imported) == 2 and imported[0]["source"] == "Burp"
                assert all(f["status"] == "inconclusive" for f in updated["run"]["report"]["findings"])
            finally:
                server.shutdown()
                worker.join()
        print("Real Team HTTP endpoint accepted the selected metadata, rejected token replay, and bound both observations.")
        from team.proof_engine import import_source
        batch = import_source("burp", (temp / "two.json").read_bytes())["observations"]
        if len(batch) != 2 or [r["marker"] for r in batch] != [True, False]:
            raise ValueError("Workbench rejected the handoff integration contract")
        result = OUT / "authzledger-burp-handoff.jar"
        # Fixed entry timestamps and ordering; only compiled production classes and rights notice.
        import zipfile
        manifest = b"Manifest-Version: 1.0\r\nImplementation-Title: AuthzLedger Handoff\r\nImplementation-Vendor: Nasser Aldin Farag (0xFarag)\r\n\r\n"
        entries = {"META-INF/MANIFEST.MF": manifest, "META-INF/NOTICE.txt": (HERE.parent / "burp" / "NOTICE.txt").read_bytes()}
        entries.update((f.relative_to(classes).as_posix(), f.read_bytes()) for f in classes.rglob("*.class"))
        with zipfile.ZipFile(temp / result.name, "w") as jar:
            for path, content in sorted(entries.items()):
                info = zipfile.ZipInfo(path)
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                jar.writestr(info, content)
        (temp / result.name).replace(result)
        checksum = hashlib.sha256(result.read_bytes()).hexdigest()
        (OUT / (result.name + ".sha256")).write_text(checksum + "  " + result.name + "\n", encoding="ascii")
        print(f"{result}: {checksum}")
if __name__ == "__main__":
    main()
