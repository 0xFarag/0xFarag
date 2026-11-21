# ALL RIGHTS RESERVED. © Nasser Aldin Farag (0xFarag).
import os
import re
import stat
import subprocess
import sys
import types

def run():
    if os.name == "nt" and sys.version_info < (3, 13):
        print("Windows requires Python 3.13 or newer for os.fchmod.", file=sys.stderr)
        return 2
    openssl = sys.argv[1]
    version = subprocess.run([openssl, "version"], capture_output=True, check=False, timeout=15)
    major = re.match(rb"OpenSSL (\d+)\.", version.stdout)
    if version.returncode or not major or int(major[1]) < 3:
        print("OpenSSL 3 or newer is required.", file=sys.stderr)
        return 2

    def approved_run(argv, **options):
        if argv[0] != "openssl":
            raise ValueError("unexpected verifier dependency")
        return subprocess.run([openssl, *argv[1:]], **options)

    namespace = {"__name__": "authzledger_recipient"}
    original_source = sys.stdin.buffer.read()
    exec(compile(original_source, "verify_bundle.py", "exec"), namespace)
    namespace["subprocess"] = types.SimpleNamespace(
        run=approved_run, PIPE=subprocess.PIPE, TimeoutExpired=subprocess.TimeoutExpired
    )
    if os.name == "nt":
        historical_check = namespace["_no_symlink_components"]

        def check_components(path):
            historical_check(path)
            for component in (path, *path.parents):
                try:
                    metadata = component.lstat()
                except FileNotFoundError:
                    continue
                if metadata.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    raise ValueError("reparse points are not accepted")

        namespace["_no_symlink_components"] = check_components
    return namespace["main"](sys.argv[2:])

try:
    sys.exit(run())
except (OSError, subprocess.TimeoutExpired) as error:
    print("Verifier dependency failed: " + str(error), file=sys.stderr)
    sys.exit(2)
