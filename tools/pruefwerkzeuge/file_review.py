"""Local file fingerprints and optional ClamAV evidence. © Nasser Aldin Farag (0xFarag). All rights reserved."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from threading import Thread


MAX_FILE = 256 * 1024 * 1024
MAX_SCAN = 16 * 1024 * 1024
MAX_OUTPUT = 64 * 1024
PROCESS_TIMEOUT = 75
RIGHTS = "© Nasser Aldin Farag (0xFarag). All rights reserved."


def _file_bytes(path, keep):
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_FILE:
            raise ValueError("Choose a regular file up to 256 MiB.")
        hashes = {"sha256": hashlib.sha256(), "sha1": hashlib.sha1(usedforsecurity=False),
                  "md5": hashlib.md5(usedforsecurity=False)}
        content = bytearray() if keep and before.st_size <= MAX_SCAN else None
        size = 0
        for chunk in iter(lambda: stream.read(256 * 1024), b""):
            size += len(chunk)
            if size > before.st_size:
                raise ValueError("The file changed during reading.")
            for digest in hashes.values():
                digest.update(chunk)
            if content is not None:
                content.extend(chunk)
        after = os.fstat(stream.fileno())
        if (size != before.st_size or after.st_size != size or after.st_mtime_ns != before.st_mtime_ns
                or after.st_ctime_ns != before.st_ctime_ns):
            raise ValueError("The file changed during reading.")
    return {"size_bytes": size, **{name: digest.hexdigest() for name, digest in hashes.items()}}, content


def _engine_path():
    # Treat absolute PATH entries as the operator's installed-tool selection. Never search the working directory.
    cwd = Path.cwd().resolve()
    directories = [entry for entry in os.get_exec_path() if os.path.isabs(entry) and Path(entry).resolve() != cwd]
    if not directories:
        return None
    path = shutil.which("clamscan.exe" if os.name == "nt" else "clamscan", path=os.pathsep.join(directories))
    if path and Path(path).resolve().parent != cwd:
        return str(Path(path).resolve())
    return None


def _run_scan(executable, content, tempdir):
    cmd = [executable, "--stdout", "--heuristic-alerts=yes", "--alert-exceeds-max=yes",
           "--alert-encrypted=yes", "--max-filesize=16M", "--max-scansize=64M", "--max-files=256",
           "--max-recursion=8", "--max-scantime=30000", "--tempdir=" + tempdir, "-"]
    environment = {**os.environ, "LANG": "C", "LC_ALL": "C"}
    # Limit the output as it is produced. Neither the source pathname nor output from the engine is disclosed.
    with subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          env=environment) as process:
        output = bytearray()
        failures = []

        def feed():
            try:
                with process.stdin as pipe:
                    pipe.write(content)
            except OSError:
                failures.append("input_incomplete")

        def collect():
            try:
                with process.stdout as pipe:
                    output.extend(pipe.read(MAX_OUTPUT + 1))
                    if len(output) > MAX_OUTPUT:
                        process.kill()
            except OSError:
                failures.append("output_incomplete")

        threads = [Thread(target=feed, daemon=True), Thread(target=collect, daemon=True)]
        for thread in threads:
            thread.start()
        try:
            process.wait(timeout=PROCESS_TIMEOUT)
        except subprocess.TimeoutExpired:
            failures.append("timeout")
            process.kill()
            process.wait()
        for thread in threads:
            thread.join(timeout=2)
        if any(thread.is_alive() for thread in threads):
            failures.append("stream_timeout")
        if len(output) > MAX_OUTPUT:
            return "output_limit", None, ""
        if failures and not (failures == ["input_incomplete"] and process.returncode == 2):
            return ("timeout" if "timeout" in failures else failures[0]), process.returncode, ""
        return None, process.returncode, output.decode("utf-8", errors="replace").replace("\r\n", "\n")


def _scan_status(code, output):
    versions = re.findall(r"^Engine version:\s*([0-9][0-9A-Za-z.+-]{0,40})[ \t]*$", output, re.M)
    details = {"engine_version": versions[0] if len(versions) == 1 else None}
    if code not in (0, 1):
        return {**details, "status": "error", "reason": "engine_error"}
    names = re.findall(r"^stdin:\s+([^\r\n]+?) FOUND[ \t]*$", output, re.M)
    limited = any(name.startswith(("Heuristics.Limits.Exceeded", "Heuristics.Encrypted", "Heuristics.Broken"))
                  for name in names)
    warnings = re.search(r"\b(?:WARNING|ERROR|skipped|timeout|timed out)\b|^Total errors:\s*[1-9]",
                         output, re.I | re.M)
    if limited:
        return {**details, "status": "incomplete", "reason": "engine_limit_or_opaque_content"}
    scanned = re.search(r"^Scanned files:[ \t]*1[ \t]*$", output, re.M)
    infected = re.search(r"^Infected files:[ \t]*1[ \t]*$", output, re.M)
    definitions = re.search(r"^Known viruses:[ \t]*[1-9][0-9]*[ \t]*$", output, re.M)
    if warnings or not (details["engine_version"] and definitions):
        return {**details, "status": "incomplete", "reason": "engine_warning_or_incomplete_summary"}
    # ClamAV 1.5's stdin handler increments the infected counter rather than the
    # scanned counter for a detection. A clean verdict still needs one scanned file.
    reported_scan_count = re.search(r"^Scanned files:[ \t]*[01][ \t]*$", output, re.M)
    if code == 1 and reported_scan_count and infected and names:
        return {**details, "status": "detection_reported"}
    if (code == 0 and scanned and not names and re.search(r"^stdin: OK[ \t]*$", output, re.M)
            and re.search(r"^Infected files:[ \t]*0[ \t]*$", output, re.M)):
        return {**details, "status": "no_detection_reported"}
    return {**details, "status": "incomplete", "reason": "unexpected_engine_result"}


def review_file(path: Path, *, clamav=False):
    identifiers, content = _file_bytes(path, clamav)
    engine = {"name": "ClamAV", "status": "not_requested", "engine_version": None}
    if clamav:
        if content is None or not content:
            engine.update(status="incomplete", reason="input_exceeds_scan_limit" if content is None else "empty_input")
        elif not (executable := _engine_path()):
            engine.update(status="unavailable", reason="clamscan_not_installed")
        else:
            try:
                with tempfile.TemporaryDirectory(prefix="authzledger-clamav-") as folder:
                    failure, code, output = _run_scan(executable, content, folder)
            except OSError:
                engine.update(status="error", reason="engine_io_error")
            else:
                if failure:
                    engine.update(status="incomplete", reason=failure)
                else:
                    engine.update(_scan_status(code, output))
    return {"schema": "authzledger.local-file-review.v1", "rights": RIGHTS, "signature": "unsigned",
            "file": identifiers, "engine": engine, "max_hash_bytes": MAX_FILE, "max_scan_bytes": MAX_SCAN}
