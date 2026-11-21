"""Adapt Windows's native path spelling to the canonical POSIX receipt inventory."""
import hashlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
source = (HERE / "upstream_verifier.py").read_bytes()
if hashlib.sha256(source).hexdigest() != "afe47e30606d61f09025fa8b2703d7446b08cc0a3093e4b82eace355bfba5303":
    raise ValueError("different upstream verifier source")
old = b'expected_directories.update(str(parent) for parent in Path(name).parents if str(parent) != ".")'
new = b'expected_directories.update(parent.as_posix() for parent in Path(name).parents if parent.as_posix() != ".")'
if source.count(old) != 1:
    raise ValueError("unrecognized original inventory implementation")
(HERE / "receipt_portable.py").write_bytes(source.replace(old, new))
