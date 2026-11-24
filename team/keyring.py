# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Installation signing keys. Callers commit the surrounding evidence transaction."""
import base64
from datetime import datetime, timezone
import os
from pathlib import Path
import stat
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .evidence_formats import canonical, sha


ROTATION_DAYS = 90
PERIOD = ROTATION_DAYS * 86400
SLOTS = ("evidence-signing.key", "evidence-signing-next.key")
STAGING = ".evidence-signing.stage"
BOOTSTRAP = ".evidence-signing.birth"
HISTORY_CONTEXT = b"authzledger.team-key-history.v1\n"


class KeyStoreError(Exception):
    status = 503

    def __init__(self, message):
        super().__init__(message)
        self.message = message


def unix_time():
    return int(time.time())


def _date(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")


def init_db(db):
    db.execute("CREATE TABLE IF NOT EXISTS evidence_signer (id INTEGER PRIMARY KEY CHECK(id=1), fingerprint TEXT NOT NULL)")
    db.execute("""CREATE TABLE IF NOT EXISTS evidence_key_generations (
               generation INTEGER PRIMARY KEY CHECK(generation>=1), fingerprint TEXT NOT NULL UNIQUE,
               public_key TEXT NOT NULL, activated_at INTEGER NOT NULL, retired_at INTEGER)""")
    db.execute("""CREATE TABLE IF NOT EXISTS evidence_key_history_seal (
               id INTEGER PRIMARY KEY CHECK(id=1), signature BLOB NOT NULL)""")


def key_descriptor(public_key):
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"algorithm": "Ed25519", "public_key": base64.b64encode(raw).decode("ascii"), "fingerprint": sha(raw)}


def _directory(data_dir):
    directory = Path(data_dir)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise KeyStoreError("Signing directory must be a local directory")
    if os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o022):
        raise KeyStoreError("Signing directory must be owned by the service account and protected against other writers")
    return directory


def _sync_dir(directory):
    if os.name == "posix":
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _store(directory, name, raw):
    # Only the connection holding SQLite's write lock uses this fixed staging path.
    stage = directory / STAGING
    stage.unlink(missing_ok=True)
    fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        destination = directory / name
        if os.name == "nt":
            import ctypes
            from ctypes import wintypes
            move = ctypes.WinDLL("kernel32", use_last_error=True).MoveFileExW
            move.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
            move.restype = wintypes.BOOL
            # MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH
            if not move(str(stage), str(destination), 0x1 | 0x8):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            os.replace(stage, destination)
            _sync_dir(directory)
    finally:
        stage.unlink(missing_ok=True)


def _read(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise KeyStoreError("Invalid signing key path")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise KeyStoreError("Invalid signing key file")
        if os.name == "posix" and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise KeyStoreError("Signing key file permissions must be owner-only")
        raw = stream.read(8193)
        if len(raw) > 8192:
            raise KeyStoreError("Invalid signing key file")
        return raw


def _dpapi(data, *, decrypt):
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("size", wintypes.DWORD), ("data", ctypes.POINTER(ctypes.c_ubyte))]

    source = Blob(len(data), (ctypes.c_ubyte * len(data)).from_buffer_copy(data))
    output = Blob()
    api = ctypes.WinDLL("crypt32", use_last_error=True)
    call = api.CryptUnprotectData if decrypt else api.CryptProtectData
    # Null description, entropy and prompt. Current user scope, CRYPTPROTECT_UI_FORBIDDEN.
    if not call(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(output)):
        raise KeyStoreError("Cannot access the signing key with this Windows user profile")
    try:
        return ctypes.string_at(output.data, output.size)
    finally:
        ctypes.memset(output.data, 0, output.size)
        ctypes.windll.kernel32.LocalFree(ctypes.cast(output.data, ctypes.c_void_p))


def _save_key(directory, name, key):
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    if os.name == "nt":
        raw = b"AZLDPAPI1" + _dpapi(raw, decrypt=False)
    _store(directory, name, raw)


def _load_key(directory, name):
    try:
        raw = _read(directory / name)
    except FileNotFoundError:
        raise KeyStoreError("Installation signing key is missing; restore the matching backup") from None
    wrapped = os.name == "nt" and raw.startswith(b"AZLDPAPI1") and len(raw) != 32
    try:
        key = Ed25519PrivateKey.from_private_bytes(_dpapi(raw[9:], decrypt=True) if wrapped else raw)
    except ValueError:
        raise KeyStoreError("Invalid signing key data") from None
    return key, wrapped


def _rows(db):
    return [dict(generation=g, fingerprint=f, public_key=p, activated_at=a, retired_at=r)
            for g, f, p, a, r in db.execute("SELECT generation,fingerprint,public_key,activated_at,retired_at "
                                            "FROM evidence_key_generations ORDER BY generation")]


def _seal(db, key):
    signature = key.sign(HISTORY_CONTEXT + canonical(_rows(db)))
    db.execute("INSERT OR REPLACE INTO evidence_key_history_seal VALUES(1,?)", (signature,))


def _history(db, directory):
    rows = _rows(db)
    pinned = db.execute("SELECT fingerprint FROM evidence_signer WHERE id=1").fetchone()
    seal = db.execute("SELECT signature FROM evidence_key_history_seal WHERE id=1").fetchone()
    if not rows and not seal:
        return rows, pinned[0] if pinned else None
    try:
        if not rows or not seal or not pinned or pinned[0] != rows[-1]["fingerprint"]:
            raise ValueError
        raw = base64.b64decode(rows[-1]["public_key"], validate=True)
        anchor_file = directory / (_slot(rows[-1]["generation"]) + ".pub")
        if sha(raw) != pinned[0] or _read(anchor_file) != raw:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(raw).verify(seal[0], HISTORY_CONTEXT + canonical(rows))
    except (InvalidSignature, TypeError, ValueError, OSError):
        raise KeyStoreError("Installation signing history differs from its trust anchor") from None
    return rows, pinned[0]


def _slot(generation):
    return SLOTS[(generation - 1) % 2]


def _register(db, directory, key, generation, timestamp):
    desc = key_descriptor(key.public_key())
    _store(directory, _slot(generation) + ".pub", base64.b64decode(desc["public_key"]))
    db.execute("INSERT INTO evidence_key_generations VALUES(?,?,?,?,NULL)",
               (generation, desc["fingerprint"], desc["public_key"], timestamp))
    db.execute("INSERT OR REPLACE INTO evidence_signer VALUES(1,?)", (desc["fingerprint"],))
    _seal(db, key)
    return key, desc


def _initial(db, directory, pin, timestamp):
    primary = directory / SLOTS[0]
    if os.path.lexists(directory / (SLOTS[0] + ".pub")):
        if not os.path.lexists(directory / BOOTSTRAP) or not os.path.lexists(primary):
            raise KeyStoreError("Installation signing history is missing; restore the matching backup")
    if os.path.lexists(directory / (SLOTS[1] + ".pub")) or (not pin and os.path.lexists(directory / SLOTS[1])):
        raise KeyStoreError("Private signing slot exists without an installation trust anchor")
    if pin or os.path.lexists(primary):
        key, wrapped = _load_key(directory, SLOTS[0])
        fingerprint = key_descriptor(key.public_key())["fingerprint"]
        if not pin:
            # Resume only our unfinished first provisioning. An unpinned legacy key is ambiguous.
            try:
                birth = _read(directory / BOOTSTRAP)
            except FileNotFoundError:
                birth = b""
            if birth != fingerprint.encode("ascii"):
                raise KeyStoreError("Signing key exists without its installation trust anchor")
        elif pin != fingerprint:
            raise KeyStoreError("Signing key differs from the installation trust anchor")
        if os.name == "nt" and not wrapped:
            _save_key(directory, SLOTS[0], key)
        _store(directory, BOOTSTRAP, fingerprint.encode("ascii"))
    else:
        key = Ed25519PrivateKey.generate()
        _store(directory, BOOTSTRAP, key_descriptor(key.public_key())["fingerprint"].encode("ascii"))
        _save_key(directory, SLOTS[0], key)
    return _register(db, directory, key, 1, timestamp)


def signer(db, data_dir, *, rotate=True):
    if not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")
    try:
        # Standalone Python callers can pass a new database as in the original signer API.
        init_db(db)
        directory = _directory(data_dir)
        rows, pin = _history(db, directory)
        timestamp = unix_time()
        if not rows:
            return _initial(db, directory, pin, timestamp)
        current = rows[-1]
        key, wrapped = _load_key(directory, _slot(current["generation"]))
        if os.name == "nt" and not wrapped:
            raise KeyStoreError("Expected a Windows-protected signing key")
        desc = key_descriptor(key.public_key())
        if desc["fingerprint"] != pin:
            raise KeyStoreError("Signing key differs from the installation trust anchor")
        if not rotate or timestamp < current["activated_at"] + PERIOD:
            return key, desc
        generation = current["generation"] + 1
        key = Ed25519PrivateKey.generate()
        _save_key(directory, _slot(generation), key)
        db.execute("UPDATE evidence_key_generations SET retired_at=? WHERE generation=?", (timestamp, generation-1))
        return _register(db, directory, key, generation, timestamp)
    except OSError:
        raise KeyStoreError("Cannot persist or access the installation signing key") from None


def history(db, data_dir):
    if not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")
    try:
        directory = _directory(data_dir)
    except OSError:
        raise KeyStoreError("Cannot access the installation signing directory") from None
    rows, _ = _history(db, directory)
    if not rows:
        signer(db, data_dir, rotate=False)
        rows, _ = _history(db, directory)
    entries = []
    for row in reversed(rows):
        retired = row["retired_at"]
        entries.append({"algorithm": "Ed25519", "fingerprint": row["fingerprint"], "public_key": row["public_key"],
                        "status": "retired" if retired is not None else "active", "activated_at": _date(row["activated_at"]),
                        "retired_at": _date(retired) if retired is not None else None,
                        "rotate_after": None if retired is not None else _date(row["activated_at"] + PERIOD)})
    return {"active_fingerprint": entries[0]["fingerprint"], "rotation_days": ROTATION_DAYS, "keys": entries}


def prune_committed(db, data_dir):
    """Run after commit, in a new exclusive writer transaction, so a rollback never loses the old key."""
    if db.in_transaction:
        raise RuntimeError("Signing key cleanup requires a committed transaction")
    db.execute("BEGIN IMMEDIATE")
    try:
        directory = _directory(data_dir)
        rows, pin = _history(db, directory)
        if rows:
            generation = rows[-1]["generation"]
            active, _ = _load_key(directory, _slot(generation))
            if key_descriptor(active.public_key())["fingerprint"] != pin:
                raise KeyStoreError("Signing key differs from the installation trust anchor")
            inactive = _slot(generation + 1)
            stale = [inactive, inactive + ".pub", BOOTSTRAP, STAGING]
            for name in stale:
                (directory / name).unlink(missing_ok=True)
            _sync_dir(directory)
        db.commit()
    except BaseException:
        db.rollback()
        raise
