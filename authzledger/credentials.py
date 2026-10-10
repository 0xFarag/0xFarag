"""Origin/identity-scoped credential resolution; values remain process-local.

No secret hashes, token parsing, automatic login, refresh or browser persistence.
The legacy env reference contract stays byte-for-byte unchanged.
"""
from __future__ import annotations

import os
import re
import secrets
import threading

from .model import ContractError, _target

_ENV = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")


def _value(value):
    if not isinstance(value, str) or not value or len(value) > 16384 or any(ord(c) < 32 or ord(c) == 127 or ord(c) > 255 for c in value):
        raise ContractError("a required credential is missing or not a valid HTTP header value.")
    return value


class CredentialResolver:
    def __init__(self):
        self._sessions = {}
        self._lock = threading.RLock()

    def __repr__(self):
        return "<CredentialResolver values=redacted>"

    def bind_session(self, env_name, value, *, identity, target_origin):
        if not isinstance(env_name, str) or not _ENV.fullmatch(env_name):
            raise ContractError("session credential reference is invalid.")
        if not isinstance(identity, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", identity):
            raise ContractError("session credential identity is invalid.")
        origin = _target(target_origin)
        value = _value(value)
        generation = secrets.token_hex(16)
        with self._lock:
            previous = self._sessions.get(env_name)
            if previous and (previous["identity"], previous["origin"]) != (identity, origin):
                raise ContractError("session reference is already scoped to another identity or origin.")
            self._sessions[env_name] = {"value": value, "identity": identity, "origin": origin, "generation": generation}
        return {"ref": "session://" + env_name, "generation": generation, "identity": identity,
                "target_origin": origin, "binding": "declared", "present": True}

    def clear(self):
        with self._lock:
            self._sessions.clear()

    def remove(self, env_name):
        with self._lock:
            self._sessions.pop(env_name, None)

    def resolve(self, reference, *, identity, target_origin, generation=None):
        if not isinstance(reference, str):
            raise ContractError("credential reference is invalid.")
        scheme, separator, name = reference.partition("://")
        if not separator or scheme not in {"env", "session"} or not _ENV.fullmatch(name):
            raise ContractError("credential reference is invalid.")
        origin = _target(target_origin)
        with self._lock:
            session = self._sessions.get(name)
            if scheme == "session" or session is not None:
                if not session or session["identity"] != identity or session["origin"] != origin:
                    raise ContractError("session credential is unavailable for this identity and origin.")
                if generation is not None and generation != session["generation"]:
                    raise ContractError("session credential generation changed; review required.")
                return session["value"]
        return _value(os.environ.get(name))

    def resolve_many(self, refs, scope, generation=None):
        if not isinstance(refs, (list, tuple)) or not isinstance(scope, dict) or set(scope) != {"identity", "target_origin"}:
            raise ContractError("credential scope or reference list is invalid.")
        return {reference: self.resolve(reference, generation=generation, **scope) for reference in refs}

    def resolve_contract(self, contract):
        # Caller validates the source contract before resolving. All identities
        # resolve before any transport, including unused identities as in v1.
        resolved = {}
        for identity, config in contract["identities"].items():
            headers = {}
            for key, reference in config["headers"].items():
                headers[key] = self.resolve("env://" + reference["env"], identity=identity,
                                            target_origin=contract["target"]) if isinstance(reference, dict) else reference
            resolved[identity] = headers
        return resolved

    def metadata(self):
        with self._lock:
            return [{"ref": "session://" + name, "generation": entry["generation"], "identity": entry["identity"],
                     "target_origin": entry["origin"], "binding": "declared", "present": True}
                    for name, entry in sorted(self._sessions.items())]
