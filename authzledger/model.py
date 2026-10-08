"""Strict, secret-free validation for explicitly scoped authorization contracts."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import math
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit


class ContractError(ValueError):
    """A contract cannot be executed safely or unambiguously."""


DEFAULT_LIMITS = {"max_requests": 50, "timeout_seconds": 5,
                  "max_response_bytes": 65536, "concurrency": 4}
_LIMIT_BOUNDS = {"max_requests": (1, 1000), "timeout_seconds": (0.1, 60),
                 "max_response_bytes": (1, 1048576), "concurrency": (1, 16)}
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")
_IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_ENV = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")
_HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_SENSITIVE = re.compile(r"auth|cookie|token|key|secret|credential|session|role|permission|identity|tenant|account", re.I)
_FORBIDDEN_HEADERS = {"host", "content-length", "transfer-encoding", "connection",
                      "proxy-connection", "keep-alive", "te", "trailer", "upgrade",
                      "expect", "accept-encoding", "forwarded", "x-real-ip"}
_CASE_HEADERS = {"accept", "accept-language", "content-type", "user-agent",
                 "cache-control", "pragma", "x-request-id", "x-correlation-id"}
_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_MAX_FILE_BYTES = 2 * 1048576


def _error(message: str) -> None:
    raise ContractError(message)


def _fields(value: object, allowed: set[str], label: str, required: set[str] | None = None) -> dict:
    if not isinstance(value, dict):
        _error(f"{label} must be an object.")
    if any(not isinstance(key, str) for key in value):
        _error(f"{label} keys must be strings.")
    if set(value) - allowed:
        _error(f"{label} contains unknown fields.")
    if required and required - set(value):
        _error(f"{label} is missing required fields.")
    return value


def _string(value: object, label: str, maximum: int = 200) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        _error(f"{label} must be a nonempty string of at most {maximum} characters.")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        _error(f"{label} contains control characters.")
    try:
        value.encode("utf-8")
    except UnicodeError:
        _error(f"{label} must be valid Unicode.")
    return value


def _identifier(value: object, label: str, pattern: re.Pattern = _ID) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        _error(f"{label} is not a valid identifier.")
    return value


def _json_value(value: object, label: str, depth: int = 0) -> None:
    if depth > 40:
        _error(f"{label} is nested too deeply.")
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, (int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            _error(f"{label} contains a non-finite number.")
        return
    if isinstance(value, list):
        for item in value:
            _json_value(item, label, depth + 1)
        return
    if isinstance(value, dict) and all(isinstance(key, str) for key in value):
        for item in value.values():
            _json_value(item, label, depth + 1)
        return
    _error(f"{label} must contain JSON values only.")


def _target(value: object) -> str:
    value = _string(value, "target", 2048)
    if not value.isascii() or any(c.isspace() for c in value) or "\\" in value or "%" in value:
        _error("target must be an ASCII HTTP(S) origin without escapes.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        _error("target is not a valid HTTP(S) origin.")
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
            or "?" in value or "#" in value):
        _error("target must be an HTTP(S) origin without credentials, path, query or fragment.")
    host = parsed.hostname
    if ":" in host:
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            _error("target has an invalid IPv6 address.")
        host = f"[{host.lower()}]"
    elif not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9.])?", host):
        _error("target has an invalid hostname.")
    if port is not None and not 1 <= port <= 65535:
        _error("target port is outside the valid range.")
    if parsed.netloc.endswith(":"):
        _error("target port must not be empty.")
    port_part = "" if port is None or (parsed.scheme, port) in {("http", 80), ("https", 443)} else f":{port}"
    return f"{parsed.scheme}://{host.lower()}{port_part}"


def _path(value: object) -> str:
    value = _string(value, "case path", 8192)
    if (not value.isascii() or not value.startswith("/") or value.startswith("//")
            or "#" in value or "\\" in value or any(c.isspace() for c in value)):
        _error("case path must be an exact ASCII relative URL starting with one slash.")
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        _error("case path contains an invalid percent escape.")
    # Reject parser disagreements and nested encodings before URL construction.
    decoded = value
    for _ in range(8):
        if any(ord(c) < 32 or ord(c) == 127 for c in decoded) or "\\" in decoded:
            _error("case path contains encoded control characters or backslashes.")
        path_part = decoded.split("?", 1)[0]
        if path_part.startswith("//") or any(part in {".", ".."} for part in path_part.split("/")):
            _error("case path contains traversal or a network-path reference.")
        if re.search(r"%(?:2f|5c|3f|23)", path_part, re.I):
            _error("case path contains an encoded URL delimiter.")
        next_decoded = unquote(decoded, encoding="utf-8", errors="replace")
        if next_decoded == decoded:
            return value
        decoded = next_decoded
    _error("case path contains excessive nested encodings.")


def _headers(value: object, *, case: bool = False) -> dict:
    if not isinstance(value, dict) or len(value) > 32:
        _error("headers must be an object with at most 32 entries.")
    result = {}
    names = set()
    for key, header_value in value.items():
        if not isinstance(key, str) or len(key) > 128 or not _HEADER.fullmatch(key):
            _error("header name is invalid.")
        lowered = key.lower()
        if lowered in names:
            _error("header names must be unique ignoring case.")
        names.add(lowered)
        if lowered in _FORBIDDEN_HEADERS or lowered.startswith(("proxy-", "x-forwarded-")):
            _error("routing and connection headers cannot be configured.")
        if case and lowered not in _CASE_HEADERS:
            _error("case headers are limited to content negotiation and request identifiers; use identity headers for security context.")
        if isinstance(header_value, dict):
            if case:
                _error("case headers must be literals.")
            _fields(header_value, {"env"}, "header environment reference", {"env"})
            result[key] = {"env": _identifier(header_value["env"], "environment variable", _ENV)}
        else:
            if not isinstance(header_value, str) or len(header_value) > 16384:
                _error("header values must be strings or environment references.")
            if any(ord(c) < 32 or ord(c) == 127 or ord(c) > 255 for c in header_value):
                _error("header values contain invalid characters.")
            if _SENSITIVE.search(lowered):
                _error("sensitive identity headers must use environment references.")
            result[key] = header_value
    return result


def _pointer(value: object) -> str:
    if not isinstance(value, str) or len(value) > 2048 or (value and not value.startswith("/")):
        _error("JSON checks must use RFC 6901 JSON pointers.")
    if re.search(r"~(?![01])", value):
        _error("JSON pointer contains an invalid escape.")
    return value


def _expect(value: object) -> dict:
    _fields(value, {"status", "json", "json_absent"}, "expect", {"status"})
    statuses = value["status"]
    if (not isinstance(statuses, list) or not statuses or len(statuses) > 100
            or any(type(status) is not int or not 100 <= status <= 599 for status in statuses)
            or len(set(statuses)) != len(statuses)):
        _error("expect.status must contain distinct HTTP status integers.")
    result = {"status": sorted(statuses)}
    if "json" in value:
        checks = value["json"]
        if not isinstance(checks, dict) or len(checks) > 100:
            _error("expect.json must be an object with at most 100 pointer checks.")
        for pointer, expected in checks.items():
            _pointer(pointer)
            _json_value(expected, "JSON expectation")
        result["json"] = copy.deepcopy(checks)
    if "json_absent" in value:
        absent = value["json_absent"]
        if not isinstance(absent, list) or len(absent) > 100:
            _error("expect.json_absent must be a list with at most 100 pointers.")
        for pointer in absent:
            _pointer(pointer)
        if len(set(absent)) != len(absent):
            _error("expect.json_absent contains duplicate pointers.")
        if set(absent).intersection(result.get("json", {})):
            _error("a JSON pointer cannot be both required and absent.")
        result["json_absent"] = list(absent)
    return result


def _case(value: object, identities: dict, allow_mutations: bool) -> dict:
    _fields(value, {"id", "identity", "method", "path", "expect", "requires", "body", "headers"},
            "case", {"id", "identity", "method", "path", "expect"})
    case_id = _identifier(value["id"], "case id")
    identity = _identifier(value["identity"], "case identity", _IDENTITY)
    if identity not in identities:
        _error("case references an undefined identity.")
    method = value["method"]
    if not isinstance(method, str) or method not in _METHODS:
        _error("case method must be a supported uppercase HTTP method.")
    if method not in _SAFE_METHODS and not allow_mutations:
        _error("mutating methods require explicit --allow-mutations authorization.")
    requires = value.get("requires", [])
    if not isinstance(requires, list) or len(requires) > 1000:
        _error("case requires must be a list of case identifiers.")
    for dependency in requires:
        _identifier(dependency, "prerequisite id")
    if len(set(requires)) != len(requires):
        _error("case requires contains duplicate identifiers.")
    result = {"id": case_id, "identity": identity, "method": method, "path": _path(value["path"]),
              "requires": list(requires), "expect": _expect(value["expect"]),
              "headers": _headers(value.get("headers", {}), case=True)}
    if "body" in value:
        if method in {"GET", "HEAD"}:
            _error("GET and HEAD bodies are not supported.")
        _json_value(value["body"], "case body")
        if len(json.dumps(value["body"], allow_nan=False).encode("utf-8")) > 1048576:
            _error("case body exceeds 1 MiB.")
        result["body"] = copy.deepcopy(value["body"])
    return result


def _pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            _error("contract contains duplicate JSON object keys.")
        result[key] = value
    return result


def load_contract(path_or_dict, *, allow_mutations: bool = False) -> dict:
    """Read and normalize a contract without reading credential environments."""
    if isinstance(path_or_dict, dict):
        value = path_or_dict
    else:
        try:
            with Path(path_or_dict).open("rb") as stream:
                raw = stream.read(_MAX_FILE_BYTES + 1)
            if len(raw) > _MAX_FILE_BYTES:
                _error("contract file exceeds 2 MiB.")
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, RecursionError, ValueError) as exc:
            if isinstance(exc, ContractError):
                raise
            raise ContractError("contract file could not be read as UTF-8 JSON.") from None
    _fields(value, {"version", "name", "target", "limits", "identities", "cases", "matrices"},
            "contract", {"version", "name", "target", "identities"})
    if type(value["version"]) is not int or value["version"] != 1:
        _error("only contract version 1 is supported.")
    supplied_limits = value.get("limits", {})
    _fields(supplied_limits, set(DEFAULT_LIMITS), "limits")
    limits = dict(DEFAULT_LIMITS, **supplied_limits)
    for key, number in limits.items():
        low, high = _LIMIT_BOUNDS[key]
        correct_type = type(number) in {int, float} if key == "timeout_seconds" else type(number) is int
        if not correct_type or not low <= number <= high:
            _error(f"limits.{key} must be between {low} and {high}.")
    identities = value["identities"]
    if not isinstance(identities, dict) or not identities or len(identities) > 100:
        _error("identities must contain between 1 and 100 named objects.")
    normalized_identities = {}
    for name, identity in identities.items():
        _identifier(name, "identity name", _IDENTITY)
        _fields(identity, {"headers"}, "identity", {"headers"})
        normalized_identities[name] = {"headers": _headers(identity["headers"])}
    raw_cases = value.get("cases", [])
    matrices = value.get("matrices", [])
    if not isinstance(raw_cases, list) or not isinstance(matrices, list):
        _error("cases and matrices must be lists.")
    expanded = list(raw_cases)
    for matrix in matrices:
        _fields(matrix, {"id", "method", "path", "rules", "body", "headers"},
                "matrix", {"id", "method", "path", "rules"})
        matrix_id = _identifier(matrix["id"], "matrix id")
        rules = matrix["rules"]
        if not isinstance(rules, list) or not rules:
            _error("matrix rules must be a nonempty list.")
        for rule in rules:
            _fields(rule, {"identity", "expect", "requires"}, "matrix rule", {"identity", "expect"})
            identity = _identifier(rule["identity"], "matrix identity", _IDENTITY)
            item = {key: matrix[key] for key in ("method", "path", "body", "headers") if key in matrix}
            item.update(rule)
            item["id"] = f"{matrix_id}:{identity}"
            expanded.append(item)
            if len(expanded) > limits["max_requests"]:
                _error("expanded cases exceed limits.max_requests.")
    if not expanded or len(expanded) > limits["max_requests"]:
        _error("contract must contain 1 to limits.max_requests expanded cases.")
    cases = [_case(case, normalized_identities, allow_mutations) for case in expanded]
    ids = [case["id"] for case in cases]
    if len(set(ids)) != len(ids):
        _error("expanded case identifiers must be unique.")
    id_set = set(ids)
    pending = {}
    for case in cases:
        if set(case["requires"]) - id_set:
            _error("case references an undefined prerequisite.")
        pending[case["id"]] = set(case["requires"])
    resolved = set()
    while pending:
        ready = {case_id for case_id, dependencies in pending.items() if dependencies <= resolved}
        if not ready:
            _error("case prerequisites contain a dependency cycle.")
        resolved.update(ready)
        for case_id in ready:
            del pending[case_id]
    return {"version": 1, "name": _string(value["name"], "name"), "target": _target(value["target"]),
            "limits": limits, "identities": normalized_identities, "cases": cases}


def contract_digest(contract: dict) -> str:
    """Hash canonical contract JSON; never resolve environment references."""
    try:
        payload = json.dumps(contract, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                             allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError):
        raise ContractError("contract cannot be serialized as canonical JSON.") from None
    return hashlib.sha256(payload).hexdigest()


def plan(contract: dict) -> dict:
    """Return the explicit execution scope without header or body values."""
    cases = [{"id": case["id"], "identity": case["identity"], "method": case["method"],
              "path": case["path"], "requires": list(case["requires"]),
              "checks": ["status"] + ["json"] * len(case["expect"].get("json", {}))
                        + ["json_absent"] * len(case["expect"].get("json_absent", []))}
             for case in contract["cases"]]
    return {"schema_version": 1, "name": contract["name"], "target": contract["target"],
            "contract_sha256": contract_digest(contract), "limits": dict(contract["limits"]),
            "identities": list(contract["identities"]), "request_count": len(cases),
            "mutating_requests": sum(case["method"] not in _SAFE_METHODS for case in cases),
            "cases": cases}
