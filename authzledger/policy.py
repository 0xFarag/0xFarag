"""Independent policy-as-code decisions with explicit, secret-free provenance.

The local evaluator is a deliberately small decision language, not a parser of
the contract's expectations. OPA calls are opt-in and require an explicit origin
allowlist. Neither adapter receives identity credentials or request bodies.
"""

from __future__ import annotations

import copy
import fnmatch
import hashlib
import http.client
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from .engine import (_DeadlineHTTPHandler, _DeadlineHTTPSHandler, _NoRedirect,
                     _RequestDeadline, _read_body)
from .model import contract_digest, load_contract


class PolicyError(ValueError):
    """The policy or its external decision is ambiguous or unsafe."""


_DECISIONS = {"allow", "deny", "unknown"}
_BASE_FIELDS = {"schema_version", "engine", "context", "case_context"}
_LOCAL_FIELDS = _BASE_FIELDS | {"default", "rules"}
_OPA_FIELDS = _BASE_FIELDS | {"endpoint", "allowed_origins", "timeout_seconds",
                              "max_response_bytes", "credential_env"}
_MAX_BYTES = 2 * 1048576
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z")


def _canonical(value) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        raise PolicyError("policy must contain finite JSON values") from None


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("policy contains duplicate JSON object keys")
        result[key] = value
    return result


def _object(value, fields, label):
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise PolicyError(f"{label} must be an object")
    if set(value) - fields:
        raise PolicyError(f"{label} contains unknown fields")


def _context(value, label):
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise PolicyError(f"{label} must be an object")
    if len(_canonical(value)) > 65536:
        raise PolicyError(f"{label} exceeds 64 KiB")
    # JSON serialization rejects Python-only values only after recursively
    # coercing some keys; require native string keys at every depth instead.
    def check(item, depth=0):
        if depth > 32:
            raise PolicyError(f"{label} is nested too deeply")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise PolicyError(f"{label} keys must be strings")
            for child in item.values():
                check(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                check(child, depth + 1)
        elif item is not None and type(item) not in (str, int, float, bool):
            raise PolicyError(f"{label} must contain JSON values")
    check(value)


def _origin(value, label):
    if not isinstance(value, str) or len(value) > 2048 or not value.isascii():
        raise PolicyError(f"{label} must be an ASCII HTTP(S) URL")
    if any(ord(char) <= 32 or ord(char) == 127 for char in value) or "\\" in value:
        raise PolicyError(f"{label} contains invalid URL characters")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise PolicyError(f"{label} is not a valid URL") from None
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or "%" in parsed.netloc
            or parsed.netloc.endswith(":")):
        raise PolicyError(f"{label} must have no credentials, query or fragment")
    if port is not None and not 1 <= port <= 65535:
        raise PolicyError(f"{label} has an invalid port")
    host = parsed.hostname.lower()
    if ":" in host:
        host = "[" + host + "]"
    port_part = "" if port is None or (parsed.scheme, port) in {("http", 80), ("https", 443)} else f":{port}"
    return parsed, f"{parsed.scheme}://{host}{port_part}"


def load_policy(path_or_dict) -> dict:
    """Read and validate one explicit policy without resolving credentials."""
    if isinstance(path_or_dict, dict):
        try:
            value = copy.deepcopy(path_or_dict)
        except (RecursionError, TypeError, ValueError):
            raise PolicyError("policy cannot be copied as bounded JSON data") from None
    else:
        try:
            with Path(path_or_dict).open("rb") as stream:
                raw = stream.read(_MAX_BYTES + 1)
            if len(raw) > _MAX_BYTES:
                raise PolicyError("policy file exceeds 2 MiB")
            value = json.loads(raw, object_pairs_hook=_unique_pairs)
        except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
            if isinstance(exc, PolicyError):
                raise
            raise PolicyError("policy file could not be read as UTF-8 JSON") from None
    _object(value, _LOCAL_FIELDS | _OPA_FIELDS, "policy")
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise PolicyError("only policy schema version 1 is supported")
    if value.get("engine") not in ("local", "opa"):
        raise PolicyError("policy engine must be local or opa")
    _object(value, _LOCAL_FIELDS if value["engine"] == "local" else _OPA_FIELDS, "policy")
    _context(value.get("context", {}), "policy context")
    case_context = value.get("case_context", {})
    if not isinstance(case_context, dict) or len(case_context) > 1000:
        raise PolicyError("case_context must contain at most 1000 case objects")
    for case_id, context in case_context.items():
        if not isinstance(case_id, str) or not _IDENTIFIER.fullmatch(case_id):
            raise PolicyError("case_context contains an invalid case id")
        _context(context, "case context")
    if value["engine"] == "local":
        if value.get("default", "unknown") not in ("allow", "deny", "unknown"):
            raise PolicyError("local policy default must be allow, deny or unknown")
        rules = value.get("rules")
        if not isinstance(rules, list) or len(rules) > 1000:
            raise PolicyError("local rules must be an array of at most 1000 rules")
        ids = set()
        for rule in rules:
            _object(rule, {"id", "effect", "identities", "methods", "paths", "context"}, "rule")
            identifier = rule.get("id")
            if not isinstance(identifier, str) or not _IDENTIFIER.fullmatch(identifier) or identifier in ids:
                raise PolicyError("rule ids must be valid and unique")
            ids.add(identifier)
            if rule.get("effect") not in ("allow", "deny"):
                raise PolicyError("rule effect must be allow or deny")
            for field in ("identities", "methods", "paths"):
                matches = rule.get(field, ["*"])
                if (not isinstance(matches, list) or not matches or len(matches) > 1000
                        or any(not isinstance(item, str) or not item or len(item) > 8192
                               or any(ord(char) < 32 for char in item) for item in matches)):
                    raise PolicyError(f"rule {field} must be a nonempty string array")
                if field == "methods" and any(item not in {"*", "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"} for item in matches):
                    raise PolicyError("rule methods must be uppercase HTTP methods or *")
            _context(rule.get("context", {}), "rule context")
        value.setdefault("default", "unknown")
    else:
        parsed, endpoint_origin = _origin(value.get("endpoint"), "OPA endpoint")
        if not parsed.path.startswith("/v1/data/") or parsed.path.endswith("/"):
            raise PolicyError("OPA endpoint must identify an exact /v1/data/ decision")
        if any(part in {".", ".."} for part in parsed.path.split("/")) or "%" in parsed.path:
            raise PolicyError("OPA endpoint must not contain traversal or escapes")
        origins = value.get("allowed_origins")
        if not isinstance(origins, list) or not origins or len(origins) > 32:
            raise PolicyError("OPA requires an explicit allowed_origins array")
        normalized = []
        for origin in origins:
            parts, normalized_origin = _origin(origin, "OPA allowed origin")
            if parts.path not in {"", "/"}:
                raise PolicyError("OPA allowed origins cannot contain a path")
            normalized.append(normalized_origin)
        if endpoint_origin not in normalized:
            raise PolicyError("OPA endpoint origin is outside the explicit policy scope")
        value["endpoint"] = endpoint_origin + parsed.path
        value["allowed_origins"] = sorted(set(normalized))
        timeout = value.setdefault("timeout_seconds", 5)
        if type(timeout) not in (int, float) or not 0.1 <= timeout <= 30:
            raise PolicyError("OPA timeout_seconds must be between 0.1 and 30")
        limit = value.setdefault("max_response_bytes", 65536)
        if type(limit) is not int or not 1 <= limit <= 1048576:
            raise PolicyError("OPA max_response_bytes must be between 1 and 1048576")
        if "credential_env" in value and (not isinstance(value["credential_env"], str)
                or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", value["credential_env"])):
            raise PolicyError("OPA credential_env is not a valid environment reference")
    if len(_canonical(value)) > _MAX_BYTES:
        raise PolicyError("policy exceeds 2 MiB")
    return value


def _equal(left, right):
    # A policy context value true must never match the integer 1.
    return _canonical(left) == _canonical(right)


def _local_decision(case, context, config, digest):
    matched = []
    for rule in config["rules"]:
        if any(not any(fnmatch.fnmatchcase(case[source], pattern) for pattern in rule.get(field, ["*"]))
               for source, field in (("identity", "identities"), ("method", "methods"), ("path", "paths"))):
            continue
        if any(key not in context or not _equal(context[key], expected)
               for key, expected in rule.get("context", {}).items()):
            continue
        matched.append(rule)
    selected = next((rule for rule in matched if rule["effect"] == "deny"), None)
    if selected is None:
        selected = next((rule for rule in matched if rule["effect"] == "allow"), None)
    decision = selected["effect"] if selected else config["default"]
    return {"decision": decision, "source": "local-policy",
            "provenance": {"engine": "authzledger-rules-v1", "policy_sha256": digest,
                           "matched_rules": [rule["id"] for rule in matched],
                           "selected_rule": selected["id"] if selected else None,
                           "deny_precedence": True},
            "explanation": "Explicit deny rule took precedence." if selected and decision == "deny"
                           else "First matching allow rule selected." if selected
                           else "No rule matched; explicit policy default used."}


def _opa_decision(case, context, config, digest, credential):
    request_input = {"identity": case["identity"], "method": case["method"],
                     "path": case["path"], "context": context}
    payload = _canonical({"input": request_input})
    if len(payload) > _MAX_BYTES:
        raise PolicyError("OPA request input exceeds 2 MiB")
    headers = {"Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "identity"}
    if credential:
        headers["Authorization"] = "Bearer " + credential
    request = urllib.request.Request(config["endpoint"], data=payload, headers=headers, method="POST")
    deadline = _RequestDeadline(time.monotonic() + config["timeout_seconds"])
    response = None
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                             _DeadlineHTTPHandler(deadline), _DeadlineHTTPSHandler(deadline))
        response = opener.open(request, timeout=config["timeout_seconds"])
        if response.status != 200 or response.headers.get("Content-Encoding", "identity").lower() not in {"", "identity"}:
            raise PolicyError("OPA returned an unsupported HTTP response")
        raw = _read_body(response, config["max_response_bytes"], deadline.deadline)
        result = json.loads(raw, object_pairs_hook=_unique_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(PolicyError("OPA returned nonfinite JSON")))
        if not isinstance(result, dict) or type(result.get("result")) is not bool:
            raise PolicyError("OPA decision must be an explicit JSON boolean result")
        # Do not propagate decision_id or untrusted text: an OPA server can echo
        # credentials there. Hash the complete bounded response instead.
        return {"decision": "allow" if result["result"] else "deny", "source": "opa",
                "provenance": {"engine": "opa-rest-v1", "endpoint": config["endpoint"],
                               "policy_sha256": digest, "input_sha256": hashlib.sha256(payload).hexdigest(),
                               "response_sha256": hashlib.sha256(raw).hexdigest(),
                               "policy_revision": "not independently attested"},
                "explanation": "Boolean decision from the explicitly scoped OPA endpoint; policy revision is not attested."}
    except PolicyError:
        raise
    except (OSError, ValueError, OverflowError, RecursionError, urllib.error.URLError, http.client.HTTPException):
        raise PolicyError("OPA decision request failed or response was invalid") from None
    finally:
        expired = deadline.close()
        if response is not None:
            response.close()
        if expired:
            raise PolicyError("OPA decision request exceeded its deadline")


def evaluate_policy(contract, config) -> dict:
    """Evaluate independent policy input for every case; never infer intent.

    Explicit context may be supplied by the operator. Identity credential
    headers, contract expectations and request bodies never cross this boundary.
    OPA transport errors abort evaluation; they are never converted into deny.
    """
    contract = load_contract(contract, allow_mutations=True)
    config = load_policy(config)
    if config["engine"] == "local":
        selectors = sum(sum(len(rule.get(field, ["*"])) for field in ("identities", "methods", "paths"))
                        for rule in config["rules"])
        if len(contract["cases"]) * selectors > 10000000:
            raise PolicyError("local policy exceeds the 10,000,000-selector evaluation budget; reduce cases or rule patterns")
    if set(config.get("case_context", {})) - {case["id"] for case in contract["cases"]}:
        raise PolicyError("policy case_context references an undefined contract case")
    digest = hashlib.sha256(_canonical(config)).hexdigest()
    credential = None
    if config["engine"] == "opa" and "credential_env" in config:
        credential = os.environ.get(config["credential_env"])
        if (not credential or len(credential) > 16384 or any(ord(char) < 33 or ord(char) > 126 for char in credential)):
            raise PolicyError("OPA credential environment is missing or invalid")
    decisions = {}
    for case in contract["cases"]:
        context = dict(config.get("context", {}), **config.get("case_context", {}).get(case["id"], {}))
        value = (_local_decision(case, context, config, digest) if config["engine"] == "local"
                 else _opa_decision(case, context, config, digest, credential))
        value["input_sha256"] = hashlib.sha256(_canonical({"identity": case["identity"],
                                                         "method": case["method"], "path": case["path"],
                                                         "context": context})).hexdigest()
        decisions[case["id"]] = value
    return {"schema_version": 1, "kind": "policy-evaluation", "engine": config["engine"],
            "contract_sha256": contract_digest(contract), "target": contract["target"],
            "policy_sha256": digest, "decisions": decisions,
            "trust": "Operator-supplied independent policy input; no claim of deployed policy equivalence."}
