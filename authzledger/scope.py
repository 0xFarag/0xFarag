"""Versioned assessment scope and bounded, IP-pinned transport capabilities.

Scope is an operator declaration, not independent proof of target ownership.
Validating retained scope bytes is offline; freshness is checked only for I/O.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import math
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .model import _target, _path, _identifier, ContractError
from .oracles import seal, canonical


class ScopeError(ValueError):
    pass


def canonical_origin(value):
    if not isinstance(value, str):
        raise ScopeError("invalid_origin")
    if value.startswith("tcp://"):
        parsed = urlsplit(value)
        if parsed.scheme != "tcp" or not parsed.hostname or parsed.port is None or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None:
            raise ScopeError("invalid_service_origin")
        checked = _target("http://" + parsed.netloc)
        hostname = urlsplit(checked).hostname
        display = "[" + hostname + "]" if ":" in hostname else hostname
        return "tcp://" + display + ":" + str(parsed.port)
    try:
        return _target(value)
    except (ValueError, TypeError) as exc:
        raise ScopeError("invalid_origin") from None


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ScopeError("invalid_scope_expiry")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(timezone.utc)
    except ValueError:
        raise ScopeError("invalid_scope_expiry") from None


def validate_scope(value):
    """Normalize and seal a closed, explicit policy without DNS or other I/O."""
    required = {"schema_version", "kind", "id", "authorization_ref", "origins", "operations", "allowed_networks", "expires_at", "limits", "allowed_effects"}
    allowed = required | {"denied_networks", "scope_digest", "schema_id"}
    if not isinstance(value, dict) or set(value) - allowed or required - set(value):
        raise ScopeError("invalid_scope_fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1 or value["kind"] != "assessment-scope":
        raise ScopeError("unsupported_scope_schema")
    try:
        _identifier(value["id"], "scope id")
    except ValueError:
        raise ScopeError("invalid_scope_id") from None
    authorization = value["authorization_ref"]
    if not isinstance(authorization, str) or not 1 <= len(authorization) <= 256 or any(ord(c) < 32 or ord(c) == 127 for c in authorization):
        raise ScopeError("authorization_reference_required")
    origins = value["origins"]
    if not isinstance(origins, list) or not 1 <= len(origins) <= 256:
        raise ScopeError("explicit_origins_required")
    origins = sorted({canonical_origin(item) for item in origins})
    from .execution import REQUEST_KINDS
    operations = value["operations"]
    if not isinstance(operations, list) or not 1 <= len(operations) <= 10000:
        raise ScopeError("explicit_operations_required")
    effects = value["allowed_effects"]
    if not isinstance(effects, list) or not effects or set(effects) - {"read", "mutate"} or len(effects) != len(set(effects)):
        raise ScopeError("invalid_effect_authorization")
    normalized_ops = []
    for op in operations:
        if not isinstance(op, dict) or set(op) - {"origin", "method", "path", "purpose", "effect"} or {"origin", "method", "path", "purpose"} - set(op):
            raise ScopeError("invalid_operation_fields")
        origin = canonical_origin(op["origin"])
        method, purpose = op["method"], op["purpose"]
        if origin not in origins or purpose not in REQUEST_KINDS:
            raise ScopeError("operation_outside_scope")
        if not isinstance(method, str) or method not in {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE", "CONNECT"}:
            raise ScopeError("invalid_operation_method")
        try:
            path = _path(op["path"])
        except ValueError:
            raise ScopeError("invalid_operation_path") from None
        if origin.startswith("tcp://"):
            if purpose != "service" or method != "CONNECT" or path != "/":
                raise ScopeError("invalid_service_operation")
        elif method == "CONNECT" or purpose == "service":
            raise ScopeError("invalid_http_operation")
        # This is an operator declaration. GET/HEAD may still have side effects.
        effect = op.get("effect", "read" if method in {"GET", "HEAD", "OPTIONS", "CONNECT"} else "mutate")
        if effect not in effects:
            raise ScopeError("effect_not_authorized")
        normalized_ops.append({"origin": origin, "method": method, "path": path, "purpose": purpose, "effect": effect})
    normalized_ops = sorted({canonical(op): op for op in normalized_ops}.values(), key=lambda op: (op["origin"], op["purpose"], op["method"], op["path"], op["effect"]))
    # Reject ambiguous duplicate authorizations carrying different effects.
    keys = [(op["origin"], op["purpose"], op["method"], op["path"]) for op in normalized_ops]
    if len(keys) != len(set(keys)):
        raise ScopeError("conflicting_operation_effects")
    networks = {}
    for field in ("allowed_networks", "denied_networks"):
        items = value.get(field, [])
        if not isinstance(items, list) or len(items) > 256 or (field == "allowed_networks" and not items):
            raise ScopeError("explicit_network_boundary_required")
        try:
            if any(not isinstance(item, str) or "/" not in item for item in items):
                raise ValueError
            networks[field] = sorted({str(ipaddress.ip_network(item, strict=True)) for item in items})
        except (ValueError, TypeError):
            raise ScopeError("invalid_network_boundary") from None
    limits = value["limits"]
    bounds = {"max_requests": (1, 1000000), "concurrency": (1, 16), "timeout_seconds": (.1, 60), "max_response_bytes": (1, 1048576)}
    if not isinstance(limits, dict) or set(limits) != set(bounds):
        raise ScopeError("invalid_scope_limits")
    for key, (minimum, maximum) in bounds.items():
        current = limits[key]
        types = (int, float) if key == "timeout_seconds" else (int,)
        if type(current) not in types or not math.isfinite(current) or not minimum <= current <= maximum:
            raise ScopeError("invalid_scope_limits")
    expires = _timestamp(value["expires_at"]).isoformat().replace("+00:00", "Z")
    result = {"schema_id": "authzledger.assessment-scope", "schema_version": 1, "kind": "assessment-scope", "id": value["id"], "authorization_ref": authorization, "origins": origins, "operations": normalized_ops, "expires_at": expires, "limits": copy.deepcopy(limits), "allowed_effects": sorted(effects), **networks}
    result = seal("assessment-scope", result, "scope_digest")
    if "scope_digest" in value and value["scope_digest"] != result["scope_digest"]:
        raise ScopeError("scope_digest_mismatch")
    if "schema_id" in value and value["schema_id"] != result["schema_id"]:
        raise ScopeError("unsupported_scope_schema")
    return result


def verify_scope(value):
    try:
        return [] if canonical(value) == canonical(validate_scope(value)) else ["scope_mismatch"]
    except (ValueError, TypeError, KeyError):
        return ["invalid_scope"]


def seconds_remaining(scope):
    return _timestamp(scope["expires_at"]).timestamp() - time.time()


def assert_scope_active(scope):
    if seconds_remaining(scope) <= 0:
        from .execution import ExecutionError
        raise ExecutionError("authorization-expired")


def context_for_scope(scope, *, max_requests=None, cleanup_reserve=0, allow_cleanup_after_cancel=False):
    from .execution import ExecutionContext
    normalized = validate_scope(scope)
    assert_scope_active(normalized)
    limit = normalized["limits"]["max_requests"]
    if max_requests is not None:
        if type(max_requests) is not int or not 1 <= max_requests <= limit:
            raise ScopeError("request_budget_cannot_expand_scope")
        limit = max_requests
    targets = {"application": normalized["origins"],
               "pdp": sorted({op["origin"] + op["path"] for op in normalized["operations"] if op["purpose"] == "pdp"}),
               "advisory": sorted({op["origin"] + op["path"] for op in normalized["operations"] if op["purpose"] == "advisory"})}
    return ExecutionContext(limit, targets, normalized["limits"]["timeout_seconds"], normalized["limits"]["concurrency"],
                            cleanup_reserve=cleanup_reserve, allow_cleanup_after_cancel=allow_cleanup_after_cancel,
                            approved_operations=[(op["origin"], op["purpose"], op["method"], op["path"]) for op in normalized["operations"]], scope_policy=normalized)


# A cancellable resolver subprocess avoids unbounded blocked getaddrinfo threads.
# At most ExecutionContext.concurrency subprocesses are active for one context.
_RESOLVER_SCRIPT = "import json,socket,sys; r=socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),0,socket.SOCK_STREAM); print(json.dumps(r if len(r)<=64 else [],separators=(',',':')))"


def _resolve_addresses(host, port, deadline):
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        family = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
        destination = (str(literal), port, 0, 0) if literal.version == 6 else (str(literal), port)
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", destination)]
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    process = subprocess.Popen([sys.executable, "-I", "-c", _RESOLVER_SCRIPT, host, str(port)], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
    try:
        output, _ = process.communicate(timeout=max(.001, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise TimeoutError from None
    if process.returncode != 0 or len(output) > 65536:
        raise OSError("DNS resolution failed")
    try:
        values = json.loads(output)
        if not isinstance(values, list) or not values or len(values) > 64:
            raise ValueError
        result = []
        for family, kind, protocol, canon, destination in values:
            if family not in {socket.AF_INET, socket.AF_INET6} or kind != socket.SOCK_STREAM or protocol not in {0, socket.IPPROTO_TCP} or not isinstance(destination, list) or len(destination) not in {2, 4}:
                raise ValueError
            ipaddress.ip_address(destination[0])
            if destination[1] != port:
                raise ValueError
            result.append((family, kind, protocol, "", tuple(destination)))
        return result
    except (ValueError, TypeError):
        raise OSError("Invalid DNS response") from None


def _address_allowed(scope, address):
    try:
        ip = ipaddress.ip_address(address)
        # IPv4-mapped IPv6 must satisfy the effective IPv4 boundary as well.
        effective = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
        allowed = any(effective.version == net.version and effective in net for net in map(ipaddress.ip_network, scope["allowed_networks"]))
        denied = any(effective.version == net.version and effective in net for net in map(ipaddress.ip_network, scope["denied_networks"]))
        return allowed and not denied
    except ValueError:
        return False


class BoundSocketPolicy:
    """One context and one origin; DNS results are checked before socket creation."""
    def __init__(self, context, origin, *, kind="application"):
        self.context = context
        self.scope = context.scope_policy
        self.kind = kind
        self.origin = canonical_origin(origin)
        if self.origin not in self.scope["origins"]:
            from .execution import ExecutionError
            raise ExecutionError("origin-outside-scope")

    def resolve(self, host, port, deadline):
        from .execution import ExecutionError
        assert_scope_active(self.scope)
        parsed = urlsplit(self.origin)
        expected_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if host.lower() != parsed.hostname.lower() or port != expected_port:
            raise ExecutionError("transport-target-mismatch")
        values = _resolve_addresses(host, port, min(deadline, time.monotonic() + max(0, seconds_remaining(self.scope))))
        if not values or any(not _address_allowed(self.scope, item[4][0]) for item in values):
            raise ExecutionError("resolved-address-outside-scope")
        assert_scope_active(self.scope)
        if self.context._is_cancelled() and not (self.kind == "cleanup" and self.context.allow_cleanup_after_cancel):
            raise ExecutionError("cancelled")
        # Never perform a hidden fallback connection to another address.
        return values[:1]


def probe_service(context, origin, *, operation_id="service-probe", banner_bytes=128):
    """One approved TCP connection with a bounded optional banner, never two."""
    from .execution import ExecutionContext, ExecutionError
    from .engine import _RequestDeadline
    if not isinstance(context, ExecutionContext) or context.scope_policy is None:
        raise ScopeError("service_probe_requires_bound_scope")
    origin = canonical_origin(origin)
    if not origin.startswith("tcp://") or type(banner_bytes) is not int or not 0 <= banner_bytes <= 4096:
        raise ScopeError("invalid_service_probe")
    result = {"origin": origin, "state": "blocked", "error_code": None, "peer_ip": None, "protocol_hint": None, "version_hint": None, "version_basis": None, "banner_sha256": None, "banner_bytes": 0, "elapsed_ms": 0, "scope_digest": context.scope_policy["scope_digest"]}
    started = time.monotonic()
    reservation = None
    def connect():
        deadline = _RequestDeadline(reservation.deadline, connection_policy=context.connection_policy(origin, kind="service"))
        try:
            parsed = urlsplit(origin)
            with deadline.create_connection((parsed.hostname, parsed.port), context.timeout_seconds, None) as sock:
                result["state"] = "open"
                result["peer_ip"] = str(sock.getpeername()[0])
                data = b""
                if banner_bytes:
                    try:
                        sock.settimeout(min(.2, max(.001, reservation.deadline-time.monotonic())))
                        data = sock.recv(min(banner_bytes, context.max_response_bytes))
                    except (TimeoutError, socket.timeout):
                        pass
                result["banner_bytes"] = len(data)
                result["banner_sha256"] = hashlib.sha256(data).hexdigest() if data else None
                # Only normalized protocol/version tokens leave this function.
                text = data.decode("ascii", "ignore")
                if text.startswith("SSH-"):
                    result["protocol_hint"] = "ssh"
                    match = re.match(r"SSH-([0-9]+(?:\.[0-9]+){0,3})-", text)
                    if match: result.update(version_hint=match.group(1), version_basis="protocol")
                elif text.startswith("HTTP/"):
                    result["protocol_hint"] = "http"
                elif text.startswith("220 "):
                    if "smtp" in text.lower(): result["protocol_hint"] = "smtp"
                    elif "ftp" in text.lower(): result["protocol_hint"] = "ftp"
        finally:
            deadline.close()
    try:
        reservation = context.reserve(kind="service", operation_id=operation_id, target_origin=origin, method="CONNECT", path="/")
        context.dispatch(reservation, connect)
    except ExecutionError as exc:
        result.update(state="blocked", error_code=exc.code)
    except ConnectionRefusedError:
        result.update(state="closed", error_code="connection-refused")
    except (TimeoutError, socket.timeout):
        result.update(state="error", error_code="timeout")
    except OSError:
        result.update(state="error", error_code="connection-error")
    result["elapsed_ms"] = round((time.monotonic()-started)*1000, 3)
    if reservation is not None:
        # dispatch owns finalization; this only enriches a completed ledger row.
        try:
            context.finish(reservation, outcome="completed" if result["state"] == "open" else "error", elapsed_ms=result["elapsed_ms"], response_bytes=result["banner_bytes"])
        except ExecutionError:
            pass
    return result
