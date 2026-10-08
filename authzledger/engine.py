"""Bounded, control-aware execution of explicitly configured HTTP requests."""

from __future__ import annotations

import concurrent.futures
import hashlib
import http.client
import json
import os
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from functools import partial

from . import __version__
from .evidence import seal_report
from .model import ContractError, contract_digest, load_contract


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _RequestDeadline:
    """Interrupt socket I/O at the request deadline, including header parsing.

    Closing only an HTTPConnection is insufficient once HTTPResponse owns its
    buffered socket file. shutdown() interrupts that file's blocked reads too.
    An OS resolver blocked in getaddrinfo remains outside Python's control.
    """

    def __init__(self, deadline: float):
        self.deadline = deadline
        self.expired = False
        self._closed = False
        self._lock = threading.Lock()
        self._sockets = []
        self._timer = threading.Timer(max(0, deadline - time.monotonic()), self._expire)
        self._timer.daemon = True
        self._timer.start()

    @staticmethod
    def _shutdown(sock):
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        finally:
            sock.close()

    def _expire(self):
        with self._lock:
            if self._closed:
                return
            self.expired = True
            sockets = list(self._sockets)
        for sock in sockets:
            self._shutdown(sock)

    def watch(self, sock):
        with self._lock:
            remaining = self.deadline - time.monotonic()
            rejected = self._closed or self.expired or remaining <= 0
            if not rejected:
                self._sockets.append(sock)
        if rejected:
            self._shutdown(sock)
            raise TimeoutError
        sock.settimeout(remaining)
        return sock

    def create_connection(self, address, timeout, source_address):
        # Resolve once, then share the remaining deadline across all address
        # candidates. socket.create_connection applies its timeout separately
        # to each candidate, which could otherwise multiply the time budget.
        host, port = address
        last_error = None
        for family, kind, protocol, _, destination in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
            if time.monotonic() >= self.deadline:
                raise TimeoutError
            sock = socket.socket(family, kind, protocol)
            try:
                self.watch(sock)
                if source_address:
                    sock.bind(source_address)
                sock.connect(destination)
                return sock
            except OSError as exc:
                last_error = exc
                sock.close()
        if last_error is not None:
            raise last_error
        raise OSError("No connection addresses available")

    def close(self) -> bool:
        with self._lock:
            self._closed = True
            sockets, self._sockets = self._sockets, []
            expired = self.expired
        self._timer.cancel()
        for sock in sockets:
            self._shutdown(sock)
        return expired


class _DeadlineHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, *, deadline, **kwargs):
        super().__init__(host, **kwargs)
        self._create_connection = deadline.create_connection


class _DeadlineHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, *, deadline, **kwargs):
        super().__init__(host, **kwargs)
        self._deadline = deadline
        self._create_connection = deadline.create_connection

    def connect(self):
        http.client.HTTPConnection.connect(self)
        server_hostname = self._tunnel_host or self.host
        # Register the TLS socket before its handshake, because wrapping a
        # socket detaches the original object watched during TCP connection.
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname,
                                               do_handshake_on_connect=False)
        self._deadline.watch(self.sock)
        self.sock.do_handshake()


class _DeadlineHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, deadline):
        super().__init__()
        self._connection = partial(_DeadlineHTTPConnection, deadline=deadline)

    def http_open(self, request):
        return self.do_open(self._connection, request)


class _DeadlineHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, deadline):
        super().__init__()
        self._connection = partial(_DeadlineHTTPSConnection, deadline=deadline)

    def https_open(self, request):
        return self.do_open(self._connection, request, context=self._context)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _control_type(case: dict) -> str:
    statuses = case["expect"]["status"]
    if all(200 <= status < 300 for status in statuses):
        return "positive"
    if all(status in {401, 403, 404} for status in statuses):
        return "negative"
    return "configured"


def _record(case: dict, outcome: str, reason: str) -> dict:
    return {"id": case["id"], "identity": case["identity"], "method": case["method"],
            "path": case["path"], "requires": list(case["requires"]),
            "control_type": _control_type(case), "outcome": outcome, "status": None,
            "duration_ms": 0, "checks": [], "reason": reason, "response_sha256": None}


def _credentials(contract: dict) -> dict:
    resolved = {}
    for identity, config in contract["identities"].items():
        headers = {}
        for key, reference in config["headers"].items():
            if isinstance(reference, dict):
                value = os.environ.get(reference["env"])
                if not value:
                    raise ContractError("a required credential environment variable is missing or empty.")
                if len(value) > 16384 or any(ord(c) < 32 or ord(c) == 127 or ord(c) > 255 for c in value):
                    raise ContractError("a credential environment variable is not a valid HTTP header value.")
                headers[key] = value
            else:
                headers[key] = reference
        resolved[identity] = headers
    return resolved


_MISSING = object()


def _pointer(document, pointer: str):
    current = document
    if not pointer:
        return current
    for token in pointer[1:].split("/"):
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                return _MISSING
            current = current[token]
        elif isinstance(current, list):
            if not token.isascii() or not token.isdigit() or (len(token) > 1 and token[0] == "0"):
                return _MISSING
            try:
                index = int(token)
            except ValueError:
                return _MISSING
            if index >= len(current):
                return _MISSING
            current = current[index]
        else:
            return _MISSING
    return current


def _json_equal(actual, expected) -> bool:
    # JSON booleans are not interchangeable with JSON numbers in Python.
    if isinstance(actual, bool) or isinstance(expected, bool):
        return type(actual) is type(expected) and actual == expected
    if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
        return actual == expected
    if type(actual) is not type(expected):
        return False
    if isinstance(actual, dict):
        return actual.keys() == expected.keys() and all(_json_equal(actual[key], expected[key]) for key in actual)
    if isinstance(actual, list):
        return len(actual) == len(expected) and all(_json_equal(a, b) for a, b in zip(actual, expected))
    return actual == expected


def _reject_constant(value):
    raise ValueError("non-finite JSON number")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("ambiguous JSON object")
        result[key] = value
    return result


def _checks(case: dict, status: int, body: bytes) -> tuple[list, str]:
    expected = case["expect"]
    checks = [{"type": "status", "passed": status in expected["status"]}]
    json_checks = expected.get("json", {})
    absent_checks = expected.get("json_absent", [])
    if json_checks or absent_checks:
        try:
            document = json.loads(body, parse_constant=_reject_constant, object_pairs_hook=_unique_pairs)
            json_valid = True
        except (ValueError, UnicodeError, RecursionError):
            document, json_valid = None, False
        checks.append({"type": "json_parse", "passed": json_valid})
        for pointer, value in json_checks.items():
            actual = _pointer(document, pointer) if json_valid else _MISSING
            checks.append({"type": "json", "passed": actual is not _MISSING and _json_equal(actual, value)})
        for pointer in absent_checks:
            checks.append({"type": "json_absent", "passed": json_valid and _pointer(document, pointer) is _MISSING})
        if not json_valid:
            return checks, "Response was not unambiguous valid JSON."
    return checks, "Configured checks passed." if all(check["passed"] for check in checks) else "Configured checks failed."


def _read_body(response, limit: int, deadline: float) -> bytes:
    chunks = []
    size = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        # read1 performs at most one underlying read, allowing the deadline to
        # be checked between chunks even when the peer trickles response data.
        try:
            response.fp.raw._sock.settimeout(remaining)
        except AttributeError:
            pass
        chunk = response.read1(min(65536, limit + 1 - size))
        if not chunk:
            if getattr(response, "length", None) not in (None, 0):
                raise http.client.IncompleteRead(b"")
            return b"".join(chunks)
        size += len(chunk)
        if size > limit:
            raise OverflowError
        chunks.append(chunk)


def _execute(case: dict, target: str, headers: dict, limits: dict) -> dict:
    started = time.monotonic()
    result = _record(case, "error", "Request could not be completed.")
    request_headers = {"user-agent": f"AuthzLedger/{__version__}", "accept": "application/json", "accept-encoding": "identity"}
    request_headers.update({key.lower(): value for key, value in headers.items()})
    request_headers.update({key.lower(): value for key, value in case["headers"].items()})
    body = None
    if "body" in case:
        body = json.dumps(case["body"], ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")
        request_headers.setdefault("content-type", "application/json")
    request = urllib.request.Request(target + case["path"], data=body, headers=request_headers, method=case["method"])
    deadline = _RequestDeadline(started + limits["timeout_seconds"])
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                         _DeadlineHTTPHandler(deadline), _DeadlineHTTPSHandler(deadline))
    response = None
    try:
        try:
            response = opener.open(request, timeout=limits["timeout_seconds"])
        except urllib.error.HTTPError as exc:
            response = exc
        result["status"] = response.status
        if 300 <= response.status < 400:
            result["reason"] = "Redirect response refused."
            return result
        encoding = response.headers.get("Content-Encoding", "identity").strip().lower()
        if encoding not in {"", "identity"}:
            result["reason"] = "Encoded response refused."
            return result
        payload = _read_body(response, limits["max_response_bytes"], started + limits["timeout_seconds"])
        result["response_sha256"] = hashlib.sha256(payload).hexdigest()
        checks, reason = _checks(case, response.status, payload)
        result["checks"] = checks
        result["outcome"] = "pass" if all(check["passed"] for check in checks) else "fail"
        result["reason"] = reason
    except OverflowError:
        result["reason"] = "Response exceeded the configured byte limit."
    except (TimeoutError, socket.timeout):
        result["reason"] = "Request timed out."
    except ssl.SSLError:
        result["reason"] = "TLS connection failed."
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            result["reason"] = "Request timed out."
        elif isinstance(exc.reason, ssl.SSLError):
            result["reason"] = "TLS connection failed."
        else:
            result["reason"] = "Connection failed."
    except (OSError, ValueError, http.client.HTTPException):
        result["reason"] = "Request could not be completed."
    finally:
        expired = deadline.close()
        if response is not None:
            response.close()
        if expired:
            result.update(outcome="error", reason="Request timed out.", checks=[], response_sha256=None)
        elapsed_ms = round((time.monotonic() - started) * 1000, 3)
        # JavaScript JSON.stringify emits 0/7, not 0.0/7.0. Normalize integral
        # durations before sealing so the browser cannot accidentally break hashes.
        result["duration_ms"] = int(elapsed_ms) if elapsed_ms.is_integer() else elapsed_ms
    return result


def run(contract: dict) -> dict:
    """Execute a normalized contract, preserving dependency and result order.

    Mutating-method permission is granted when loading the contract. Revalidate
    here to prevent raw dictionaries from bypassing scope or limit validation.
    """
    contract = load_contract(contract, allow_mutations=True)
    credentials = _credentials(contract)  # Resolve all before any HTTP traffic.
    started_at = _utc()
    cases = contract["cases"]
    results = {}
    pending = {case["id"]: case for case in cases}
    futures = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=contract["limits"]["concurrency"],
                                                thread_name_prefix="authzledger") as pool:
        while pending or futures:
            for case_id, case in list(pending.items()):
                if not all(dependency in results for dependency in case["requires"]):
                    continue
                if any(results[dependency]["outcome"] != "pass" for dependency in case["requires"]):
                    results[case_id] = _record(case, "inconclusive", "Prerequisite did not pass; request was not sent.")
                    del pending[case_id]
                    continue
                if len(futures) >= contract["limits"]["concurrency"]:
                    continue
                future = pool.submit(_execute, case, contract["target"], credentials[case["identity"]], contract["limits"])
                futures[future] = case
                del pending[case_id]
            if futures:
                completed, _ = concurrent.futures.wait(futures, return_when=concurrent.futures.FIRST_COMPLETED)
                for future in completed:
                    case = futures.pop(future)
                    try:
                        results[case["id"]] = future.result()
                    except Exception:
                        # Neither raw exceptions nor credential-bearing request
                        # objects may cross the report boundary.
                        results[case["id"]] = _record(case, "error", "Request could not be completed.")
            elif pending:
                # Validation rejects cycles; this branch also guards accidental
                # scheduler regressions instead of spinning indefinitely.
                for case_id, case in pending.items():
                    results[case_id] = _record(case, "inconclusive", "Prerequisite could not be evaluated; request was not sent.")
                pending.clear()
    ordered = [results[case["id"]] for case in cases]
    summary = {outcome: sum(result["outcome"] == outcome for result in ordered)
               for outcome in ("pass", "fail", "error", "inconclusive")}
    summary["total"] = len(ordered)
    report = {"schema_version": 1, "tool": {"name": "AuthzLedger", "version": __version__},
              "name": contract["name"], "target": contract["target"],
              "contract_sha256": contract_digest(contract), "started_at": started_at,
              "finished_at": _utc(), "summary": summary, "results": ordered}
    return seal_report(report)
