"""One bounded request ledger shared by every explicitly approved transport.

Reservations count before dispatch under the same lock. No request is retried by
this service, and a dispatched request is never refunded, including failed I/O.
"""
from __future__ import annotations

import math
import ipaddress
import threading
import time
from dataclasses import dataclass
from contextlib import contextmanager
from urllib.parse import urlsplit

from .model import _target, ContractError

REQUEST_KINDS = frozenset({"application", "identity_control", "object_control", "negative_control",
                           "pdp", "setup", "state_probe", "replay", "reduction", "cleanup", "advisory"})


class ExecutionError(ValueError):
    """Sanitized refusal before network I/O."""
    def __init__(self, code):
        self.code = code
        super().__init__("Request not dispatched: " + code + ".")


@dataclass(frozen=True)
class Reservation:
    sequence: int
    kind: str
    operation_id: str
    target_origin: str
    deadline: float


class ExecutionContext:
    def __init__(self, max_requests, allowed_origins, timeout_seconds, concurrency,
                 cleanup_reserve=0, allow_cleanup_after_cancel=False, *, stop_event=None,
                 approved_operations=None):
        if type(max_requests) is not int or not 1 <= max_requests <= 1000000:
            raise ExecutionError("invalid-budget")
        if type(concurrency) is not int or not 1 <= concurrency <= 16:
            raise ExecutionError("invalid-concurrency")
        if type(timeout_seconds) not in (int, float) or not 0.1 <= timeout_seconds <= 86400 or not math.isfinite(timeout_seconds):
            raise ExecutionError("invalid-timeout")
        if type(cleanup_reserve) is not int or not 0 <= cleanup_reserve <= max_requests:
            raise ExecutionError("invalid-cleanup-reserve")
        if type(allow_cleanup_after_cancel) is not bool:
            raise ExecutionError("invalid-cleanup-policy")
        if stop_event is not None and not isinstance(stop_event, threading.Event):
            raise ExecutionError("invalid-stop-event")
        scopes = allowed_origins if isinstance(allowed_origins, dict) else {"application": allowed_origins}
        if set(scopes) - {"application", "pdp", "advisory"}:
            raise ExecutionError("invalid-scope")
        app_origins = scopes.get("application", [])
        pdp_endpoints = scopes.get("pdp", [])
        advisory_endpoints = scopes.get("advisory", [])
        if not isinstance(app_origins, (list, tuple, set)) or not isinstance(pdp_endpoints, (list, tuple, set)) or not isinstance(advisory_endpoints, (list, tuple, set)):
            raise ExecutionError("invalid-scope")
        try:
            self._application_origins = frozenset(_target(value) for value in app_origins)
            endpoints = []
            for value in pdp_endpoints:
                if (not isinstance(value, str) or len(value) > 2048 or not value.isascii()
                        or any(ord(c) <= 32 or ord(c) == 127 for c in value) or "\\" in value):
                    raise ExecutionError("invalid-pdp-scope")
                parsed = urlsplit(value)
                origin = _target(parsed.scheme + "://" + parsed.netloc)
                if (not parsed.path.startswith("/v1/data/") or parsed.path.endswith("/")
                        or parsed.query or parsed.fragment or "%" in parsed.path
                        or any(part in {".", ".."} for part in parsed.path.split("/"))):
                    raise ExecutionError("invalid-pdp-scope")
                endpoints.append(origin + parsed.path)
            self._pdp_endpoints = frozenset(endpoints)
            advisory = []
            for value in advisory_endpoints:
                if (not isinstance(value, str) or len(value) > 2048 or not value.isascii()
                        or any(ord(c) <= 32 or ord(c) == 127 for c in value) or "\\" in value):
                    raise ExecutionError("invalid-advisory-scope")
                parsed = urlsplit(value)
                origin = _target(parsed.scheme + "://" + parsed.netloc)
                if (parsed.scheme != "http" or not ipaddress.ip_address(parsed.hostname).is_loopback
                        or parsed.path != "/api/generate" or parsed.query or parsed.fragment):
                    raise ExecutionError("invalid-advisory-scope")
                advisory.append(origin + parsed.path)
            self._advisory_endpoints = frozenset(advisory)
        except (ValueError, TypeError, AttributeError):
            raise ExecutionError("invalid-scope") from None
        if not self._application_origins and not self._pdp_endpoints and not self._advisory_endpoints:
            raise ExecutionError("empty-scope")
        if approved_operations is not None:
            try:
                self._operations = frozenset(tuple(item) for item in approved_operations)
                if any(len(item) != 3 or any(not isinstance(part, str) for part in item) for item in self._operations):
                    raise ValueError
            except (ValueError, TypeError):
                raise ExecutionError("invalid-operation-scope") from None
        else:
            self._operations = None
        self.max_requests = max_requests
        self.timeout_seconds = timeout_seconds
        self.concurrency = concurrency
        self.cleanup_reserve = cleanup_reserve
        self.allow_cleanup_after_cancel = allow_cleanup_after_cancel
        self._stop_events = [stop_event] if stop_event is not None else []
        self._condition = threading.Condition(threading.RLock())
        self._records = {}
        self._leases = {}
        self._next = 0
        self._cancelled = False
        self._cancel_reason = None
        self._dispatched = 0
        self._normal_dispatched = 0
        self._cleanup_dispatched = 0
        self._reserved_total = 0
        self._normal_reserved = 0
        self._cleanup_reserved = 0
        self._active = 0
        self._held_normal = 0
        self._held_cleanup = 0
        self._kind_counts = {kind: 0 for kind in REQUEST_KINDS}

    def _is_cancelled(self):
        return self._cancelled or any(event.is_set() for event in self._stop_events)

    def add_stop_event(self, event):
        """Bind an additional cancellation source; this can only narrow scope."""
        if not isinstance(event, threading.Event):
            raise ExecutionError("invalid-stop-event")
        with self._condition:
            if event not in self._stop_events:
                self._stop_events.append(event)
            self._condition.notify_all()

    def _check_scope(self, kind, target_origin, method, path):
        if not isinstance(kind, str) or kind not in REQUEST_KINDS:
            raise ExecutionError("invalid-request-kind")
        try:
            origin = _target(target_origin)
        except ContractError:
            raise ExecutionError("origin-outside-scope") from None
        if kind == "pdp":
            if method != "POST" or not isinstance(path, str) or origin + path not in self._pdp_endpoints:
                raise ExecutionError("pdp-operation-outside-scope")
        elif kind == "advisory":
            if method != "POST" or not isinstance(path, str) or origin + path not in self._advisory_endpoints:
                raise ExecutionError("advisory-operation-outside-scope")
        elif origin not in self._application_origins:
            raise ExecutionError("origin-outside-scope")
        if self._operations is not None and (kind, method, path) not in self._operations:
            raise ExecutionError("operation-outside-scope")
        return origin

    def _remaining(self, kind, lease=None):
        if lease is not None:
            quota = self._leases.get(lease)
            return quota["cleanup" if kind == "cleanup" else "normal"] if quota is not None else 0
        total = self.max_requests - self._dispatched - self._reserved_total - self._held_normal - self._held_cleanup
        if kind == "cleanup":
            # Cleanup has its own envelope and cannot borrow normal budget.
            used = self._cleanup_dispatched + self._cleanup_reserved + self._held_cleanup
            return max(0, min(total, self.cleanup_reserve - used))
        used = self._normal_dispatched + self._normal_reserved + self._held_normal
        return max(0, min(total, self.max_requests - self.cleanup_reserve - used))

    def remaining(self, kind="application"):
        if not isinstance(kind, str) or kind not in REQUEST_KINDS:
            raise ExecutionError("invalid-request-kind")
        with self._condition:
            return self._remaining(kind)

    def reserve(self, *, kind, operation_id, target_origin, deadline=None, method=None, path=None, _lease=None):
        origin = self._check_scope(kind, target_origin, method, path)
        if not isinstance(operation_id, str) or not operation_id or len(operation_id) > 128 or any(ord(c) < 32 for c in operation_id):
            raise ExecutionError("invalid-operation-id")
        if deadline is None:
            deadline = time.monotonic() + self.timeout_seconds
        if type(deadline) not in (int, float) or not 0 < deadline < 1e20 or not math.isfinite(deadline):
            raise ExecutionError("invalid-deadline")
        deadline = min(deadline, time.monotonic() + self.timeout_seconds)
        with self._condition:
            while True:
                if self._is_cancelled() and not (kind == "cleanup" and self.allow_cleanup_after_cancel):
                    raise ExecutionError("cancelled")
                if time.monotonic() >= deadline:
                    raise ExecutionError("deadline-exceeded")
                if self._remaining(kind, _lease) <= 0:
                    raise ExecutionError("request-budget")
                if self._active < self.concurrency:
                    break
                self._condition.wait(min(0.05, max(0, deadline - time.monotonic())))
            if _lease is not None:
                self._leases[_lease]["cleanup" if kind == "cleanup" else "normal"] -= 1
                if kind == "cleanup":
                    self._held_cleanup -= 1
                else:
                    self._held_normal -= 1
            self._reserved_total += 1
            self._active += 1
            if kind == "cleanup":
                self._cleanup_reserved += 1
            else:
                self._normal_reserved += 1
            self._next += 1
            reservation = Reservation(self._next, kind, operation_id, origin, deadline)
            self._records[reservation.sequence] = {"reservation": reservation, "state": "reserved",
                                                  "outcome": None, "elapsed_ms": 0, "response_bytes": 0, "lease": _lease}
            return reservation

    def _entry(self, reservation):
        entry = self._records.get(getattr(reservation, "sequence", None))
        if entry is None or entry["reservation"] is not reservation:
            raise ExecutionError("foreign-reservation")
        return entry

    def release(self, reservation):
        with self._condition:
            entry = self._entry(reservation)
            if entry["state"] != "reserved":
                raise ExecutionError("reservation-not-releasable")
            self._release_entry(entry)
            self._condition.notify_all()

    def _release_entry(self, entry):
        entry["state"] = "released"
        self._reserved_total -= 1
        self._active -= 1
        if entry["reservation"].kind == "cleanup":
            self._cleanup_reserved -= 1
        else:
            self._normal_reserved -= 1
        lease = entry.get("lease")
        if lease in self._leases:
            key = "cleanup" if entry["reservation"].kind == "cleanup" else "normal"
            self._leases[lease][key] += 1
            if key == "cleanup":
                self._held_cleanup += 1
            else:
                self._held_normal += 1

    @contextmanager
    def lease(self, requests, *, cleanup_requests=0):
        """Atomically hold a complete control/probe/cleanup envelope.

        The yielded child shares counters, cancellation, deadlines and slots.
        Other consumers cannot spend its held quota before a mutation's probe.
        """
        if type(requests) is not int or requests < 0 or type(cleanup_requests) is not int or cleanup_requests < 0 or requests + cleanup_requests == 0:
            raise ExecutionError("invalid-lease-budget")
        token = object()
        with self._condition:
            if self._is_cancelled():
                raise ExecutionError("cancelled")
            if requests > self._remaining("application") or cleanup_requests > self._remaining("cleanup"):
                raise ExecutionError("request-budget")
            self._leases[token] = {"normal": requests, "cleanup": cleanup_requests}
            self._held_normal += requests
            self._held_cleanup += cleanup_requests
        child = _LeasedContext(self, token)
        try:
            yield child
        finally:
            with self._condition:
                # Never refund already dispatched requests. Pending reservations
                # become unusable when their explicitly scoped lease closes.
                for entry in self._records.values():
                    if entry.get("lease") is token and entry["state"] == "reserved":
                        self._release_entry(entry)
                quota = self._leases.pop(token)
                self._held_normal -= quota["normal"]
                self._held_cleanup -= quota["cleanup"]
                self._condition.notify_all()

    def dispatch(self, reservation, transport_call):
        with self._condition:
            entry = self._entry(reservation)
            if entry["state"] != "reserved":
                raise ExecutionError("reservation-already-used")
            if self._is_cancelled() and not (reservation.kind == "cleanup" and self.allow_cleanup_after_cancel):
                self._release_entry(entry)
                self._condition.notify_all()
                raise ExecutionError("cancelled")
            if time.monotonic() >= reservation.deadline:
                self._release_entry(entry)
                self._condition.notify_all()
                raise ExecutionError("deadline-exceeded")
            entry["state"] = "dispatched"
            self._reserved_total -= 1
            self._dispatched += 1
            self._kind_counts[reservation.kind] += 1
            if reservation.kind == "cleanup":
                self._cleanup_reserved -= 1
                self._cleanup_dispatched += 1
            else:
                self._normal_reserved -= 1
                self._normal_dispatched += 1
        started = time.monotonic()
        outcome = "error"
        try:
            response = transport_call()
            outcome = "completed"
            return response
        finally:
            self.finish(reservation, outcome=outcome, elapsed_ms=round((time.monotonic() - started) * 1000, 3), response_bytes=0)

    def finish(self, reservation, *, outcome, elapsed_ms, response_bytes):
        if not isinstance(outcome, str) or outcome not in {"completed", "error", "pass", "fail", "inconclusive"}:
            raise ExecutionError("invalid-outcome")
        if type(response_bytes) is not int or response_bytes < 0 or type(elapsed_ms) not in (int, float) or not 0 <= elapsed_ms < 1e20 or not math.isfinite(elapsed_ms):
            raise ExecutionError("invalid-completion")
        with self._condition:
            entry = self._entry(reservation)
            if entry["state"] not in {"dispatched", "finished"}:
                raise ExecutionError("reservation-not-dispatched")
            if entry["state"] == "dispatched":
                self._active -= 1
            entry.update(state="finished", outcome=outcome, elapsed_ms=elapsed_ms, response_bytes=response_bytes)
            self._condition.notify_all()

    def cancel(self, *, reason="operator"):
        # Reasons are codes, never exception strings or operator-entered secrets.
        if not isinstance(reason, str) or reason not in {"operator", "deadline", "budget", "stop-event", "control-failure"}:
            raise ExecutionError("invalid-cancel-reason")
        with self._condition:
            self._cancelled = True
            self._cancel_reason = reason
            self._condition.notify_all()

    def snapshot(self):
        with self._condition:
            entries = list(self._records.values())
            return {"schema_version": 1, "kind": "request-budget-ledger", "approved_total": self.max_requests,
                    "dispatched_total": self._dispatched,
                    "reserved_pending": self._reserved_total,
                    "leased_pending": self._held_normal + self._held_cleanup,
                    "remaining": self._remaining("application"), "cleanup_remaining": self._remaining("cleanup"),
                    "cancelled": self._is_cancelled(), "cancel_reason": self._cancel_reason,
                    "by_kind": dict(sorted(self._kind_counts.items())),
                    "requests": [{"sequence": entry["reservation"].sequence, "kind": entry["reservation"].kind,
                                  "operation_id": entry["reservation"].operation_id, "state": entry["state"],
                                  "outcome": entry["outcome"], "elapsed_ms": entry["elapsed_ms"],
                                  "response_bytes": entry["response_bytes"]} for entry in entries]}


class _LeasedContext(ExecutionContext):
    """Private scoped facade: no second transport or independent budget."""
    def __init__(self, parent, token):
        self._parent, self._token = parent, token
        self.max_requests = parent.max_requests
        self.concurrency = parent.concurrency
        self.timeout_seconds = parent.timeout_seconds
        self.cleanup_reserve = parent.cleanup_reserve
        self.allow_cleanup_after_cancel = parent.allow_cleanup_after_cancel

    def reserve(self, **kwargs):
        if "_lease" in kwargs:
            raise ExecutionError("invalid-lease")
        return self._parent.reserve(**kwargs, _lease=self._token)

    def remaining(self, kind="application"):
        if not isinstance(kind, str) or kind not in REQUEST_KINDS:
            raise ExecutionError("invalid-request-kind")
        with self._parent._condition:
            return self._parent._remaining(kind, self._token)

    def dispatch(self, reservation, transport_call):
        return self._parent.dispatch(reservation, transport_call)

    def finish(self, reservation, **kwargs):
        return self._parent.finish(reservation, **kwargs)

    def release(self, reservation):
        return self._parent.release(reservation)

    def cancel(self, **kwargs):
        return self._parent.cancel(**kwargs)

    def add_stop_event(self, event):
        return self._parent.add_stop_event(event)

    def snapshot(self):
        return self._parent.snapshot()

    def lease(self, requests, *, cleanup_requests=0):
        raise ExecutionError("nested-lease-not-supported")
