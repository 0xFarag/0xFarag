# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Read an existing ZAP alert list on a dedicated local instance."""
import http.client
import ipaddress
import json
import os
import re
import time
from urllib.parse import urlsplit

DEFAULT_ORIGIN = "http://127.0.0.1:8080"
MAX_ALERTS = 500
MAX_BYTES = 1_048_576
TIMEOUT = 6
ALERT_PATH = f"/JSON/alert/view/alerts/?start=0&count={MAX_ALERTS + 1}"


class ZapImportError(ValueError):
    def __init__(self, code, status):
        super().__init__(code)
        self.code = code
        self.status = status


def _origin(value):
    try:
        if not isinstance(value, str) or len(value) > 180 or not value.isascii() or any(c.isspace() for c in value):
            raise ValueError
        uri = urlsplit(value)
        host = ipaddress.ip_address(uri.hostname or "")
        if (uri.scheme not in ("http", "https") or uri.username is not None or
                "%" in str(host) or not host.is_loopback or not uri.port or
                uri.path not in ("", "/") or "?" in value or "#" in value):
            raise ValueError
        return uri.scheme, str(host), uri.port
    except (ValueError, TypeError):
        raise ZapImportError("zap_config", 400) from None


def _digits(value):
    if type(value) not in (int, str) or not re.fullmatch(r"[0-9]{1,12}", str(value)):
        raise ValueError
    return str(value)


def _observation(row):
    from .proof_imports import safe_host, safe_path
    if not isinstance(row, dict):
        raise ValueError
    raw = row["url"]
    if not isinstance(raw, str) or len(raw) > 8192 or any(ord(c) < 33 or ord(c) == 127 for c in raw):
        raise ValueError
    uri = urlsplit(raw)
    if (uri.scheme not in ("https", "http") or not uri.hostname or uri.username is not None
            or uri.port == 0 or "\\" in uri.netloc):
        raise ValueError
    method = row["method"]
    if method not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"):
        raise ValueError
    status = row.get("statusCode")
    if status is not None:
        if not re.fullmatch(r"[1-5][0-9]{2}", _digits(status)):
            raise ValueError
        status = int(status)
    return {"id": "zap-" + _digits(row["id"]), "host": safe_host(uri.hostname),
            "method": method, "path": safe_path(uri.path or "/"), "status": status,
            "marker": False, "rule": _digits(row["pluginId"]), "source": "ZAP"}


def read_alerts(base_url, api_key):
    origin = _origin(base_url)
    if origin != _origin(os.environ.get("AUTHZLEDGER_ZAP_ORIGIN", DEFAULT_ORIGIN)):
        raise ZapImportError("zap_config", 403)
    if not isinstance(api_key, str) or not re.fullmatch(r"[!-~]{1,256}", api_key):
        raise ZapImportError("zap_credentials", 400)

    # Direct sockets. No system proxies, cookies, redirects or target URL requests.
    scheme, host, port = origin
    connection = (http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection)(
        host, port, timeout=TIMEOUT)
    deadline = time.monotonic() + TIMEOUT
    try:
        connection.request("GET", ALERT_PATH, headers={"Accept": "application/json", "X-ZAP-API-Key": api_key})
        with connection.getresponse() as response:
            if response.status in (401, 403):
                raise ZapImportError("zap_denied", 403)
            if response.status != 200 or response.headers.get_content_type() != "application/json":
                raise ZapImportError("zap_response", 502)
            data = bytearray()
            while len(data) <= MAX_BYTES:
                if time.monotonic() >= deadline:
                    raise ZapImportError("zap_unreachable", 502)
                chunk = response.read1(min(65536, MAX_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > MAX_BYTES:
                raise ZapImportError("zap_limit", 413)
    except (OSError, http.client.HTTPException):
        raise ZapImportError("zap_unreachable", 502) from None
    finally:
        connection.close()

    try:
        rows = json.loads(data)["alerts"]
        if not isinstance(rows, list):
            raise ValueError
        if not rows:
            raise ZapImportError("zap_empty", 422)
        if len(rows) > MAX_ALERTS:
            raise ZapImportError("zap_limit", 413)
        observations = [_observation(row) for row in rows]
        if len({item["id"] for item in observations}) != len(observations):
            raise ValueError
        return observations
    except ZapImportError:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise ZapImportError("zap_response", 502) from None
