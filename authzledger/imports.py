"""Bounded, offline HTTP-message imports with a secret-free projection.

Import provenance hashes bind this redacted projection, never the original file.
An imported response or scanner assertion is an unverified external observation.
Only explicit assessment mapping can turn an entry into an executable contract.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import math
import re
import xml.etree.ElementTree as ET
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit


class ImportError(ValueError):
    """An import is malformed, unsupported, or exceeds an explicit bound."""


DEFAULT_LIMITS = {
    "max_file_bytes": 10 * 1048576, "max_entries": 500,
    "max_body_bytes": 1048576, "max_json_depth": 64,
    "max_headers": 100, "max_header_bytes": 65536,
}
PROFILES = ("burp-xml", "zap-json-plus", "har-1.2")
_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_SAFE_HEADERS = {"accept", "accept-language", "content-type", "cache-control", "pragma"}
_TRANSPORT_HEADERS = {"host", "content-length", "connection", "accept-encoding"}
_BROWSER_CONTEXT_HEADERS = {"origin", "referer", "user-agent", "sec-fetch-dest", "sec-fetch-mode",
                            "sec-fetch-site", "sec-fetch-user", "sec-ch-ua", "sec-ch-ua-mobile",
                            "sec-ch-ua-platform", "dnt", "priority", "upgrade-insecure-requests"}
_SENSITIVE = re.compile(r"auth|cookie|token|password|passwd|secret|credential|session|api.?key|csrf|xsrf|bearer", re.I)
_TOKEN = re.compile(r"(?:[A-Za-z0-9_-]{32,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)\Z")
_UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")
_REDACTED = "[REDACTED]"


def _fail(code: str) -> None:
    # No decoder text, input values, paths, or raw parser exceptions escape.
    raise ImportError(code)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _digest(value: object) -> str:
    return hashlib.sha256(b"AuthzLedger:import-projection:v1\n" + _canonical(value)).hexdigest()


def _limits(value: dict | None) -> dict:
    result = dict(DEFAULT_LIMITS)
    result["redact_headers"] = []
    if value is None:
        return result
    if not isinstance(value, dict) or set(value) - set(result):
        _fail("invalid_import_limits")
    for key, item in value.items():
        if key == "redact_headers":
            if (not isinstance(item, list) or len(item) > 100
                    or any(not isinstance(v, str) or not _HEADER_NAME.fullmatch(v) for v in item)):
                _fail("invalid_redaction_headers")
            result[key] = [v.lower() for v in item]
        elif type(item) is not int or not 1 <= item <= DEFAULT_LIMITS[key]:
            _fail("invalid_import_limits")
        else:
            result[key] = item
    return result


def _text(value: object, maximum: int = 65536) -> str:
    if not isinstance(value, str) or len(value) > maximum:
        _fail("invalid_or_oversized_string")
    if any(0xD800 <= ord(c) <= 0xDFFF for c in value):
        _fail("invalid_unicode")
    return value


def _object(value: object) -> dict:
    if not isinstance(value, dict):
        _fail("expected_object")
    return value


def _array(value: object, maximum: int) -> list:
    if not isinstance(value, list) or len(value) > maximum:
        _fail("invalid_or_oversized_array")
    return value


def _strict_json(raw: bytes, limits: dict) -> object:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        _fail("invalid_utf8")
    # Bound nesting before invoking the recursive JSON decoder.
    depth, quoted, escaped = 0, False, False
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > limits["max_json_depth"]:
                _fail("json_depth_exceeded")
        elif char in "]}":
            depth -= 1

    def pairs(items: list) -> dict:
        result = {}
        for key, value in items:
            if key in result:
                _fail("duplicate_json_key")
            _text(key)
            result[key] = value
        return result

    try:
        result = json.loads(text, object_pairs_hook=pairs,
                            parse_constant=lambda _: _fail("nonfinite_json"))
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, ImportError):
            raise
        _fail("invalid_json")
    stack = [result]
    while stack:
        item = stack.pop()
        if isinstance(item, float) and not math.isfinite(item):
            _fail("nonfinite_json")
        if isinstance(item, str):
            _text(item, limits["max_file_bytes"])
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return result


def _slot(entry: dict, location: str, kind: str) -> str:
    index = len(entry["secret_slots"])
    if index >= 1000:
        _fail("redaction_slot_count_exceeded")
    slot_id = f"slot-{index + 1}"
    entry["secret_slots"].append({"id": slot_id, "location": location,
                                  "kind": kind, "required": True})
    return _REDACTED


def _block(entry: dict, code: str) -> None:
    if code not in entry["execution_blockers"]:
        entry["execution_blockers"].append(code)


def _remember(entry: dict, value: str) -> None:
    if value:
        entry.setdefault("_secret_values", set()).add(value)


def _redact_echoes(entry: dict, pattern: re.Pattern | None) -> None:
    """Remove known credentials echoed in apparently harmless request fields."""
    values = entry.pop("_secret_values", set())
    def scrub(value: object) -> object:
        if isinstance(value, str):
            if value in values:
                return _REDACTED
            return pattern.sub(_REDACTED, value) if pattern else value
        if isinstance(value, list):
            return [scrub(item) for item in value]
        if isinstance(value, dict):
            return {str(scrub(key)): scrub(item) for key, item in value.items()}
        return value

    for field in ("origin", "path", "headers", "json", "query_pairs", "secret_slots"):
        if field in entry:
            sanitized = scrub(entry[field])
            if sanitized != entry[field]:
                entry[field] = sanitized
                _block(entry, "credential_echo_requires_mapping")


def _url(entry: dict, raw: str) -> None:
    raw = _text(raw, 16384)
    if any(ord(c) < 33 or ord(c) == 127 for c in raw) or "\\" in raw:
        _block(entry, "unsupported_url")
        return
    try:
        parsed = urlsplit(raw)
        port = parsed.port
        host = parsed.hostname
    except ValueError:
        _block(entry, "unsupported_url")
        return
    if parsed.scheme not in {"http", "https"} or not host or not host.isascii():
        _block(entry, "unsupported_url")
        return
    if parsed.username is not None or parsed.password is not None:
        _remember(entry, unquote(parsed.username or ""))
        _remember(entry, unquote(parsed.password or ""))
        _slot(entry, "url.userinfo", "credential")
        _block(entry, "url_credentials_require_mapping")
    bracketed = f"[{host}]" if ":" in host else host.lower()
    port_part = f":{port}" if port is not None and port != {"http": 80, "https": 443}[parsed.scheme] else ""
    entry["origin"] = f"{parsed.scheme}://{bracketed}{port_part}"
    parts = (parsed.path or "/").split("/")
    sensitive_next = False
    for index, segment in enumerate(parts):
        decoded = unquote(segment)
        credential_path = sensitive_next
        redact = bool(segment and (sensitive_next or (_TOKEN.fullmatch(decoded) and not _UUID.fullmatch(decoded))))
        sensitive_next = bool(_SENSITIVE.search(decoded))
        if redact:
            _remember(entry, decoded)
            parts[index] = quote(_slot(entry, f"path/{index}", "credential_path" if credential_path else "path_value"), safe="")
            _block(entry, "redacted_path_requires_mapping")
    path = "/".join(parts)
    if not path.startswith("/"):
        _block(entry, "unsupported_request_target")
    if parsed.query:
        try:
            pairs = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=False,
                              max_num_fields=500, encoding="utf-8", errors="strict")
        except (ValueError, UnicodeError):
            _block(entry, "unsupported_query")
            pairs = []
        # Query order is retained, but all values need deliberate non-secret mapping.
        names, redacted = set(), []
        for index, (name, value) in enumerate(pairs):
            if _SENSITIVE.search(name):
                _remember(entry, value)
            if name in names:
                _block(entry, "duplicate_query_name")
            names.add(name)
            safe_name = name if len(name) <= 128 and not _TOKEN.fullmatch(name) else "redacted-name"
            kind = "credential_query" if _SENSITIVE.search(name) else "query_value"
            redacted.append((safe_name, _slot(entry, f"query/{index}", kind)))
        entry["query_pairs"] = [[name, value] for name, value in redacted]
        path += "?" + urlencode(redacted)
        _block(entry, "redacted_query_requires_mapping")
    if parsed.fragment:
        _block(entry, "url_fragment_omitted")
    entry["path"] = path


def _headers(entry: dict, pairs: list, limits: dict) -> str:
    if len(pairs) > limits["max_headers"]:
        _fail("header_count_exceeded")
    if sum(len(k.encode("utf-8")) + len(v.encode("utf-8")) + 4 for k, v in pairs) > limits["max_header_bytes"]:
        _fail("header_bytes_exceeded")
    seen, content_type = set(), ""
    for index, (name, value) in enumerate(pairs):
        lower = name.lower()
        if not _HEADER_NAME.fullmatch(name) or any(ord(c) < 32 or ord(c) == 127 for c in value):
            _block(entry, "invalid_header")
            continue
        if lower in seen:
            _block(entry, "duplicate_header")
        seen.add(lower)
        if lower == "content-type":
            content_type = value.lower()
        if lower in {"transfer-encoding", "content-encoding", "trailer", "upgrade"}:
            _block(entry, "unsupported_http_framing")
        elif lower in _TRANSPORT_HEADERS:
            entry["gaps"].append(f"transport_header_omitted:{lower}")
        elif (lower not in _SAFE_HEADERS or lower in limits["redact_headers"]
              or _SENSITIVE.search(value) or _TOKEN.search(value)):
            if lower not in _BROWSER_CONTEXT_HEADERS:
                _remember(entry, value)
            if lower in {"authorization", "proxy-authorization"} and " " in value:
                _remember(entry, value.split(" ", 1)[1])
            if lower == "cookie":
                for part in value.split(";"):
                    if "=" in part:
                        _remember(entry, part.split("=", 1)[1].strip())
            _slot(entry, f"headers/{index}/{lower}", "header")
        else:
            entry["headers"][lower] = value
    return content_type


def _redact_json(value: object, entry: dict, pointer: str = "") -> object:
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            safe_key = key if len(key) <= 128 and not _TOKEN.fullmatch(key) else f"redacted-key-{len(result)}"
            child = pointer + "/" + safe_key.replace("~", "~0").replace("/", "~1")
            if _SENSITIVE.search(key):
                pending = [item]
                while pending:
                    secret = pending.pop()
                    if isinstance(secret, str):
                        _remember(entry, secret)
                    elif isinstance(secret, dict):
                        pending.extend(secret.values())
                    elif isinstance(secret, list):
                        pending.extend(secret)
                result[safe_key] = _slot(entry, "json" + child, "credential_json")
                _block(entry, "redacted_json_requires_mapping")
            else:
                result[safe_key] = _redact_json(item, entry, child)
        return result
    if isinstance(value, list):
        return [_redact_json(item, entry, pointer + f"/{i}") for i, item in enumerate(value)]
    if isinstance(value, str):
        _block(entry, "redacted_json_requires_mapping")
        return _slot(entry, "json" + pointer, "json_value")
    return value


def _body(entry: dict, raw: bytes, content_type: str, limits: dict) -> None:
    if len(raw) > limits["max_body_bytes"]:
        _fail("body_bytes_exceeded")
    if not raw:
        return
    media_type = content_type.split(";", 1)[0].strip()
    if media_type != "application/json" and not media_type.endswith("+json"):
        _block(entry, "unsupported_body_format")
        entry["gaps"].append("request_body_omitted")
        return
    try:
        value = _strict_json(raw, limits)
    except ImportError:
        _block(entry, "invalid_json_body")
        entry["gaps"].append("request_body_omitted")
        return
    entry["json"] = _redact_json(value, entry)


def _raw_http(entry: dict, raw: bytes, limits: dict, *, response: bool = False) -> None:
    if len(raw) > limits["max_body_bytes"] + limits["max_header_bytes"]:
        _fail("message_bytes_exceeded")
    if not raw:
        entry["gaps"].append("missing_response" if response else "missing_request")
        if not response:
            _block(entry, "missing_request")
        return
    if b"\r\n\r\n" in raw:
        head, body = raw.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
    elif b"\n\n" in raw and b"\r" not in raw:
        head, body = raw.split(b"\n\n", 1)
        lines = head.split(b"\n")
    else:
        entry["gaps"].append("incomplete_response" if response else "incomplete_request")
        if not response:
            _block(entry, "incomplete_request")
        return
    if len(head) > limits["max_header_bytes"] or len(body) > limits["max_body_bytes"]:
        _fail("message_component_bytes_exceeded")
    if len(lines) - 1 > limits["max_headers"]:
        _fail("header_count_exceeded")
    if response:
        match = re.fullmatch(rb"HTTP/(?:1\.[01]|2|2\.0) ([1-5][0-9]{2})(?: [^\r\n]*)?", lines[0])
        if match:
            entry["response"]["status"] = int(match.group(1))
        else:
            entry["gaps"].append("invalid_response_status")
        return
    try:
        first = lines[0].decode("ascii")
        method, target, version = first.split(" ")
    except (UnicodeError, ValueError):
        _block(entry, "invalid_request_line")
        return
    if method not in _METHODS or version not in {"HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0"}:
        _block(entry, "unsupported_request_line")
    entry["method"] = method if method in _METHODS else None
    pairs = []
    for line in lines[1:]:
        if b":" not in line or line.startswith((b" ", b"\t")):
            _block(entry, "invalid_header")
            continue
        name, value = line.split(b":", 1)
        try:
            name_text = name.decode("ascii")
        except UnicodeError:
            _block(entry, "non_ascii_header")
            continue
        try:
            value_text = value.strip().decode("ascii")
        except UnicodeError:
            _block(entry, "non_ascii_header")
            try:
                value_text = value.strip().decode("utf-8")
            except UnicodeError:
                value_text = value.strip().decode("latin-1")
            _remember(entry, value_text)
            if name_text.lower() in {"authorization", "proxy-authorization"} and " " in value_text:
                _remember(entry, value_text.split(" ", 1)[1])
            _slot(entry, f"headers/{len(pairs)}/{name_text.lower()}", "header")
            continue
        pairs.append((name_text, value_text))
    content_type = _headers(entry, pairs, limits)
    for name, value in pairs:
        if name.lower() == "content-length" and (len(value) > 12 or not value.isdecimal() or int(value) != len(body)):
            _block(entry, "content_length_mismatch")
        if name.lower() == "host" and entry["origin"]:
            expected = urlsplit(entry["origin"]).netloc
            if value.lower() != expected:
                _block(entry, "host_origin_mismatch")
    # Message and metadata must agree. Compare private values only in memory.
    try:
        raw_url = entry.pop("_source_url")
        source = urlsplit(raw_url)
        expected = (source.path or "/") + (("?" + source.query) if source.query else "")
        if target.startswith(("http://", "https://")):
            target_parts = urlsplit(target)
            if (target_parts.scheme, target_parts.netloc) != (source.scheme, source.netloc):
                _block(entry, "request_origin_mismatch")
            target = (target_parts.path or "/") + (("?" + target_parts.query) if target_parts.query else "")
        if target != expected:
            _block(entry, "request_target_mismatch")
    except (KeyError, ValueError):
        _block(entry, "request_target_unverifiable")
    _body(entry, body, content_type, limits)


def _entry(profile: str, index: int, location: str, url: str) -> dict:
    entry = {"method": None, "origin": None, "path": None, "headers": {},
             "source_refs": [{"profile": profile, "entry_index": index, "location": location}],
             "secret_slots": [], "execution_blockers": [], "gaps": [],
             "response": {"status": None, "body_retained": False}, "source_assertions": [],
             "_source_url": url}
    _url(entry, url)
    return entry


def _xml_message(node: ET.Element | None, limits: dict) -> bytes:
    if node is None or node.text is None:
        return b""
    text = node.text
    if node.get("base64", "false").lower() == "true":
        maximum = limits["max_header_bytes"] + limits["max_body_bytes"]
        compact = "".join(text.split())
        if len(compact) > 4 * ((maximum + 2) // 3):
            _fail("base64_bytes_exceeded")
        try:
            raw = base64.b64decode(compact, validate=True)
        except (ValueError, UnicodeError):
            _fail("invalid_base64")
        if len(raw) > maximum:
            _fail("base64_bytes_exceeded")
        return raw
    if node.get("base64", "false").lower() != "false":
        _fail("unsupported_xml_encoding")
    return text.encode("utf-8")


def _burp(raw: bytes, limits: dict) -> list:
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeError:
        _fail("invalid_utf8")
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", text, re.I) or "\x00" in text:
        _fail("xml_declarations_forbidden")
    try:
        root = ET.fromstring(text)
    except (ET.ParseError, ValueError):
        _fail("invalid_xml")
    if root.tag != "items":
        _fail("unsupported_burp_root")
    stack = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > limits["max_json_depth"]:
            _fail("xml_depth_exceeded")
        stack.extend((child, depth + 1) for child in node)
    nodes = list(root)
    if len(nodes) > limits["max_entries"]:
        _fail("entry_count_exceeded")
    result = []
    for index, node in enumerate(nodes):
        if node.tag != "item":
            _fail("unsupported_burp_item")
        if any(len(node.findall(name)) > 1 for name in ("url", "request", "response", "method")):
            _fail("duplicate_xml_field")
        entry = _entry("burp-xml", index, f"/items/item/{index}", node.findtext("url", ""))
        _raw_http(entry, _xml_message(node.find("request"), limits), limits)
        _raw_http(entry, _xml_message(node.find("response"), limits), limits, response=True)
        declared_method = node.findtext("method")
        if declared_method is not None and entry["method"] != declared_method:
            _block(entry, "declared_method_mismatch")
        result.append(entry)
    return result


def _zap(raw: bytes, limits: dict) -> list:
    root = _object(_strict_json(raw, limits))
    sites = _array(root.get("site"), limits["max_entries"])
    result = []
    for site_index, raw_site in enumerate(sites):
        site = _object(raw_site)
        for alert_index, raw_alert in enumerate(_array(site.get("alerts", []), limits["max_entries"])):
            alert = _object(raw_alert)
            instances = _array(alert.get("instances", []), limits["max_entries"])
            for instance_index, raw_instance in enumerate(instances or [{}]):
                if len(result) >= limits["max_entries"]:
                    _fail("entry_count_exceeded")
                instance = _object(raw_instance)
                entry = _entry("zap-json-plus", len(result),
                               f"/site/{site_index}/alerts/{alert_index}/instances/{instance_index}",
                               _text(instance.get("uri", site.get("@name", ""))))
                for response, prefix in ((False, "request"), (True, "response")):
                    head = _text(instance.get(prefix + "-header", ""), limits["max_header_bytes"])
                    body = _text(instance.get(prefix + "-body", ""), limits["max_body_bytes"])
                    message = head.rstrip("\r\n") + "\r\n\r\n" + body if head else ""
                    _raw_http(entry, message.encode("utf-8"), limits, response=response)
                if "method" in instance and instance["method"] != entry["method"]:
                    _block(entry, "declared_method_mismatch")
                plugin = alert.get("pluginid")
                risk = alert.get("riskcode")
                entry["source_assertions"].append({"kind": "source_assertion", "tool": "ZAP",
                    "plugin_id": plugin if isinstance(plugin, str) and re.fullmatch(r"[0-9]{1,12}", plugin) else None,
                    "risk_code": str(risk) if type(risk) in {str, int} and str(risk) in {"0", "1", "2", "3"} else None,
                    "verification": "not_verified"})
                entry["gaps"].append("scanner_free_text_and_evidence_omitted")
                result.append(entry)
    return result


def _har(raw: bytes, limits: dict) -> list:
    log = _object(_object(_strict_json(raw, limits)).get("log"))
    if log.get("version") != "1.2":
        _fail("unsupported_har_version")
    result = []
    for index, raw_item in enumerate(_array(log.get("entries"), limits["max_entries"])):
        item = _object(raw_item)
        request = _object(item.get("request"))
        entry = _entry("har-1.2", index, f"/log/entries/{index}", _text(request.get("url")))
        method = request.get("method")
        if not isinstance(method, str) or method not in _METHODS:
            _block(entry, "unsupported_request_method")
        else:
            entry["method"] = method
        pairs = []
        for raw_header in _array(request.get("headers", []), limits["max_headers"]):
            header = _object(raw_header)
            pairs.append((_text(header.get("name")), _text(header.get("value"))))
        content_type = _headers(entry, pairs, limits)
        version = request.get("httpVersion", "HTTP/1.1")
        if not isinstance(version, str) or version not in {"HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0"}:
            _block(entry, "unsupported_http_version")
        for name, value in pairs:
            if name.lower() == "host" and entry["origin"] and value.lower() != urlsplit(entry["origin"]).netloc:
                _block(entry, "host_origin_mismatch")
        cookies = _array(request.get("cookies", []), limits["max_headers"])
        for raw_cookie in cookies:
            cookie = _object(raw_cookie)
            if "value" in cookie:
                _remember(entry, _text(cookie["value"]))
        if cookies and not any(slot["location"].endswith("/cookie") for slot in entry["secret_slots"]):
            _slot(entry, "cookies", "header")
        if "postData" in request:
            post = _object(request["postData"])
            if post.get("params"):
                _block(entry, "unsupported_body_format")
                entry["gaps"].append("request_body_omitted")
            elif "text" in post:
                mime = _text(post.get("mimeType", content_type))
                if content_type and mime.split(";", 1)[0] != content_type.split(";", 1)[0]:
                    _block(entry, "body_content_type_mismatch")
                _body(entry, _text(post["text"], limits["max_body_bytes"]).encode("utf-8"), mime, limits)
            else:
                _block(entry, "missing_request_body")
        elif type(request.get("bodySize")) is int and request["bodySize"] > 0:
            _block(entry, "missing_request_body")
        post_data = request.get("postData", {})
        body_text = post_data.get("text", "")
        declared_length = len(body_text.encode("utf-8")) if isinstance(body_text, str) else None
        for name, value in pairs:
            if name.lower() == "content-length" and (len(value) > 12 or not value.isdecimal()
                    or declared_length is None or int(value) != declared_length):
                _block(entry, "content_length_mismatch")
        # The URL is authoritative; HAR's parallel query projection must match exactly.
        if "queryString" in request:
            try:
                actual = parse_qsl(urlsplit(request["url"]).query, keep_blank_values=True,
                                   max_num_fields=500)
            except ValueError:
                actual = []
                _block(entry, "unsupported_query")
            query = []
            for raw_pair in _array(request["queryString"], 500):
                pair = _object(raw_pair)
                query.append((_text(pair.get("name")), _text(pair.get("value"))))
            if query != actual:
                _block(entry, "query_projection_mismatch")
        response = item.get("response")
        if isinstance(response, dict):
            response_headers = _array(response.get("headers", []), limits["max_headers"])
            total_header_bytes = 0
            for raw_header in response_headers:
                header = _object(raw_header)
                name, value = _text(header.get("name")), _text(header.get("value"))
                total_header_bytes += len(name.encode("utf-8")) + len(value.encode("utf-8")) + 4
            if total_header_bytes > limits["max_header_bytes"]:
                _fail("header_bytes_exceeded")
            status = response.get("status")
            if type(status) is int and 100 <= status <= 599:
                entry["response"]["status"] = status
            else:
                entry["gaps"].append("missing_response_status")
            content = response.get("content", {})
            if not isinstance(content, dict):
                _fail("invalid_response_content")
            if "text" in content:
                response_text = _text(content["text"], limits["max_file_bytes"])
                if content.get("encoding") == "base64":
                    maximum = limits["max_body_bytes"]
                    if len(response_text) > 4 * ((maximum + 2) // 3):
                        _fail("base64_bytes_exceeded")
                    try:
                        decoded = base64.b64decode(response_text, validate=True)
                    except (ValueError, UnicodeError):
                        _fail("invalid_base64")
                    if len(decoded) > maximum:
                        _fail("body_bytes_exceeded")
                elif len(response_text.encode("utf-8")) > limits["max_body_bytes"]:
                    _fail("body_bytes_exceeded")
                elif content.get("encoding") is not None and content.get("encoding") != "":
                    entry["gaps"].append("unsupported_response_encoding")
        else:
            entry["gaps"].append("missing_response")
        result.append(entry)
    return result


def parse_import(raw_bytes: bytes, format_profile: str, limits: dict | None = None) -> dict:
    """Return an offline, bounded and deterministically redacted ImportBatch v1.

    ``limits`` may lower hard defaults and add ``redact_headers``. No option
    disables redaction, enables entity resolution, or authorizes network use.
    Header slots need identity binding. Redacted query/body/path values are
    execution blockers until the operator supplies a new explicit mapping.
    """
    effective = _limits(limits)
    if type(raw_bytes) is not bytes or not raw_bytes or len(raw_bytes) > effective["max_file_bytes"]:
        _fail("invalid_or_oversized_import")
    if not isinstance(format_profile, str) or format_profile not in PROFILES:
        _fail("unsupported_import_profile")
    entries = {"burp-xml": _burp, "zap-json-plus": _zap, "har-1.2": _har}[format_profile](raw_bytes, effective)
    known_secrets = set().union(*(entry.get("_secret_values", set()) for entry in entries))
    # Keep echo filtering bounded across a hostile multi-message import as well.
    if (len(known_secrets) > 4096 or sum(len(value) for value in known_secrets) > 262144
            or sum(len(entry["secret_slots"]) for entry in entries) > 8192):
        _fail("redaction_budget_exceeded")
    variants = {variant for value in known_secrets for variant in
                (value, quote(value, safe=""), quote(value, safe="").lower()) if len(variant) >= 4}
    pattern = re.compile("|".join(re.escape(value) for value in sorted(variants, key=lambda s: (-len(s), s)))) if variants else None
    for entry in entries:
        entry.pop("_source_url", None)
        entry["_secret_values"] = known_secrets
        _redact_echoes(entry, pattern)
        entry["gaps"].append("response_body_and_headers_omitted")
        entry["id"] = "import-" + _digest(entry)[:24]
    batch = {"kind": "import-batch", "schema_version": 1, "format_profile": format_profile,
             "hash_basis": "redacted-normalized-projection-v1", "entries": entries,
             "limitations": [
                 "Source digest binds only the redacted normalized projection, not original bytes.",
                 "Response bodies, response headers, scanner prose and credential values are not retained.",
                 "Imported responses and scanner assertions are unverified; they do not confirm findings.",
                 "All query values and JSON strings require explicit remapping; unknown headers require binding.",
                 "Path identifiers are retained unless credential-labeled or token-like; review paths before persistence.",
                 "Imported origin does not authorize execution; assessment scope and identity mapping are required."]}
    batch["import_sha256"] = _digest(batch)
    return batch


def _resolve_imported_entry(entry: dict, mappings: dict) -> dict:
    """Create a new projection from explicit, declared non-secret field mappings.

    ``mappings`` maps slot IDs to ``{"literal": scalar}`` or ``{"omit": True}``.
    Query/body credential positions only support omission. Credential path slots
    remain blocked. Header slots are handled by the scoped identity resolver.
    Array members may be replaced; removing them is unsupported to avoid index
    ambiguity. Mapping receipts retain the parent entry ID and safe literals.
    """
    if not isinstance(entry, dict) or not isinstance(mappings, dict) or len(mappings) > 1000:
        _fail("invalid_import_mapping")
    original = copy.deepcopy(entry)
    entry_id = original.pop("id", None)
    try:
        if len(_canonical(original)) > 4 * 1048576 or len(_canonical(mappings)) > 1048576:
            _fail("mapping_bytes_exceeded")
        expected = "import-" + _digest(original)[:24]
    except (TypeError, ValueError):
        _fail("invalid_import_entry")
    if entry_id != expected:
        _fail("import_entry_digest_mismatch")
    if not mappings:
        return copy.deepcopy(entry)
    result = copy.deepcopy(entry)
    slots = {slot["id"]: slot for slot in result["secret_slots"]}
    if any(not isinstance(key, str) or key not in slots for key in mappings):
        _fail("unknown_import_mapping_slot")
    resolved, receipts = set(), []
    query_removals = set()
    for slot_id in sorted(mappings):
        change, slot = mappings[slot_id], slots[slot_id]
        if not isinstance(change, dict) or set(change) not in ({"literal"}, {"omit"}):
            _fail("invalid_import_mapping")
        omit = "omit" in change
        if omit and change["omit"] is not True:
            _fail("invalid_import_mapping")
        value = change.get("literal")
        if not omit:
            if isinstance(value, (list, dict)) or type(value) not in {str, int, float, bool, type(None)}:
                _fail("mapping_requires_scalar_literal")
            if isinstance(value, float) and not math.isfinite(value):
                _fail("mapping_requires_finite_literal")
            if isinstance(value, str):
                _text(value, 2048)
                if (any(ord(c) < 32 or ord(c) == 127 for c in value)
                        or (_TOKEN.fullmatch(value) and not _UUID.fullmatch(value)) or re.search(r"(?:bearer|basic)\s+", value, re.I)
                        or _REDACTED in value):
                    _fail("mapping_literal_looks_sensitive")
        kind, location = slot["kind"], slot["location"]
        if kind in {"header", "credential", "credential_path"}:
            _fail("credential_mapping_requires_identity_resolver")
        if kind in {"credential_query", "credential_json"} and not omit:
            _fail("credential_literals_forbidden")
        if kind in {"query_value", "credential_query"}:
            index = int(location.split("/")[1])
            if omit:
                query_removals.add(index)
            else:
                result["query_pairs"][index][1] = ("" if value is None else
                    str(value).lower() if isinstance(value, bool) else str(value))
        elif kind in {"json_value", "credential_json"}:
            pointer = location[len("json"):]
            if not pointer:
                if omit:
                    result.pop("json", None)
                else:
                    result["json"] = value
            else:
                tokens = [part.replace("~1", "/").replace("~0", "~") for part in pointer[1:].split("/")]
                parent = result["json"]
                for token in tokens[:-1]:
                    parent = parent[int(token)] if isinstance(parent, list) else parent[token]
                if isinstance(parent, list):
                    if omit:
                        _fail("array_member_omission_unsupported")
                    parent[int(tokens[-1])] = value
                elif omit:
                    del parent[tokens[-1]]
                else:
                    parent[tokens[-1]] = value
        elif kind == "path_value":
            if omit or not isinstance(value, str) or not value or value in {".", ".."}:
                _fail("path_mapping_requires_literal_identifier")
            path, separator, query = result["path"].partition("?")
            parts = path.split("/")
            parts[int(location.split("/")[1])] = quote(value, safe="")
            result["path"] = "/".join(parts) + (separator + query if separator else "")
        else:
            _fail("unsupported_import_mapping_kind")
        resolved.add(slot_id)
        receipts.append({"slot_id": slot_id, "location": location,
                         "operation": "omit" if omit else "declared_non_secret_literal",
                         **({} if omit else {"literal": value})})
    if "query_pairs" in result:
        result["query_pairs"] = [pair for i, pair in enumerate(result["query_pairs"]) if i not in query_removals]
        for slot in result["secret_slots"]:
            if slot["id"] not in resolved and slot["kind"] in {"query_value", "credential_query"}:
                old_index = int(slot["location"].split("/")[1])
                slot["location"] = f"query/{old_index - sum(index < old_index for index in query_removals)}"
        path = result["path"].split("?", 1)[0]
        result["path"] = path + (("?" + urlencode([tuple(pair) for pair in result["query_pairs"]])) if result["query_pairs"] else "")
    result["secret_slots"] = [slot for slot in result["secret_slots"] if slot["id"] not in resolved]
    for blocker, kinds in (("redacted_query_requires_mapping", {"query_value", "credential_query"}),
                           ("redacted_json_requires_mapping", {"json_value", "credential_json"}),
                           ("redacted_path_requires_mapping", {"path_value", "credential_path"})):
        if not any(slot["kind"] in kinds for slot in result["secret_slots"]):
            result["execution_blockers"] = [code for code in result["execution_blockers"] if code != blocker]
    result["source_entry_id"] = entry.get("source_entry_id", entry_id)
    result["parent_entry_id"] = entry_id
    result["mapping_receipts"] = entry.get("mapping_receipts", []) + receipts
    result.pop("id", None)
    result["id"] = "import-" + _digest(result)[:24]
    return result


def resolve_imported_entry(entry: dict, mappings: dict) -> dict:
    """Resolve declared public field values without changing the original entry.

    Slot mappings are ``{"literal": scalar}`` or ``{"omit": True}``. Credential
    slots never accept literals. Scope and method are not mapping fields.
    """
    try:
        return _resolve_imported_entry(entry, mappings)
    except (KeyError, IndexError, TypeError, ValueError, RecursionError) as exc:
        if isinstance(exc, ImportError):
            raise
        _fail("invalid_import_mapping")
