# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Bounded local parsers. Stored rows contain no URLs, bodies, paths or headers."""
import base64
import hashlib
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit

FORMATS = ("burp", "zap", "har", "nmap", "nuclei", "openapi")
MAX_FILE = 1024 * 1024
MAX_ROWS = 1000


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(obj):
    return json.dumps(obj, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def read_json(text):
    def invalid(_):
        raise ValueError("invalid JSON number")
    return json.loads(text, object_pairs_hook=reject_duplicates, parse_constant=invalid)


def host(value):
    """Return a canonical hostname/IP. Resolve no names and open no connections."""
    if not isinstance(value, str) or not value or len(value) > 8192:
        return None
    if any(ord(ch) < 33 or ord(ch) == 127 or ch == '\\' for ch in value):
        return None
    if "://" in value:
        url = urlsplit(value)
        if url.scheme.lower() not in ("http", "https") or not url.hostname or url.username or url.password:
            return None
        _ = url.port
        value = url.hostname
    value = value.lower().removesuffix(".")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if len(value) <= 253 and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split(".")):
            return value
    return None


def sequence(value):
    if not isinstance(value, list):
        raise ValueError("expected an array")
    return value


def xml_document(text):
    # ElementTree never receives entity declarations, external subsets or parameter
    # references. Burp's native ELEMENT/ATTLIST declarations and Nmap's empty
    # DOCTYPE can be stripped before parsing.
    if text.count("<") > 40000 or re.search(r"<!\s*ENTITY\b", text, re.I):
        raise ValueError("unsupported XML")
    prefix = re.match(r'\s*(?:<\?xml\s[^?]*\?>\s*)?(?:(?:<!--.*?-->|<\?xml-stylesheet\s[^?]*\?>)\s*)*', text, re.S)
    body = text[prefix.end():]
    declared_root = None
    if body.startswith("<!DOCTYPE"):
        decl = re.match(r"<!DOCTYPE\s+(issues|nmaprun|items)\s*(?:\[([\s\S]{0,32768}?)\]\s*)?>", body)
        if not decl:
            raise ValueError("unsupported XML declaration")
        declared_root = decl.group(1)
        subset = decl.group(2) or ""
        allowed = r"\s*(?:<!(?:ELEMENT|ATTLIST)\s+[A-Za-z][A-Za-z0-9_.:#|(),?*+=\s\x22\x27-]*>\s*)*"
        if not re.fullmatch(allowed, subset):
            raise ValueError("unsupported XML subset")
        body = re.sub(r"^\s*(?:<\?xml-stylesheet\s[^?]*\?>\s*)*", "", body[decl.end():])
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b|<\?", body, re.I):
        raise ValueError("unsupported XML declaration")
    root = ET.fromstring(body)
    if declared_root and root.tag != declared_root:
        raise ValueError("XML declaration does not match root")
    return root


def parse_records(fmt, raw):
    if fmt not in FORMATS or not 0 < len(raw) <= MAX_FILE:
        raise ValueError("invalid source format or size")
    text = raw.decode("utf-8-sig")
    rows = []

    def add(kind, asset, value, status=None, method=None, payload=None):
        if len(rows) >= MAX_ROWS:
            raise ValueError("record limit exceeded")
        resolved = host(asset)
        record = {"record": len(rows) + 1, "kind": kind, "asset_id": sha(resolved.encode()) if resolved else None,
                  "fingerprint": sha(value if isinstance(value, bytes) else canonical(value))}
        if type(status) is int and 100 <= status <= 599:
            record["status_code"] = status
        if kind in ("scanner_alert", "http_exchange") and resolved and isinstance(method, str) and re.fullmatch(r"[A-Za-z]{1,16}", method):
            url = urlsplit(asset)
            if url.scheme.lower() in ("http", "https"):
                default_port = 443 if url.scheme.lower() == "https" else 80
                # A scanner instance has no equivalent body representation across exports.
                # Keep the full method and target, including the query, as provenance only.
                endpoint = [method.upper(), url.scheme.lower(), resolved,
                            url.port if url.port is not None else default_port, url.path or "/", url.query]
                record["endpoint_key"] = sha(canonical(endpoint))
                if kind == "http_exchange":
                    record["request_key"] = sha(canonical([method.upper(),url.scheme.lower(),resolved,
                                                          url.port or default_port,url.path or "/",url.query,payload]))
        rows.append(record)
        return record

    if fmt in ("burp", "nmap"):
        doc = xml_document(text)
        if fmt == "burp" and doc.tag in ("issues", "items"):
            for entry in doc.findall("issue" if doc.tag == "issues" else "item"):
                if doc.tag == "issues" and not entry.findtext("name"):
                    raise ValueError("invalid Burp issue")
                address = entry.findtext("url") or entry.findtext("host")
                if not address:
                    raise ValueError("missing Burp host")
                status = entry.findtext("status") or ""
                payload = None
                if doc.tag == "items":
                    request = entry.find("request")
                    if request is not None and request.text:
                        raw_request = (base64.b64decode("".join(request.text.split()), validate=True)
                                       if request.get("base64") == "true" else request.text.encode())
                        # Preserve body identity for a later comparison without exposing message contents.
                        normalized_headers = raw_request.partition(b"\r\n\r\n")
                        if not normalized_headers[1]:
                            normalized_headers = raw_request.partition(b"\n\n")
                        if normalized_headers[2]:
                            payload = sha(normalized_headers[2])
                add("burp_issue" if doc.tag == "issues" else "http_exchange", address, ET.tostring(entry),
                    int(status) if status.isascii() and status.isdigit() and len(status) == 3 else None, entry.findtext("method"), payload)
        elif fmt == "nmap" and doc.tag == "nmaprun":
            for machine in doc.findall("host"):
                address = next((a.get("addr") for a in machine.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
                if not address:
                    continue
                ipaddress.ip_address(address)
                for port in machine.findall("ports/port"):
                    if port.get("protocol") not in ("tcp","udp","sctp","ip") or not 0 <= int(port.get("portid", "-1")) <= 65535 or port.find("state") is None:
                        raise ValueError("invalid Nmap port")
                    add("port_state", address, ET.tostring(port))
        else:
            raise ValueError("unexpected XML root")
    elif fmt == "nuclei":
        for line in text.splitlines():
            if not line.strip():
                continue
            item = read_json(line)
            if item.get("type") != "http" or item.get("matcher-status") is not True or not isinstance(item.get("template-id"), str):
                raise ValueError("invalid Nuclei HTTP match")
            add("http_match", item["matched-at"], item)
    else:
        data = read_json(text)
        if fmt == "har":
            log = data["log"]
            if log["version"] not in ("1.1","1.2"):
                raise ValueError("unsupported HAR")
            for item in sequence(log["entries"]):
                req = item["request"]
                if not isinstance(req["method"], str) or not isinstance(item["response"], dict):
                    raise ValueError("invalid HAR entry")
                if "postData" in req and not isinstance(req["postData"], dict):
                    raise ValueError("invalid HAR request body")
                status = item["response"]["status"]
                if type(status) is not int or (status != 0 and not 100 <= status <= 599):
                    raise ValueError("invalid HAR status")
                payload = sha(canonical(req["postData"])) if "postData" in req else None
                add("http_exchange", req["url"], item, status, req["method"], payload)
        elif fmt == "zap":
            for site in sequence(data["site"]):
                for alert in sequence(site["alerts"]):
                    rule = alert["pluginid"]
                    if type(rule) not in (int, str) or not re.fullmatch(r"[0-9]{1,10}", str(rule)):
                        raise ValueError("invalid ZAP rule ID")
                    instances = sequence(alert["instances"])
                    if not instances:
                        raise ValueError("ZAP alert is missing its instances")
                    metadata = {"rule_id": str(rule)}
                    alert_ref = alert.get("alertRef")
                    if isinstance(alert_ref, str) and re.fullmatch(r"[0-9]{1,10}(?:-[0-9]{1,10})?", alert_ref):
                        metadata["alert_ref"] = alert_ref
                    for key, maximum in (("riskcode", 3), ("confidence", 4)):
                        value = alert.get(key)
                        if type(value) in (str, int) and str(value) in {str(i) for i in range(maximum + 1)}:
                            metadata[key] = int(value)
                    for entry in instances:
                        uri = entry["uri"]
                        if not host(uri) or urlsplit(uri).scheme.lower() not in ("http", "https"):
                            raise ValueError("invalid ZAP instance URI")
                        row = add("scanner_alert", uri, [rule, entry], method=entry.get("method"))
                        row.update(metadata)
        elif fmt == "openapi":
            if not isinstance(data.get("info"), dict) or not re.fullmatch(r"3\.[012]\.\d+", data["openapi"]):
                raise ValueError("unsupported OpenAPI document")
            for path, item in data["paths"].items():
                if path.startswith("x-"):
                    continue
                if not path.startswith("/") or "$ref" in item:
                    raise ValueError("unresolved or invalid OpenAPI path")
                for method, operation in item.items():
                    if method not in ("get","put","post","delete","options","head","patch","trace"):
                        continue
                    if not isinstance(operation, dict) or "$ref" in operation:
                        raise ValueError("unresolved OpenAPI operation")
                    servers = sequence(operation.get("servers",item.get("servers",data.get("servers",[]))))
                    url = servers[0].get("url") if len(servers) == 1 else None
                    add("declared_operation", url if url and "://" in url else None, [path,method,servers,operation])
    if not rows and fmt != "zap":
        raise ValueError("source contains no supported records")
    return rows
