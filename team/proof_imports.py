# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Strict, offline projection of source files into explicitly bounded evidence."""
import ipaddress
import re
from datetime import datetime
from urllib.parse import unquote, urlsplit
from xml.etree.ElementTree import ParseError

from .evidence_formats import MAX_FILE, MAX_ROWS, canonical, host, read_json, sha, xml_document

SOURCES = {"burp": "Burp", "zap": "ZAP", "har": "HAR", "openapi": "OpenAPI",
           "nmap": "Nmap", "nuclei": "Nuclei", "nessus": "Nessus", "nikto": "Nikto",
           "cobalt": "Cobalt Strike telemetry"}
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
ROUTES = set(("api v1 v2 v3 users user accounts account invoices invoice orders order items item objects object "
              "projects project organizations teams profile status health public private auth login logout session me "
              "control admin").split())
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,95}\Z")
FIELDS = {"id", "host", "method", "path", "status", "marker", "rule", "source", "severity"}
SEVERITY_LEVELS = ("info", "low", "medium", "high", "critical", "unknown")
# Refuse common credential structures before an operator-supplied label can be retained.
# Opaque business identifiers still require review by the operator.
CREDENTIAL = re.compile(
    r"(?:authorization|proxy-authorization|cookie|set-cookie)\s*:|"
    r"(?:password|passwd|access[_-]?token|api[_-]?key|client[_-]?secret)\s*=|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|\bBearer\s+\S|"
    r"(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|"
    r"eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{3,}\.[A-Za-z0-9_-]{5,}|"
    r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}|xox[bpars]-[A-Za-z0-9-]{12,}", re.I)



def _require(ok, message):
    if not ok:
        raise ValueError(message)


def safe_host(value):
    _require(isinstance(value, str) and "://" not in value and "%" not in value and not CREDENTIAL.search(value), "invalid host")
    result = host(value)
    _require(result is not None, "invalid host")
    return result


def safe_path(value):
    _require(isinstance(value, str) and len(value) <= 8192 and value.startswith("/")
             and not value.startswith("//"), "invalid path")
    path = value.split("?", 1)[0].split("#", 1)[0]
    _require(len(path.split("/")) <= 64 and not re.search(r"[\x00-\x20\x7f\\]", path), "invalid path")
    result = []
    for segment in path.split("/"):
        _require(not re.search(r"%(?![0-9a-fA-F]{2})", segment), "invalid URL encoding")
        decoded = unquote(segment, errors="strict")
        _require(decoded not in (".", "..") and not re.search(r"[/%\\\x00-\x1f\x7f]", decoded), "ambiguous path")
        if (not segment or segment in ROUTES or re.fullmatch(r"[0-9]{1,9}|redacted-[0-9a-f]{24}", segment)):
            result.append(segment)
        else:
            result.append("redacted-" + sha(segment.encode())[:24])
    return "/".join(result)


def endpoint(value):
    _require(isinstance(value, str) and len(value) <= 8192 and not re.search(r"[\x00-\x20\\]", value), "invalid URL")
    url = urlsplit(value)
    _require(url.scheme.lower() in ("http", "https") and url.username is None and url.password is None
             and url.hostname and url.port != 0, "invalid HTTP URL")
    return safe_host(url.hostname), safe_path(url.path or "/")


def normalize(row, label):
    _require(isinstance(row, dict) and set(row) <= FIELDS and FIELDS - {"marker", "severity"} <= set(row),
             "invalid observation fields")
    _require(row["source"] == label, "unexpected source")
    for field in ("id", "rule"):
        _require(isinstance(row[field], str) and IDENTIFIER.fullmatch(row[field])
                 and not CREDENTIAL.search(row[field]), "invalid observation identifier")
    method = row["method"]
    status = row["status"]
    marker = row.get("marker", False)
    _require(isinstance(method, str) and (method in METHODS or (method == "SERVICE" and label in ("Nmap", "Nessus"))
             or (method == "UNKNOWN" and label in ("Burp", "ZAP", "Nuclei", "Nikto", "Cobalt Strike telemetry"))),
             "invalid method")
    _require(status is None or type(status) is int and 100 <= status <= 599, "invalid HTTP status")
    _require(type(marker) is bool, "invalid marker")
    if label in ("Nmap", "Nuclei", "OpenAPI"):
        _require(not marker, "inventory or scanner assertions cannot assert a protected marker")
    if label in ("Nessus", "Nikto", "Cobalt Strike telemetry"):
        _require(status is None and not marker, "scanner records cannot attest HTTP controls")
    result = {"id": row["id"], "host": safe_host(row["host"]), "method": method, "path": safe_path(row["path"]),
              "status": status, "marker": marker, "rule": row["rule"], "source": label}
    if "severity" in row:
        _require(label in ("Nessus", "Nuclei") and row["severity"] in SEVERITY_LEVELS, "invalid source severity")
        result["severity"] = row["severity"]
    return result


def source_object(fmt, digest, rows, observed_absent=None):
    _require(fmt in (*SOURCES, "lab") and isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest),
             "invalid source identity")
    _require(isinstance(rows, list) and 1 <= len(rows) <= MAX_ROWS, "invalid observation count")
    label = SOURCES.get(fmt, "Lab")
    result = [normalize(row, label) for row in rows]
    _require(len({r["id"] for r in result}) == len(result), "duplicate observation identifier")
    source = {"format": fmt, "sha256": digest, "observations": result}
    if observed_absent is not None:
        require_ids = {r["id"] for r in result if not r["marker"] and r["status"] in (401, 403)}
        _require(isinstance(observed_absent, list) and all(isinstance(key, str) for key in observed_absent)
                 and len(observed_absent) == len(set(observed_absent)) and set(observed_absent) <= require_ids,
                 "invalid negative marker attestations")
        if observed_absent:
            source["observedAbsent"] = list(observed_absent)
    return source


def _array(value):
    _require(isinstance(value, list), "expected an array")
    return value


def _number(value, maximum):
    _require(isinstance(value, str) and re.fullmatch(r"[0-9]{1,12}", value) and int(value) <= maximum,
             "invalid numeric report field")
    return int(value)


def _read_scanner_xml(fmt, text, add):
    _require(not re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.I), "DTD is prohibited")
    root = xml_document(text)
    if fmt == "nessus":
        _require(root.tag == "NessusClientData_v2", "invalid Nessus report")
        for target in root.iterfind("Report/ReportHost"):
            hostname = safe_host(target.get("name"))
            for item in target.iterfind("ReportItem"):
                plugin = _number(item.get("pluginID"), 999999999999)
                port = _number(item.get("port"), 65535)
                severity = _number(item.get("severity"), 4)
                protocol = item.get("protocol")
                _require(protocol in ("tcp", "udp", "icmp", "ip", "sctp"), "invalid Nessus protocol")
                add(hostname, "SERVICE", "/", rule=f"plugin-{plugin}-{protocol}-{port}", severity=SEVERITY_LEVELS[severity])
        return

    _require(root.tag in ("niktoscan", "niktoscans"), "invalid Nikto report")
    path = "niktoscan/scandetails" if root.tag == "niktoscans" else "scandetails"
    for scan in root.iterfind(path):
        hostname = safe_host(scan.get("targethostname") or scan.get("targetip"))
        port = scan.get("targetport")
        port_label = f"-port-{_number(port, 65535)}" if port is not None else ""
        for item in scan.iterfind("item"):
            item_id = _number(item.get("id"), 999999999999)
            route = safe_path(item.findtext("uri") or "/")
            add(hostname, item.get("method") or "UNKNOWN", route, rule=f"item-{item_id}{port_label}")


def _read_telemetry(data, add):
    _require(isinstance(data, dict) and set(data) == {"schema", "source", "events"}
             and data["schema"] == "authzledger.defensive-telemetry.v1" and data["source"] == "cobalt-strike",
             "invalid defensive telemetry envelope")
    record_ids = set()
    for event in _array(data["events"]):
        _require(isinstance(event, dict) and set(event) == {"record_id", "asset", "observed_at", "event_type"},
                 "invalid defensive telemetry fields")
        ident, timestamp, kind = event["record_id"], event["observed_at"], event["event_type"]
        _require(isinstance(ident, str) and re.fullmatch(r"[^\x00-\x20\x7f]{1,255}", ident) and ident not in record_ids,
                 "invalid or duplicate telemetry record id")
        record_ids.add(ident)
        _require(kind in ("detection", "containment", "review"), "invalid defensive event type")
        _require(isinstance(timestamp, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{3})?Z", timestamp),
                 "invalid UTC timestamp")
        datetime.fromisoformat(timestamp[:-1])
        add(safe_host(event["asset"]), "UNKNOWN", "/", rule=kind, locator=[ident, timestamp])


def import_source(fmt, raw):
    """The returned object is safe to persist. Raw input and request metadata are discarded."""
    _require(isinstance(fmt, str) and fmt.lower() in SOURCES, "unknown import format")
    fmt = fmt.lower()
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_FILE, "source exceeds size limit or is empty")
    try:
        text = raw.decode("utf-8-sig")
        rows, absent = _read(fmt, text)
        return source_object(fmt, sha(raw), rows, absent)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, OverflowError, ParseError, RecursionError):
        raise ValueError("invalid or unsupported source document") from None


def _read(fmt, text):
    label = SOURCES[fmt]
    rows = []

    def add(hostname, method, path, status=None, rule="protected-marker", locator=None, severity=None):
        _require(len(rows) < MAX_ROWS, "too many observations")
        # Source-local deterministic key. Non-evidence fields do not influence the identity.
        key = [fmt, len(rows) + 1, hostname, method, path, rule, locator]
        record = {"id": fmt + "-" + sha(canonical(key))[:24], "host": hostname, "method": method,
                  "path": path, "status": status, "marker": False, "rule": rule, "source": label}
        if severity is not None:
            record["severity"] = severity
        rows.append(record)

    content = text.lstrip()
    if fmt in ("nessus", "nikto"):
        _read_scanner_xml(fmt, text, add)
        return rows, None
    if fmt == "cobalt":
        _read_telemetry(read_json(text), add)
        return rows, None
    if content.startswith(("{", "[")) and fmt != "nuclei":
        data = read_json(text)
        if isinstance(data, list) or isinstance(data, dict) and "observations" in data:
            absent = None
            if isinstance(data, dict):
                _require(set(data) <= {"observations", "observedAbsent"}, "unknown envelope fields")
                absent = data.get("observedAbsent")
                data = data["observations"]
            return _array(data), absent
    else:
        data = None
    if fmt == "har":
        log = data["log"]
        _require(log["version"] in ("1.1", "1.2"), "invalid HAR version")
        for item in _array(log["entries"]):
            request = item["request"]
            hostname, path = endpoint(request["url"])
            status = item["response"]["status"]
            _require(type(status) is int and (status == 0 or 100 <= status <= 599), "invalid HAR status")
            add(hostname, request["method"], path, status or None, locator=item.get("startedDateTime"))
    elif fmt == "zap":
        for site in _array(data["site"]):
            for alert in _array(site["alerts"]):
                rule = str(alert["pluginid"])
                _require(re.fullmatch(r"[0-9]{1,10}", rule), "invalid ZAP rule")
                for item in _array(alert["instances"]):
                    hostname, path = endpoint(item["uri"])
                    add(hostname, item.get("method", "UNKNOWN"), path, rule=rule)
    elif fmt == "openapi":
        _require(isinstance(data["info"], dict) and re.fullmatch(r"3\.[012]\.\d+", data["openapi"]),
                 "invalid OpenAPI version")
        for path, resource in data["paths"].items():
            if path.startswith("x-"):
                continue
            _require(isinstance(resource, dict) and "$ref" not in resource, "unresolved path")
            for method, operation in resource.items():
                if method.upper() not in METHODS or method != method.lower():
                    continue
                _require(isinstance(operation, dict) and "$ref" not in operation, "unresolved operation")
                servers = _array(operation.get("servers", resource.get("servers", data.get("servers", []))))
                _require(servers, "an explicit HTTP server is required")
                for server in servers:
                    url = urlsplit(server["url"])
                    hostname, _ = endpoint(server["url"])
                    _require(not url.query and not url.fragment and "{" not in url.netloc, "ambiguous server")
                    add(hostname, method.upper(), url.path.rstrip("/") + path, rule="declared-operation")
    elif fmt == "nuclei":
        for line in text.splitlines():
            if not line.strip():
                continue
            item = read_json(line)
            _require(item["type"] == "http" and type(item["matcher-status"]) is bool
                     and isinstance(item["template-id"], str) and IDENTIFIER.fullmatch(item["template-id"]), "invalid HTTP match")
            if not item["matcher-status"]:
                continue
            hostname, path = endpoint(item["matched-at"])
            info = item.get("info", {})
            _require(isinstance(info, dict) and ("severity" not in info or info["severity"] in SEVERITY_LEVELS),
                     "invalid Nuclei severity")
            add(hostname, "UNKNOWN", path, rule=item["template-id"], severity=info.get("severity"))
    elif fmt in ("burp", "nmap"):
        if fmt == "burp":
            _require(not re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.I), "DTD is prohibited")
        root = xml_document(text)
        if fmt == "burp":
            _require(root.tag in ("items","issues"), "invalid Burp document")
            for row in root.findall("item" if root.tag == "items" else "issue"):
                url = row.findtext("url")
                if not url and root.tag == "issues":
                    hostname, _ = endpoint(row.findtext("host"))
                    path = safe_path(row.findtext("path") or "/")
                else:
                    hostname, path = endpoint(url)
                code = row.findtext("status")
                _require(code in (None, "") or re.fullmatch(r"[1-5][0-9]{2}", code), "invalid status")
                add(hostname, row.findtext("method") or "UNKNOWN", path, int(code) if code else None, locator=row.findtext("time"))
        else:
            _require(root.tag == "nmaprun", "invalid Nmap document")
            for machine in root.findall("host"):
                address = next((a.get("addr") for a in machine.findall("address") if a.get("addrtype") in ("ipv4","ipv6")), None)
                _require(address, "missing IP address")
                for port in machine.findall("ports/port"):
                    protocol = port.get("protocol")
                    number = int(port.get("portid", "-1"))
                    state = port.find("state")
                    _require(protocol in ("tcp","udp","sctp","ip") and 0 <= number <= 65535 and state is not None
                             and state.get("state") in ("open","closed","filtered","unfiltered","open|filtered","closed|filtered"),
                             "invalid port data")
                    rule = f"{protocol}-{number}-{state.get('state').replace('|','-')}"
                    add(str(ipaddress.ip_address(address)), "SERVICE", "/", rule=rule)
    return rows, None
