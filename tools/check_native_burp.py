#!/usr/bin/env python3
"""Offline acceptance check for the pinned public native Burp fixture.

The XML parity check is deliberately limited to exact known public bytes. It
does not parse XML, allow DTDs, or create a compatible XML file from an export.
"""
from __future__ import annotations

import base64
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from authzledger.experiments import verify_execution
from authzledger.imports import ImportError, parse_import


DEFAULT_FIXTURE = ROOT / "fixtures" / "imports" / "burp-native-v1"
NATIVE_ACTION = "Burp message editor Raw tab: Copy to file with no text selected"
BURP_JAR_SHA256 = "3571f8cadbfd65b0b090d2753735c40b76ad7fdde0b927df2b22ec46ea09693a"
# Exact original files from the complete public capture on 10 October 2026.
# A fresh capture needs separately reviewed pins; it cannot replace this one.
PINNED_NATIVE_SHA256 = {
    "burp-request.http": "494b9be5fc48c4f8faf23bf2f01d1647e473fbe81831d74143d6368c8c5cbedb",
    "burp-response.http": "552123446e70539dd222b275c733b451ccc4dac7a76702888c750cb44a5ecd61",
    "burp-http-messages.xml": "1f4157ec2e306dc11c9192e7f0efcf9425b92b53af4b8526b322025d488cd67d",
}


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def _read(directory: Path, name: str, maximum: int = 10 * 1048576) -> bytes:
    _require(isinstance(name, str) and Path(name).name == name, "invalid_fixture_filename")
    path = directory / name
    _require(not path.is_symlink(), "fixture_symlink_forbidden")
    with path.open("rb") as stream:
        result = stream.read(maximum + 1)
    _require(len(result) <= maximum, "fixture_file_oversized")
    return result


def _json(directory: Path, name: str) -> object:
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, "duplicate_evidence_key")
            result[key] = value
        return result
    return json.loads(_read(directory, name), object_pairs_hook=pairs,
                      parse_constant=lambda _: _require(False, "nonfinite_evidence"))


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _check_native_burp(directory: Path) -> dict:
    names = {"burp-request.http", "burp-response.http", "burp-http-messages.xml"}
    _require(set(PINNED_NATIVE_SHA256) == names, "native_capture_not_pinned")
    original = {name: _read(directory, name) for name in sorted(names)}
    for name, raw in original.items():
        _require(_sha(raw) == PINNED_NATIVE_SHA256[name], "native_bytes_changed:" + name)
    request = original["burp-request.http"]
    response = original["burp-response.http"]
    xml = original["burp-http-messages.xml"]
    provenance = _json(directory, "burp-real.provenance.json")
    _require(isinstance(provenance, dict), "invalid_native_provenance")
    _require((provenance.get("producer"), provenance.get("edition"), provenance.get("version")) ==
             ("Burp Suite", "Community", "2026.9.2"), "native_producer_mismatch")
    _require(provenance.get("profile") == "burp-http-pair-v1", "native_profile_mismatch")
    _require(provenance.get("native_action") == NATIVE_ACTION, "native_export_action_mismatch")
    _require(provenance.get("distribution_sha256") == BURP_JAR_SHA256, "native_distribution_mismatch")
    _require(provenance.get("distribution_url") ==
             "https://portswigger.net/burp/releases/startdownload?product=desktop&type=jar&version=2026.9.2",
             "native_distribution_source_mismatch")
    _require(provenance.get("native_files_unchanged") is True and
             provenance.get("public_synthetic_fixture") is True, "native_capture_declaration_missing")
    _require(datetime.fromisoformat(provenance["capture_time"]).utcoffset() is not None,
             "capture_time_requires_offset")
    expected_native = {name: PINNED_NATIVE_SHA256[name] for name in ("burp-request.http", "burp-response.http")}
    _require(provenance.get("native_files_sha256") == expected_native, "native_provenance_hash_mismatch")
    _require(provenance.get("harness_sha256") == _sha((ROOT / "tools" / "capture_burp_fixture.py").read_bytes()),
             "capture_harness_changed")

    # Only the exact pinned public export reaches this bounded extraction. No
    # general XML parser runs, no DTD is stripped, and the source stays intact.
    _require(b"<!DOCTYPE items [" in xml and b'burpVersion="2026.9.2"' in xml,
             "native_xml_profile_mismatch")
    for element, raw in ((b"request", request), (b"response", response)):
        pattern = b"<" + element + b' base64="true"><!\\[CDATA\\[([A-Za-z0-9+/=\\r\\n]+)\\]\\]></' + element + b">"
        found = re.findall(pattern, xml)
        _require(len(found) == 1, "native_xml_message_count")
        decoded = base64.b64decode(b"".join(found[0].split()), validate=True)
        _require(decoded == raw, "native_xml_raw_message_mismatch")
    try:
        parse_import(xml, "burp-xml")
    except ImportError as exc:
        _require(str(exc) == "xml_declarations_forbidden", "native_xml_wrong_rejection")
    else:
        raise ValueError("native_dtd_xml_was_accepted")
    _require(provenance.get("xml_export") == {
        "sha256": PINNED_NATIVE_SHA256["burp-http-messages.xml"],
        "import_result": "xml_declarations_forbidden", "accepted": False,
    }, "native_xml_receipt_mismatch")

    origin = provenance["source_origin"]
    batch = parse_import(request, "burp-http-pair-v1", source_origin=origin, response_bytes=response)
    _require(batch == _json(directory, "burp-real.import.json"), "native_import_receipt_mismatch")
    entry = batch["entries"][0]
    _require((entry["method"], entry["origin"], entry["path"], entry["response"]["status"]) ==
             ("GET", origin, "/invoice/A", 200), "native_import_fields_mismatch")
    _require(not entry["execution_blockers"], "native_import_has_blockers")
    _require(entry["source_refs"][0]["origin_basis"] == "explicit_operator_binding", "origin_basis_missing")

    execution = _json(directory, "burp-real.execution.json")
    _require(isinstance(execution, dict) and not verify_execution(execution), "native_execution_verification_failed")
    _require(execution["plan"]["spec"]["sources"] == [entry["id"]], "native_execution_source_mismatch")
    _require(execution["contract"]["target"] == origin, "native_execution_origin_mismatch")
    rule = execution["plan"]["spec"]["rule"]
    _require((rule["kind"], rule["pointer"], rule["value"], rule["resource_id"]) ==
             ("forbid_field_equal", "/marker", "synthetic-A", "invoice-A"), "native_execution_rule_mismatch")
    ledger = execution["budget_ledger"]
    _require(ledger["dispatched_total"] == 4 and ledger["approved_total"] == 4,
             "native_execution_budget_mismatch")
    findings = execution["findings"]
    _require(len(findings) == 1 and findings[0]["status"] == "confirmed" and
             findings[0]["category"] == "denial_data_disclosure" and findings[0]["identity"] == "peer",
             "native_execution_finding_mismatch")
    observed = _json(directory, "request-receipts.json")
    _require(isinstance(observed, list) and len(observed) == 5, "native_observation_count_mismatch")
    _require(provenance.get("native_capture_requests") == 1 and
             provenance.get("controlled_execution_requests") == 4, "native_request_count_mismatch")
    expected_observed = [("native_capture", "GET", "/invoice/A", 200),
                         ("controlled_execution", "GET", "/invoice/A", 200),
                         ("controlled_execution", "GET", "/me", 200),
                         ("controlled_execution", "GET", "/known-denial", 403),
                         ("controlled_execution", "GET", "/invoice/A", 403)]
    _require([(item["phase"], item["method"], item["path"], item["status"]) for item in observed] ==
             expected_observed, "native_observed_sequence_mismatch")
    request_head = request.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
    _require(observed[0]["request_line_hex"] == (request_head[0] + b"\r\n").hex(),
             "native_observed_request_line_mismatch")
    native_headers = [[name.decode("ascii"), value.strip(b" \t").decode("ascii")]
                      for name, value in (line.split(b":", 1) for line in request_head[1:])]
    _require(observed[0]["headers"] == native_headers, "native_observed_headers_mismatch")

    ready = _json(directory, "capture-ready.json")
    _require(ready["edition"] == "Community" and ready["native_action"] == NATIVE_ACTION,
             "native_ui_receipt_mismatch")
    screenshots = provenance.get("screenshots_sha256")
    _require(isinstance(screenshots, dict) and 1 <= len(screenshots) <= 16 and
             sorted(ready["screenshots"]) == sorted(screenshots), "native_screenshot_inventory_mismatch")
    for name, digest in screenshots.items():
        _require(name.endswith(".png"), "native_screenshot_extension")
        raw = _read(directory, name)
        _require(raw.startswith(b"\x89PNG\r\n\x1a\n") and _sha(raw) == digest, "native_screenshot_hash_mismatch")
    return {"profile": "burp-http-pair-v1", "producer": "Burp Suite Community 2026.9.2",
            "native_files_sha256": dict(PINNED_NATIVE_SHA256), "import_sha256": batch["import_sha256"],
            "source_id": entry["id"], "execution_digest": execution["execution_digest"],
            "native_capture_requests": 1, "controlled_execution_requests": 4,
            "xml_import_result": "xml_declarations_forbidden", "screenshots_checked": len(screenshots),
            "verification": "pinned public fixture integrity and recorded controlled execution; no vendor attestation"}


def check_native_burp(directory: Path | None = None) -> dict:
    """Return verified fixture receipt, or raise ValueError; never use network."""
    try:
        return _check_native_burp(DEFAULT_FIXTURE if directory is None else Path(directory))
    except (OSError, KeyError, TypeError, UnicodeError) as exc:
        raise ValueError("native_fixture_missing_or_malformed") from exc


if __name__ == "__main__":
    try:
        print(json.dumps(check_native_burp(), indent=2, sort_keys=True))
    except ValueError as exc:
        print("Native Burp acceptance blocked: " + str(exc), file=sys.stderr)
        raise SystemExit(1)
