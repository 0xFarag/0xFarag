"""Check external AuthzLedger Demo D projection against fixed local reference evidence."""

import argparse
import hashlib
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent
INPUT_LIMIT = 256 * 1024
SOURCE_NAMES = ("nmap.xml", "ffuf.json", "nuclei.jsonl")
NMAP_LOCATOR = "/nmaprun/host[1]/ports/port[1]"


class ContractError(ValueError):
    """The supplied evidence does not satisfy the fixed Demo D contract."""


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("Doppelter JSON-Objektschlüssel")
        result[key] = value
    return result


def invalid_number(_value):
    raise ContractError("Ungültige JSON-Zahl")


def read_limited(path):
    with path.open("rb") as stream:
        data = stream.read(INPUT_LIMIT + 1)
    if len(data) > INPUT_LIMIT:
        raise ContractError("Datei über dem Grössenlimit")
    return data


def decode_json(data):
    return json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicate_keys,
                      parse_constant=invalid_number)


def read_projection(path):
    return decode_json(read_limited(path))


def row_id(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for field in ("source", "record", "locator", "key", "target"):
            if isinstance(value.get(field), str):
                return value[field]
    raise ContractError("Zeile ohne vertragliche Identität")


def index_rows(rows, path):
    indexed = {}
    for row in rows:
        key = row_id(row)
        if key in indexed:
            raise ContractError(f"{path}: doppelte Zeilenidentität")
        indexed[key] = row
    return indexed


def compare(expected, actual, path="$"):
    """Object fields are exact, contract collections are unordered with unique identities."""
    if type(expected) is not type(actual):
        raise ContractError(f"{path}: abweichender Typ")
    if isinstance(expected, dict):
        if expected.keys() != actual.keys():
            missing = sorted(expected.keys() - actual.keys())
            raise ContractError(f"{path}: Feldmenge weicht ab; fehlend={missing}")
        for key, value in expected.items():
            compare(value, actual[key], f"{path}.{key}")
    elif isinstance(expected, list):
        wanted = index_rows(expected, path)
        received = index_rows(actual, path)
        if wanted.keys() != received.keys():
            missing = sorted(wanted.keys() - received.keys())
            raise ContractError(f"{path}: Zeilenmenge weicht ab; fehlend={missing}")
        for key, value in wanted.items():
            compare(value, received[key], f"{path}[{key}]")
    elif expected != actual:
        raise ContractError(f"{path}: Wert weicht vom Soll ab")


def verify_fixture_sources(expected, directory):
    """Resolve agreed locators only, after their files match the trusted reference digest."""
    receipts = index_rows(expected["receipts"], "$.receipts")
    observations = index_rows(expected["graph"]["observations"], "$.graph.observations")
    contents = {}
    for source in SOURCE_NAMES:
        contents[source] = read_limited(directory / source)
        if hashlib.sha256(contents[source]).hexdigest() != receipts[source]["sha256"]:
            raise ContractError(f"{source}: SHA-256 des Quellmaterials stimmt nicht")

    port = ET.fromstring(contents["nmap.xml"]).find("./host[1]/ports/port[1]")
    state, service = port.find("state"), port.find("service")
    compare(observations["nmap.xml#" + NMAP_LOCATOR]["asserted"], {
        "state": state.attrib["state"], "reason": state.attrib["reason"],
        "method": service.attrib["method"], "name": service.attrib["name"],
        "confidence": int(service.attrib["conf"]),
    }, "nmap.xml#" + NMAP_LOCATOR)

    ffuf = decode_json(contents["ffuf.json"])
    first, excluded = ffuf["results"]
    compare(observations["ffuf.json#/results/0"]["asserted"], {
        "status": first["status"], "length": first["length"],
        "method": first.get("method", ffuf.get("config", {}).get("method")),
    }, "ffuf.json#/results/0")
    compare(first["url"], observations["ffuf.json#/results/0"]["target"])
    compare("https://198.51.100.20/help", excluded["url"])
    compare("out_of_scope", index_rows(receipts["ffuf.json"]["records"],
                                       "ffuf.json")["/results/1"]["disposition"])

    for line_number, raw in enumerate(contents["nuclei.jsonl"].splitlines(), 1):
        source = f"nuclei.jsonl#line:{line_number}"
        row = decode_json(raw)
        compare(observations[source]["target"], row["matched-at"], source)
        compare(observations[source]["asserted"], {
            "template_id": row["template-id"], "matcher": row["matcher-name"],
            "matched": row["matcher-status"], "source_severity": row["info"]["severity"],
        }, source)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("projection", type=Path, help="Export im dokumentierten Projektionsformat")
    parser.add_argument("--reimport", type=Path, help="zweiter Export nach identischem Reimport")
    parser.add_argument("--sources", type=Path, default=ROOT / "fixtures",
                        help="Verzeichnis mit den drei unveränderten Quelldateien")
    args = parser.parse_args(argv)
    try:
        expected = read_projection(ROOT / "expected" / "projection.json")
        verify_fixture_sources(expected, args.sources)
        compare(expected, read_projection(args.projection))
        if args.reimport:
            compare(expected, read_projection(args.reimport))
    except (OSError, ValueError, TypeError, KeyError, RecursionError, ET.ParseError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    print("PASS: 3 Quellen, 5 Quellrecords, 4 Beobachtungen, 1 Finding-Hinweis,"
          " 1 Scope-Ausschluss, 0 confirmed.")
    if args.reimport:
        print("PASS: identische beobachtbare Projektion nach Reimport.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
