"""Lokale Dateiprüfung. © Nasser Aldin Farag (0xFarag). All rights reserved."""
import argparse
import json
from pathlib import Path
import sys

from file_review import review_file


def main():
    parser = argparse.ArgumentParser(description="Datei lokal hashen und optional mit installiertem ClamAV prüfen.")
    parser.add_argument("datei", type=Path, help="Vorhandene reguläre Datei bis 256 MiB")
    parser.add_argument("--clamav", action="store_true", help="Lokales clamscan bei Dateien bis 16 MiB aufrufen")
    args = parser.parse_args()
    try:
        result = review_file(args.datei, clamav=args.clamav)
    except (ValueError, OSError):
        parser.exit(2, "Datei nicht lesbar, während des Lesens verändert oder ausserhalb der Grössengrenze.\n")
    print(json.dumps(result, ensure_ascii=True, indent=2))
    if args.clamav:
        state = result["engine"]["status"]
        if state == "detection_reported":
            return 1
        if state != "no_detection_reported":
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
