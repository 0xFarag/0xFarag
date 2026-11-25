# © Nasser Aldin Farag (0xFarag). All rights reserved.
"""Offline entry point for the same review engine used by the Web workbench."""
import argparse
from pathlib import Path
import sys

from .evidence_formats import MAX_FILE, canonical, read_json
from .proof_engine import evaluate, import_source, make_scope, record_retest, verify_semantics


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    review = sub.add_parser("assess", help="assess a scope and passive local captures")
    review.add_argument("--scope", type=Path, required=True, help="JSON object with hosts, roe, budget")
    review.add_argument("--controls", type=Path, required=True, help="JSON with four operator-reviewed booleans")
    review.add_argument("--source", action="append", nargs=2, metavar=("FORMAT", "FILE"), required=True)
    retest = sub.add_parser("retest", help="record selected cases against a separately imported after capture")
    retest.add_argument("--report", type=Path, required=True, help="existing unsigned CLI report")
    retest.add_argument("--select", nargs="*", required=True, metavar="CASE_ID")
    retest.add_argument("--controls", type=Path, required=True, help="four fresh control decisions")
    retest.add_argument("--after", nargs=2, metavar=("FORMAT", "FILE"), help="omit for an unassessed selection")
    verify = sub.add_parser("verify-semantics", help="replay a projected report (no signature verification)")
    verify.add_argument("report", type=Path)
    args = parser.parse_args(argv)

    def bounded(path, limit):
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
        if not 0 < len(data) <= limit:
            raise ValueError("file is empty or exceeds the size limit")
        return data

    try:
        if args.action == "verify-semantics":
            verify_semantics(read_json(bounded(args.report, 32 * MAX_FILE)))
            print("Semantic replay verified.")
        elif args.action == "retest":
            report = read_json(bounded(args.report, 32 * MAX_FILE))
            verify_semantics(report)
            if "keyId" in report:
                raise ValueError("provide the unsigned evaluation report; signed handovers are immutable")
            controls = read_json(bounded(args.controls, 2048))
            after = import_source(args.after[0], bounded(Path(args.after[1]), MAX_FILE)) if args.after else None
            record_retest(report, args.select, after, controls)
            print(canonical(report).decode())
        else:
            scope = make_scope(**read_json(bounded(args.scope, 8192)))
            controls = read_json(bounded(args.controls, 2048))
            sources = [import_source(fmt, bounded(Path(filename), MAX_FILE)) for fmt, filename in args.source]
            print(canonical(evaluate(scope, sources, controls)).decode())
    except (TypeError, ValueError, OSError) as exc:
        parser.exit(2, "Evidence review failed: " + str(exc) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
