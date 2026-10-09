"""Explicit, scriptable commands with stable exit codes."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .evidence import compare_reports, verify_report
from .model import ContractError, load_contract, plan
from .reports import render_diff_html, render_html, render_junit


def read_json(path: str) -> dict:
    def reject_constant(value):
        raise ValueError("Non-finite JSON number")

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON keys are ambiguous")
            result[key] = value
        return result

    try:
        with open(path, encoding="utf-8") as handle:
            value = json.load(handle, object_pairs_hook=unique_pairs, parse_constant=reject_constant)
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds the supported depth") from exc
    if not isinstance(value, dict):
        raise ValueError("Expected a JSON object")
    return value


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")


def save_report(report: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "report.json", report)
    (out / "report.html").write_text(render_html(report), encoding="utf-8")
    (out / "junit.xml").write_text(render_junit(report), encoding="utf-8")


def print_summary(report: dict) -> None:
    s = report["summary"]
    print(f"AuthzLedger {__version__} | {s['total']} configured checks")
    print(f"PASS {s['pass']}  FAIL {s['fail']}  ERROR {s['error']}  INCONCLUSIVE {s['inconclusive']}")
    for case in report["results"]:
        print(f"  {case['outcome'].upper():12} {case['id']}")
    print(f"Evidence anchor: {report['evidence']['root_sha256']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="authzledger", description="Turn API authorization findings into repeatable checks.")
    parser.add_argument("--version", action="version", version=f"AuthzLedger {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create owner/other controls and a cross-user contract to adapt to your API")
    init.add_argument("--target", required=True, help="Exact authorized HTTP(S) origin")
    init.add_argument("--out", type=Path, default=Path("authorization.json"))
    for command in ("plan", "run"):
        sub = commands.add_parser(command, help="Inspect scoped requests" if command == "plan" else "Execute an explicit authorization contract")
        sub.add_argument("contract")
        sub.add_argument("--allow-mutations", action="store_true", help="Permit explicitly configured POST/PUT/PATCH/DELETE cases")
        if command == "run":
            sub.add_argument("--out", type=Path, required=True)
    verify = commands.add_parser("verify", help="Check report integrity; optionally compare a separately retained anchor")
    verify.add_argument("report")
    verify.add_argument("--anchor")
    diff = commands.add_parser("diff", help="Compare two verified reports of the same contract")
    diff.add_argument("baseline")
    diff.add_argument("current")
    diff.add_argument("--out", type=Path, required=True)
    demo = commands.add_parser("demo", help="Run the local vulnerable/fixed fixture and write real evidence")
    demo.add_argument("--out", type=Path, default=Path("artifacts/demo"))
    studio = commands.add_parser("studio", help="Launch the local loopback workbench")
    studio.add_argument("--port", type=int, default=0, help="Loopback port; default selects a free port")
    studio.add_argument("--open", action="store_true", help="Open the session URL in your default browser")
    matrix = commands.add_parser("matrix", help="Compile an explicit access matrix with generated positive-control dependencies")
    matrix.add_argument("project")
    matrix.add_argument("--out", type=Path, required=True)
    migration = commands.add_parser("policy-diff", help="Explain proposed rule/binding changes without classifying them as fixes")
    migration.add_argument("before")
    migration.add_argument("after")
    migration.add_argument("--out", type=Path, required=True)
    benchmark = commands.add_parser("benchmark", help="Run eight local fault scenarios and a status-only comparison")
    benchmark.add_argument("--out", type=Path, default=Path("artifacts/benchmark"))
    api_import = commands.add_parser("import-openapi", help="Index an offline OpenAPI JSON document or compile selected operations")
    api_import.add_argument("specification")
    api_import.add_argument("--config", help="Explicit identities, operation selections, fixture parameters and expectations")
    api_import.add_argument("--allow-mutations", action="store_true")
    api_import.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "benchmark":
            from .benchmark import run_benchmark
            result = run_benchmark(args.out)
            for row in result["scenarios"]:
                print(row["scenario"], "ACCEPTED" if row["accepted"] else "FAILED", row["summary"])
            print(result["limitation"])
            return 0 if result["accepted"] else 1
        if args.command in {"matrix", "policy-diff"}:
            from .matrix import compile_matrix, policy_diff
            if args.command == "matrix":
                result = compile_matrix(read_json(args.project))
                args.out.mkdir(parents=True, exist_ok=False)
                for name in ("project", "contract", "manifest"):
                    write_json(args.out / (name + ".json"), result[name])
                print(f"Compiled {result['manifest']['coverage']['total']} explicit checks. No requests sent.")
            else:
                result = policy_diff(read_json(args.before), read_json(args.after))
                with args.out.open("x", encoding="utf-8") as handle:
                    json.dump(result, handle, indent=2, ensure_ascii=True, allow_nan=False)
                    handle.write("\n")
                print(f"{len(result['changes'])} affected relationships; proposed policy migration, not a remediation result.")
            return 0
        if args.command == "studio":
            if not 0 <= args.port <= 65535:
                raise ValueError("Invalid loopback port")
            from .studio import serve
            return serve(args.port, open_browser=args.open)
        if args.command == "import-openapi":
            from .openapi import catalog, compile_contract
            from .studio import MAX_UPLOAD, parse_json
            with open(args.specification, "rb") as stream:
                raw = stream.read(MAX_UPLOAD + 1)
            if len(raw) > MAX_UPLOAD:
                raise ValueError("OpenAPI document is too large")
            document = parse_json(raw)
            result = compile_contract(document, read_json(args.config), allow_mutations=args.allow_mutations) if args.config else catalog(document)
            with args.out.open("x", encoding="utf-8") as handle:
                json.dump(result, handle, indent=2, ensure_ascii=True, allow_nan=False)
                handle.write("\n")
            print(f"Created {args.out}. Import sent no network requests.")
            return 0
        if args.command == "init":
            contract = load_contract({
                "version": 1, "name": "API authorization contract", "target": args.target,
                "identities": {
                    "owner": {"headers": {"Authorization": {"env": "AUTHZ_OWNER_TOKEN"}}},
                    "other": {"headers": {"Authorization": {"env": "AUTHZ_OTHER_TOKEN"}}},
                },
                "cases": [
                    {"id": "owner-access", "identity": "owner", "method": "GET", "path": "/replace-with-owner-resource", "expect": {"status": [200]}},
                    {"id": "other-access", "identity": "other", "method": "GET", "path": "/replace-with-other-resource", "expect": {"status": [200]}},
                    {"id": "cross-user-denied", "identity": "other", "method": "GET", "path": "/replace-with-owner-resource", "requires": ["owner-access", "other-access"], "expect": {"status": [403, 404]}},
                ],
            })
            with args.out.open("x", encoding="utf-8") as handle:
                json.dump(contract, handle, indent=2, ensure_ascii=True, allow_nan=False)
                handle.write("\n")
            print(f"Created {args.out}. Replace the resource paths and add body assertions before running.")
            print("Set AUTHZ_OWNER_TOKEN and AUTHZ_OTHER_TOKEN to the complete authorization header values.")
            print("Inspect with: authzledger plan " + str(args.out))
            return 0
        if args.command in {"plan", "run"}:
            contract = load_contract(args.contract, allow_mutations=args.allow_mutations)
            if args.command == "plan":
                print(json.dumps(plan(contract), indent=2))
                return 0
            from .engine import run
            report = run(contract)
            save_report(report, args.out)
            print_summary(report)
            if report["summary"]["error"] or report["summary"]["inconclusive"]:
                return 2
            return 1 if report["summary"]["fail"] else 0
        if args.command == "verify":
            report = read_json(args.report)
            errors = verify_report(report)
            if args.anchor and not errors and report["evidence"]["root_sha256"] != args.anchor:
                errors.append("Retained anchor does not match report")
            if errors:
                print("Integrity check FAILED: " + "; ".join(errors), file=sys.stderr)
                return 2
            print("Integrity check passed" + ("; retained anchor matches" if args.anchor else "; no external anchor supplied"))
            return 0
        if args.command == "diff":
            comparison = compare_reports(read_json(args.baseline), read_json(args.current))
            args.out.mkdir(parents=True, exist_ok=True)
            write_json(args.out / "diff.json", comparison)
            (args.out / "diff.html").write_text(render_diff_html(comparison), encoding="utf-8")
            print(json.dumps({key: comparison[key] for key in ("regressions", "resolved", "unchanged", "added", "removed", "inconclusive")}, indent=2))
            if comparison["inconclusive"]:
                return 2
            return 1 if comparison["regressions"] else 0
        from .demo import run_demo
        return run_demo(args.out)
    except ContractError as exc:
        # Model errors contain fixed field labels, never supplied values.
        print(f"Contract error: {exc}", file=sys.stderr)
        return 2
    except (ValueError, OSError) as exc:
        # Do not include contract data, network exceptions or filesystem contents.
        print(f"AuthzLedger could not complete: {type(exc).__name__}. Check input, credentials and output permissions.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted; no complete report was produced.", file=sys.stderr)
        return 130
