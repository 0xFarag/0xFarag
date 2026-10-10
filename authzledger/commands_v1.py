"""Studio-equivalent authorization intelligence commands, with explicit scopes."""
from __future__ import annotations

import json
from pathlib import Path

from .model import load_contract


def add_commands(commands):
    graph = commands.add_parser("graph", help="Map intent, evaluated policy and verified observations")
    graph.add_argument("contract")
    graph.add_argument("--report")
    graph.add_argument("--policy", help="Independent local rules or explicitly scoped OPA config")
    graph.add_argument("--allow-mutations", action="store_true")
    graph.add_argument("--out", type=Path, required=True)
    explain = commands.add_parser("explain", help="Explain evidence; optional local AI is advisory only")
    explain.add_argument("graph")
    explain.add_argument("--ai-config", help="Opt in to explicitly configured local Ollama inference")
    explain.add_argument("--out", type=Path, required=True)
    differential = commands.add_parser("intelligence-diff", help="Separate policy drift from behavioral regressions")
    differential.add_argument("before")
    differential.add_argument("after")
    differential.add_argument("--out", type=Path, required=True)
    for name in ("assure", "watch"):
        command = commands.add_parser(name, help="Run controlled assurance once" if name == "assure" else "Run finite, budgeted continuous assurance")
        command.add_argument("contract")
        command.add_argument("--policy")
        command.add_argument("--history", type=Path)
        command.add_argument("--allow-mutations", action="store_true")
        command.add_argument("--out", type=Path, required=True)
        if name == "watch":
            command.add_argument("--iterations", type=int, required=True)
            command.add_argument("--interval", type=float, default=5)
            command.add_argument("--max-requests", type=int, default=1000)
            command.add_argument("--max-history-age", type=float)
    history = commands.add_parser("history", help="Inspect and verify a retained local history chain")
    history.add_argument("database", type=Path)
    history.add_argument("--run", type=int)
    history.add_argument("--limit", type=int, default=100)
    history.add_argument("--out", type=Path)
    retest = commands.add_parser("retest", help="Plan dependency-complete retest; execute only with --execute")
    retest.add_argument("contract")
    retest.add_argument("--case", action="append", dest="selected_ids")
    retest.add_argument("--execute", action="store_true")
    retest.add_argument("--policy")
    retest.add_argument("--history", type=Path)
    retest.add_argument("--allow-mutations", action="store_true")
    retest.add_argument("--out", type=Path, required=True)
    comparison = commands.add_parser("compare-retest", help="Compare a full source baseline with an exact dependency-closed retest offline")
    comparison.add_argument("source_contract")
    comparison.add_argument("baseline")
    comparison.add_argument("current")
    comparison.add_argument("--case", action="append", dest="selected_ids")
    comparison.add_argument("--out", type=Path, required=True, help="New directory for comparison.json and comparison.html")
    verify_comparison = commands.add_parser("verify-comparison", help="Recompute every comparison claim from retained original sources offline")
    verify_comparison.add_argument("comparison")
    keygen = commands.add_parser("keygen", help="Generate Ed25519 operator keys without overwriting files")
    keygen.add_argument("--private", type=Path, required=True)
    keygen.add_argument("--public", type=Path, required=True)
    bundle = commands.add_parser("bundle", help="Sign a verified report and optional graph/explanation attachments")
    bundle.add_argument("report")
    bundle.add_argument("--key", type=Path, required=True)
    bundle.add_argument("--graph")
    bundle.add_argument("--contract", help="Exact source contract; required when attaching a graph")
    bundle.add_argument("--explanation")
    bundle.add_argument("--comparison", help="Source-bound comparison whose current report exactly matches this report; also binds its HTML view")
    bundle.add_argument("--out", type=Path, required=True)
    verify = commands.add_parser("verify-bundle", help="Independently validate signatures against an externally trusted key")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("--public-key", type=Path, required=True)


def _write(path, value):
    with Path(path).open("x", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
        handle.write("\n")


def _read_bounded_json(path):
    """Read new comparison surfaces with strict JSON and existing proof limits."""
    from .signing import MAX_REPORT_BYTES
    from .studio import parse_json
    with Path(path).open("rb") as handle:
        raw = handle.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise ValueError("Comparison input exceeds the supported evidence size limit")
    return parse_json(raw)


def execute_command(args):
    from .cli import read_json, save_report
    name = args.command
    if name in {"compare-retest", "verify-comparison"}:
        from .comparison import create_comparison, verify_comparison
        from .reports import render_comparison_html
        if name == "verify-comparison":
            errors = verify_comparison(_read_bounded_json(args.comparison))
            if errors:
                print("Comparison verification FAILED: " + "; ".join(errors))
                return 2
            print("Comparison source bindings, control closure, profiles and derived claims verified offline. Execution truth and identity are not attested.")
            return 0
        if args.out.exists():
            raise ValueError("Output already exists; select a new comparison destination")
        result = create_comparison(_read_bounded_json(args.source_contract),
                                   _read_bounded_json(args.baseline), _read_bounded_json(args.current),
                                   args.selected_ids)
        rendered = render_comparison_html(result)
        # Validate size before creating a deliverable that cannot be signed/read.
        from .signing import MAX_REPORT_BYTES
        encoded = json.dumps(result, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
        if len(encoded.encode("utf-8")) > MAX_REPORT_BYTES:
            raise ValueError("Comparison output exceeds the supported evidence size limit")
        args.out.mkdir(parents=True, exist_ok=False)
        with (args.out / "comparison.json").open("x", encoding="utf-8") as handle:
            handle.write(encoded)
        with (args.out / "comparison.html").open("x", encoding="utf-8") as handle:
            handle.write(rendered)
        summary = result["summary"]
        print(f"Compared {result['coverage']['retested_cases']} cases; {summary['not_retested']} not retested. Configured check transitions only: {args.out}")
        return 2 if summary["inconclusive"] or summary["testability_lost"] else 1 if summary["regression"] else 0
    if name == "keygen":
        from .signing import generate_keypair
        generate_keypair(args.private, args.public)
        print("Created Ed25519 keypair. Retain the public key separately from evidence packages.")
        return 0
    if name == "bundle":
        from .signing import create_bundle
        from .intelligence import verify_graph
        report = read_json(args.report)
        attachments = {}
        if args.comparison:
            from .comparison import verify_comparison
            from .reports import render_comparison_html
            comparison = _read_bounded_json(args.comparison)
            errors = verify_comparison(comparison)
            if errors or comparison.get("current_report") != report:
                raise ValueError("Comparison attachment is invalid or does not match the signed report")
            attachments["comparison.json"] = json.dumps(comparison, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            attachments["comparison.html"] = render_comparison_html(comparison).encode("utf-8")
        if args.graph:
            if not args.contract:
                raise ValueError("A graph proof requires its source contract")
            contract = load_contract(args.contract, allow_mutations=True)
            graph = read_json(args.graph)
            if (verify_graph(graph, contract, report) or graph.get("evidence_report_root_sha256") != report.get("evidence", {}).get("root_sha256")
                    or graph.get("contract_sha256") != report.get("contract_sha256") or graph.get("target") != report.get("target")):
                raise ValueError("Graph attachment does not match the signed report")
            attachments["graph.json"] = json.dumps(graph, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
            attachments["contract.json"] = json.dumps(contract, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if args.explanation:
            if not args.graph:
                raise ValueError("An explanation proof requires its source graph")
            explanation = read_json(args.explanation)
            if (explanation.get("kind") != "authorization-explanation" or explanation.get("schema_version") != 1
                    or explanation.get("graph_sha256") != graph["graph_sha256"]
                    or explanation.get("contract_sha256") != graph["contract_sha256"]):
                raise ValueError("Explanation does not match the proof graph")
            attachments["explanation.json"] = json.dumps(explanation, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        create_bundle(report, args.out, args.key, attachments=attachments or None)
        print(f"Signed evidence package: {args.out}")
        return 0
    if name == "verify-bundle":
        from .signing import verify_bundle
        errors = verify_bundle(args.bundle, args.public_key)
        if errors:
            print("Evidence package verification FAILED: " + "; ".join(errors))
            return 2
        print("Signature, trusted key, manifest, file hashes and report semantics verified.")
        return 0
    if name == "graph":
        from .intelligence import build_graph
        contract = load_contract(args.contract, allow_mutations=args.allow_mutations)
        graph = build_graph(contract, read_json(args.report) if args.report else None,
                            read_json(args.policy) if args.policy else None)
        _write(args.out, graph)
        print(f"Authorization graph written: {args.out}")
        return 0
    if name == "explain":
        from .reasoning import explain_graph
        result = explain_graph(read_json(args.graph), read_json(args.ai_config) if args.ai_config else None)
        _write(args.out, result)
        print("Evidence explanation written. AI annotations do not influence authorization decisions.")
        return 0
    if name == "intelligence-diff":
        from .intelligence import differential_graphs
        result = differential_graphs(read_json(args.before), read_json(args.after))
        _write(args.out, result)
        return 2 if result["inconclusive"] else 1 if any(result.get(key) for key in
            ("regressions", "privilege_escalations", "policy_drift", "intended_drift", "context_drift", "removed")) else 0
    if name == "history":
        from .history import HistoryStore
        if not args.database.is_file():
            raise ValueError("History database does not exist")
        with HistoryStore(args.database) as store:
            errors = store.verify_chain()
            if errors:
                print("History chain verification FAILED: " + "; ".join(errors))
                return 2
            result = store.get_run(args.run) if args.run is not None else {"runs": store.list_runs(args.limit)}
            if args.out:
                _write(args.out, result)
            else:
                print(json.dumps(result, indent=2, ensure_ascii=True, allow_nan=False))
        return 0
    if name in {"assure", "watch", "retest"}:
        from .assurance import retest_plan, run_once, watch
        from .history import HistoryStore
        contract = load_contract(args.contract, allow_mutations=args.allow_mutations)
        policy = read_json(args.policy) if args.policy else None
        if name == "retest":
            result = retest_plan(contract, args.selected_ids, allow_mutations=args.allow_mutations)
            if not args.execute:
                _write(args.out, result)
                print("Retest plan written. No HTTP requests sent.")
                return 0
            contract = result["contract"]
        if args.out.exists():
            raise ValueError("Output already exists; select a new evidence destination")
        store = HistoryStore(args.history) if args.history else None
        try:
            if name == "watch":
                result = watch(contract, policy, store, max_iterations=args.iterations,
                               interval_seconds=args.interval, max_requests_total=args.max_requests,
                               max_history_age_seconds=args.max_history_age,
                               allow_mutations=args.allow_mutations)
                args.out.mkdir(parents=True, exist_ok=False)
                _write(args.out / "assurance.json", result)
            else:
                result = run_once(contract, policy, store, allow_mutations=args.allow_mutations)
                save_report(result["report"], args.out)
                _write(args.out / "graph.json", result["graph"])
                _write(args.out / "assurance.json", result)
            print(f"Authorization assurance: {result['status']}. Evidence: {args.out}")
            return result["exit_code"]
        finally:
            if store:
                store.close()
    return None
