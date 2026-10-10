"""CLI entry points for the same bounded assessment services used by Studio."""
from __future__ import annotations

import hmac
import json
from pathlib import Path


def add_commands(commands):
    parser = commands.add_parser("assessment", help="Import, prove, reduce, retest and hand over an explicit assessment")
    actions = parser.add_subparsers(dest="assessment_action", required=True)
    command = actions.add_parser("demo", help="Reproduce three bounded proofs against synthetic loopback fixtures")
    command.add_argument("--out", type=Path, required=True)
    command = actions.add_parser("import", help="Parse a bounded offline Burp, ZAP or HAR export")
    command.add_argument("source", type=Path)
    command.add_argument("--format", required=True, choices=("burp-xml", "zap-json-plus", "har-1.2"))
    command.add_argument("--out", type=Path, required=True)
    for name in ("plan", "workflow-plan", "assurance-plan"):
        command = actions.add_parser(name, help="Compile and inspect a deterministic plan without target traffic")
        command.add_argument("specification", type=Path)
        command.add_argument("--out", type=Path, required=True)
    command = actions.add_parser("mapped-plan", help="Compile one imported request using explicit identity, object and control bindings")
    command.add_argument("source", type=Path)
    command.add_argument("bindings", type=Path)
    command.add_argument("--entry", required=True)
    command.add_argument("--mapping", type=Path, help="Explicit public literal/omit mapping for redacted import fields")
    command.add_argument("--out", type=Path, required=True)
    command = actions.add_parser("impact-plan", help="Explain change-based retest selection; unknown dependencies require full scope")
    command.add_argument("contract", type=Path)
    command.add_argument("changes", type=Path)
    command.add_argument("--impact-map", type=Path)
    command.add_argument("--out", type=Path, required=True)
    for name in ("run", "workflow-run", "minimize", "assurance-run"):
        command = actions.add_parser(name, help="Execute only an explicitly approved exact plan")
        command.add_argument("plan", type=Path)
        command.add_argument("--approve", required=True, help="Exact plan_digest from the reviewed plan")
        command.add_argument("--out", type=Path, required=True)
        if name == "assurance-run":
            command.add_argument("--history", type=Path, required=True, help="Durable local workflow history; existing history is verified before traffic")
    command = actions.add_parser("reduction-plan", help="Plan an explicitly selected, budgeted reproducer reduction")
    command.add_argument("execution", type=Path)
    command.add_argument("units", type=Path)
    command.add_argument("--max-requests", type=int, default=40)
    command.add_argument("--out", type=Path, required=True)
    command = actions.add_parser("retest-plan", help="Select variants and their complete source-bound control closure")
    command.add_argument("baseline", type=Path)
    command.add_argument("--variant", action="append", required=True, dest="variants")
    command.add_argument("--out", type=Path, required=True)
    command = actions.add_parser("compare", help="Compare retained assessment executions offline")
    command.add_argument("baseline", type=Path)
    command.add_argument("current", type=Path)
    command.add_argument("--out", type=Path, required=True)
    command = actions.add_parser("snapshot", help="Freeze verified execution evidence for consistent reporting")
    command.add_argument("executions", type=Path, nargs="*")
    command.add_argument("--id", default="assessment")
    command.add_argument("--title", default="Security assessment")
    command.add_argument("--metadata", type=Path, help="Reviewed impact, standards mappings and CVSS vectors")
    command.add_argument("--workflow", type=Path, action="append", default=[])
    command.add_argument("--assurance", type=Path, action="append", default=[])
    command.add_argument("--reduction", type=Path, action="append", default=[])
    command.add_argument("--comparison", type=Path, action="append", default=[])
    command.add_argument("--out", type=Path, required=True)
    command = actions.add_parser("report", help="Render HTML, PDF and JSON from the same verified snapshot")
    command.add_argument("snapshot", type=Path)
    command.add_argument("--formats", nargs="+", choices=("html", "pdf", "json"), default=["html", "pdf", "json"])
    command.add_argument("--out", type=Path, required=True)
    command = actions.add_parser("bundle", help="Bind the snapshot and exported reports into an Ed25519 evidence package")
    command.add_argument("snapshot", type=Path)
    command.add_argument("--key", type=Path, required=True)
    command.add_argument("--out", type=Path, required=True)
    for name in ("verify", "inspect"):
        command = actions.add_parser(name, help="Verify retained assessment semantics offline")
        command.add_argument("document", type=Path)
        if name == "inspect":
            command.add_argument("--finding", help="Inspect one finding through the shared evidence service")


def _read(path, *, object_only=True):
    from .studio import parse_json
    with Path(path).open("rb") as source:
        raw = source.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024:
        raise ValueError("Assessment input exceeds the supported size limit")
    document = parse_json(raw, object_only=object_only)
    try:
        json.dumps(document, allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("Expected bounded finite JSON") from exc
    return document


def _write(path, document):
    raw = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n"
    with Path(path).open("x", encoding="utf-8") as output:
        output.write(raw)


def _approved(plan, approval):
    expected = plan.get("plan_digest")
    if not isinstance(expected, str) or not isinstance(approval, str) or not hmac.compare_digest(expected, approval):
        raise ValueError("Review and approve the exact plan digest before execution")


def _verifier(document):
    kind = document.get("kind")
    if kind == "assessment-snapshot":
        from .assessment_reports import verify_assessment
        return verify_assessment(document)
    if kind == "experiment-execution":
        from .experiments import verify_execution
        return verify_execution(document)
    if kind == "workflow-trace":
        from .workflows import verify_workflow
        return verify_workflow(document)
    if kind == "reduction-trace":
        from .minimize import verify_reduction
        return verify_reduction(document)
    if kind == "workflow-assurance-result":
        from .workflow_assurance import verify_workflow_assurance
        return verify_workflow_assurance(document)
    raise ValueError("Unsupported assessment document kind")


def execute_command(args):
    if args.command != "assessment":
        return None
    action = args.assessment_action
    if action == "demo":
        from .assessment_demo import run_demos
        result = run_demos(args.out)
        print("Three synthetic loopback demonstrations verified; requests: " + str(result["network_requests"]))
        print("Retained reports and proof: " + str(args.out))
        return 0
    if action == "import":
        from .imports import parse_import
        if args.out.exists():
            raise ValueError("Output already exists")
        with args.source.open("rb") as source:
            raw = source.read(10 * 1024 * 1024 + 1)
        result = parse_import(raw, args.format)
        _write(args.out, result)
        print(f"Imported {len(result['entries'])} source entries offline; explicit mapping and controls are required.")
        return 0
    if action in {"plan", "workflow-plan", "assurance-plan", "mapped-plan", "reduction-plan", "retest-plan", "compare", "impact-plan"}:
        if args.out.exists():
            raise ValueError("Output already exists")
        if action == "plan":
            from .experiments import compile_experiment
            result = compile_experiment(_read(args.specification))
        elif action == "workflow-plan":
            from .workflows import compile_workflow
            result = compile_workflow(_read(args.specification))
        elif action == "assurance-plan":
            from .workflow_assurance import compile_workflow_assurance
            result = compile_workflow_assurance(_read(args.specification))
        elif action == "mapped-plan":
            from .experiments import compile_imported_experiment
            source = _read(args.source)
            entries = [entry for entry in source.get("entries", []) if entry.get("id") == args.entry]
            if len(entries) != 1:
                raise ValueError("Select exactly one retained imported entry")
            entry = entries[0]
            if args.mapping:
                from .imports import resolve_imported_entry
                entry = resolve_imported_entry(entry, _read(args.mapping))
            result = compile_imported_experiment(entry, _read(args.bindings))
        elif action == "impact-plan":
            from .assessments import plan_impacted_retest
            result = plan_impacted_retest(_read(args.contract), _read(args.changes, object_only=False),
                                         _read(args.impact_map) if args.impact_map else None)
        elif action == "reduction-plan":
            from .minimize import plan_reduction
            result = plan_reduction(_read(args.execution), _read(args.units, object_only=False), max_requests=args.max_requests)
        elif action == "retest-plan":
            from .experiments import plan_experiment_retest
            result = plan_experiment_retest(_read(args.baseline), args.variants)
        else:
            from .experiments import compare_executions
            result = compare_executions(_read(args.baseline), _read(args.current))
        _write(args.out, result)
        print("Offline result written: " + str(args.out))
        if result.get("plan_digest"):
            print("Plan SHA-256: " + result["plan_digest"])
        return 0
    if action in {"run", "workflow-run", "minimize", "assurance-run"}:
        document = _read(args.plan)
        _approved(document, args.approve)
        # Reserve the output destination before any target traffic.
        args.out.mkdir(parents=True, exist_ok=False)
        if action == "run":
            from .experiments import execute_experiment
            result = execute_experiment(document)
        elif action == "workflow-run":
            from .workflows import execute_workflow
            result = execute_workflow(document)
        elif action == "assurance-run":
            from .workflow_assurance import run_workflow_assurance
            from .history import HistoryStore
            with HistoryStore(args.history) as history:
                result = run_workflow_assurance(document, history=history)
        else:
            from .minimize import execute_reduction
            result = execute_reduction(document)
        errors = _verifier(result)
        if errors:
            raise ValueError("Execution result failed semantic verification")
        _write(args.out / "execution.json", result)
        if isinstance(result.get("report"), dict):
            _write(args.out / "report.json", result["report"])
        print("Execution evidence written: " + str(args.out))
        if action == "minimize":
            return 0 if result["one_minimal"] else 2
        if action == "assurance-run":
            return result["exit_code"]
        findings = result.get("findings", [])
        if (any(item.get("interpretation") == "inconclusive" for item in findings)
                or any(item.get("interpretation") == "inconclusive" for item in result.get("variants", []))):
            return 2
        return 1 if (any(item.get("status") == "confirmed" for item in findings)
                     or any(item.get("interpretation") == "violation" for item in result.get("variants", []))) else 0
    if action == "snapshot":
        from .assessment_reports import freeze_assessment
        if args.out.exists():
            raise ValueError("Output already exists")
        metadata = _read(args.metadata) if args.metadata else {}
        metadata.update(assessment_id=args.id, title=args.title)
        snapshot = freeze_assessment([_read(path) for path in args.executions], metadata,
                                     comparisons=[_read(path) for path in args.comparison],
                                     workflows=[_read(path) for path in args.workflow],
                                     assurances=[_read(path) for path in args.assurance],
                                     reductions=[_read(path) for path in args.reduction])
        _write(args.out, snapshot)
        print("Verified assessment snapshot written.")
        return 0
    if action == "report":
        from .assessment_reports import export_assessment
        export_assessment(_read(args.snapshot), args.out, formats=tuple(args.formats))
        print("Assessment reports written from one snapshot: " + str(args.out))
        return 0
    if action == "bundle":
        from .assessment_reports import create_assessment_bundle
        create_assessment_bundle(_read(args.snapshot), args.out, args.key)
        print("Signed assessment proof written: " + str(args.out))
        return 0
    document = _read(args.document)
    errors = _verifier(document)
    if errors:
        print("Assessment verification failed.")
        return 2
    if action == "inspect":
        if args.finding:
            from .assessments import inspect_finding
            document = inspect_finding(document, args.finding)
        print(json.dumps(document, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False))
    else:
        print("Assessment source bindings and derived semantics verified offline; remote execution truth is not independently attested.")
    return 0
