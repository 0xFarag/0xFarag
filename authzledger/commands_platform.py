"""Persistent assessment commands, sharing WorkbenchService with Studio."""
from __future__ import annotations

import json
from pathlib import Path

_ACTIONS = {"create", "list", "show", "registry", "surface-import", "discover-plan", "discover-run",
            "check-plan", "check-run", "check-retest-plan", "check-retest-run", "freeze", "schedule", "run-due", "delta", "knowledge", "playbook-plan", "playbook-run", "recover", "annotate"}


def add_commands(actions):
    index = actions.add_parser("federation-index", help="Inspect surface provenance from a frozen assessment snapshot offline")
    index.add_argument("snapshot", type=Path, help="Frozen platform snapshot JSON from assessment freeze")
    index.add_argument("--out", type=Path, help="New index JSON file; stdout when omitted")
    preview = actions.add_parser("federation-preview", help="Compare local tool exports in one offline inventory projection")
    retain = actions.add_parser("federation-retain", help="Retain a reviewed federation receipt on an existing assessment")
    for command in (preview, retain):
        command.add_argument("--scope-service", dest="allowed_services", action="append", required=True,
                             help="Exact TCP service with a literal IP and port, e.g. tcp://192.0.2.10:443 (repeatable)")
        for profile, label in (("nmap", "Nmap XML"), ("ffuf", "ffuf JSON"), ("nuclei", "Nuclei JSONL")):
            command.add_argument("--" + profile, type=Path, action="append", metavar="FILE", help=label + " export (one file)")
        command.add_argument("--out", type=Path, help="New JSON file; stdout when omitted")
    retain.add_argument("assessment_id")
    retain.add_argument("--store", required=True, type=Path, help="Existing assessment store")
    retain.add_argument("--expected-revision", required=True, type=int)
    retain.add_argument("--reviewed-projection", required=True, type=Path, help="Exact projection JSON reviewed from federation-preview")
    retain.add_argument("--release-sources", required=True, action="store_true", help="Approve retaining source digests and redacted evidence")
    for action in sorted(_ACTIONS):
        parser = actions.add_parser(action, help={
            "create": "Create a persistent assessment with explicit authorization scope",
            "list": "List retained local assessments", "show": "Inspect one assessment and its evidence offline",
            "registry": "List supported versioned checks and profiles",
            "surface-import": "Add a redacted offline source to an assessment",
            "discover-plan": "Plan bounded discovery without target traffic", "discover-run": "Execute an approved discovery plan",
            "check-plan": "Compile a control-bound check within an assessment", "check-run": "Execute one exact approved check plan",
            "check-retest-plan": "Plan a source-bound check retest", "check-retest-run": "Execute an approved check retest",
            "freeze": "Freeze persistent assessment evidence for reports and proof",
            "schedule": "Register a finite explicitly approved local schedule",
            "run-due": "Run currently due approved work; never starts a background daemon",
            "delta": "Compare two retained surface catalogs without target requests",
            "knowledge": "Bind a reviewed local knowledge pack to explicit observations offline",
            "playbook-plan": "Compose explicitly retained plans with static dependencies",
            "playbook-run": "Execute an exact approved static playbook through the shared context",
            "recover": "Reconcile interrupted local jobs without target traffic or automatic retry",
            "annotate": "Record source-bound reviewer decisions without changing computed verdicts",
        }[action])
        if action != "registry":
            parser.add_argument("--store", type=Path, required=True, help="Local SQLite history/workbench file")
        if action not in {"create", "list", "registry", "run-due"}:
            parser.add_argument("assessment_id")
        if action == "create":
            parser.add_argument("--title", required=True)
            parser.add_argument("--scope", type=Path, required=True)
            parser.add_argument("--engagement", type=Path, help="Reviewed engagement reference, RoE reference and notes")
        if action == "surface-import":
            parser.add_argument("source", type=Path)
            parser.add_argument("--format", required=True, choices=("burp-xml", "burp-http-pair-v1", "zap-json-plus", "har-1.2", "nmap-xml-v1", "nuclei-jsonl-v1"))
            parser.add_argument("--source-origin")
            parser.add_argument("--response", type=Path)
            parser.add_argument("--expected-revision", type=int)
        if action == "discover-plan":
            parser.add_argument("--seeds", type=Path, required=True)
        if action == "check-plan":
            parser.add_argument("specification", type=Path)
        if action == "playbook-plan":
            parser.add_argument("--steps", type=Path, required=True)
        if action == "check-retest-plan":
            parser.add_argument("execution_id")
            parser.add_argument("--finding", action="append", dest="selection")
        if action in {"discover-run", "check-run", "check-retest-run", "schedule", "playbook-run"}:
            parser.add_argument("plan_id")
            parser.add_argument("--approve", required=True, help="Exact plan_digest of the reviewed retained plan")
        if action == "schedule":
            parser.add_argument("--interval-seconds", type=int, required=True)
            parser.add_argument("--iterations", type=int, required=True)
            parser.add_argument("--request-budget", type=int, required=True)
        if action == "run-due":
            parser.add_argument("--assessment-id")
        if action == "delta":
            parser.add_argument("baseline_catalog_id")
            parser.add_argument("current_catalog_id")
        if action == "knowledge":
            parser.add_argument("observations", type=Path)
            parser.add_argument("--pack", type=Path)
        if action == "annotate":
            parser.add_argument("--file", type=Path, required=True, help="Full annotations mapping keyed by snapshot finding record ID")
            parser.add_argument("--expected-revision", type=int, required=True)
        parser.add_argument("--out", type=Path, help="New JSON output file; stdout when omitted")


def _federation_sources(args):
    from .federation_offline import MAX_TOTAL_BYTES
    from .model import ContractError
    sources = []
    remaining = MAX_TOTAL_BYTES
    for profile in ("nmap", "ffuf", "nuclei"):
        paths = getattr(args, profile)
        if paths is None:
            continue
        if len(paths) != 1 or not paths[0].is_file():
            raise ContractError("Choose one regular local file per source family.")
        with paths[0].open("rb") as stream:
            raw = stream.read(remaining + 1)
        remaining -= len(raw)
        if remaining < 0:
            raise ContractError("Choose files totalling at most 2 MiB.")
        sources.append((profile, raw))
    return sources


def execute_command(args):
    action = args.assessment_action
    if action not in _ACTIONS and action not in {"federation-index", "federation-preview", "federation-retain"}:
        return None
    from .commands_assessment import _read, _write
    if args.out is not None and args.out.exists():
        raise ValueError("Output already exists")
    if action == "federation-index":
        from .federation_index import build_surface_index
        result = build_surface_index(_read(args.snapshot))
    elif action == "federation-preview":
        from .federation_offline import project_federation
        result = project_federation(args.allowed_services, _federation_sources(args))
    elif action == "registry":
        from .detectors import catalog
        result = catalog()
    else:
        from .workbench import WorkbenchStore, WorkbenchService
        if action == "federation-retain" and not args.store.is_file():
            raise ValueError("Choose the existing assessment store")
        store = WorkbenchStore(args.store)
        service = WorkbenchService(store)
        try:
            if action == "federation-retain":
                from .federation_records import federation_preview_digest
                preview_digest = federation_preview_digest(_read(args.reviewed_projection))
                result = service.retain_federation(args.assessment_id, args.allowed_services, _federation_sources(args),
                                                   expected_revision=args.expected_revision, preview_digest=preview_digest)
            elif action == "create":
                result = service.create(args.title, _read(args.scope), _read(args.engagement) if args.engagement else None)
            elif action == "list":
                result = {"assessments": service.list()}
            elif action == "show":
                result = service.get(args.assessment_id)
            elif action == "surface-import":
                from .imports import DEFAULT_LIMITS
                limit = DEFAULT_LIMITS["max_file_bytes"]
                if args.format != "burp-http-pair-v1" and (args.source_origin is not None or args.response is not None):
                    raise ValueError("Raw context fields require the raw-pair profile")
                with args.source.open("rb") as source:
                    raw = source.read(limit + 1)
                response = None
                if args.response is not None:
                    with args.response.open("rb") as source:
                        response = source.read(limit + 1)
                if len(raw) + len(response or b"") > limit:
                    raise ValueError("Import exceeds the supported size limit")
                result = service.import_source(args.assessment_id, raw, args.format, source_origin=args.source_origin,
                    response_bytes=response, expected_revision=args.expected_revision)
            elif action == "discover-plan":
                result = service.discover_plan(args.assessment_id, _read(args.seeds, object_only=False))
            elif action == "check-plan":
                result = service.check_plan(args.assessment_id, _read(args.specification))
            elif action == "playbook-plan":
                result = service.playbook_plan(args.assessment_id, _read(args.steps, object_only=False))
            elif action == "check-retest-plan":
                result = service.retest_plan(args.assessment_id, args.execution_id, args.selection)
            elif action in {"discover-run", "check-run", "check-retest-run", "playbook-run"}:
                method = {"discover-run": service.discover_execute, "check-run": service.check_execute,
                          "check-retest-run": service.retest_execute, "playbook-run": service.playbook_execute}[action]
                result = method(args.assessment_id, args.plan_id, args.approve)
            elif action == "freeze":
                result = service.report(args.assessment_id)
            elif action == "schedule":
                result = service.schedule(args.assessment_id, args.plan_id, args.approve,
                    args.interval_seconds, args.iterations, args.request_budget)
            elif action == "delta":
                result = service.delta(args.assessment_id, args.baseline_catalog_id, args.current_catalog_id)
            elif action == "knowledge":
                result = service.knowledge(args.assessment_id, _read(args.observations, object_only=False),
                    _read(args.pack) if args.pack else None)
            elif action == "recover":
                result = service.recover_interrupted(args.assessment_id)
            elif action == "annotate":
                result = service.annotate(args.assessment_id, _read(args.file), args.expected_revision)
            else:
                result = {"runs": service.run_due(args.assessment_id)}
        finally:
            store.close()
    if args.out is not None:
        _write(args.out, result)
    else:
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False))
    if action not in {"check-run", "check-retest-run", "playbook-run"}:
        return 0
    value = result.get("value", result) if isinstance(result, dict) else {}
    findings = value.get("findings", [])
    if any(item.get("evidence_level") == "inconclusive" for item in findings):
        return 2
    return 1 if any(item.get("evidence_level") == "confirmed" for item in findings) else 0
