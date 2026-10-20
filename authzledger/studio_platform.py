"""Authenticated Studio routes for the shared persistent assessment service."""
from __future__ import annotations

import base64
import binascii
import tempfile
import zipfile
from pathlib import Path

from .model import ContractError


def platform_route(handler, body):
    route = handler.path.removeprefix("/api/platform/")
    fields = {
        "create": {"title", "scope", "engagement"}, "get": {"assessment_id"},
        "update": {"assessment_id", "title", "scope", "engagement", "expected_revision"},
        "import": {"assessment_id", "profile", "text", "request_base64", "response_base64", "source_origin", "expected_revision"},
        "discover-plan": {"assessment_id", "seeds"},
        "check-plan": {"assessment_id", "spec"},
        "retest-plan": {"assessment_id", "execution_id", "selection"},
        "playbook-plan": {"assessment_id", "steps"},
        "run": {"review", "approve", "authorized"},
        "freeze": {"assessment_id"}, "export": {"snapshot_id", "format"}, "proof": {"snapshot_id"},
        "schedule": {"assessment_id", "plan_id", "approve", "authorized", "interval_seconds", "iterations", "request_budget"},
        "run-due": {"assessment_id", "authorized"},
        "delta": {"assessment_id", "baseline_catalog_id", "current_catalog_id", "checks"},
        "knowledge": {"assessment_id", "observations", "pack"},
        "recover": {"assessment_id"},
        "annotate": {"assessment_id", "annotations", "expected_revision"},
    }
    if route not in fields or set(body) - fields[route]:
        raise ContractError("Unsupported platform operation or fields.")
    service = handler.server.workbench
    identifier = body.get("assessment_id")
    if route == "create":
        result = {"assessment": service.create(body.get("title"), body.get("scope"), body.get("engagement"))}
    elif route == "get":
        result = service.get(identifier)
    elif route == "update":
        if handler.server.active:
            raise ContractError("Wait for active execution to finish before changing its scope.")
        patch = {"title": body.get("title"), "scope": body.get("scope")}
        if "engagement" in body:
            patch["engagement"] = body["engagement"]
        result = {"assessment": service.store.update(identifier, patch, body.get("expected_revision"))}
    elif route == "import":
        from .imports import DEFAULT_LIMITS
        maximum = DEFAULT_LIMITS["max_file_bytes"]
        profile = body.get("profile")
        response = None
        if profile == "burp-http-pair-v1":
            if "text" in body:
                raise ContractError("Raw messages require binary file transport.")

            def decode(field):
                value = body.get(field)
                if not isinstance(value, str) or len(value) > 4 * ((maximum + 2) // 3):
                    raise ContractError("Choose a bounded raw HTTP file.")
                try:
                    raw = base64.b64decode(value, validate=True)
                except (ValueError, binascii.Error):
                    raise ContractError("Invalid raw HTTP file encoding.") from None
                return raw

            raw = decode("request_base64")
            response = decode("response_base64") if "response_base64" in body else None
        else:
            if {"request_base64", "response_base64", "source_origin"} & set(body):
                raise ContractError("Raw-message fields require the raw-pair profile.")
            text = body.get("text")
            if not isinstance(text, str):
                raise ContractError("Choose a supported request export.")
            raw = text.encode("utf-8")
        if len(raw) + len(response or b"") > maximum:
            raise ContractError("The imported messages exceed the supported limit.")
        artifact = service.import_source(identifier, raw, profile, source_origin=body.get("source_origin"),
            response_bytes=response, expected_revision=body.get("expected_revision"))
        result = {"artifact": artifact}
    elif route in {"discover-plan", "check-plan", "retest-plan", "playbook-plan"}:
        if route == "discover-plan":
            artifact = service.discover_plan(identifier, body.get("seeds"))
            operation = "discovery"
        elif route == "check-plan":
            artifact = service.check_plan(identifier, body.get("spec"))
            operation = "check"
        elif route == "playbook-plan":
            artifact = service.playbook_plan(identifier, body.get("steps"))
            operation = "playbook"
        else:
            artifact = service.retest_plan(identifier, body.get("execution_id"), body.get("selection"))
            operation = "retest"
        result = {"artifact": artifact, "review": handler.server.platform_review(identifier, artifact, operation),
                  "operation": operation}
    elif route == "run":
        if body.get("authorized") is not True or not isinstance(body.get("review"), str):
            raise ContractError("Confirm authorization for this exact reviewed plan.")
        result = handler.server.start_platform_job(body["review"], body.get("approve"))
    elif route == "schedule":
        if body.get("authorized") is not True:
            raise ContractError("Explicit authorization is required for finite scheduled execution.")
        result = {"schedule": service.schedule(identifier, body.get("plan_id"), body.get("approve"),
            body.get("interval_seconds"), body.get("iterations"), body.get("request_budget"))}
    elif route == "run-due":
        if body.get("authorized") is not True:
            raise ContractError("Confirm execution of currently due approved schedules.")
        result = handler.server.start_platform_due_job(identifier)
    elif route == "delta":
        result = service.delta(identifier, body.get("baseline_catalog_id"),
            body.get("current_catalog_id"), body.get("checks"))
    elif route == "knowledge":
        result = {"artifact": service.knowledge(identifier, body.get("observations"), body.get("pack"))}
    elif route == "recover":
        result = {"recovery": service.recover_interrupted(identifier)}
    elif route == "annotate":
        result = {"assessment": service.annotate(identifier, body.get("annotations"), body.get("expected_revision"))}
    elif route == "freeze":
        snapshot = service.report(identifier)
        snapshot_id = handler.server.retain_assessment(handler.server.platform_snapshots, snapshot)
        result = {"snapshot": snapshot, "snapshot_id": snapshot_id}
    else:
        snapshot = handler.server.platform_snapshots.get(body.get("snapshot_id"))
        if snapshot is None:
            raise ContractError("Freeze a retained assessment snapshot before exporting.")
        from .platform_reports import export_platform, create_platform_bundle
        with tempfile.TemporaryDirectory(prefix="authzledger-platform-export-") as directory:
            folder = Path(directory)
            if route == "export":
                format_name = body.get("format")
                mime = {"json": "application/json", "html": "text/html; charset=utf-8", "pdf": "application/pdf"}
                if format_name not in mime:
                    raise ContractError("Choose JSON, HTML or PDF.")
                export_platform(snapshot, folder / "reports", formats=(format_name,))
                files = list((folder / "reports").glob("*." + format_name))
                if len(files) != 1:
                    raise ContractError("The report renderer did not produce one complete report.")
                handler.respond(200, files[0].read_bytes(), mime[format_name], "authzledger-assessment." + format_name)
            else:
                if not handler.server.signing_key or not handler.server.public_key:
                    raise ContractError("Create a session signing key or configure signing keys before exporting proof.")
                from .signing import verify_bundle
                bundle = folder / "proof"
                create_platform_bundle(snapshot, bundle, handler.server.signing_key)
                if verify_bundle(bundle, handler.server.public_key):
                    raise ContractError("Independent proof verification failed; no package exported.")
                archive = folder / "authzledger-assessment-proof.zip"
                with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
                    for file in sorted(bundle.rglob("*")):
                        if file.is_file():
                            zipped.write(file, str(file.relative_to(bundle)))
                handler.respond(200, archive.read_bytes(), "application/zip", archive.name)
        return
    handler.respond(200, result)
