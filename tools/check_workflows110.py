#!/usr/bin/env python3
"""Reproduce state/replay/control/reduction acceptance on a fresh loopback lab."""
from __future__ import annotations
import argparse
import copy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from authzledger.assessment_demo import require

from authzledger.lab110 import workflow_lab, workflow_spec
from authzledger.workflows import compile_workflow, execute_workflow, verify_workflow
from authzledger.minimize import removable_units, plan_reduction, execute_reduction, verify_reduction


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True, help="New output directory")
    args = parser.parse_args(argv)
    if args.out.exists():
        parser.error("output directory must be new")
    outputs = {}
    with workflow_lab() as (origin, state):
        spec = workflow_spec(origin)
        spec["contract"]["cases"][4]["body"]["noise"] = "demonstrably unnecessary"
        plan = compile_workflow(spec)
        outputs["workflow-plan.json"] = plan
        outputs["workflow-spec.json"] = spec
        vulnerable = execute_workflow(plan)
        require(vulnerable["variants"][0]["interpretation"] == "violation", "Workflow acceptance assertion failed")
        require(not verify_workflow(vulnerable), "Workflow acceptance assertion failed")
        outputs["skip-approval-vulnerable.json"] = vulnerable
        state["vulnerable"] = False
        safe = execute_workflow(plan)
        require(safe["variants"][0]["interpretation"] == "satisfied", "Workflow acceptance assertion failed")
        require(not verify_workflow(safe), "Workflow acceptance assertion failed")
        outputs["skip-approval-safe.json"] = safe
        replay_spec = copy.deepcopy(spec)
        replay_spec["rule"] = {"id": "idempotency", "kind": "effect_increase", "pointer": "/effects", "max_delta": 1}
        replay_spec["variants"] = [{"id": "repeated-completion", "repeat": {"complete": 2}}]
        replay_plan = compile_workflow(replay_spec)
        idempotent = execute_workflow(replay_plan)
        require(idempotent["variants"][0]["interpretation"] == "satisfied", "Workflow acceptance assertion failed")
        outputs["idempotent-safe.json"] = idempotent
        state["replay"] = True
        replayed = execute_workflow(replay_plan)
        require(replayed["variants"][0]["interpretation"] == "violation", "Workflow acceptance assertion failed")
        require(not verify_workflow(replayed), "Workflow acceptance assertion failed")
        outputs["replay-vulnerable.json"] = replayed
        state["control"] = False
        requests_before = len(state["requests"])
        unconfirmed = execute_workflow(plan)
        require(unconfirmed["variants"][0]["interpretation"] == "inconclusive", "Workflow acceptance assertion failed")
        require(len(state["requests"]) == requests_before + 1, "Workflow acceptance assertion failed")
        outputs["invalid-control.json"] = unconfirmed
        state.update(control=True, vulnerable=True, replay=False)
        units = [unit for unit in removable_units(vulnerable) if unit.get("pointer") == "/noise"]
        reduction = execute_reduction(plan_reduction(vulnerable, units, max_requests=18))
        require(reduction["one_minimal"], "Workflow acceptance assertion failed")
        require(not verify_reduction(reduction), "Workflow acceptance assertion failed")
        require(not state["objects"], "Workflow acceptance assertion failed")
        outputs["minimal-reproducer.json"] = reduction
        acceptance = {"workflow_skip_approval": "violation_vs_satisfied", "replay": "independent_effect_counter",
                      "invalid_controls": "inconclusive_without_setup", "reduction": "fresh_fixture_per_attempt",
                      "reduction_requests": reduction["requests_used"], "one_minimal": reduction["one_minimal"],
                      "all_objects_cleaned": not state["objects"], "requests": len(state["requests"]),
                      "state_verification": "evaluation_attested", "network": "synthetic_loopback_only"}
    # All verifications above are repeated after the fixture server is stopped.
    for name, output in outputs.items():
        if output.get("kind") == "workflow-trace": require(not verify_workflow(output), "Offline workflow verification failed")
        if output.get("kind") == "reduction-trace": require(not verify_reduction(output), "Offline workflow verification failed")
    args.out.mkdir(parents=True)
    for name, value in dict(outputs, **{"acceptance.json": acceptance}).items():
        (args.out / name).write_text(json.dumps(value, indent=2, ensure_ascii=True, allow_nan=False) + "\n", encoding="utf-8")
    print(json.dumps(acceptance, sort_keys=True))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
