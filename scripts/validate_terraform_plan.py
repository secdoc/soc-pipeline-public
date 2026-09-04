#!/usr/bin/env python3
"""Reject destructive or create actions in an import-first Terraform plan."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

FORBIDDEN_ACTIONS = {"create", "delete"}


def forbidden_changes(plan: dict) -> list[dict[str, object]]:
    findings = []
    for resource in plan.get("resource_changes") or []:
        actions = list((resource.get("change") or {}).get("actions") or [])
        if FORBIDDEN_ACTIONS.intersection(actions):
            findings.append({"address": resource.get("address"), "actions": actions})
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("plan_json", type=Path)
    args = parser.parse_args()
    plan = json.loads(args.plan_json.read_text(encoding="utf-8"))
    findings = forbidden_changes(plan)
    print(json.dumps({"accepted": not findings, "forbidden_changes": findings}, sort_keys=True))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
