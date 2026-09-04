#!/usr/bin/env python3
"""Validate a Security Visibility Portal configuration without starting a listener."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from security_portal.config import load_config
from security_portal.server import build_payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--collect", action="store_true", help="also collect configured sources")
    args = parser.parse_args()
    config = load_config(args.config)
    result = {"status": "ok", "integrations": len(config["integrations"]), "read_only": True}
    if args.collect:
        payload = build_payload(config)
        result["overview"] = payload["overview"]
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
