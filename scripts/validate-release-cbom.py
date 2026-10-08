#!/usr/bin/env python3
"""Apply release-safety checks to a generated CBOM before publishing it.

The schema validator checks structure. This policy check prevents accidental disclosure of private
key material or machine-local absolute paths in the public CBOM artifact.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

SECRET_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN VPQC SECRET KEY-----",
)
ABSOLUTE_PATH = re.compile(r"(?:^|[\s=('\"])(?:/home/|/Users/|[A-Za-z]:[\\/]|/workspace/)")


def strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [item for child in value.values() for item in strings(child)]
    if isinstance(value, list):
        return [item for child in value for item in strings(child)]
    return []


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} CBOM.json", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read CBOM {path}: {exc}", file=sys.stderr)
        return 1

    problems: list[str] = []
    for value in strings(document):
        for marker in SECRET_MARKERS:
            if marker in value:
                problems.append(f"private-key PEM marker found: {marker}")
                break
        if ABSOLUTE_PATH.search(value):
            problems.append(f"absolute machine path found: {value[:160]}")

    if problems:
        print("release CBOM policy failed:", file=sys.stderr)
        for problem in sorted(set(problems)):
            print(f"- {problem}", file=sys.stderr)
        return 1
    print(f"release CBOM policy: PASS ({path.name})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
