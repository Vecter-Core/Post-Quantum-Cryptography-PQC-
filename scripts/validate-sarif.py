#!/usr/bin/env python3
"""Validate a SARIF report against the official SARIF 2.1.0 JSON schema.

Usage: validate-sarif.py REPORT.sarif SCHEMA.json
SCHEMA.json is sarif-schema-2.1.0.json from
https://github.com/oasis-tcs/sarif-spec/tree/main/sarif-2.1/schema
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft7Validator

report, schema = (json.loads(Path(p).read_text()) for p in sys.argv[1:3])
errors = sorted(Draft7Validator(schema).iter_errors(report), key=lambda e: list(e.path))
for e in errors[:20]:
    print(f"INVALID at /{'/'.join(map(str, e.path))}: {e.message[:200]}")
runs = report.get("runs", [])
# GitHub code scanning also needs unique rule ids and results that point at a known rule.
rules = {r["id"] for run in runs for r in run["tool"]["driver"].get("rules", [])}
dangling = [r["ruleId"] for run in runs for r in run["results"] if r["ruleId"] not in rules]
if dangling:
    errors.append(f"results without a rule: {sorted(set(dangling))}")
    print(errors[-1])
print("valid SARIF 2.1.0" if not errors else f"{len(errors)} problems")
sys.exit(1 if errors else 0)
