#!/usr/bin/env python3
"""Validate a CycloneDX document (CBOM, SBOM) against the official JSON schema.

Usage: validate-cbom.py BOM.json SCHEMA_DIR [SPEC_VERSION]
SPEC_VERSION is 1.6 (CBOM, the default) or 1.5 (the SBOM that cargo-cyclonedx writes).
SCHEMA_DIR must contain bom-<SPEC_VERSION>.schema.json, spdx.schema.json and
jsf-0.82.schema.json (from https://github.com/CycloneDX/specification/tree/master/schema).
"""
import json
import sys
from pathlib import Path

from jsonschema import Draft7Validator
from referencing import Registry, Resource

bom_path, schema_dir = sys.argv[1], Path(sys.argv[2])
spec = sys.argv[3] if len(sys.argv) > 3 else "1.6"
schema = json.loads((schema_dir / f"bom-{spec}.schema.json").read_text())
registry = Registry()
for name in ("spdx.schema.json", "jsf-0.82.schema.json"):
    res = json.loads((schema_dir / name).read_text())
    registry = registry.with_resource(name, Resource.from_contents(res))
    if "$id" in res:
        registry = registry.with_resource(res["$id"], Resource.from_contents(res))

validator = Draft7Validator(schema, registry=registry)
errors = sorted(validator.iter_errors(json.loads(Path(bom_path).read_text())), key=lambda e: list(e.path))
for e in errors[:20]:
    print(f"INVALID at /{'/'.join(map(str, e.path))}: {e.message[:200]}")
print(f"valid CycloneDX {spec}" if not errors else f"{len(errors)} schema errors")
sys.exit(1 if errors else 0)
