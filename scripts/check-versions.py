#!/usr/bin/env python3
"""Check that release-facing bindings use the workspace version.

This intentionally uses small, format-specific checks instead of a TOML/XML dependency so it can
run in the minimal CI and release environments. It does not inspect dependency versions.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M)
if not EXPECTED:
    print("cannot find [workspace.package] version in Cargo.toml", file=sys.stderr)
    raise SystemExit(1)
version = EXPECTED.group(1)
ref_name = __import__("os").environ.get("GITHUB_REF_NAME", "")
if ref_name.startswith("v") and ref_name[1:] != version:
    print(f"tag {ref_name!r} does not match workspace version {version!r}", file=sys.stderr)
    raise SystemExit(1)

checks = {
    "bindings/js/Cargo.toml": (r'^version\s*=\s*"([^"]+)"', version),
    "bindings/js/package.json": (r'"version"\s*:\s*"([^"]+)"', version),
    "bindings/python/Cargo.toml": (r'^version\s*=\s*"([^"]+)"', version),
    "bindings/python/pyproject.toml": (r'^version\s*=\s*"([^"]+)"', version),
    "bindings/java/pom.xml": (r'^\s*<version>([^<]+)</version>', version),
    "bindings/dart/pubspec.yaml": (r'^version:\s*([^\s#]+)', version),
    "bindings/dotnet/src/Vpqc.csproj": (r'^\s*<Version>([^<]+)</Version>', version),
    "bindings/ruby/vpqc.gemspec": (r'^\s*s\.version\s*=\s*"([^"]+)"', version),
}

errors: list[str] = []
print(f"workspace version: {version}")
for relative, (pattern, expected) in checks.items():
    path = ROOT / relative
    if not path.exists():
        errors.append(f"{relative}: file missing")
        continue
    matches = re.findall(pattern, path.read_text(), re.M)
    if not matches:
        errors.append(f"{relative}: version field not found")
    elif matches[0] != expected:
        errors.append(f"{relative}: found {matches[0]!r}, expected {expected!r}")
    else:
        print(f"{relative}: {matches[0]}")

if errors:
    print("version consistency check failed:", file=sys.stderr)
    for error in errors:
        print(f"- {error}", file=sys.stderr)
    raise SystemExit(1)
print("version consistency: PASS")
