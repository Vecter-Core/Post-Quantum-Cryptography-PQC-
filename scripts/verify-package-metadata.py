#!/usr/bin/env python3
"""Verify version metadata in packed Python, npm and NuGet artifacts.

Usage: verify-package-metadata.py DIST_DIR
"""
from __future__ import annotations

import json
import re
import sys
import zipfile
from pathlib import Path
from tarfile import TarFile


def workspace_version() -> str:
    text = (Path(__file__).resolve().parents[1] / "Cargo.toml").read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not match:
        raise ValueError("workspace version not found")
    return match.group(1)


def verify_wheel(path: Path, expected: str) -> list[str]:
    errors: list[str] = []
    with zipfile.ZipFile(path) as archive:
        metadata = [n for n in archive.namelist() if n.endswith("/METADATA")]
        if len(metadata) != 1:
            return [f"{path.name}: expected one wheel METADATA file"]
        content = archive.read(metadata[0]).decode()
    match = re.search(r"^Version:\s*(\S+)$", content, re.M)
    if not match or match.group(1) != expected:
        errors.append(f"{path.name}: wheel version is {match.group(1) if match else '<missing>'!r}, expected {expected!r}")
    return errors


def verify_npm(path: Path, expected: str) -> list[str]:
    with TarFile.open(path, "r:gz") as archive:
        members = [m for m in archive.getmembers() if m.name.endswith("/package/package.json") or m.name == "package/package.json"]
        if len(members) != 1:
            return [f"{path.name}: expected one package/package.json"]
        package = json.loads(archive.extractfile(members[0]).read())
    actual = package.get("version")
    return [] if actual == expected else [f"{path.name}: npm version is {actual!r}, expected {expected!r}"]


def verify_nuget(path: Path, expected: str) -> list[str]:
    with zipfile.ZipFile(path) as archive:
        nuspecs = [n for n in archive.namelist() if n.endswith(".nuspec")]
        if len(nuspecs) != 1:
            return [f"{path.name}: expected one .nuspec file"]
        content = archive.read(nuspecs[0]).decode()
    match = re.search(r"<version>([^<]+)</version>", content, re.I)
    actual = match.group(1).strip() if match else None
    return [] if actual == expected else [f"{path.name}: NuGet version is {actual!r}, expected {expected!r}"]


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} DIST_DIR", file=sys.stderr)
        return 2
    expected = workspace_version()
    directory = Path(sys.argv[1])
    artifacts = sorted(directory.glob("*.whl")) + sorted(directory.glob("*.tgz")) + sorted(directory.glob("*.nupkg"))
    if not artifacts:
        print(f"no Python/npm/NuGet packages found in {directory}", file=sys.stderr)
        return 1
    errors: list[str] = []
    for artifact in artifacts:
        try:
            if artifact.suffix == ".whl":
                found = verify_wheel(artifact, expected)
            elif artifact.suffix == ".tgz":
                found = verify_npm(artifact, expected)
            else:
                found = verify_nuget(artifact, expected)
        except (OSError, ValueError, json.JSONDecodeError, UnicodeDecodeError, zipfile.BadZipFile):
            found = [f"{artifact.name}: unreadable or malformed package"]
        if found:
            errors.extend(found)
        else:
            print(f"{artifact.name}: metadata PASS ({expected})")
    if errors:
        print("package metadata verification failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print(f"package metadata: PASS ({len(artifacts)} packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
