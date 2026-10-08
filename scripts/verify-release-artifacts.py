#!/usr/bin/env python3
"""Verify the minimum layout of release archives before checksums/attestation.

Usage: verify-release-artifacts.py DIST_DIR

This is deliberately format-level validation. It does not replace platform execution tests, which
run in the producing jobs before artifacts are uploaded.
"""
from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path


def archive_names(path: Path) -> set[str]:
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            return {member.name for member in archive.getmembers()}
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            return set(archive.namelist())
    raise ValueError(f"unsupported archive: {path.name}")


def has_suffix(names: set[str], suffix: str) -> bool:
    return any(name == suffix or name.endswith("/" + suffix) for name in names)


def verify(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        names = archive_names(path)
    except (OSError, tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
        return [f"{path.name}: cannot read archive: {exc}"]
    if not names:
        return [f"{path.name}: archive is empty"]

    if path.name.startswith("vpqc-") and "static" not in path.name:
        if not has_suffix(names, "README.md"):
            errors.append("missing README.md")
        if not has_suffix(names, "LICENSE"):
            errors.append("missing LICENSE")

    if "static" in path.name:
        if not has_suffix(names, "vpqc"):
            errors.append("missing static vpqc CLI")
    elif "linux" in path.name or "macos" in path.name or "windows" in path.name:
        if not (has_suffix(names, "vpqc") or has_suffix(names, "vpqc.exe")):
            errors.append("missing vpqc CLI")
        if not has_suffix(names, "vpqc.h"):
            errors.append("missing vpqc.h")

    if errors:
        return [f"{path.name}: {error}" for error in errors]
    print(f"{path.name}: layout PASS ({len(names)} entries)")
    return []


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} DIST_DIR", file=sys.stderr)
        return 2
    directory = Path(sys.argv[1])
    archives = sorted(directory.glob("*.tar.gz")) + sorted(directory.glob("*.zip"))
    if not archives:
        print(f"no release archives found in {directory}", file=sys.stderr)
        return 1
    errors = [error for archive in archives for error in verify(archive)]
    if errors:
        print("release artifact verification failed:", file=sys.stderr)
        print("\n".join(f"- {error}" for error in errors), file=sys.stderr)
        return 1
    print(f"release artifact layout: PASS ({len(archives)} archives)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
