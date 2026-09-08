#!/usr/bin/env python3
"""Fail-closed structural preflight for an offline CRP import.

The script never installs, activates, contacts a network, or changes runtime
state. CheeseWAF remains responsible for cryptographic trust and CWEDP staging.
"""
from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

EXPECTED_PREFIXES = ("manifest.json", "signatures/manifest.json")


def _regular_zip_entry(info: zipfile.ZipInfo) -> bool:
    # Reject directory entries and Unix symlinks before reading their payload.
    mode = (info.external_attr >> 16) & 0o170000
    return not info.is_dir() and mode not in (0o120000, 0o040000)


def verify_offline_package(package: Path, trust_roots: Path, sources: Path, revocations: Path) -> dict[str, object]:
    for required in (package, trust_roots, sources, revocations):
        if not required.is_file() or required.is_symlink():
            raise ValueError(f"required offline input is missing or unsafe: {required}")
    try:
        json.loads(trust_roots.read_text(encoding="utf-8"))
        json.loads(sources.read_text(encoding="utf-8"))
        json.loads(revocations.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"offline trust/source/revocation input is not valid JSON: {exc}") from exc
    with zipfile.ZipFile(package) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        if names.count("manifest.json") != 1 or names.count("signatures/manifest.json") != 1:
            raise ValueError("offline CRP must contain exactly one manifest and one signature set")
        artifact_names = [name for name in names if name.startswith("artifact/") and name.count("/") == 1]
        if len(artifact_names) != 1:
            raise ValueError("offline CRP must contain exactly one artifact/<file>")
        expected = {"manifest.json", artifact_names[0], "signatures/manifest.json"}
        if set(names) != expected or len(names) != 3:
            raise ValueError(f"offline CRP contains unsupported entries: {names!r}")
        if any(not _regular_zip_entry(info) for info in infos):
            raise ValueError("offline CRP contains a directory or symlink")
        manifest = json.loads(archive.read("manifest.json"))
        signatures = json.loads(archive.read("signatures/manifest.json"))
        if not isinstance(manifest, dict) or not isinstance(signatures, list):
            raise ValueError("manifest must be an object and signatures must be an array")
        if manifest.get("source") in {"http", "https", "online"}:
            raise ValueError("offline CRP source cannot require network access")
    return {"mode": "offline", "network_requests": 0, "package": str(package), "entries": names, "staged": False, "activation": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True, type=Path)
    parser.add_argument("--trust-roots", required=True, type=Path)
    parser.add_argument("--sources", required=True, type=Path)
    parser.add_argument("--revocations", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = verify_offline_package(args.package, args.trust_roots, args.sources, args.revocations)
    except (OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        print(f"offline import preflight failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
