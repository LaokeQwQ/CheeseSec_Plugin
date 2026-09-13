#!/usr/bin/env python3
"""Validate the plugin-store repository's JSON and CRP v1 schemas."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

try:
    from scripts.signature_verifier import verify_signature_set
except ModuleNotFoundError:  # direct script execution from the scripts directory
    from signature_verifier import verify_signature_set

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schema" / "crp-v1"


def strict_load(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


def tracked_json_files() -> list[Path]:
    output = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    paths = [ROOT / raw.decode("utf-8") for raw in output.split(b"\0") if raw]
    return [path for path in paths if path.suffix == ".json"]


def digest_bytes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def validate_example(path: Path, validator: Draft202012Validator) -> None:
    instance = strict_load(path)
    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    if errors:
        raise ValueError(f"{path}: {errors[0].message}")
    artifact = instance["artifact"]
    artifact_name = artifact.get("name")
    artifact_dir = path.parent / "artifact"
    if not artifact_dir.is_dir() or artifact_dir.is_symlink():
        raise ValueError(f"{path}: artifact directory is missing or unsafe")
    artifact_entries = list(artifact_dir.iterdir())
    candidates = [item for item in artifact_entries if item.is_file() and not item.is_symlink()]
    if len(artifact_entries) != len(candidates):
        raise ValueError(f"{path}: artifact directory contains a directory or symlink")
    if len(candidates) != 1:
        raise ValueError(f"{path}: expected exactly one regular artifact file")
    if artifact_name and candidates[0].name != artifact_name:
        raise ValueError(f"{path}: artifact.name does not match {candidates[0].name}")
    data = candidates[0].read_bytes()
    if artifact["size"] != len(data):
        raise ValueError(f"{path}: artifact.size does not match file size")
    got = digest_bytes(data)
    declared = artifact.get("digests") or instance.get("digests")
    if declared != got:
        raise ValueError(f"{path}: artifact digests do not match artifact bytes")
    if "digests" in artifact and "digests" in instance and instance["digests"] != artifact["digests"]:
        raise ValueError(f"{path}: top-level and artifact digests differ")


def validate_signature_example(path: Path, validator: Draft202012Validator) -> None:
    instance = strict_load(path)
    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.path))
    if errors:
        raise ValueError(f"{path}: {errors[0].message}")
    if not instance:
        raise ValueError(f"{path}: empty signature sets cannot be publication examples")


def validate_signature_binding(manifest_path: Path) -> None:
    policy_dir = ROOT / "policy"
    roots = strict_load(policy_dir / "trust-roots.json")
    sources = strict_load(policy_dir / "source-registry.json")
    revocations = strict_load(policy_dir / "revocations.json")
    signature_path = manifest_path.parent / "signatures" / "manifest.json"
    artifact_dir = manifest_path.parent / "artifact"
    candidates = [item for item in artifact_dir.iterdir() if item.is_file() and not item.is_symlink()]
    if len(candidates) != 1:
        raise ValueError(f"{manifest_path}: expected one artifact for signature verification")
    result = verify_signature_set(
        manifest_path.read_bytes(),
        signature_path.read_bytes(),
        roots,
        sources,
        revocations,
        now=datetime.now(timezone.utc),
    )
    if result["manifest_sha256"] != hashlib.sha256(manifest_path.read_bytes()).hexdigest():
        raise ValueError(f"{manifest_path}: signature verifier returned an inconsistent manifest digest")


def main() -> int:
    manifest_schema_path = SCHEMA_DIR / "manifest.schema.json"
    signatures_schema_path = SCHEMA_DIR / "signatures.schema.json"
    schemas = {
        manifest_schema_path: strict_load(manifest_schema_path),
        signatures_schema_path: strict_load(signatures_schema_path),
    }
    for path, schema in schemas.items():
        Draft202012Validator.check_schema(schema)
        print(f"schema ok: {path.relative_to(ROOT)}")

    # Every tracked JSON file must be valid UTF-8 JSON with no duplicate keys.
    for path in tracked_json_files():
        strict_load(path)
        print(f"json ok: {path.relative_to(ROOT)}")

    # Keep future examples honest if they are added to this publication repo.
    format_checker = FormatChecker()
    manifest_validator = Draft202012Validator(schemas[manifest_schema_path], format_checker=format_checker)
    signatures_validator = Draft202012Validator(schemas[signatures_schema_path], format_checker=format_checker)
    for path in sorted(ROOT.glob("examples/**/manifest.json")):
        if path.parent.name == "signatures":
            continue
        validate_example(path, manifest_validator)
        validate_signature_binding(path)
        print(f"manifest example ok: {path.relative_to(ROOT)}")
    for path in sorted(ROOT.glob("examples/**/signatures/manifest.json")):
        validate_signature_example(path, signatures_validator)
        print(f"signature example ok: {path.relative_to(ROOT)}")

    print("repository JSON and schema validation passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"validation failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
