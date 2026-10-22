#!/usr/bin/env python3
"""Build a deterministic, append-only publication bundle for Cloudflare R2.

The output contains only validated JSON publication objects and a manifest of
their digests. It never creates CRP archives, reads signing keys, or contacts
Cloudflare.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
CHANNELS = ("stable", "canary", "dev")
POLICY_FILES = (
    "endpoints.json",
    "trust-roots.json",
    "source-registry.json",
    "revocations.json",
)


def strict_load(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{path}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def source_bytes(relative: str) -> bytes:
    path = ROOT / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"publication input is missing or unsafe: {relative}")
    return path.read_bytes()


def load_json(relative: str) -> Any:
    return strict_load(ROOT / relative)


def git_commit() -> str:
    return subprocess.check_output(["git", "rev-parse", "--verify", "HEAD"], cwd=ROOT, text=True).strip()


def sequence_json(relative: str, field: str, sequence: int, *, empty_fields: tuple[str, ...] = ()) -> bytes:
    value = load_json(relative)
    if not isinstance(value, dict):
        raise ValueError(f"{relative}: publication index must be an object")
    current = value.get(field)
    if not isinstance(current, int) or current < 0:
        raise ValueError(f"{relative}: {field} must be a non-negative integer")
    if current > sequence:
        raise ValueError(f"{relative}: existing {field} {current} is above requested sequence {sequence}")
    for empty_field in empty_fields:
        if value.get(empty_field) != []:
            raise ValueError(f"bootstrap publication requires empty {relative} {empty_field}")
    value[field] = sequence
    return canonical_json(value)


def require_empty_bootstrap_indexes() -> None:
    for relative, fields in (
        ("catalog/index.json", ("releases", "withdrawals")),
        ("ota/index.json", ("releases",)),
    ):
        value = load_json(relative)
        if not isinstance(value, dict):
            raise ValueError(f"bootstrap publication requires empty {relative} index")
        for field in fields:
            if value.get(field) != []:
                raise ValueError(f"bootstrap publication requires empty {relative} {field}")


def add_object(root: Path, objects: list[dict[str, Any]], key: str, data: bytes, cache_class: str) -> None:
    if key.startswith("/") or ".." in Path(key).parts or "//" in key or "\\" in key:
        raise ValueError(f"unsafe publication key: {key}")
    path = root / key
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    digest = hashlib.sha256(data).hexdigest()
    objects.append(
        {
            "key": key,
            "file": str(path.relative_to(root)),
            "size": len(data),
            "sha256": digest,
            "content_type": "application/json; charset=utf-8",
            "cache_class": cache_class,
        }
    )


def build(output: Path, sequence: int, channel: str, *, bootstrap_public_only: bool = False) -> dict[str, Any]:
    if channel not in (*CHANNELS, "all"):
        raise ValueError(f"channel must be one of {', '.join(CHANNELS)} or all")
    channels = CHANNELS if channel == "all" else (channel,)
    if sequence < 0 or sequence > 99999999999999999999:
        raise ValueError("sequence must fit in 20 decimal digits")
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"output directory must be empty: {output}")
    if bootstrap_public_only:
        # Refuse before dependency validation or output creation. Bootstrap is
        # only safe while source indexes contain no releases or withdrawals.
        require_empty_bootstrap_indexes()
    subprocess.check_call(
        [os.environ.get("CHEESESEC_PYTHON", sys.executable), str(ROOT / "scripts" / "validate_commercial_contracts.py")],
        cwd=ROOT,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix="cheesesec-publication-", dir=output.parent))
    try:
        objects: list[dict[str, Any]] = []
        sequence_text = f"{sequence:020d}"

        catalog = sequence_json(
            "catalog/index.json", "catalog_sequence", sequence,
            empty_fields=("releases", "withdrawals") if bootstrap_public_only else (),
        )
        catalog_key = f"indexes/catalog/seq-{sequence_text}.json"
        add_object(temporary, objects, catalog_key, catalog, "short-revalidate")
        add_object(temporary, objects, "catalog/index.json", catalog, "short-revalidate")

        ota = sequence_json(
            "ota/index.json", "index_sequence", sequence,
            empty_fields=("releases",) if bootstrap_public_only else (),
        )
        for ota_channel in channels:
            ota_key = f"indexes/ota/{ota_channel}/seq-{sequence_text}.json"
            add_object(temporary, objects, ota_key, ota, "short-revalidate")
            add_object(temporary, objects, f"ota/channels/{ota_channel}/index.json", ota, "short-revalidate")
            ota_pointer = canonical_json({"channel": ota_channel, "sequence": sequence, "key": ota_key, "sha256": hashlib.sha256(ota).hexdigest()})
            add_object(temporary, objects, f"pointers/ota/{ota_channel}.json", ota_pointer, "short-revalidate")

        # Bootstrap publishes the read surface without promoting fixture trust
        # roots or source identities into a production admission policy.
        policy_files = ("endpoints.json",) if bootstrap_public_only else POLICY_FILES
        for name in policy_files:
            data = source_bytes(f"policy/{name}")
            versioned_key = f"indexes/policy/seq-{sequence_text}/{name}"
            add_object(temporary, objects, versioned_key, data, "short-revalidate")
            add_object(temporary, objects, f"policy/{name}", data, "short-revalidate")

        for scope in ("store-v1", "crp-v1"):
            schema_dir = ROOT / "schema" / scope
            for path in sorted(schema_dir.glob("*.schema.json")):
                relative = path.relative_to(ROOT).as_posix()
                data = source_bytes(relative)
                add_object(temporary, objects, relative, data, "short-revalidate")
                add_object(temporary, objects, f"indexes/policy/seq-{sequence_text}/{scope}/{path.name}", data, "short-revalidate")

        catalog_pointer = canonical_json({"sequence": sequence, "key": catalog_key, "sha256": hashlib.sha256(catalog).hexdigest()})
        add_object(temporary, objects, "pointers/catalog.json", catalog_pointer, "short-revalidate")

        manifest = {
            "format": "cheesesec-publication-bundle-v1",
            "source_commit": git_commit(),
            "sequence": sequence,
            "channel": channel,
            "objects": sorted(objects, key=lambda item: item["key"]),
        }
        if bootstrap_public_only:
            manifest["bootstrap_public_only"] = True
        (temporary / "bundle-manifest.json").write_bytes(canonical_json(manifest))
        if output.exists():
            output.rmdir()
        os.replace(temporary, output)
        return manifest
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--sequence", required=True, type=int)
    parser.add_argument("--channel", choices=(*CHANNELS, "all"), default="stable")
    parser.add_argument(
        "--bootstrap-public-only", action="store_true",
        help="publish only empty indexes, endpoint policy and public schemas; refuse existing releases or withdrawals",
    )
    args = parser.parse_args(argv)
    try:
        manifest = build(args.output_dir, args.sequence, args.channel, bootstrap_public_only=args.bootstrap_public_only)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    print(json.dumps({"output_dir": str(args.output_dir), "objects": len(manifest["objects"]), "sequence": manifest["sequence"], "source_commit": manifest["source_commit"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
