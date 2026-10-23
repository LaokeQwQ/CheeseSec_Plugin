#!/usr/bin/env python3
"""Publish planned (descriptor-only) extension metadata to the store index.

This is intentionally separate from signed CRP release publication: these
records are `status=planned`, `installable=false`, and point at an immutable
descriptor JSON. They never create a download or an installable catalog entry.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schema/store-v1/catalog.schema.json").read_text(encoding="utf-8"))
CATALOG = json.loads((ROOT / "schema/store-v1/catalog.schema.json").read_text(encoding="utf-8"))
EXTENSION_SCHEMA = {"$ref": "#/$defs/extension", "$defs": CATALOG.get("$defs", {})}
_RELEASE = json.loads((ROOT / "schema/store-v1/release.schema.json").read_text(encoding="utf-8"))
_REGISTRY = Registry().with_resource(_RELEASE["$id"], Resource.from_contents(_RELEASE))

# Stable public names for the three planned notifier provider packs. The
# provider_id in the pack is the signed descriptor identity; the catalog
# plugin_id is the shorter storefront identity.
PACKS = {
    "dingtalk.json": ("notifier-dingtalk", "DingTalk notifications", "DingTalk custom robot provider pack. Core-owned delivery; no plugin egress."),
    "feishu.json": ("notifier-feishu", "Feishu notifications", "Feishu custom bot provider pack. Core-owned delivery; no plugin egress."),
    "email.json": ("notifier-email", "Email notifications", "SMTP email provider pack. Core-owned delivery; no plugin egress."),
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def validate(value: object, label: str) -> None:
    errors = sorted(Draft202012Validator(SCHEMA, registry=_REGISTRY).iter_errors(value), key=lambda e: list(e.path))
    if errors:
        path = ".".join(str(p) for p in errors[0].path)
        raise ValueError(f"{label}: {path}: {errors[0].message}")


def extension_records(directory: Path) -> tuple[list[dict], list[tuple[str, bytes]]]:
    records = []
    objects = []
    for filename, (plugin_id, title, summary) in PACKS.items():
        path = directory / filename
        data = path.read_bytes()
        sha = digest(data)
        descriptor_name = f"{plugin_id}-1.0.0.json"
        record = {
            "extension_id": f"official-{plugin_id}-1.0.0",
            "plugin_id": plugin_id,
            "namespace": f"official/{plugin_id}",
            "type": "notifier-provider",
            "version": "1.0.0",
            "status": "planned",
            "installable": False,
            "title": title,
            "summary": summary,
            "descriptor_sha256": sha,
            "descriptor_url": f"https://res.cheesesec.com/sha256/{sha}/{descriptor_name}",
        }
        Draft202012Validator(EXTENSION_SCHEMA).validate(record)
        records.append(record)
        objects.append((f"resources/sha256/{sha}/{descriptor_name}", data))
    return records, objects


def wrangler(args: list[str]) -> None:
    subprocess.run(args, check=True)


def put(bucket: str, key: str, data: bytes, content_type: str, cache: str, wrangler_bin: str) -> None:
    with tempfile.NamedTemporaryFile(prefix="cheesesec-extension-", delete=False) as handle:
        handle.write(data)
        name = handle.name
    try:
        wrangler([
            wrangler_bin, "r2", "object", "put", f"{bucket}/{key}", "--remote",
            "--file", name, "--content-type", content_type, "--cache-control", cache,
        ])
    finally:
        Path(name).unlink(missing_ok=True)


def get(bucket: str, key: str, wrangler_bin: str) -> bytes:
    with tempfile.NamedTemporaryFile(prefix="cheesesec-extension-read-", delete=False) as handle:
        name = handle.name
    try:
        wrangler([wrangler_bin, "r2", "object", "get", f"{bucket}/{key}", "--remote", "--file", name])
        return Path(name).read_bytes()
    finally:
        Path(name).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", required=True, help="current live catalog snapshot")
    parser.add_argument("--extension-dir", default=str(ROOT / "examples/extensions/notifier-providers"))
    parser.add_argument("--index-bucket", default="cheesesec-publication-index-prod")
    parser.add_argument("--resources-bucket", default="cheesesec-public-resources-prod")
    parser.add_argument("--wrangler", default=str(ROOT / "edge/node_modules/.bin/wrangler"))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    previous = json.loads(Path(args.catalog).read_text(encoding="utf-8"))
    validate(previous, "previous catalog")
    records, descriptors = extension_records(Path(args.extension_dir))
    catalog = {**previous, "catalog_sequence": previous["catalog_sequence"] + 1,
               "extensions": records}
    validate(catalog, "new catalog")
    catalog_bytes = canonical(catalog)
    history_key = f"indexes/catalog/seq-{catalog['catalog_sequence']:020d}.json"
    pointer = {"sequence": catalog["catalog_sequence"], "key": history_key, "sha256": digest(catalog_bytes)}
    plan = {
        "catalog_sequence": catalog["catalog_sequence"],
        "extensions": [record["extension_id"] for record in records],
        "descriptors": [{"key": key, "sha256": digest(data)} for key, data in descriptors],
        "history_key": history_key,
        "catalog_sha256": digest(catalog_bytes),
    }
    print(json.dumps(plan, indent=2))
    if not args.apply:
        return 0
    if not Path(args.wrangler).exists():
        raise SystemExit(f"wrangler not found: {args.wrangler}")
    for key, data in descriptors:
        sha = digest(data)
        put(args.resources_bucket, key, data, "application/json; charset=utf-8",
            "public, max-age=31536000, immutable", args.wrangler)
        if digest(get(args.resources_bucket, key, args.wrangler)) != sha:
            raise SystemExit(f"descriptor read-back mismatch: {key}")
    index_cache = "public, max-age=60, s-maxage=60, must-revalidate"
    put(args.index_bucket, history_key, catalog_bytes, "application/json; charset=utf-8", index_cache, args.wrangler)
    put(args.index_bucket, "catalog/index.json", catalog_bytes, "application/json; charset=utf-8", index_cache, args.wrangler)
    put(args.index_bucket, "pointers/catalog.json", canonical(pointer), "application/json; charset=utf-8", index_cache, args.wrangler)
    if digest(get(args.index_bucket, "catalog/index.json", args.wrangler)) != digest(catalog_bytes):
        raise SystemExit("catalog read-back mismatch")
    print("planned extension publication complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
