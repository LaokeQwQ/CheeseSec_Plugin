#!/usr/bin/env python3
"""Build and independently verify one signed CRP release; never contact storage."""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import zipfile
import tempfile
from datetime import datetime, timezone

from signature_verifier import _go_manifest_object, _signature_signing_bytes, _strict_load_bytes, verify_signature_set
from validate_commercial_contracts import _schema_validate, validate_release_record

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 128 * 1024 * 1024


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def read_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("input must be a bounded regular file")
    return path.read_bytes()


def load(path):
    return _strict_load_bytes(read_file(path), Path(path).name)


def digests(data):
    return {name: hashlib.new(name, data).hexdigest() for name in ("md5", "sha1", "sha256")}


def runtime_manifest_identity(manifest):
    normalized = json.dumps(_go_manifest_object(manifest), ensure_ascii=False, separators=(",", ":")).encode()
    return digests(b"cheesewaf-crp-manifest-v1\n" + normalized)["sha256"]


def schema(value, scope, name):
    _schema_validate(value, load(ROOT / "schema" / scope / (name + ".schema.json")), name)


def archive(manifest, signatures, name, artifact):
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        for path, data, mode in (("manifest.json", manifest, 0o644), ("signatures/manifest.json", signatures, 0o644), ("artifact/" + name, artifact, 0o755)):
            item = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
            item.create_system = 3
            item.external_attr = (0o100000 | mode) << 16
            item.compress_type = zipfile.ZIP_DEFLATED
            package.writestr(item, data, compresslevel=9)
    return output.getvalue()


def add_object(output, objects, bucket, key, data, content_type):
    relative = bucket + "/" + key
    path = output / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    objects.append({"bucket": bucket, "key": key, "file": relative, "size": len(data), "sha256": digests(data)["sha256"], "content_type": content_type})


def build(args):
    output = Path(args.output)
    if output.exists():
        raise ValueError("output must not already exist")
    artifact = read_file(args.artifact)
    name = Path(args.artifact).name
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,254}", name):
        raise ValueError("unsafe artifact filename")
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
        raise ValueError("source commit must be a complete SHA")
    previous_bytes = read_file(args.previous_catalog)
    previous = _strict_load_bytes(previous_bytes, "previous catalog")
    schema(previous | {"releases": []}, "store-v1", "catalog")
    roots, registry, revocations = load(args.trust_roots), load(args.source_registry), load(args.revocations)
    for value, title in ((roots, "trust-roots"), (registry, "source-registry"), (revocations, "revocations")):
        schema(value, "store-v1", title)
        if "official-demo-" in json.dumps(value):
            raise ValueError("demo trust keys are not production release inputs")
    review, descriptor, provenance = load(args.review), load(args.descriptor), load(args.provenance)
    if review.get("decision") != "approved" or not review.get("reviewers") or not review.get("review_id"):
        raise ValueError("independent approved review evidence is required")
    if review.get("source_commit") != args.source_commit or review.get("artifact_sha256") != digests(artifact)["sha256"]:
        raise ValueError("review evidence must bind the source commit and artifact SHA-256")
    if provenance.get("source_commit") != args.source_commit:
        raise ValueError("provenance must bind the complete source commit")
    if not isinstance(provenance, dict) or not provenance.get("compatibility") or not provenance.get("description"):
        raise ValueError("provenance must state compatibility and real behavior")
    manifest = {"api_version": "crp.cheesewaf.io/v1", "kind": "CheeseWAFResourcePackage", "name": args.plugin_id,
                "plugin_id": args.plugin_id, "version": args.version, "namespace": args.namespace,
                "publisher": args.publisher, "source": args.source, "source_root": args.source_root,
                "release_sequence": args.sequence, "artifact": {"name": name, "size": len(artifact), "digests": digests(artifact)}}
    schema(manifest, "crp-v1", "manifest")
    signed_at = args.signed_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    signatures = []
    with tempfile.TemporaryDirectory(prefix="cheesesec-release-sign-") as raw:
        message = Path(raw) / "signing-envelope"
        signature_path = Path(raw) / "signature"
        for spec in args.key:
            key_id, separator, key_path = spec.partition("=")
            if not separator or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", key_id):
                raise ValueError("key must be KEY_ID=PEM_PATH")
            key = Path(key_path)
            if key.is_symlink() or not key.is_file() or key.stat().st_mode & 0o077 or key.resolve().is_relative_to(ROOT):
                raise ValueError("private signing keys must be mode 0600 outside repository")
            sig = {"key_id": key_id, "algorithm": "ed25519", "signed_at": signed_at}
            message.write_bytes(_signature_signing_bytes(manifest, sig))
            result = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(key), "-in", str(message), "-out", str(signature_path)], capture_output=True)
            if result.returncode:
                raise ValueError("Ed25519 signing failed")
            sig["value"] = base64.b64encode(signature_path.read_bytes()).decode()
            signatures.append(sig)
    manifest_bytes, signature_bytes = canonical(manifest), canonical(signatures)
    expected_descriptor = {"plugin_id": args.plugin_id, "version": args.version, "namespace": args.namespace, "source": args.source, "source_root": args.source_root}
    if any(descriptor.get(key) != value for key, value in expected_descriptor.items()):
        raise ValueError("descriptor identity differs from manifest")
    descriptor = {**descriptor, "manifest_identity": runtime_manifest_identity(manifest), "artifact_identity": digests(artifact)["sha256"]}
    schema(descriptor, "store-v1", "sidecar-descriptor")
    schema(signatures, "crp-v1", "signatures")
    verification = verify_signature_set(manifest_bytes, signature_bytes, roots, registry, revocations)
    level = args.namespace.split("/", 1)[0]
    source_keys = [root for root in roots["roots"] if root["source_root"] == args.source_root and root["trust_level"] == level and root["status"] == "active"]
    if len({root["public_key"] for root in source_keys}) != len(source_keys):
        raise ValueError("active signing keys must have distinct public keys")
    if level in {"official", "enterprise"} and len(source_keys) < 3:
        raise ValueError("official and enterprise release roots require at least three active keys")
    verification_bytes = canonical(verification)
    crp_bytes = archive(manifest_bytes, signature_bytes, name, artifact)
    crp_digest = digests(crp_bytes)
    evidence = canonical(review)
    record = {"api_version": "store.cheesesec.com/v1", "record_type": "publication", "release_id": verification["release_id"],
              "plugin_id": args.plugin_id, "namespace": args.namespace, "trust_level": level, "version": args.version,
              "source": args.source, "source_root": args.source_root, "release_sequence": args.sequence, "immutable": True, "high_risk": False,
              "crp": {"size": len(crp_bytes), "digests": crp_digest, "resource_url": f"https://res.cheesesec.com/sha256/{crp_digest['sha256']}/{args.plugin_id}-{args.version}.crp"},
              "artifact": manifest["artifact"], "manifest_sha256": digests(manifest_bytes)["sha256"], "signature_set_sha256": digests(signature_bytes)["sha256"],
              "descriptor_sha256": digests(canonical(descriptor))["sha256"], "provenance_sha256": digests(canonical(provenance))["sha256"],
              "review": {"review_id": review["review_id"], "decision": "approved", "reviewers": review["reviewers"], "evidence_sha256": digests(evidence)["sha256"]},
              "signature_evidence": {"status": "verified", **{key: verification[key] for key in ("required_signatures", "valid_key_ids", "manifest_sha256", "source_root", "trust_level", "release_sequence")},
                  "verification_report_sha256": digests(verification_bytes)["sha256"], "signature_set_sha256": digests(signature_bytes)["sha256"],
                  "valid_until": min(root["valid_until"] for root in source_keys if root["key_id"] in verification["valid_key_ids"])}}
    contracts = {"release_schema": load(ROOT / "schema/store-v1/release.schema.json"), "trust_roots": roots}
    validate_release_record(record, contracts, published=True)
    if any(item.get("release_id") == record["release_id"] for item in previous["releases"]):
        raise ValueError("release identity already exists")
    if any(item.get("namespace") == args.namespace and item.get("release_sequence", -1) >= args.sequence for item in previous["releases"]):
        raise ValueError("release sequence is not monotonic within namespace")
    catalog = {**previous, "catalog_sequence": previous["catalog_sequence"] + 1, "releases": previous["releases"] + [record]}
    catalog_schema = load(ROOT / "schema/store-v1/catalog.schema.json")
    catalog_schema["properties"]["releases"]["items"] = contracts["release_schema"]
    _schema_validate(catalog, catalog_schema, "new catalog")
    output.mkdir(parents=True)
    objects = []
    media = "application/json; charset=utf-8"
    for filename, data, kind in ((f"{args.plugin_id}-{args.version}.crp", crp_bytes, "application/octet-stream"), ("manifest.json", manifest_bytes, media), ("signatures.json", signature_bytes, media), ("descriptor.json", canonical(descriptor), media), ("provenance.json", canonical(provenance), media), ("review.json", evidence, media), ("verification.json", verification_bytes, media), ("release.json", canonical(record), media)):
        add_object(output, objects, "resources", f"resources/sha256/{digests(data)['sha256']}/{filename}", data, kind)
    for filename, value in (("trust-roots.json", roots), ("source-registry.json", registry), ("revocations.json", revocations)):
        add_object(output, objects, "index", "policy/" + filename, canonical(value), media)
    catalog_bytes = canonical(catalog)
    history_key = f"indexes/catalog/seq-{catalog['catalog_sequence']:020d}.json"
    add_object(output, objects, "index", history_key, catalog_bytes, media)
    add_object(output, objects, "index", "catalog/index.json", catalog_bytes, media)
    pointer = {"sequence": catalog["catalog_sequence"], "key": history_key, "sha256": digests(catalog_bytes)["sha256"]}
    add_object(output, objects, "index", "pointers/catalog.json", canonical(pointer), media)
    (output / "previous-catalog.json").write_bytes(previous_bytes)
    bundle = {"format": "cheesesec-signed-release-v1", "source_commit": args.source_commit, "release_id": record["release_id"], "catalog_sequence": catalog["catalog_sequence"], "previous_catalog_sha256": digests(previous_bytes)["sha256"], "previous_catalog_file": "previous-catalog.json", "objects": objects}
    (output / "bundle-manifest.json").write_bytes(canonical(bundle))
    validate(output)
    return {"bundle": str(output), "release_id": record["release_id"], "catalog_sequence": catalog["catalog_sequence"], "crp": record["crp"]}


def validate(bundle_path):
    root = Path(bundle_path).resolve()
    bundle_bytes = read_file(root / "bundle-manifest.json")
    bundle = _strict_load_bytes(bundle_bytes, "bundle manifest")
    if bundle.get("format") != "cheesesec-signed-release-v1" or not re.fullmatch(r"[0-9a-f]{40}", bundle.get("source_commit", "")):
        raise ValueError("invalid signed-release bundle")
    objects = {}
    for item in bundle["objects"]:
        key, bucket, relative = item["key"], item["bucket"], item["file"]
        if bucket not in {"index", "resources"} or relative != bucket + "/" + key or "\\" in key or any(part in {"", ".", ".."} for part in key.split("/")):
            raise ValueError("invalid publication path")
        path = root / relative
        if not path.resolve().is_relative_to(root) or any(parent.is_symlink() for parent in (path, *path.parents) if parent != root.parent):
            raise ValueError("publication path escapes bundle")
        data = read_file(path)
        if item["sha256"] != digests(data)["sha256"] or item["size"] != len(data) or (bucket, key) in objects:
            raise ValueError("publication object digest or identity mismatch")
        objects[(bucket, key)] = (item, data)
    catalog = _strict_load_bytes(objects[("index", "catalog/index.json")][1], "catalog")
    previous_bytes = read_file(root / "previous-catalog.json")
    previous = _strict_load_bytes(previous_bytes, "previous catalog")
    if digests(previous_bytes)["sha256"] != bundle["previous_catalog_sha256"]:
        raise ValueError("previous catalog digest mismatch")
    if catalog["catalog_sequence"] != previous["catalog_sequence"] + 1 or catalog["catalog_sequence"] != bundle["catalog_sequence"] or catalog["withdrawals"] != previous["withdrawals"] or catalog["releases"][:-1] != previous["releases"]:
        raise ValueError("catalog is not an append-only single release")
    record = catalog["releases"][-1]
    catalog_schema = load(ROOT / "schema/store-v1/catalog.schema.json")
    catalog_schema["properties"]["releases"]["items"] = load(ROOT / "schema/store-v1/release.schema.json")
    _schema_validate(catalog, catalog_schema, "catalog")
    if record["release_id"] != bundle["release_id"]:
        raise ValueError("release identity mismatch")
    old_ids = [entry["release_id"] for entry in previous["releases"]]
    if len(set(old_ids)) != len(old_ids) or record["release_id"] in old_ids or any(item["namespace"] == record["namespace"] and item["release_sequence"] >= record["release_sequence"] for item in previous["releases"]):
        raise ValueError("release identity must be unique and sequence monotonic")
    roots, registry, revocations = [_strict_load_bytes(objects[("index", "policy/" + name + ".json")][1], name) for name in ("trust-roots", "source-registry", "revocations")]
    for policy, name in ((roots, "trust-roots"), (registry, "source-registry"), (revocations, "revocations")):
        schema(policy, "store-v1", name)
        if "official-demo-" in json.dumps(policy):
            raise ValueError("demo trust material rejected")
    crp_key = "resources/" + record["crp"]["resource_url"].split("https://res.cheesesec.com/", 1)[1]
    crp = objects[("resources", crp_key)][1]
    if len(crp) != record["crp"]["size"] or digests(crp) != record["crp"]["digests"]:
        raise ValueError("CRP digests mismatch")
    entries = {}
    with zipfile.ZipFile(io.BytesIO(crp)) as package:
        members = package.infolist()
        if len(members) != 3 or sum(item.file_size for item in members) > MAX_BYTES or any(item.file_size > 1024 * 1024 for item in members if item.filename in {"manifest.json", "signatures/manifest.json"}):
            raise ValueError("CRP must have exactly three bounded files")
        for member in members:
            mode = member.external_attr >> 16
            if member.is_dir() or mode & 0o170000 != 0o100000 or member.file_size > MAX_BYTES or member.filename in entries:
                raise ValueError("invalid CRP member")
            entries[member.filename] = package.read(member)
    manifest = _strict_load_bytes(entries["manifest.json"], "manifest")
    artifact = entries["artifact/" + manifest["artifact"]["name"]]
    if set(entries) != {"manifest.json", "signatures/manifest.json", "artifact/" + manifest["artifact"]["name"]} or digests(artifact) != manifest["artifact"]["digests"] or len(artifact) != manifest["artifact"]["size"]:
        raise ValueError("CRP artifact or layout mismatch")
    schema(manifest, "crp-v1", "manifest")
    schema(_strict_load_bytes(entries["signatures/manifest.json"], "signatures"), "crp-v1", "signatures")
    verification = verify_signature_set(entries["manifest.json"], entries["signatures/manifest.json"], roots, registry, revocations)
    if verification["release_id"] != record["release_id"] or manifest["artifact"] != record["artifact"] or any(manifest.get(key) != record[key] for key in ("plugin_id", "namespace", "version", "source", "source_root", "release_sequence")):
        raise ValueError("signed manifest identity differs from release")
    if record.get("high_risk", False) or any(record["signature_evidence"][key] != verification[key] for key in ("required_signatures", "valid_key_ids", "manifest_sha256", "source_root", "trust_level", "release_sequence")):
        raise ValueError("signature evidence does not bind the real verification result")
    source_keys = [item for item in roots["roots"] if item["source_root"] == record["source_root"] and item["trust_level"] == record["trust_level"] and item["status"] == "active"]
    if len({item["public_key"] for item in source_keys}) != len(source_keys):
        raise ValueError("active signing keys must have distinct public keys")
    if record["trust_level"] in {"official", "enterprise"} and len(source_keys) < 3:
        raise ValueError("official and enterprise release roots require at least three active keys")
    for field, data in (("manifest_sha256", entries["manifest.json"]), ("signature_set_sha256", entries["signatures/manifest.json"])):
        if record[field] != digests(data)["sha256"]:
            raise ValueError("record signature binding mismatch")
    contracts = {"release_schema": load(ROOT / "schema/store-v1/release.schema.json"), "trust_roots": roots}
    validate_release_record(record, contracts, published=True)
    extras = {}
    for field, filename in (("descriptor_sha256", "descriptor.json"), ("provenance_sha256", "provenance.json")):
        extras[filename] = _strict_load_bytes(objects[("resources", f"resources/sha256/{record[field]}/{filename}")][1], filename)
    descriptor = extras["descriptor.json"]
    schema(descriptor, "store-v1", "sidecar-descriptor")
    if descriptor["manifest_identity"] != runtime_manifest_identity(manifest) or descriptor["artifact_identity"] != manifest["artifact"]["digests"]["sha256"] or any(descriptor[key] != record[key] for key in ("plugin_id", "version", "namespace", "source", "source_root")):
        raise ValueError("descriptor binding mismatch")
    if extras["provenance.json"].get("source_commit") != bundle["source_commit"] or not extras["provenance.json"].get("compatibility") or not extras["provenance.json"].get("description"):
        raise ValueError("provenance binding or compatibility missing")
    for digest, filename in ((record["review"]["evidence_sha256"], "review.json"), (record["signature_evidence"]["verification_report_sha256"], "verification.json")):
        extras[filename] = _strict_load_bytes(objects[("resources", f"resources/sha256/{digest}/{filename}")][1], filename)
    if extras["verification.json"] != verification or extras["review.json"].get("decision") != "approved" or any(extras["review.json"].get(key) != record["review"][key] for key in ("review_id", "reviewers")):
        raise ValueError("verification or review evidence mismatch")
    if extras["review.json"].get("source_commit") != bundle["source_commit"] or extras["review.json"].get("artifact_sha256") != manifest["artifact"]["digests"]["sha256"]:
        raise ValueError("review evidence does not bind the source commit and artifact")
    expected_resources = {crp_key,
        f"resources/sha256/{record['manifest_sha256']}/manifest.json",
        f"resources/sha256/{record['signature_set_sha256']}/signatures.json",
        f"resources/sha256/{record['descriptor_sha256']}/descriptor.json",
        f"resources/sha256/{record['provenance_sha256']}/provenance.json",
        f"resources/sha256/{record['review']['evidence_sha256']}/review.json",
        f"resources/sha256/{record['signature_evidence']['verification_report_sha256']}/verification.json",
        f"resources/sha256/{digests(canonical(record))['sha256']}/release.json"}
    if {key for bucket, key in objects if bucket == "resources"} != expected_resources or objects[("resources", f"resources/sha256/{record['manifest_sha256']}/manifest.json")][1] != entries["manifest.json"] or objects[("resources", f"resources/sha256/{record['signature_set_sha256']}/signatures.json")][1] != entries["signatures/manifest.json"] or _strict_load_bytes(objects[("resources", f"resources/sha256/{digests(canonical(record))['sha256']}/release.json")][1], "release") != record:
        raise ValueError("content-addressed release evidence set differs from archive or catalog")
    history_key = f"indexes/catalog/seq-{catalog['catalog_sequence']:020d}.json"
    pointer = _strict_load_bytes(objects[("index", "pointers/catalog.json")][1], "catalog pointer")
    if objects[("index", history_key)][1] != objects[("index", "catalog/index.json")][1] or pointer != {"sequence": catalog["catalog_sequence"], "key": history_key, "sha256": digests(objects[("index", "catalog/index.json")][1])["sha256"]}:
        raise ValueError("catalog history or pointer mismatch")
    return {"release_id": record["release_id"], "catalog_sequence": catalog["catalog_sequence"], "objects": len(objects), "verified": True, "bundle_manifest_sha256": digests(bundle_bytes)["sha256"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("validate")
    check.add_argument("--bundle", required=True)
    create = sub.add_parser("build")
    for name in ("artifact", "descriptor", "provenance", "review", "trust-roots", "source-registry", "revocations", "previous-catalog", "output", "plugin-id", "namespace", "version", "source", "source-root", "source-commit"):
        create.add_argument("--" + name, required=True)
    create.add_argument("--publisher", default="CheeseSec")
    create.add_argument("--sequence", type=int, required=True)
    create.add_argument("--signed-at")
    create.add_argument("--key", action="append", required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.bundle) if args.command == "validate" else build(args), indent=2))


if __name__ == "__main__":
    main()
