#!/usr/bin/env python3
"""Offline Ed25519 verification for CheeseWAF CRP v1 signature envelopes.

The verifier intentionally uses only the Python standard library and the
platform OpenSSL CLI. It performs no network access and mirrors CheeseWAF's
domain-separated signature envelope while checking source registry, trust
level, validity window, release sequence, and revocation snapshot.
"""
from __future__ import annotations

import base64
import binascii
import calendar
import hashlib
import json
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SHA256 = re.compile(r"^[0-9a-f]{64}$")
RFC3339_NANO = re.compile(
    r"^(?P<seconds>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,9}))?(?P<zone>Z|[+-]\d{2}:\d{2})$"
)
CRP_SIGNATURE_DOMAIN = b"cheesewaf-crp-signature-v1\n"
TRUST_LEVELS = {"official", "enterprise", "community", "personal", "test", "development"}
THRESHOLDS = {
    "official": (2, 3, 3, 5),
    "enterprise": (2, 3, 3, 5),
    "community": (1, 1, 2, 2),
    "personal": (1, 1, 2, 2),
    "test": (1, 1, 2, 2),
    "development": (1, 1, 2, 2),
}
MAX_KEY_LIFETIME_DAYS = {
    "official": 1095,
    "enterprise": 1095,
    "community": 365,
    "personal": 365,
    "test": 30,
    "development": 7,
}


def _strict_load_bytes(data: bytes, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label}: invalid UTF-8 JSON: {exc}") from exc


def _records(value: Any, key: str, label: str) -> list[dict[str, Any]]:
    if isinstance(value, list):
        records = value
    elif isinstance(value, dict) and isinstance(value.get(key), list):
        records = value[key]
    else:
        raise ValueError(f"{label}: expected a list or object containing {key!r}")
    if not all(isinstance(record, dict) for record in records):
        raise ValueError(f"{label}: every record must be an object")
    return records


def _go_time_string(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field}: timestamp is required")
    match = RFC3339_NANO.fullmatch(value)
    if match is None:
        raise ValueError(f"{field}: timestamp must be RFC3339 with at most 9 fractional digits")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{field}: invalid RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field}: timestamp must include a timezone")
    utc_seconds = parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    fraction = (match.group("fraction") or "").rstrip("0")
    return utc_seconds + (f".{fraction}" if fraction else "") + "Z"


def _timestamp_nanoseconds(value: Any, field: str) -> int:
    canonical = _go_time_string(value, field)
    match = RFC3339_NANO.fullmatch(canonical)
    if match is None:
        raise ValueError(f"{field}: failed to normalize RFC3339 timestamp")
    utc_seconds = datetime.fromisoformat(match.group("seconds") + "+00:00")
    epoch_seconds = calendar.timegm(utc_seconds.utctimetuple())
    fraction = (match.group("fraction") or "").ljust(9, "0")
    return epoch_seconds * 1_000_000_000 + (int(fraction) if fraction else 0)


def _datetime_nanoseconds(value: datetime) -> int:
    if value.tzinfo is None:
        raise ValueError("verification time must include a timezone")
    utc = value.astimezone(timezone.utc)
    return calendar.timegm(utc.utctimetuple()) * 1_000_000_000 + utc.microsecond * 1_000


def _go_digests(value: Any, field: str) -> dict[str, str]:
    if value is None:
        value = {}
    if not isinstance(value, dict) or set(value) - {"md5", "sha1", "sha256"}:
        raise ValueError(f"{field}: invalid CRP v1 digest object")
    result: dict[str, str] = {}
    for name in ("md5", "sha1", "sha256"):
        digest = value.get(name, "")
        if not isinstance(digest, str):
            raise ValueError(f"{field}.{name}: digest must be a string")
        result[name] = digest
    return result


def _go_manifest_object(manifest: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "api_version",
        "kind",
        "name",
        "plugin_id",
        "version",
        "namespace",
        "publisher",
        "source",
        "source_root",
        "release_sequence",
        "digests",
        "artifact",
    }
    if set(manifest) - fields:
        raise ValueError("manifest contains fields outside CheeseWAF CRP v1")
    for name in ("version", "namespace", "source_root"):
        if not isinstance(manifest.get(name), str):
            raise ValueError(f"manifest.{name}: string is required")
    name = manifest.get("name", "")
    plugin_id = manifest.get("plugin_id", "")
    if not isinstance(name, str):
        raise ValueError("manifest.name: string is required")
    if not isinstance(plugin_id, str):
        raise ValueError("manifest.plugin_id: string is required")
    if not name and not plugin_id:
        raise ValueError("manifest must include name or plugin_id")
    for field in ("api_version", "kind", "plugin_id", "publisher", "source"):
        if field in manifest and not isinstance(manifest[field], str):
            raise ValueError(f"manifest.{field}: string is required")
    if manifest.get("api_version") not in (None, "", "crp.cheesewaf.io/v1"):
        raise ValueError("manifest.api_version: unsupported CRP v1 schema")
    if manifest.get("kind") not in (None, "", "CheeseWAFResourcePackage"):
        raise ValueError("manifest.kind: unsupported CRP v1 kind")
    sequence = manifest.get("release_sequence")
    if type(sequence) is not int or sequence < 0 or sequence > 18446744073709551615:
        raise ValueError("manifest.release_sequence must be a uint64")
    artifact = manifest.get("artifact")
    if not isinstance(artifact, dict) or set(artifact) - {"name", "size", "digests"}:
        raise ValueError("manifest.artifact: invalid CRP v1 artifact object")
    artifact_name = artifact.get("name", "")
    artifact_size = artifact.get("size")
    if not isinstance(artifact_name, str) or type(artifact_size) is not int or artifact_size < 0:
        raise ValueError("manifest.artifact: name and non-negative size are required")

    result: dict[str, Any] = {}
    for field in ("api_version", "kind"):
        if manifest.get(field):
            result[field] = manifest[field]
    result["name"] = name
    if plugin_id:
        result["plugin_id"] = plugin_id
    result["version"] = manifest["version"]
    result["namespace"] = manifest["namespace"]
    for field in ("publisher", "source"):
        if manifest.get(field):
            result[field] = manifest[field]
    result["source_root"] = manifest["source_root"]
    result["release_sequence"] = sequence
    # Go encodes zero-value struct fields even when their tags say omitempty.
    result["digests"] = _go_digests(manifest.get("digests"), "manifest.digests")
    encoded_artifact: dict[str, Any] = {}
    if artifact_name:
        encoded_artifact["name"] = artifact_name
    if artifact_size:
        encoded_artifact["size"] = artifact_size
    encoded_artifact["digests"] = _go_digests(artifact.get("digests"), "manifest.artifact.digests")
    result["artifact"] = encoded_artifact
    return result


def _signature_signing_bytes(manifest: dict[str, Any], signature: dict[str, Any]) -> bytes:
    signed_at = _go_time_string(signature.get("signed_at"), "signature.signed_at")
    envelope = {
        "manifest": _go_manifest_object(manifest),
        "key_id": signature["key_id"],
        "algorithm": signature["algorithm"],
        "signed_at": signed_at,
    }
    return CRP_SIGNATURE_DOMAIN + json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _level_for_namespace(namespace: str) -> str:
    level = namespace.split("/", 1)[0] if isinstance(namespace, str) else ""
    if level not in TRUST_LEVELS:
        raise ValueError(f"manifest namespace has unsupported trust level: {namespace!r}")
    return level


def _verify_ed25519(public_key: bytes, message: bytes, signature: bytes) -> None:
    if len(public_key) != 32:
        raise ValueError("trust root public key must be 32 bytes")
    if len(signature) != 64:
        raise ValueError("signature must decode to exactly 64-byte Ed25519 value")
    # SubjectPublicKeyInfo DER prefix for id-Ed25519 (RFC 8410).
    der = bytes.fromhex("302a300506032b6570032100") + public_key
    with tempfile.TemporaryDirectory(prefix="cheesesec-verify-") as raw:
        directory = Path(raw)
        key_path = directory / "public.der"
        message_path = directory / "manifest.json"
        signature_path = directory / "signature.bin"
        key_path.write_bytes(der)
        message_path.write_bytes(message)
        signature_path.write_bytes(signature)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(key_path),
                "-in",
                str(message_path),
                "-sigfile",
                str(signature_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise ValueError(f"Ed25519 signature verification failed{': ' + detail if detail else ''}")


def verify_signature_set(
    manifest_bytes: bytes,
    signatures_bytes: bytes,
    trust_roots: Any,
    source_registry: Any,
    revocations: Any,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    manifest = _strict_load_bytes(manifest_bytes, "manifest")
    signatures = _strict_load_bytes(signatures_bytes, "signatures")
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")
    if not isinstance(signatures, list) or not signatures:
        raise ValueError("empty signature set is not publishable")
    source_entries = _records(source_registry, "sources", "source registry")
    root_entries = _records(trust_roots, "roots", "trust roots")
    revocation_entries = _records(revocations, "events", "revocation snapshot")
    namespace = manifest.get("namespace")
    source = manifest.get("source")
    source_root = manifest.get("source_root")
    release_sequence = manifest.get("release_sequence")
    if not isinstance(namespace, str) or not isinstance(source, str) or not isinstance(source_root, str):
        raise ValueError("manifest must include namespace, source, and source_root")
    if not isinstance(release_sequence, int) or release_sequence < 0:
        raise ValueError("manifest.release_sequence must be a non-negative integer")
    trust_level = _level_for_namespace(namespace)
    bindings = [entry for entry in source_entries if entry.get("source") == source]
    if len(bindings) != 1:
        raise ValueError(f"source registry must contain exactly one binding for {source!r}")
    binding = bindings[0]
    if binding.get("source_root") != source_root:
        raise ValueError("source registry source root does not match manifest source root")
    if binding.get("trust_level") != trust_level:
        raise ValueError("source registry trust level does not match manifest namespace")
    release_id = f"{namespace}@{manifest.get('version')}#{release_sequence}"
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    revoked_keys = {entry.get("key_id") for entry in revocation_entries if entry.get("key_id")}
    revoked_releases = {entry.get("release_id") for entry in revocation_entries if entry.get("release_id")}
    if release_id in revoked_releases:
        raise ValueError(f"release is revoked: {release_id}")
    roots_by_id: dict[str, dict[str, Any]] = {}
    for root in root_entries:
        key_id = root.get("key_id")
        if not isinstance(key_id, str) or key_id in roots_by_id:
            raise ValueError("trust roots must have unique key_id values")
        roots_by_id[key_id] = root
    seen_ids: set[str] = set()
    valid_ids: list[str] = []
    current = now or datetime.now(timezone.utc)
    current_ns = _datetime_nanoseconds(current)
    for signature in signatures:
        if not isinstance(signature, dict):
            raise ValueError("signature entry must be an object")
        key_id = signature.get("key_id")
        if not isinstance(key_id, str) or key_id in seen_ids:
            raise ValueError("signature key_id values must be unique")
        seen_ids.add(key_id)
        unsupported_fields = set(signature) - {"key_id", "algorithm", "value", "signed_at"}
        if unsupported_fields:
            raise ValueError(f"signature {key_id} contains fields outside CRP v1: {sorted(unsupported_fields)!r}")
        if key_id in revoked_keys:
            raise ValueError(f"signing key is revoked: {key_id}")
        root = roots_by_id.get(key_id)
        if root is None:
            raise ValueError(f"signature key is not in the supplied trust roots: {key_id}")
        if signature.get("algorithm") != "ed25519" or root.get("algorithm") != "ed25519":
            raise ValueError(f"unsupported signature algorithm for {key_id}")
        if root.get("status", "active") != "active":
            raise ValueError(f"trust root is not active: {key_id}")
        if root.get("source_root") != source_root:
            raise ValueError(f"signature source root does not match manifest source root: {key_id}")
        if root.get("trust_level") != trust_level:
            raise ValueError(f"signature trust level does not match manifest namespace: {key_id}")
        signed_at_ns = _timestamp_nanoseconds(signature.get("signed_at"), f"signature {key_id}.signed_at")
        valid_from_ns = _timestamp_nanoseconds(root.get("valid_from"), f"trust root {key_id}.valid_from")
        valid_until_ns = _timestamp_nanoseconds(root.get("valid_until"), f"trust root {key_id}.valid_until")
        max_lifetime_ns = MAX_KEY_LIFETIME_DAYS[trust_level] * 86400 * 1_000_000_000
        if valid_until_ns <= valid_from_ns or valid_until_ns - valid_from_ns > max_lifetime_ns or signed_at_ns < valid_from_ns or signed_at_ns > valid_until_ns or current_ns > valid_until_ns:
            raise ValueError(f"signature {key_id} is outside key validity")
        if signed_at_ns > current_ns:
            raise ValueError(f"signature {key_id} is from the future")
        try:
            public_key = base64.b64decode(root.get("public_key"), validate=True)
            signature_value = base64.b64decode(signature.get("value"), validate=True)
        except (binascii.Error, TypeError) as exc:
            raise ValueError(f"signature {key_id} is not valid base64") from exc
        _verify_ed25519(public_key, _signature_signing_bytes(manifest, signature), signature_value)
        valid_ids.append(key_id)
    normal_threshold, _normal_total, high_threshold, _high_total = THRESHOLDS[trust_level]
    required = high_threshold if manifest.get("high_risk", False) else normal_threshold
    if len(valid_ids) < required:
        raise ValueError(f"signature threshold not met: {len(valid_ids)} valid, {required} required")
    return {
        "manifest_sha256": manifest_sha256,
        "release_id": release_id,
        "source_root": source_root,
        "trust_level": trust_level,
        "release_sequence": release_sequence,
        "required_signatures": required,
        "valid_key_ids": valid_ids,
    }
