#!/usr/bin/env python3
"""Offline Ed25519 verification for CRP v1 manifests.

The verifier intentionally uses only the Python standard library and the
platform OpenSSL CLI. It performs no network access and binds every accepted
signature to the manifest bytes, source registry, trust level, validity window,
release sequence, and revocation snapshot.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SHA256 = re.compile(r"^[0-9a-f]{64}$")
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


def _parse_time(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field}: timestamp is required")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"{field}: invalid RFC3339 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field}: timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


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
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    for signature in signatures:
        if not isinstance(signature, dict):
            raise ValueError("signature entry must be an object")
        key_id = signature.get("key_id")
        if not isinstance(key_id, str) or key_id in seen_ids:
            raise ValueError("signature key_id values must be unique")
        seen_ids.add(key_id)
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
        if signature.get("source_root") != source_root:
            raise ValueError(f"signature source root does not match manifest source root: {key_id}")
        if signature.get("trust_level") != trust_level:
            raise ValueError(f"signature trust level does not match manifest namespace: {key_id}")
        if signature.get("release_sequence") != release_sequence:
            raise ValueError(f"signature release sequence does not match manifest: {key_id}")
        if signature.get("manifest_sha256") != manifest_sha256:
            raise ValueError(f"signature manifest digest does not match manifest: {key_id}")
        signed_at = _parse_time(signature.get("signed_at"), f"signature {key_id}.signed_at")
        expires_at = _parse_time(signature.get("expires_at"), f"signature {key_id}.expires_at")
        valid_from = _parse_time(root.get("valid_from"), f"trust root {key_id}.valid_from")
        valid_until = _parse_time(root.get("valid_until"), f"trust root {key_id}.valid_until")
        if valid_until <= valid_from or (valid_until - valid_from).days > MAX_KEY_LIFETIME_DAYS[trust_level] or signed_at < valid_from or signed_at > valid_until or expires_at < signed_at or expires_at > valid_until or current > expires_at:
            raise ValueError(f"signature {key_id} is outside key validity")
        if signed_at > current:
            raise ValueError(f"signature {key_id} is from the future")
        try:
            public_key = base64.b64decode(root.get("public_key"), validate=True)
            signature_value = base64.b64decode(signature.get("value"), validate=True)
        except (binascii.Error, TypeError) as exc:
            raise ValueError(f"signature {key_id} is not valid base64") from exc
        _verify_ed25519(public_key, manifest_bytes, signature_value)
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
