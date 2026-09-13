#!/usr/bin/env python3
"""Validate the minimal CheeseSec store, OTA and CWEDP contracts.

This is a publication metadata gate. It checks shape, identity and append-only
rules; cryptographic verification remains a CheeseWAF CRP import responsibility.
"""
from __future__ import annotations

import argparse
import copy
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schema" / "store-v1"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
TRUST_LEVELS = {"official", "enterprise", "community", "personal", "test", "development"}


def strict_load(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{path}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


def load_contracts() -> dict[str, Any]:
    paths = {
        "trust_levels": ROOT / "policy" / "trust-levels.json",
        "endpoints": ROOT / "policy" / "endpoints.json",
        "cwedp": ROOT / "policy" / "cwedp.json",
        "catalog": ROOT / "catalog" / "index.json",
        "ota": ROOT / "ota" / "index.json",
        "sidecar_example": ROOT / "examples" / "store-v1" / "sidecar-descriptor.json",
        "release_example": ROOT / "examples" / "store-v1" / "release-record.json",
        "offline_import": ROOT / "policy" / "offline-import.json",
    }
    for schema in ("trust-levels", "endpoint-policy", "cwedp", "release", "catalog", "ota", "sidecar-descriptor", "offline-import"):
        paths[f"{schema}_schema"] = SCHEMA_DIR / f"{schema}.schema.json"
    contracts = {name: strict_load(path) for name, path in paths.items()}
    # Short aliases keep callers focused on the contract rather than its file name.
    contracts["sidecar"] = contracts["sidecar-descriptor_schema"]
    return contracts


def _schema_validate(instance: Any, schema: dict[str, Any], label: str) -> None:
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(instance),
        key=lambda error: list(error.path),
    )
    if errors:
        path = ".".join(str(part) for part in errors[0].path)
        raise ValueError(f"{label}: {path + ': ' if path else ''}{errors[0].message}")


def _catalog_schema(contracts: dict[str, Any]) -> dict[str, Any]:
    schema = copy.deepcopy(contracts["catalog_schema"])
    schema["properties"]["releases"]["items"] = contracts["release_schema"]
    return schema


def _level_for_namespace(namespace: str) -> str:
    if namespace.startswith("official/"):
        return "official"
    if namespace.startswith("enterprise/"):
        return "enterprise"
    for level in ("community", "personal", "test", "development"):
        if namespace.startswith(level + "/"):
            return level
    raise ValueError(f"unsupported namespace: {namespace}")


def validate_release_record(record: dict[str, Any], contracts: dict[str, Any], *, published: bool = False) -> None:
    _schema_validate(record, contracts["release_schema"], "release")
    level = _level_for_namespace(record["namespace"])
    if record["trust_level"] != level:
        raise ValueError(f"release {record['release_id']}: trust level does not match namespace")
    if published and record["record_type"] != "publication":
        raise ValueError(f"release {record['release_id']}: only publication records may enter the live catalog")
    expected_id = f"{record['namespace']}@{record['version']}#{record['release_sequence']}"
    if record["release_id"] != expected_id:
        raise ValueError(f"release {record['release_id']}: release_id must be namespace@version#release_sequence")
    if record["crp"]["digests"]["sha256"] != record["crp"]["resource_url"].split("/sha256/", 1)[1].split("/", 1)[0]:
        raise ValueError(f"release {record['release_id']}: resource URL is not bound to CRP SHA-256")
    if record["signature_evidence"]["status"] == "verified":
        required = record["signature_evidence"]["required_signatures"]
        if len(record["signature_evidence"]["valid_key_ids"]) < required or required == 0:
            raise ValueError(f"release {record['release_id']}: verified release lacks its signature threshold")
    elif published:
        raise ValueError(f"release {record['release_id']}: published release must have verified signatures")
    if published and record["review"]["decision"] != "approved":
        raise ValueError(f"release {record['release_id']}: published release is not approved")
    if level in {"community", "personal", "test", "development"} and published and record["review"]["reviewers"] == []:
        raise ValueError(f"release {record['release_id']}: confirmation-required release has no reviewer evidence")


def validate_contracts(contracts: dict[str, Any], *, base: dict[str, Any] | None = None) -> None:
    _schema_validate(contracts["trust_levels"], contracts["trust-levels_schema"], "trust-levels policy")
    _schema_validate(contracts["endpoints"], contracts["endpoint-policy_schema"], "endpoint policy")
    _schema_validate(contracts["cwedp"], contracts["cwedp_schema"], "CWEDP policy")
    _schema_validate(contracts["sidecar_example"], contracts["sidecar-descriptor_schema"], "sidecar descriptor")
    _schema_validate(contracts["offline_import"], contracts["offline-import_schema"], "offline import policy")
    _schema_validate(contracts["release_example"], contracts["release_schema"], "release example")
    validate_release_record(contracts["release_example"], contracts, published=False)
    _schema_validate(contracts["catalog"], _catalog_schema(contracts), "catalog index")
    _schema_validate(contracts["ota"], contracts["ota_schema"], "OTA index")

    levels = contracts["trust_levels"]["levels"]
    if {entry["id"] for entry in levels} != TRUST_LEVELS:
        raise ValueError("trust-levels policy must define exactly the six supported levels")
    level_map = {entry["id"]: entry for entry in levels}
    if level_map["official"]["normal_threshold"] != 2 or level_map["official"]["normal_total"] != 3:
        raise ValueError("official releases require 2-of-3 signatures")
    if level_map["official"]["high_risk_threshold"] != 3 or level_map["official"]["high_risk_total"] != 5:
        raise ValueError("official high-risk releases require 3-of-5 signatures")
    if level_map["enterprise"]["normal_threshold"] != 2 or level_map["enterprise"]["normal_total"] != 3:
        raise ValueError("enterprise releases require 2-of-3 signatures")
    for level in ("community", "personal", "test", "development"):
        if level_map[level]["admission"] != "needs_confirmation" or not level_map[level]["administrator_confirmation"]:
            raise ValueError(f"{level} releases must require administrator confirmation")

    endpoints = {entry["id"]: entry for entry in contracts["endpoints"]["endpoints"]}
    expected_paths = {
        "store": [
            "/v1/catalog/index.json",
            "/v1/policy/endpoints.json",
            "/v1/policy/trust-roots.json",
            "/v1/policy/source-registry.json",
            "/v1/policy/revocations.json",
            "/v1/schema/store/{name}.schema.json",
            "/v1/schema/crp/{name}.schema.json",
        ],
        "ota": ["/v1/channels/{channel}/index.json"],
        "resources": ["/sha256/{sha256}/{filename}"],
    }
    if {key: endpoints[key]["paths"] for key in expected_paths} != expected_paths:
        raise ValueError("endpoint paths do not match the fixed edge route contract")
    if any(entry["origin_role"] != "edge-public-r2" for entry in endpoints.values()):
        raise ValueError("public publication endpoints must use the edge-public-r2 origin role")
    if endpoints["store"]["cache_class"] != "short-revalidate" or endpoints["ota"]["cache_class"] != "short-revalidate":
        raise ValueError("store and OTA indexes must use short revalidation")
    if endpoints["resources"]["cache_class"] != "immutable":
        raise ValueError("resource endpoint must use immutable caching")
    if endpoints["resources"]["immutable"] is not True or endpoints["resources"]["path_policy"] != "content-addressed-sha256":
        raise ValueError("res.cheesesec.com must be immutable and content-addressed")
    if any(entry["methods"] != ["GET", "HEAD"] for entry in endpoints.values()):
        raise ValueError("store, OTA and resources endpoints are pull-only GET/HEAD surfaces")
    if contracts["endpoints"]["offline"]["network_requests"] != 0:
        raise ValueError("offline mode must not make network requests")

    if contracts["cwedp"]["pull_only"] is not True or contracts["cwedp"]["ansible_push"] is not False:
        raise ValueError("CWEDP must be pull-only and Ansible push must remain disabled")
    if contracts["cwedp"]["promotion"]["install_upgrade_rollback_executor"] != "CWEDP":
        raise ValueError("CRP lifecycle must be executed by CWEDP")
    if contracts["sidecar_example"]["runtime"] != "sidecar":
        raise ValueError("WASM and in-process plugin runtimes are forbidden")
    if contracts["sidecar_example"]["metadata"] != {"request_path": "asynchronous", "initial_mode": "observe", "egress": "deny", "activation_owner": "control-plane"}:
        raise ValueError("34A sidecar descriptor must be asynchronous, observe-first and egress-denied")

    releases = contracts["catalog"]["releases"]
    release_ids: set[str] = set()
    for release in releases:
        validate_release_record(release, contracts, published=True)
        if release["release_id"] in release_ids:
            raise ValueError(f"duplicate release_id: {release['release_id']}")
        release_ids.add(release["release_id"])
    withdrawal_ids: set[str] = set()
    withdrawn_releases: set[str] = set()
    for withdrawal in contracts["catalog"]["withdrawals"]:
        if withdrawal["withdrawal_id"] in withdrawal_ids:
            raise ValueError(f"duplicate withdrawal_id: {withdrawal['withdrawal_id']}")
        withdrawal_ids.add(withdrawal["withdrawal_id"])
        if withdrawal["release_id"] not in release_ids:
            raise ValueError(f"withdrawal refers to a release that is not retained: {withdrawal['release_id']}")
        if withdrawal["release_id"] in withdrawn_releases:
            raise ValueError(f"release has more than one withdrawal event: {withdrawal['release_id']}")
        withdrawn_releases.add(withdrawal["release_id"])
    ota_ids: set[str] = set()
    release_by_id = {release["release_id"]: release for release in releases}
    for entry in contracts["ota"]["releases"]:
        if entry["release_id"] in ota_ids:
            raise ValueError(f"duplicate OTA release_id: {entry['release_id']}")
        ota_ids.add(entry["release_id"])
        release = release_by_id.get(entry["release_id"])
        if release is None or entry["release_id"] in withdrawn_releases:
            raise ValueError(f"OTA release is not an approved catalog release: {entry['release_id']}")
        if entry["release_sequence"] != release["release_sequence"] or entry["version"] != release["version"]:
            raise ValueError(f"OTA entry changed release identity: {entry['release_id']}")
        if entry["crp_sha256"] != release["crp"]["digests"]["sha256"] or entry["resource_url"] != release["crp"]["resource_url"]:
            raise ValueError(f"OTA entry changed immutable CRP reference: {entry['release_id']}")
    if base is not None:
        validate_append_only(base, contracts)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def validate_append_only(base: dict[str, Any], current: dict[str, Any]) -> None:
    old_catalog = base.get("catalog") or {"catalog_sequence": 0, "releases": [], "withdrawals": []}
    old_ota = base.get("ota") or {"index_sequence": 0, "releases": []}
    old_releases = {entry["release_id"]: entry for entry in old_catalog.get("releases", [])}
    new_releases = {entry["release_id"]: entry for entry in current["catalog"]["releases"]}
    missing = sorted(set(old_releases) - set(new_releases))
    if missing:
        raise ValueError(f"immutable release records cannot be deleted: {', '.join(missing)}")
    for release_id, old in old_releases.items():
        if _canonical(old) != _canonical(new_releases[release_id]):
            raise ValueError(f"immutable release record was rewritten: {release_id}")
    old_withdrawals = {entry["withdrawal_id"]: entry for entry in old_catalog.get("withdrawals", [])}
    new_withdrawals = {entry["withdrawal_id"]: entry for entry in current["catalog"].get("withdrawals", [])}
    if set(old_withdrawals) - set(new_withdrawals):
        raise ValueError("withdrawal history is append-only and cannot be deleted")
    for event_id, old in old_withdrawals.items():
        if _canonical(old) != _canonical(new_withdrawals[event_id]):
            raise ValueError(f"withdrawal event was rewritten: {event_id}")
    if current["catalog"]["catalog_sequence"] < old_catalog.get("catalog_sequence", 0):
        raise ValueError("catalog_sequence moved backwards")
    if current["ota"]["index_sequence"] < old_ota.get("index_sequence", 0):
        raise ValueError("index_sequence moved backwards")


def _read_base(ref: str) -> dict[str, Any]:
    def show(path: str) -> Any:
        try:
            raw = subprocess.check_output(["git", "show", f"{ref}:{path}"], cwd=ROOT, stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            return None
        return json.loads(raw.decode("utf-8"))

    return {"catalog": show("catalog/index.json"), "ota": show("ota/index.json")}  # type: ignore[return-value]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", help="Git ref used to enforce append-only release history")
    args = parser.parse_args(argv)
    try:
        contracts = load_contracts()
        base = _read_base(args.base_ref) if args.base_ref else None
        validate_contracts(contracts, base=base)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"commercial contract validation failed: {exc}", file=sys.stderr)
        return 1
    print("commercial store, OTA, sidecar and CWEDP contracts passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
