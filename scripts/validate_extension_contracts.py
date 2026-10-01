#!/usr/bin/env python3
"""Validate the planned Jev, EDR and DuckDB extension descriptors."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "extensions-v1" / "extension-descriptor.schema.json"
POLICY_PATH = ROOT / "policy" / "extension-contracts.json"
EXAMPLE_ROOT = ROOT / "examples" / "extensions"


def strict_load(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{path}: duplicate JSON key {key!r}")
            result[key] = value

        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


def schema_validate(instance: Any, schema: dict[str, Any], label: str) -> None:
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(instance),
        key=lambda error: list(error.path),
    )
    if errors:
        path = ".".join(str(part) for part in errors[0].path)
        raise ValueError(f"{label}: {path + ': ' if path else ''}{errors[0].message}")


def load_contracts() -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    schema = strict_load(SCHEMA_PATH)
    policy = strict_load(POLICY_PATH)
    descriptors = []
    for path in sorted(EXAMPLE_ROOT.glob("*/descriptor.json")):
        descriptor = strict_load(path)
        descriptor["_path"] = path
        descriptors.append(descriptor)
    return schema, policy, descriptors


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_descriptor(descriptor: dict[str, Any], schema: dict[str, Any], policy: dict[str, Any]) -> None:
    path = descriptor.get("_path")
    label = str(path.relative_to(ROOT)) if isinstance(path, Path) else descriptor.get("descriptor_id", "descriptor")
    instance = {key: value for key, value in descriptor.items() if key != "_path"}
    schema_validate(instance, schema, label)

    _assert(instance["publication"] == {"status": "planned", "installable": False, "crp_binding": "descriptor-only"}, f"{label}: extension is not descriptor-only")
    _assert(instance["activation"] == {"request_path": "asynchronous", "initial_mode": "observe", "activation_owner": "control-plane"}, f"{label}: activation must be asynchronous observe-first control-plane")
    _assert(instance["output"]["direct_actions"] == [], f"{label}: direct actions are forbidden")

    extension_class = instance["class"]
    deployment = instance["deployment"]
    class_policy = policy["classes"].get(extension_class)
    _assert(class_policy is not None, f"{label}: unsupported extension class")
    _assert(deployment in class_policy["deployments"], f"{label}: deployment is not allowed for {extension_class}")
    _assert(descriptor["network"]["mode"] not in class_policy["forbidden_network_modes"], f"{label}: network mode is forbidden for {extension_class}")
    _assert(set(instance["capabilities"]) & set(class_policy["allowed_outputs"]), f"{label}: descriptor has no allowed output capability")

    network = instance["network"]
    lease = network["lease"]
    if deployment == "hosted-api":
        _assert(extension_class == "risk-advisor", f"{label}: hosted API is reserved for risk advisors")
        _assert(descriptor["deployment_config"]["provider"] == policy["jev"]["hosted_provider"], f"{label}: hosted provider is not Typesafe")
        _assert(network["mode"] == "brokered", f"{label}: hosted Jev must use brokered egress")
        _assert(network["allowed_targets"] == [policy["jev"]["hosted_target"]], f"{label}: hosted target is not fixed")
        _assert(lease["required"] is True and 0 < lease["max_ttl_seconds"] <= policy["max_online_lease_seconds"], f"{label}: hosted Jev lease is not bounded")
        _assert(lease["max_requests"] > 0 and lease["max_bytes"] > 0, f"{label}: hosted Jev lease must have positive request and byte limits")
        _assert(set(instance["deployment_config"]) == {"provider", "endpoint_ref", "tls_pin_ref"}, f"{label}: hosted Jev config has unexpected fields")
        _assert(instance["deployment_config"].get("endpoint_ref") == policy["jev"]["hosted_target"], f"{label}: endpoint reference is not fixed")
        _assert(instance["deployment_config"].get("tls_pin_ref"), f"{label}: hosted Jev must declare a TLS pin reference")
        _assert(instance["input"]["schema"] == policy["jev"]["required_input_schema"], f"{label}: hosted Jev input schema changed")
        _assert(policy["jev"]["required_output_schema"] in instance["output"]["schemas"], f"{label}: hosted Jev must emit the risk-hint schema")
    elif deployment == "local-lite":
        _assert(extension_class == "risk-advisor", f"{label}: local-lite is reserved for Jev Lite")
        _assert(set(instance["deployment_config"]) == {"provider", "model_ref"}, f"{label}: local-lite config has unexpected fields")
        _assert(instance["deployment_config"]["provider"] == policy["jev"]["lite_provider"], f"{label}: local-lite provider is not Jev Lite")
        _assert(instance["deployment_config"].get("model_ref"), f"{label}: local-lite must bind a model reference")
        _assert(network["mode"] == "deny" and network["allowed_targets"] == [], f"{label}: local-lite must deny egress")
        _assert(lease == {"required": False, "max_ttl_seconds": 0, "max_requests": 0, "max_bytes": 0}, f"{label}: local-lite must not request a lease")
        _assert(instance["input"]["schema"] == policy["jev"]["required_input_schema"], f"{label}: local-lite input schema changed")
        _assert(policy["jev"]["required_output_schema"] in instance["output"]["schemas"], f"{label}: local-lite must emit the risk-hint schema")
    elif deployment == "local-sidecar":
        _assert(extension_class == "event-correlator", f"{label}: local-sidecar is reserved for event correlators")
        _assert(set(instance["deployment_config"]) == {"provider"}, f"{label}: event correlator config has unexpected fields")
        _assert(instance["deployment_config"]["provider"] == "cheesewaf", f"{label}: event correlator provider must be CheeseWAF")
        _assert(network["mode"] == "deny" and network["allowed_targets"] == [], f"{label}: event correlator must deny egress")
        _assert(lease == {"required": False, "max_ttl_seconds": 0, "max_requests": 0, "max_bytes": 0}, f"{label}: event correlator must not request a lease")
        _assert(instance["input"]["schema"] == policy["edr"]["required_input_schema"], f"{label}: EDR input schema changed")
        _assert(instance["input"]["data_class"] == policy["edr"]["required_data_class"], f"{label}: EDR data class changed")
        _assert(instance["input"]["host_telemetry"] is policy["edr"]["host_telemetry"], f"{label}: host telemetry must remain disabled")
    elif deployment == "host-provided":
        _assert(extension_class == "analytics", f"{label}: host-provided is reserved for analytics")
        config = instance["deployment_config"]
        _assert(set(config) == {"provider", "version_range", "artifact_policy", "database_read_only"}, f"{label}: DuckDB config has unexpected fields")
        _assert(config["provider"] == policy["duckdb"]["provider"], f"{label}: analytics provider must be DuckDB")
        _assert(config["artifact_policy"] == policy["duckdb"]["artifact_policy"], f"{label}: DuckDB binary must be host-provided")
        _assert(config["database_read_only"] is True, f"{label}: DuckDB must be read-only")
        _assert(network["mode"] == "deny" and network["allowed_targets"] == [], f"{label}: analytics must deny egress")
        _assert(lease == {"required": False, "max_ttl_seconds": 0, "max_requests": 0, "max_bytes": 0}, f"{label}: analytics must not request a lease")
        _assert(instance["input"]["schema"] == policy["duckdb"]["required_input_schema"], f"{label}: DuckDB input schema changed")
        _assert(instance["input"]["data_class"] == policy["duckdb"]["required_data_class"], f"{label}: DuckDB data class changed")
    else:  # pragma: no cover - schema validation catches this first.
        raise ValueError(f"{label}: unsupported deployment")


def validate_contracts() -> list[str]:
    schema, policy, descriptors = load_contracts()
    schema_validate(policy, {"type": "object"}, "extension policy")
    _assert(policy["api_version"] == schema["properties"]["api_version"]["const"], "extension policy api_version is not bound")
    _assert(policy["crp_v1_unchanged"] is True, "extension policy must preserve CRP v1")
    _assert(policy["direct_actions"] == [], "extension policy must forbid direct actions")
    _assert(len(descriptors) == 4, "expected four planned extension descriptors")
    ids: set[str] = set()
    for descriptor in descriptors:
        descriptor_id = descriptor["descriptor_id"]
        _assert(descriptor_id not in ids, f"duplicate descriptor_id: {descriptor_id}")
        ids.add(descriptor_id)
        validate_descriptor(descriptor, schema, policy)
    return sorted(ids)


def main() -> int:
    try:
        ids = validate_contracts()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"extension contract validation failed: {exc}")
        return 1
    print(f"planned extension contracts passed: {', '.join(ids)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
