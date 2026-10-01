#!/usr/bin/env python3
"""Validate the planned Jev, EDR and DuckDB extension descriptors."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "extensions-v1" / "extension-descriptor.schema.json"
POLICY_PATH = ROOT / "policy" / "extension-contracts.json"
EXAMPLE_ROOT = ROOT / "examples" / "extensions"
MESSAGE_SCHEMA_ROOT = ROOT / "schema" / "extensions-v1"
MESSAGE_SCHEMA_FILES = {
    "risk_hint": MESSAGE_SCHEMA_ROOT / "risk-hint.schema.json",
    "waf_security_event": MESSAGE_SCHEMA_ROOT / "waf-security-event.schema.json",
    "analysis_record": MESSAGE_SCHEMA_ROOT / "analysis-record.schema.json",
    "audit_parquet": MESSAGE_SCHEMA_ROOT / "audit-parquet.schema.json",
}
MESSAGE_FIXTURE_ROOT = ROOT / "examples" / "extensions" / "messages"
MESSAGE_FIXTURE_FILES = {
    "risk_hint": MESSAGE_FIXTURE_ROOT / "risk-hint.json",
    "waf_security_event": MESSAGE_FIXTURE_ROOT / "waf-security-event.json",
    "analysis_record": MESSAGE_FIXTURE_ROOT / "analysis-record.json",
    "audit_parquet": MESSAGE_FIXTURE_ROOT / "audit-parquet.json",
}
DUCKDB_ROW_SCHEMA_PATH = MESSAGE_SCHEMA_ROOT / "audit-event-row.schema.json"
DUCKDB_ROW_FIXTURE_PATH = MESSAGE_FIXTURE_ROOT / "audit-event-row.json"
DUCKDB_EXECUTION_PROFILE = {
    "profile_id": "duckdb-read-only-snapshot-v1",
    "runtime_isolation": "os-sandbox",
    "query_artifact": "reviewed-signed-template",
    "allow_arbitrary_sql": False,
    "allowed_relation": "audit_events",
    "snapshot_access": "manifest-refs-allowlist",
    "persistent_database": False,
    "network_egress": "deny",
    "filesystem": {
        "snapshot_mount": "read-only",
        "temporary_workspace": "isolated-bounded",
        "other_host_paths": "deny",
    },
    "duckdb_settings": {
        "enable_external_access": False,
        "allowed_paths": "manifest-only",
        "allow_community_extensions": False,
        "autoload_known_extensions": False,
        "autoinstall_known_extensions": False,
        "lock_configuration": True,
    },
    "limits": {
        "wall_time_seconds": 30,
        "cpu_milli": 1000,
        "process_memory_bytes": 1073741824,
        "duckdb_memory_bytes": 805306368,
        "pids": 64,
        "threads": 1,
        "input_bytes": 104857600,
        "temporary_bytes": 536870912,
        "max_parallel_jobs": 1,
        "max_output_rows": 10000,
        "max_output_bytes": 1048576,
    },
}


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


def load_message_contracts(policy: dict[str, Any] | None = None) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    if policy is None:
        policy = strict_load(POLICY_PATH)
    bindings = policy.get("messages")
    _assert(isinstance(bindings, dict), "extension policy must bind message schemas")
    _assert(set(bindings) == set(MESSAGE_SCHEMA_FILES), "message schema bindings are incomplete")
    for name, binding in bindings.items():
        _assert(
            binding == {
                "schema": f"cheesewaf/{name.replace('_', '-')}/v1" if name != "waf_security_event" else "cheesewaf/waf-security-event/v1",
                "file": str(MESSAGE_SCHEMA_FILES[name].relative_to(ROOT)),
                "fixture": str(MESSAGE_FIXTURE_FILES[name].relative_to(ROOT)),
            },
            f"message policy binding changed: {name}",
        )
    schemas = {name: strict_load(ROOT / bindings[name]["file"]) for name in MESSAGE_SCHEMA_FILES}
    fixtures = {name: strict_load(ROOT / bindings[name]["fixture"]) for name in MESSAGE_FIXTURE_FILES}
    return schemas, fixtures


def load_duckdb_row_contract(policy: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    expected = {
        "row_schema": "cheesewaf/audit-event-row/v1",
        "row_schema_file": str(DUCKDB_ROW_SCHEMA_PATH.relative_to(ROOT)),
        "row_fixture": str(DUCKDB_ROW_FIXTURE_PATH.relative_to(ROOT)),
    }
    duckdb_policy = policy.get("duckdb")
    _assert(isinstance(duckdb_policy, dict), "DuckDB policy is missing")
    for field, value in expected.items():
        _assert(duckdb_policy.get(field) == value, f"DuckDB row schema binding changed: {field}")
    return strict_load(ROOT / expected["row_schema_file"]), strict_load(ROOT / expected["row_fixture"])


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
        _assert(set(config) == {"provider", "version_range", "artifact_policy", "persistent_database", "query_policy_ref"}, f"{label}: DuckDB config has unexpected fields")
        _assert(config["provider"] == policy["duckdb"]["provider"], f"{label}: analytics provider must be DuckDB")
        _assert(config["artifact_policy"] == policy["duckdb"]["artifact_policy"], f"{label}: DuckDB binary must be host-provided")
        _assert(config["persistent_database"] is False, f"{label}: DuckDB must not persist a writable database")
        _assert(config["query_policy_ref"] == policy["duckdb"]["query_policy_ref"], f"{label}: DuckDB query policy is not bound")
        _assert(network["mode"] == "deny" and network["allowed_targets"] == [], f"{label}: analytics must deny egress")
        _assert(lease == {"required": False, "max_ttl_seconds": 0, "max_requests": 0, "max_bytes": 0}, f"{label}: analytics must not request a lease")
        _assert(instance["input"]["schema"] == policy["duckdb"]["required_input_schema"], f"{label}: DuckDB input schema changed")
        _assert(instance["input"]["data_class"] == policy["duckdb"]["required_data_class"], f"{label}: DuckDB data class changed")
        _assert(policy.get("duckdb_execution") == DUCKDB_EXECUTION_PROFILE, f"{label}: DuckDB execution isolation or limits changed")
        _assert(config["query_policy_ref"] == DUCKDB_EXECUTION_PROFILE["profile_id"], f"{label}: DuckDB execution profile reference changed")
        _assert(instance["output"]["max_bytes"] == DUCKDB_EXECUTION_PROFILE["limits"]["max_output_bytes"], f"{label}: DuckDB output byte limit is not bound")
        _assert(
            instance["resources"]
            == {
                "cpu_milli": DUCKDB_EXECUTION_PROFILE["limits"]["cpu_milli"],
                "memory_bytes": DUCKDB_EXECUTION_PROFILE["limits"]["process_memory_bytes"],
                "pids": DUCKDB_EXECUTION_PROFILE["limits"]["pids"],
            },
            f"{label}: DuckDB process resource limits are not bound",
        )
    else:  # pragma: no cover - schema validation catches this first.
        raise ValueError(f"{label}: unsupported deployment")


def _parse_datetime(value: str, label: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label}: invalid date-time {value!r}") from exc


def validate_messages(
    policy: dict[str, Any],
    descriptors: list[dict[str, Any]],
    schemas: dict[str, dict[str, Any]] | None = None,
    fixtures: dict[str, dict[str, Any]] | None = None,
) -> None:
    if schemas is None or fixtures is None:
        loaded_schemas, loaded_fixtures = load_message_contracts(policy)
        schemas = loaded_schemas if schemas is None else schemas
        fixtures = loaded_fixtures if fixtures is None else fixtures
    bindings = policy.get("messages")
    _assert(isinstance(bindings, dict), "extension policy must bind message schemas")
    _assert(set(bindings) == set(MESSAGE_SCHEMA_FILES), "message schema bindings are incomplete")
    _assert(set(schemas) == set(MESSAGE_SCHEMA_FILES), "message schema set is incomplete")
    _assert(set(fixtures) == set(MESSAGE_FIXTURE_FILES), "message fixture set is incomplete")
    for name in MESSAGE_SCHEMA_FILES:
        _assert(
            bindings[name]
            == {
                "schema": f"cheesewaf/{name.replace('_', '-')}/v1" if name != "waf_security_event" else "cheesewaf/waf-security-event/v1",
                "file": str(MESSAGE_SCHEMA_FILES[name].relative_to(ROOT)),
                "fixture": str(MESSAGE_FIXTURE_FILES[name].relative_to(ROOT)),
            },
            f"message policy binding changed: {name}",
        )

    for name, schema in schemas.items():
        binding = bindings[name]
        try:
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            raise ValueError(f"message schema {name} is invalid: {exc}") from exc
        _assert(schema["properties"]["api_version"]["const"] == binding["schema"], f"message binding changed: {name}")
        fixture = fixtures[name]
        schema_validate(fixture, schema, f"message fixture {name}")
        _assert(fixture["api_version"] == binding["schema"], f"message fixture api_version changed: {name}")

    row_schema, row_fixture = load_duckdb_row_contract(policy)
    try:
        Draft202012Validator.check_schema(row_schema)
    except Exception as exc:
        raise ValueError(f"DuckDB row schema is invalid: {exc}") from exc
    schema_validate(row_fixture, row_schema, "DuckDB audit event row fixture")

    risk_hint = fixtures["risk_hint"]
    _assert(
        _parse_datetime(risk_hint["observed_at"], "risk_hint.observed_at")
        < _parse_datetime(risk_hint["expires_at"], "risk_hint.expires_at"),
        "risk_hint expires_at must be after observed_at",
    )
    risk_producer = next(item for item in descriptors if item["plugin_id"] == risk_hint["plugin_id"])
    hint_ttl = _parse_datetime(risk_hint["expires_at"], "risk_hint.expires_at") - _parse_datetime(
        risk_hint["observed_at"], "risk_hint.observed_at"
    )
    _assert(
        hint_ttl.total_seconds() <= risk_producer["output"]["ttl_seconds"],
        "risk_hint validity exceeds the producer descriptor ttl_seconds",
    )
    analysis_record = fixtures["analysis_record"]
    _assert(
        _parse_datetime(analysis_record["window"]["from"], "analysis_record.window.from")
        < _parse_datetime(analysis_record["window"]["to"], "analysis_record.window.to"),
        "analysis_record window.to must be after window.from",
    )

    snapshot = fixtures["audit_parquet"]
    snapshot_start = _parse_datetime(snapshot["window"]["from"], "audit_parquet.window.from")
    snapshot_end = _parse_datetime(snapshot["window"]["to"], "audit_parquet.window.to")
    _assert(snapshot_start < snapshot_end, "audit_parquet window.to must be after window.from")
    _assert(
        _parse_datetime(snapshot["created_at"], "audit_parquet.created_at") >= snapshot_end,
        "audit_parquet snapshot must be created after its data window",
    )
    file_refs: set[str] = set()
    for file_record in snapshot["files"]:
        _assert(file_record["file_ref"] not in file_refs, "audit_parquet file_ref values must be unique")
        file_refs.add(file_record["file_ref"])
        file_start = _parse_datetime(file_record["window"]["from"], "audit_parquet file.window.from")
        file_end = _parse_datetime(file_record["window"]["to"], "audit_parquet file.window.to")
        _assert(snapshot_start <= file_start < file_end <= snapshot_end, "audit_parquet file window is outside the snapshot window")
    _assert(sum(item["row_count"] for item in snapshot["files"]) == snapshot["total_row_count"], "audit_parquet total row count does not match file manifests")

    by_plugin = {descriptor["plugin_id"]: descriptor for descriptor in descriptors}
    _assert(risk_hint["plugin_id"] in by_plugin, "risk hint plugin is not declared")
    _assert(
        bindings["risk_hint"]["schema"] in by_plugin[risk_hint["plugin_id"]]["output"]["schemas"],
        "risk hint plugin does not declare risk-hint output",
    )
    edr = by_plugin.get("edr-waf-correlation")
    _assert(edr is not None, "EDR descriptor is not declared")
    _assert(edr["input"]["schema"] == bindings["waf_security_event"]["schema"], "EDR input is not the WAF event schema")
    duckdb = by_plugin.get("duckdb-analysis")
    _assert(duckdb is not None, "DuckDB descriptor is not declared")
    _assert(
        bindings["analysis_record"]["schema"] in duckdb["output"]["schemas"],
        "DuckDB plugin does not declare analysis-record output",
    )
    _assert(analysis_record["plugin_id"] == duckdb["plugin_id"], "analysis record plugin is not DuckDB")
    _assert(duckdb["input"]["schema"] == bindings["audit_parquet"]["schema"], "DuckDB input is not the snapshot manifest schema")
    _assert(snapshot["row_schema"] == policy["duckdb"]["row_schema"], "audit snapshot row schema changed")
    _assert(snapshot["columns"] == list(row_schema["properties"]), "audit snapshot column set/order does not match the row schema")
    _assert(row_fixture["tenant_ref"] == snapshot["tenant_ref"], "audit row tenant does not match the snapshot")
    _assert(row_fixture["site_ref"] in snapshot["site_refs"], "audit row site is outside the snapshot scope")
    row_time = _parse_datetime(row_fixture["occurred_at"], "audit_event_row.occurred_at")
    _assert(snapshot_start <= row_time < snapshot_end, "audit row timestamp is outside the snapshot window")
    _assert(analysis_record["snapshot_ref"] == snapshot["snapshot_id"], "analysis record does not bind the input snapshot")
    _assert(
        sum(item["compressed_bytes"] for item in snapshot["files"]) <= duckdb["input"]["max_bytes"],
        "audit snapshot exceeds the DuckDB descriptor input byte limit",
    )


def validate_contracts() -> list[str]:
    schema, policy, descriptors = load_contracts()
    schema_validate(policy, {"type": "object"}, "extension policy")
    _assert(policy["api_version"] == schema["properties"]["api_version"]["const"], "extension policy api_version is not bound")
    _assert(policy["crp_v1_unchanged"] is True, "extension policy must preserve CRP v1")
    _assert(policy["direct_actions"] == [], "extension policy must forbid direct actions")
    _assert(policy["duckdb"]["query_policy_ref"] == DUCKDB_EXECUTION_PROFILE["profile_id"], "DuckDB policy reference is not bound")
    _assert(len(descriptors) == 4, "expected four planned extension descriptors")
    ids: set[str] = set()
    for descriptor in descriptors:
        descriptor_id = descriptor["descriptor_id"]
        _assert(descriptor_id not in ids, f"duplicate descriptor_id: {descriptor_id}")
        ids.add(descriptor_id)
        validate_descriptor(descriptor, schema, policy)
    message_schemas, message_fixtures = load_message_contracts(policy)
    validate_messages(policy, descriptors, message_schemas, message_fixtures)
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
