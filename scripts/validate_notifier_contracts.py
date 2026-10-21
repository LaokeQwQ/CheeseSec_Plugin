#!/usr/bin/env python3
"""Validate the planned, descriptor-only notifier provider contract."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "extensions-v1" / "notifier-provider.schema.json"
POLICY_PATH = ROOT / "policy" / "notifier-providers.json"
EXAMPLE_PATH = ROOT / "examples" / "extensions" / "notifier-provider.json"
EXPECTED_SCHEMA_ID = "https://store.cheesesec.com/schema/extensions/v1/notifier-provider.schema.json"
EXPECTED_API_VERSION = "crp.cheesewaf.io/notifier/v1"
EXPECTED_SIDECAR_CAPABILITIES = ["observe", "candidate_snapshot", "hint", "health"]
EXPECTED_PUBLICATION = {"status": "planned", "installable": False, "crp_binding": "descriptor-only"}
PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]{0,63})\}")
URL_LITERAL_TOKEN = re.compile(r"[A-Za-z0-9]{32,}")


def strict_load(path: Path) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{path}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def schema_validate(instance: Any, schema: dict[str, Any], label: str) -> None:
    Draft202012Validator.check_schema(schema)
    errors = sorted(
        Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(instance),
        key=lambda error: list(error.path),
    )
    if errors:
        path = ".".join(str(part) for part in errors[0].path)
        raise ValueError(f"{label}: {path + ': ' if path else ''}{errors[0].message}")


def validate_policy(policy: dict[str, Any], schema: dict[str, Any]) -> None:
    properties = schema["properties"]
    _assert(schema.get("$id") == EXPECTED_SCHEMA_ID, "notifier provider schema id changed")
    _assert(properties["api_version"]["const"] == EXPECTED_API_VERSION, "notifier api_version changed")
    _assert(policy["api_version"] == EXPECTED_API_VERSION, "notifier policy api_version changed")
    _assert(policy["status"] == "planned", "notifier providers must stay planned")
    _assert(policy["contract_only"] is True, "notifier providers must stay contract-only")
    _assert(policy["crp_v1_unchanged"] is True, "notifier providers must not change CRP v1")
    _assert(policy["crp_binding"] == "descriptor-only", "notifier providers must stay descriptor-only")
    _assert(policy["installable"] is False, "notifier provider packs must not be installable")
    _assert(policy["executable"] is False, "notifier provider packs must not be executable")
    _assert(policy["runtime_capability_grant"] is False, "notifier provider packs must not grant runtime capability")
    _assert(
        set(policy["allowed_types"]) == set(properties["type"]["enum"]),
        "notifier policy provider types do not match the schema",
    )
    _assert(set(policy["capabilities"]) == set(properties["capabilities"]["items"]["enum"]), "notifier capability set changed")
    for capability, grant in policy["capabilities"].items():
        _assert(grant == "core-owned-delivery-only", f"capability {capability} must stay core-owned")

    egress = policy["egress"]
    _assert(egress["owner"] == "cheesewaf-core", "notifier egress must be owned by the CheeseWAF core")
    _assert(egress["plugin_egress"] == "deny", "notifier provider packs must not gain network egress")
    _assert(egress["sidecar_capabilities"] == EXPECTED_SIDECAR_CAPABILITIES, "v1 sidecar capability set changed")
    _assert(egress["notification_capability"] == "unsupported-in-crp-v1", "CRP v1 must not claim notification support")
    _assert(egress["transport"] == "https-only-when-credentials-configured", "notifier credential transport changed")
    _assert(egress["private_endpoint_default"] is False, "private notifier endpoints must stay opt-in")

    core = policy["core_config"]
    _assert(core["section"] == "notifiers", "notifier core configuration section changed")
    _assert(core["secret_fields"] == ["token"], "notifier core credential field changed")
    _assert(set(core["secret_fields"]) <= set(core["fields"]), "notifier secret fields are not core config fields")
    _assert(core["delivery_path"] == "asynchronous", "notifier delivery must stay asynchronous")
    _assert(core["blocks_waf_request_thread"] is False, "notifier delivery must not block WAF request threads")

    for field in ("executable", "container_image", "wasm", "in_process_module", "network_egress", "sidecar_runtime"):
        _assert(field in policy["forbidden"], f"notifier policy must forbid {field}")

    limits = policy["limits"]
    config = properties["config_schema"]["properties"]["fields"]
    templates = properties["endpoint_templates"]["items"]
    _assert(limits["max_config_fields"] == config["maxItems"], "config field limit is not bound to the schema")
    _assert(limits["max_secret_fields"] == properties["secret_fields"]["maxItems"], "secret field limit is not bound")
    _assert(limits["max_endpoint_templates"] == properties["endpoint_templates"]["maxItems"], "template count limit is not bound")
    _assert(limits["max_template_bytes"] == templates["properties"]["url_template"]["maxLength"], "template size limit is not bound")
    _assert(limits["max_capabilities"] == properties["capabilities"]["maxItems"], "capability limit is not bound")
    _assert(policy["provider_pack_schema"] == str(SCHEMA_PATH.relative_to(ROOT)), "notifier schema path changed")
    _assert(policy["provider_pack_example"] == str(EXAMPLE_PATH.relative_to(ROOT)), "notifier example path changed")


def validate_provider(provider: dict[str, Any], schema: dict[str, Any], policy: dict[str, Any]) -> None:
    label = str(provider.get("provider_id", "notifier provider"))
    schema_validate(provider, schema, label)
    _assert(provider["publication"] == EXPECTED_PUBLICATION, f"{label}: notifier provider is not planned and descriptor-only")
    _assert(provider["type"] in policy["allowed_types"], f"{label}: provider type is not allowed")

    fields = {field["name"] for field in provider["config_schema"]["fields"]}
    secrets = set(provider["secret_fields"])
    _assert(len(fields) == len(provider["config_schema"]["fields"]), f"{label}: duplicate config field")
    _assert(len(secrets) == len(provider["secret_fields"]), f"{label}: duplicate secret field")
    _assert(not (fields & secrets), f"{label}: a field cannot be both non-secret and secret")
    declared = fields | secrets

    template_names: set[str] = set()
    for template in provider["endpoint_templates"]:
        name = template["name"]
        _assert(name not in template_names, f"{label}: duplicate endpoint template {name}")
        template_names.add(name)
        url = template["url_template"]
        _assert(url.startswith("https://"), f"{label}: endpoint template {name} must use HTTPS")
        _assert(template["egress_owner"] == policy["egress"]["owner"], f"{label}: {name} egress must be owned by the core")
        placeholders = set(PLACEHOLDER.findall(url))
        _assert(placeholders == set(template["variables"]), f"{label}: {name} placeholders do not match declared variables")
        _assert(placeholders <= declared, f"{label}: {name} references an undeclared config or secret field")
        _assert("token" not in url.lower() and "secret" not in url.lower(), f"{label}: {name} embeds a credential name")
        _assert(URL_LITERAL_TOKEN.search(url) is None, f"{label}: {name} embeds a literal credential")
    if provider["type"] != "email":
        _assert("notify" in template_names, f"{label}: provider must declare a notify template")
    _assert(
        set(provider["capabilities"]) <= set(policy["capabilities"]),
        f"{label}: provider claims an unsupported capability",
    )


def validate_contracts() -> list[str]:
    schema = strict_load(SCHEMA_PATH)
    policy = strict_load(POLICY_PATH)
    example = strict_load(EXAMPLE_PATH)
    schema_validate(policy, {"type": "object"}, "notifier provider policy")
    validate_policy(policy, schema)
    validate_provider(example, schema, policy)
    return sorted(provider["provider_id"] for provider in (example,))


def main() -> int:
    try:
        ids = validate_contracts()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"notifier contract validation failed: {exc}")
        return 1
    print(f"planned notifier provider contracts passed: {', '.join(ids)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
