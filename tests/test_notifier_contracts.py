#!/usr/bin/env python3
"""Tests for the planned, descriptor-only notifier provider contracts."""
from __future__ import annotations

import copy
import importlib
import unittest
from unittest import mock


def contract_module():
    return importlib.import_module("scripts.validate_notifier_contracts")


def legacy_fixture(module):
    return (
        module.strict_load(module.SCHEMA_PATH),
        module.strict_load(module.POLICY_PATH),
        module.strict_load(module.EXAMPLE_PATH),
    )


def pack_fixture(module, name):
    return (
        module.strict_load(module.SCHEMA_PATH),
        module.strict_load(module.POLICY_PATH),
        module.strict_load(module.PROVIDER_PACK_DIR / f"{name}.json"),
    )


class NotifierContractTests(unittest.TestCase):
    def test_provider_packs_pass(self) -> None:
        self.assertEqual(
            contract_module().validate_contracts(),
            [
                "official-datadog-events-1.0.0",
                "official-dingtalk-bot-1.0.0",
                "official-email-smtp-1.0.0",
                "official-feishu-bot-1.0.0",
                "official-flashcat-flashduty-1.0.0",
                "official-grafana-alertmanager-1.0.0",
                "official-nightingale-pipeline-1.0.0",
            ],
        )

    def test_provider_packs_cover_distinct_types(self) -> None:
        module = contract_module()
        types = {
            module.strict_load(path)["type"]
            for path in module.provider_pack_paths()
        }
        self.assertEqual(
            types,
            {"dingtalk", "feishu", "email", "datadog", "grafana", "flashcat", "nightingale"},
        )

    def test_legacy_feishu_example_still_passes(self) -> None:
        module = contract_module()
        schema, policy, provider = legacy_fixture(module)
        module.validate_provider(provider, schema, policy)
        self.assertEqual(provider["provider_id"], "official-feishu-bot-1.0.0")
        self.assertEqual(provider["secret_fields"], ["webhook_ref"])

    def test_dingtalk_token_parameter_may_use_a_declared_placeholder(self) -> None:
        module = contract_module()
        schema, policy, provider = pack_fixture(module, "dingtalk")
        module.validate_provider(provider, schema, policy)
        self.assertEqual(
            provider["endpoint_templates"][0]["url_template"],
            "https://oapi.dingtalk.com/robot/send?access_token={webhook_ref}",
        )

    def test_credential_parameter_must_bind_a_declared_placeholder(self) -> None:
        module = contract_module()
        schema, policy, provider = pack_fixture(module, "dingtalk")

        mutated = copy.deepcopy(provider)
        mutated["endpoint_templates"][0]["url_template"] = (
            "https://oapi.dingtalk.com/robot/send?access_token={webhook_ref}&sign=deadbeefcafe"
        )
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

        mutated = copy.deepcopy(provider)
        mutated["endpoint_templates"][0]["url_template"] = (
            "https://oapi.dingtalk.com/robot/send?access_token=" + "a" * 40
        )
        mutated["endpoint_templates"][0]["variables"] = []
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

        mutated = copy.deepcopy(provider)
        mutated["endpoint_templates"][0]["url_template"] = (
            "https://oapi.dingtalk.com/robot/send?access_token={target_name}"
        )
        mutated["endpoint_templates"][0]["variables"] = ["target_name"]
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

        mutated = copy.deepcopy(provider)
        mutated["endpoint_templates"][0]["url_template"] = (
            "https://oapi.dingtalk.com/robot/send?access_token={undeclared_ref}"
        )
        mutated["endpoint_templates"][0]["variables"] = ["undeclared_ref"]
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

    def test_duplicate_provider_ids_are_rejected(self) -> None:
        module = contract_module()
        path = module.PROVIDER_PACK_DIR / "feishu.json"
        with mock.patch.object(module, "provider_pack_paths", return_value=[path, path]):
            with self.assertRaises(ValueError):
                module.validate_contracts()

    def test_provider_cannot_become_installable(self) -> None:
        module = contract_module()
        schema, policy, provider = legacy_fixture(module)
        for field, value in (("installable", True), ("crp_binding", "crp-v1"), ("status", "released")):
            mutated = copy.deepcopy(provider)
            mutated["publication"][field] = value
            with self.assertRaises(ValueError, msg=field):
                module.validate_provider(mutated, schema, policy)

    def test_provider_type_must_stay_in_the_policy_set(self) -> None:
        module = contract_module()
        schema, policy, provider = legacy_fixture(module)
        mutated = copy.deepcopy(provider)
        mutated["type"] = "sms"
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

    def test_provider_cannot_carry_an_executable_or_secret(self) -> None:
        module = contract_module()
        schema, policy, provider = legacy_fixture(module)
        for field, value in (("executable", "notifier"), ("token", "plaintext"), ("sidecar_root", "/tmp/pack")):
            mutated = copy.deepcopy(provider)
            mutated[field] = value
            with self.assertRaises(ValueError, msg=field):
                module.validate_provider(mutated, schema, policy)

    def test_endpoint_template_must_be_https_and_owned_by_the_core(self) -> None:
        module = contract_module()
        schema, policy, provider = legacy_fixture(module)

        mutated = copy.deepcopy(provider)
        mutated["endpoint_templates"][0]["url_template"] = "http://open.feishu.cn/open-apis/bot/v2/hook/{webhook_ref}"
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

        mutated = copy.deepcopy(provider)
        mutated["endpoint_templates"][0]["egress_owner"] = "plugin"
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

    def test_placeholders_must_be_declared_fields(self) -> None:
        module = contract_module()
        schema, policy, provider = legacy_fixture(module)

        mutated = copy.deepcopy(provider)
        mutated["endpoint_templates"][0]["url_template"] = "https://open.feishu.cn/open-apis/bot/v2/hook/{undeclared_ref}"
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

        mutated = copy.deepcopy(provider)
        mutated["config_schema"]["fields"].append(
            {"name": "webhook_ref", "kind": "string", "required": False, "max_length": 64}
        )
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

    def test_secret_fields_are_references_not_values(self) -> None:
        module = contract_module()
        schema, policy, provider = legacy_fixture(module)

        mutated = copy.deepcopy(provider)
        mutated["secret_fields"] = ["a" * 64]
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

        mutated = copy.deepcopy(provider)
        mutated["endpoint_templates"][0]["url_template"] = "https://open.feishu.cn/open-apis/bot/v2/hook/" + "a" * 40
        mutated["endpoint_templates"][0]["variables"] = []
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

    def test_email_may_declare_no_http_template(self) -> None:
        module = contract_module()
        schema, policy, provider = legacy_fixture(module)

        mutated = copy.deepcopy(provider)
        mutated["type"] = "email"
        mutated["endpoint_templates"] = []
        module.validate_provider(mutated, schema, policy)

        mutated = copy.deepcopy(provider)
        mutated["endpoint_templates"] = []
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

    def test_email_pack_declares_smtp_fields_and_no_template(self) -> None:
        module = contract_module()
        schema, policy, provider = pack_fixture(module, "email")
        module.validate_provider(provider, schema, policy)
        fields = {field["name"] for field in provider["config_schema"]["fields"]}
        self.assertTrue({"smtp_host", "smtp_port", "from", "to", "tls_mode", "subject_prefix"} <= fields)
        self.assertEqual(provider["secret_fields"], ["password_ref"])
        self.assertEqual(provider["endpoint_templates"], [])

    def test_new_provider_types_are_allowed_by_policy_and_schema(self) -> None:
        module = contract_module()
        schema = module.strict_load(module.SCHEMA_PATH)
        policy = module.strict_load(module.POLICY_PATH)
        module.validate_policy(policy, schema)
        for provider_type in ("datadog", "grafana", "flashcat", "nightingale"):
            with self.subTest(provider_type=provider_type):
                self.assertIn(provider_type, schema["properties"]["type"]["enum"])
                self.assertIn(provider_type, policy["allowed_types"])

    def test_new_packs_stay_planned_and_non_installable(self) -> None:
        module = contract_module()
        for name in ("datadog", "grafana", "flashcat", "nightingale"):
            with self.subTest(pack=name):
                _, _, provider = pack_fixture(module, name)
                self.assertEqual(
                    provider["publication"],
                    {"status": "planned", "installable": False, "crp_binding": "descriptor-only"},
                )

    def test_datadog_api_key_parameter_must_bind_the_declared_secret_reference(self) -> None:
        module = contract_module()
        schema, policy, provider = pack_fixture(module, "datadog")
        module.validate_provider(provider, schema, policy)
        self.assertEqual(provider["secret_fields"], ["api_key_ref"])

        mutated = copy.deepcopy(provider)
        mutated["endpoint_templates"][0]["url_template"] = (
            "https://event-management-intake.datadoghq.com/api/v2/events?api_key={api_key_ref}"
        )
        mutated["endpoint_templates"][0]["variables"] = ["api_key_ref"]
        module.validate_provider(mutated, schema, policy)

        mutated = copy.deepcopy(provider)
        mutated["endpoint_templates"][0]["url_template"] = (
            "https://event-management-intake.datadoghq.com/api/v2/events?api_key={status}"
        )
        mutated["endpoint_templates"][0]["variables"] = ["status"]
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

    def test_flashcat_integration_key_cannot_be_a_literal(self) -> None:
        module = contract_module()
        schema, policy, provider = pack_fixture(module, "flashcat")
        module.validate_provider(provider, schema, policy)
        self.assertEqual(provider["secret_fields"], ["integration_key_ref"])

        mutated = copy.deepcopy(provider)
        mutated["endpoint_templates"][0]["url_template"] = (
            "https://api.flashcat.cloud/event/push/alert/standard?integration_key=" + "a" * 40
        )
        mutated["endpoint_templates"][0]["variables"] = []
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

        mutated = copy.deepcopy(provider)
        mutated["endpoint_templates"][0]["url_template"] = (
            "https://api.flashcat.cloud/event/push/alert/standard?integration_key={integration_key_token}"
        )
        mutated["endpoint_templates"][0]["variables"] = ["integration_key_token"]
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

    def test_self_hosted_packs_declare_their_host_and_path_variables(self) -> None:
        module = contract_module()
        hosts = {"grafana": "grafana_host", "nightingale": "n9e_host"}
        for name, host in hosts.items():
            with self.subTest(pack=name):
                schema, policy, provider = pack_fixture(module, name)
                module.validate_provider(provider, schema, policy)
                fields = {
                    field["name"]: field["kind"]
                    for field in provider["config_schema"]["fields"]
                }
                self.assertEqual(fields[host], "endpoint")
                for template in provider["endpoint_templates"]:
                    self.assertTrue(template["url_template"].startswith("https://{"))
                    self.assertLessEqual(set(template["variables"]), set(fields))

    def test_policy_cannot_grant_runtime_or_egress(self) -> None:
        module = contract_module()
        schema, policy = module.strict_load(module.SCHEMA_PATH), module.strict_load(module.POLICY_PATH)

        mutated = copy.deepcopy(policy)
        mutated["runtime_capability_grant"] = True
        with self.assertRaises(ValueError):
            module.validate_policy(mutated, schema)

        mutated = copy.deepcopy(policy)
        mutated["egress"]["plugin_egress"] = "brokered"
        with self.assertRaises(ValueError):
            module.validate_policy(mutated, schema)

        mutated = copy.deepcopy(policy)
        mutated["egress"]["notification_capability"] = "supported-in-crp-v1"
        with self.assertRaises(ValueError):
            module.validate_policy(mutated, schema)

        mutated = copy.deepcopy(policy)
        mutated["installable"] = True
        with self.assertRaises(ValueError):
            module.validate_policy(mutated, schema)


if __name__ == "__main__":
    unittest.main()
