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
            ["official-dingtalk-bot-1.0.0", "official-email-smtp-1.0.0", "official-feishu-bot-1.0.0"],
        )

    def test_provider_packs_cover_distinct_types(self) -> None:
        module = contract_module()
        types = {
            module.strict_load(path)["type"]
            for path in module.provider_pack_paths()
        }
        self.assertEqual(types, {"dingtalk", "feishu", "email"})

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
