#!/usr/bin/env python3
"""Tests for the planned, descriptor-only notifier provider contract."""
from __future__ import annotations

import copy
import importlib
import unittest


def contract_module():
    return importlib.import_module("scripts.validate_notifier_contracts")


class NotifierContractTests(unittest.TestCase):
    def test_example_passes(self) -> None:
        self.assertEqual(contract_module().validate_contracts(), ["official-feishu-bot-1.0.0"])

    def test_provider_cannot_become_installable(self) -> None:
        module = contract_module()
        schema, policy, provider = module.strict_load(module.SCHEMA_PATH), module.strict_load(module.POLICY_PATH), module.strict_load(module.EXAMPLE_PATH)
        for field, value in (("installable", True), ("crp_binding", "crp-v1"), ("status", "released")):
            mutated = copy.deepcopy(provider)
            mutated["publication"][field] = value
            with self.assertRaises(ValueError, msg=field):
                module.validate_provider(mutated, schema, policy)

    def test_provider_type_must_stay_in_the_policy_set(self) -> None:
        module = contract_module()
        schema, policy, provider = module.strict_load(module.SCHEMA_PATH), module.strict_load(module.POLICY_PATH), module.strict_load(module.EXAMPLE_PATH)
        mutated = copy.deepcopy(provider)
        mutated["type"] = "sms"
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

    def test_provider_cannot_carry_an_executable_or_secret(self) -> None:
        module = contract_module()
        schema, policy, provider = module.strict_load(module.SCHEMA_PATH), module.strict_load(module.POLICY_PATH), module.strict_load(module.EXAMPLE_PATH)
        for field, value in (("executable", "notifier"), ("token", "plaintext"), ("sidecar_root", "/tmp/pack")):
            mutated = copy.deepcopy(provider)
            mutated[field] = value
            with self.assertRaises(ValueError, msg=field):
                module.validate_provider(mutated, schema, policy)

    def test_endpoint_template_must_be_https_and_owned_by_the_core(self) -> None:
        module = contract_module()
        schema, policy, provider = module.strict_load(module.SCHEMA_PATH), module.strict_load(module.POLICY_PATH), module.strict_load(module.EXAMPLE_PATH)

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
        schema, policy, provider = module.strict_load(module.SCHEMA_PATH), module.strict_load(module.POLICY_PATH), module.strict_load(module.EXAMPLE_PATH)

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
        schema, policy, provider = module.strict_load(module.SCHEMA_PATH), module.strict_load(module.POLICY_PATH), module.strict_load(module.EXAMPLE_PATH)

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
        schema, policy, provider = module.strict_load(module.SCHEMA_PATH), module.strict_load(module.POLICY_PATH), module.strict_load(module.EXAMPLE_PATH)

        mutated = copy.deepcopy(provider)
        mutated["type"] = "email"
        mutated["endpoint_templates"] = []
        module.validate_provider(mutated, schema, policy)

        mutated = copy.deepcopy(provider)
        mutated["endpoint_templates"] = []
        with self.assertRaises(ValueError):
            module.validate_provider(mutated, schema, policy)

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
