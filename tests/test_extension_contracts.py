#!/usr/bin/env python3
"""Tests for the planned Jev, EDR and DuckDB extension contracts."""
from __future__ import annotations

import copy
import importlib
import unittest


def contract_module():
    module = importlib.import_module("scripts.validate_extension_contracts")
    return module


class ExtensionContractTests(unittest.TestCase):
    def test_all_planned_descriptors_pass(self) -> None:
        ids = contract_module().validate_contracts()
        self.assertEqual(
            ids,
            [
                "official-duckdb-analysis-1.0.0",
                "official-edr-waf-correlation-1.0.0",
                "official-jev-lite-local-1.0.0",
                "official-jev-typesafe-online-1.0.0",
            ],
        )

    def test_hosted_jev_cannot_become_direct_or_unbounded(self) -> None:
        module = contract_module()
        schema, policy, descriptors = module.load_contracts()
        hosted = next(item for item in descriptors if item["deployment"] == "hosted-api")
        hosted["network"]["mode"] = "deny"
        with self.assertRaises(ValueError):
            module.validate_descriptor(hosted, schema, policy)

        schema, policy, descriptors = module.load_contracts()
        hosted = next(item for item in descriptors if item["deployment"] == "hosted-api")
        hosted["output"]["direct_actions"] = ["block"]
        with self.assertRaises(ValueError):
            module.validate_descriptor(hosted, schema, policy)

    def test_local_and_analytics_profiles_cannot_gain_egress(self) -> None:
        module = contract_module()
        schema, policy, descriptors = module.load_contracts()
        for deployment in ("local-lite", "local-sidecar", "host-provided"):
            descriptor = next(item for item in descriptors if item["deployment"] == deployment)
            mutated = copy.deepcopy(descriptor)
            mutated["network"]["mode"] = "brokered"
            with self.assertRaises(ValueError, msg=deployment):
                module.validate_descriptor(mutated, schema, policy)

    def test_duckdb_must_be_host_provided_and_read_only(self) -> None:
        module = contract_module()
        schema, policy, descriptors = module.load_contracts()
        duckdb = next(item for item in descriptors if item["class"] == "analytics")
        mutated = copy.deepcopy(duckdb)
        mutated["deployment_config"]["database_read_only"] = False
        with self.assertRaises(ValueError):
            module.validate_descriptor(mutated, schema, policy)

        mutated = copy.deepcopy(duckdb)
        mutated["deployment"] = "local-sidecar"
        with self.assertRaises(ValueError):
            module.validate_descriptor(mutated, schema, policy)

    def test_message_contracts_bind_to_descriptors(self) -> None:
        module = contract_module()
        schema, policy, descriptors = module.load_contracts()
        schemas, fixtures = module.load_message_contracts()
        module.validate_messages(policy, descriptors, schemas, fixtures)

    def test_message_contracts_reject_invalid_time_windows_and_raw_fields(self) -> None:
        module = contract_module()
        _, policy, descriptors = module.load_contracts()
        schemas, fixtures = module.load_message_contracts()

        mutated = copy.deepcopy(fixtures)
        mutated["risk_hint"]["expires_at"] = mutated["risk_hint"]["observed_at"]
        with self.assertRaises(ValueError):
            module.validate_messages(policy, descriptors, schemas, mutated)

        mutated = copy.deepcopy(fixtures)
        mutated["analysis_record"]["window"]["from"] = mutated["analysis_record"]["window"]["to"]
        with self.assertRaises(ValueError):
            module.validate_messages(policy, descriptors, schemas, mutated)

        mutated = copy.deepcopy(fixtures["waf_security_event"])
        mutated["metadata"]["raw_request_body"] = "forbidden"
        with self.assertRaises(ValueError):
            module.schema_validate(mutated, schemas["waf_security_event"], "mutated WAF event")

if __name__ == "__main__":
    unittest.main()
