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
        mutated["deployment_config"]["persistent_database"] = True
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
        schemas, fixtures = module.load_message_contracts(policy)

        mutated = copy.deepcopy(fixtures)
        mutated["risk_hint"]["expires_at"] = mutated["risk_hint"]["observed_at"]
        with self.assertRaises(ValueError):
            module.validate_messages(policy, descriptors, schemas, mutated)

        mutated = copy.deepcopy(fixtures)
        mutated["audit_parquet"]["files"][0]["compressed_bytes"] = 104857601
        with self.assertRaises(ValueError):
            module.validate_messages(policy, descriptors, schemas, mutated)

        mutated = copy.deepcopy(fixtures)
        mutated["audit_parquet"]["total_row_count"] = 5
        with self.assertRaises(ValueError):
            module.validate_messages(policy, descriptors, schemas, mutated)

        mutated = copy.deepcopy(fixtures)
        mutated["audit_parquet"]["files"][0]["path"] = "/etc/passwd"
        with self.assertRaises(ValueError):
            module.validate_messages(policy, descriptors, schemas, mutated)

        mutated = copy.deepcopy(fixtures)
        mutated["audit_parquet"]["columns"].append("raw_request_body")
        with self.assertRaises(ValueError):
            module.validate_messages(policy, descriptors, schemas, mutated)

        mutated = copy.deepcopy(fixtures)
        mutated["risk_hint"]["expires_at"] = "2026-10-01T10:00:00Z"
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

    def test_message_policy_paths_are_bound_to_validated_files(self) -> None:
        module = contract_module()
        _, policy, descriptors = module.load_contracts()
        mutated = copy.deepcopy(policy)
        mutated["messages"]["risk_hint"]["file"] = "../../outside.json"
        with self.assertRaises(ValueError):
            module.load_message_contracts(mutated)
        with self.assertRaises(ValueError):
            module.validate_messages(mutated, descriptors)

    def test_duckdb_requires_the_fixed_isolated_query_profile(self) -> None:
        module = contract_module()
        schema, policy, descriptors = module.load_contracts()
        duckdb = next(item for item in descriptors if item["class"] == "analytics")
        mutated = copy.deepcopy(policy)
        mutated["duckdb_execution"]["allow_arbitrary_sql"] = True
        with self.assertRaises(ValueError):
            module.validate_descriptor(duckdb, schema, mutated)

    def test_duckdb_row_schema_rejects_sensitive_columns_and_scope_escape(self) -> None:
        module = contract_module()
        _, policy, descriptors = module.load_contracts()
        schemas, fixtures = module.load_message_contracts(policy)
        row_schema, row_fixture = module.load_duckdb_row_contract(policy)
        mutated_row = copy.deepcopy(row_fixture)
        mutated_row["raw_request_body"] = "forbidden"
        with self.assertRaises(ValueError):
            module.schema_validate(mutated_row, row_schema, "mutated DuckDB row")

        mutated_messages = copy.deepcopy(fixtures)
        mutated_messages["audit_parquet"]["tenant_ref"] = "tenant:other"
        with self.assertRaises(ValueError):
            module.validate_messages(policy, descriptors, schemas, mutated_messages)

if __name__ == "__main__":
    unittest.main()
