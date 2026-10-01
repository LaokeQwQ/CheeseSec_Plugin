#!/usr/bin/env python3
"""Tests for the planned Jev, EDR and DuckDB extension contracts."""
from __future__ import annotations

import copy
import hashlib
import importlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


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

    def test_jev_identity_and_no_fallback_are_bound(self) -> None:
        module = contract_module()
        schema, policy, descriptors = module.load_contracts()
        hosted = next(item for item in descriptors if item["deployment"] == "hosted-api")
        mutated = copy.deepcopy(hosted)
        mutated["plugin_id"] = "jev-lite-local"
        with self.assertRaises(ValueError):
            module.validate_descriptor(mutated, schema, policy)

        mutated = copy.deepcopy(hosted)
        mutated["deployment_config"]["fallback"] = "local-lite"
        with self.assertRaises(ValueError):
            module.validate_descriptor(mutated, schema, policy)

        mutated = copy.deepcopy(hosted)
        mutated["deployment_config"]["tls_pin_ref"] = "attacker-pin"
        with self.assertRaises(ValueError):
            module.validate_descriptor(mutated, schema, policy)

        mutated = copy.deepcopy(hosted)
        mutated["network"]["lease"]["max_requests"] = 32
        mutated["network"]["lease"]["max_bytes"] = 10485760
        with self.assertRaises(ValueError):
            module.validate_descriptor(mutated, schema, policy)

        mutated_policy = copy.deepcopy(policy)
        mutated_hosted = copy.deepcopy(hosted)
        mutated_policy["max_online_lease_seconds"] = 600
        mutated_hosted["network"]["lease"]["max_ttl_seconds"] = 600
        with self.assertRaises(ValueError):
            module.validate_descriptor(mutated_hosted, schema, mutated_policy)

        mutated_policy = copy.deepcopy(policy)
        mutated_hosted = copy.deepcopy(hosted)
        mutated_policy["jev"]["hosted_identity"]["provider"] = "typesafe-jev-lite"
        mutated_hosted["deployment_config"]["provider"] = "typesafe-jev-lite"
        with self.assertRaises(ValueError):
            module.validate_descriptor(mutated_hosted, schema, mutated_policy)

        mutated_policy = copy.deepcopy(policy)
        mutated_hosted = copy.deepcopy(hosted)
        mutated_policy["jev"]["hosted_identity"]["tls_pin_ref"] = "attacker-pin"
        mutated_hosted["deployment_config"]["tls_pin_ref"] = "attacker-pin"
        with self.assertRaises(ValueError):
            module.validate_descriptor(mutated_hosted, schema, mutated_policy)

        mutated = copy.deepcopy(hosted)
        mutated["capabilities"].append("analysis_record")
        with self.assertRaises(ValueError):
            module.validate_descriptor(mutated, schema, policy)

        lite = next(item for item in descriptors if item["deployment"] == "local-lite")
        mutated = copy.deepcopy(lite)
        mutated["deployment_config"]["provider"] = "typesafe"
        with self.assertRaises(ValueError):
            module.validate_descriptor(mutated, schema, policy)

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

        mutated = copy.deepcopy(duckdb)
        mutated["runtime"] = "sidecar"
        with self.assertRaises(ValueError):
            module.validate_descriptor(mutated, schema, policy)

        mutated = copy.deepcopy(duckdb)
        mutated["output"]["schemas"].append("cheesewaf/candidate-snapshot/v1")
        with self.assertRaises(ValueError):
            module.validate_descriptor(mutated, schema, policy)

    def test_edr_event_binds_authenticated_peer_scope_and_sequence(self) -> None:
        module = contract_module()
        _, policy, descriptors = module.load_contracts()
        schemas, fixtures = module.load_message_contracts(policy)
        event = fixtures["waf_security_event"]
        module.schema_validate(event, schemas["waf_security_event"], "valid WAF security event")
        peer = {
            "tenant_ref": event["tenant_ref"],
            "source_instance_ref": event["source_instance_ref"],
            "stream_ref": event["stream_ref"],
            "site_refs": [event["site_ref"]],
        }
        module.validate_edr_context_binding(event, peer, event["sequence"] - 1)
        module.validate_edr_context_binding(event, peer, event["sequence"] - 3)

        mutated = copy.deepcopy(event)
        del mutated["source_instance_ref"]
        with self.assertRaises(ValueError):
            module.schema_validate(mutated, schemas["waf_security_event"], "missing EDR source")

        mutated = copy.deepcopy(event)
        mutated["sequence"] = 0
        with self.assertRaises(ValueError):
            module.schema_validate(mutated, schemas["waf_security_event"], "zero EDR sequence")

        wrong_tenant = copy.deepcopy(peer)
        wrong_tenant["tenant_ref"] = "tenant:other"
        with self.assertRaises(ValueError):
            module.validate_edr_context_binding(event, wrong_tenant, event["sequence"] - 1)

        wrong_source = copy.deepcopy(peer)
        wrong_source["source_instance_ref"] = "instance:other"
        with self.assertRaises(ValueError):
            module.validate_edr_context_binding(event, wrong_source, event["sequence"] - 1)

        wrong_site = copy.deepcopy(peer)
        wrong_site["site_refs"] = ["site:other"]
        with self.assertRaises(ValueError):
            module.validate_edr_context_binding(event, wrong_site, event["sequence"] - 1)

        with self.assertRaises(ValueError):
            module.validate_edr_context_binding(event, peer, event["sequence"])

    def test_edr_and_duckdb_descriptors_cannot_be_relabelled(self) -> None:
        module = contract_module()
        schema, policy, descriptors = module.load_contracts()
        edr = next(item for item in descriptors if item["class"] == "event-correlator")
        mutated = copy.deepcopy(edr)
        mutated["namespace"] = "community/other/edr"
        with self.assertRaises(ValueError):
            module.validate_descriptor(mutated, schema, policy)

        duckdb = next(item for item in descriptors if item["class"] == "analytics")
        mutated = copy.deepcopy(duckdb)
        mutated["plugin_id"] = "other-analytics"
        with self.assertRaises(ValueError):
            module.validate_descriptor(mutated, schema, policy)

    def test_message_contracts_bind_to_descriptors(self) -> None:
        module = contract_module()
        schema, policy, descriptors = module.load_contracts()
        schemas, fixtures = module.load_message_contracts()
        module.validate_messages(policy, descriptors, schemas, fixtures)

    def test_edr_transport_policy_cannot_drop_authenticated_bindings(self) -> None:
        module = contract_module()
        _, policy, descriptors = module.load_contracts()
        schemas, fixtures = module.load_message_contracts(policy)
        mutated = copy.deepcopy(policy)
        mutated["edr"]["tenant_binding"] = "payload-only"
        with self.assertRaises(ValueError):
            module.validate_messages(mutated, descriptors, schemas, fixtures)

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

        mutated = copy.deepcopy(fixtures)
        mutated["analysis_record"]["window"]["from"] = "2026-10-01T07:59:00Z"
        with self.assertRaisesRegex(ValueError, "inside the input snapshot window"):
            module.validate_messages(policy, descriptors, schemas, mutated)

        mutated = copy.deepcopy(fixtures)
        mutated["analysis_record"]["window"]["to"] = "2026-10-01T09:01:00Z"
        with self.assertRaisesRegex(ValueError, "inside the input snapshot window"):
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

    def test_duckdb_analysis_record_binds_execution_provenance(self) -> None:
        module = contract_module()
        _, policy, descriptors = module.load_contracts()
        schemas, fixtures = module.load_message_contracts(policy)

        mutated = copy.deepcopy(fixtures)
        mutated["analysis_record"]["query_template_sha256"] = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        with self.assertRaises(ValueError):
            module.validate_messages(policy, descriptors, schemas, mutated)

        mutated = copy.deepcopy(fixtures)
        mutated["analysis_record"]["execution_profile_sha256"] = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        with self.assertRaises(ValueError):
            module.validate_messages(policy, descriptors, schemas, mutated)

        mutated = copy.deepcopy(fixtures)
        mutated["audit_parquet"]["created_at"] = "2026-10-01T09:03:00Z"
        with self.assertRaises(ValueError):
            module.validate_messages(policy, descriptors, schemas, mutated)

        mutated = copy.deepcopy(policy)
        mutated["duckdb"]["query_template_sha256"] = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        with self.assertRaises(ValueError):
            module.validate_messages(mutated, descriptors, schemas, fixtures)

        mutated_policy = copy.deepcopy(policy)
        mutated_record = copy.deepcopy(fixtures["analysis_record"])
        template = module.ROOT / module.EXPECTED_DUCKDB_TEMPLATE["query_template_file"]
        changed_template = template.read_bytes() + b"-- changed template\n"
        changed_digest = hashlib.sha256(changed_template).hexdigest()
        mutated_policy["duckdb"]["query_template_sha256"] = changed_digest
        mutated_record["query_template_sha256"] = changed_digest
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            temporary_template = temporary_root / module.EXPECTED_DUCKDB_TEMPLATE["query_template_file"]
            temporary_template.parent.mkdir(parents=True)
            temporary_template.write_bytes(changed_template)
            with patch.object(module, "ROOT", temporary_root):
                with self.assertRaisesRegex(ValueError, "canonical template policy changed"):
                    module.validate_duckdb_provenance(
                        mutated_policy,
                        fixtures["audit_parquet"],
                        mutated_record,
                    )

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
