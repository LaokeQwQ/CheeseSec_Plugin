#!/usr/bin/env python3
"""Contract tests for the minimal commercial store/OTA publication surface."""
from __future__ import annotations

import importlib.util
import copy
import unittest


def contract_module():
    spec = importlib.util.find_spec("scripts.validate_commercial_contracts")
    if spec is None:
        raise AssertionError("commercial contract validator is not implemented")
    module = importlib.import_module("scripts.validate_commercial_contracts")
    return module


class CommercialContractTests(unittest.TestCase):
    def test_catalog_policies_and_examples_are_valid(self) -> None:
        module = contract_module()
        contracts = module.load_contracts()
        module.validate_contracts(contracts)

    def test_all_trust_levels_have_bounded_admission_policy(self) -> None:
        contracts = contract_module().load_contracts()
        levels = contracts["trust_levels"]["levels"]
        self.assertEqual(
            {entry["id"] for entry in levels},
            {"official", "enterprise", "community", "personal", "test", "development"},
        )
        for entry in levels:
            self.assertIn(entry["admission"], {"trusted", "needs_confirmation"})
            self.assertGreaterEqual(entry["normal_threshold"], 1)
            self.assertGreaterEqual(entry["normal_total"], entry["normal_threshold"])
            self.assertGreaterEqual(entry["high_risk_threshold"], entry["normal_threshold"])

    def test_pull_only_and_no_wasm_are_explicit(self) -> None:
        contracts = contract_module().load_contracts()
        self.assertTrue(contracts["cwedp"]["pull_only"])
        self.assertFalse(contracts["cwedp"]["ansible_push"])
        self.assertEqual(contracts["sidecar"]["properties"]["runtime"]["const"], "sidecar")

    def test_append_only_guard_rejects_release_rewrite(self) -> None:
        module = contract_module()
        contracts = module.load_contracts()
        release = contracts["release_example"]
        previous = {"catalog": {"catalog_sequence": 1, "releases": [release], "withdrawals": []}, "ota": {"index_sequence": 1, "releases": []}}
        current = copy.deepcopy(contracts)
        current["catalog"]["releases"] = [copy.deepcopy(release)]
        current["catalog"]["catalog_sequence"] = 2
        current["catalog"]["releases"][0]["provenance_sha256"] = "8888888888888888888888888888888888888888888888888888888888888888"
        with self.assertRaises(ValueError):
            module.validate_append_only(previous, current)

    def test_release_example_carries_verified_signature_evidence(self) -> None:
        contracts = contract_module().load_contracts()
        evidence = contracts["release_example"]["signature_evidence"]
        self.assertEqual(evidence["status"], "verified")
        self.assertGreaterEqual(len(evidence["valid_key_ids"]), evidence["required_signatures"])
        self.assertEqual(evidence["source_root"], contracts["release_example"]["source_root"])
        self.assertEqual(evidence["trust_level"], contracts["release_example"]["trust_level"])

    def test_ota_binding_requires_signature_and_source_root(self) -> None:
        contracts = contract_module().load_contracts()
        ota_schema = contracts["ota_schema"]
        required = set(ota_schema["properties"]["releases"]["items"]["required"])
        self.assertTrue({"signature_set_sha256", "manifest_sha256", "source_root", "trust_level"} <= required)

    def test_withdrawal_record_hash_chain_is_immutable(self) -> None:
        module = contract_module()
        contracts = module.load_contracts()
        release = copy.deepcopy(contracts["release_example"])
        release["record_type"] = "publication"
        event = {
            "release_id": release["release_id"],
            "withdrawal_id": "withdraw-demo-1",
            "reason_code": "policy",
            "evidence_sha256": "8888888888888888888888888888888888888888888888888888888888888888",
            "withdrawn_at": "2026-02-01T00:00:00Z",
            "event_sequence": 1,
            "previous_event_sha256": None,
            "source_root": release["source_root"],
            "release_sequence": release["release_sequence"],
        }
        event["record_sha256"] = __import__("hashlib").sha256(module._canonical(event).encode()).hexdigest()
        current = copy.deepcopy(contracts)
        current["catalog"]["releases"] = [release]
        current["catalog"]["withdrawals"] = [event]
        current["ota"]["releases"] = []
        module.validate_contracts(current)
        event["reason_code"] = "malware"
        with self.assertRaises(ValueError):
            module.validate_contracts(current)


if __name__ == "__main__":
    unittest.main()
