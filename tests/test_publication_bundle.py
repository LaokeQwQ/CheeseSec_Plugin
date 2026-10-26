#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def builder_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "build_publication_bundle.py"
    spec = importlib.util.spec_from_file_location("publication_builder", path)
    if spec is None or spec.loader is None:
        raise AssertionError("publication builder is not importable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublicationBundleTests(unittest.TestCase):
    def test_build_is_deterministic_and_contains_fixed_keys(self) -> None:
        module = builder_module()
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_manifest = module.build(Path(first) / "bundle", 7, "stable")
            second_manifest = module.build(Path(second) / "bundle", 7, "stable")
            self.assertEqual(first_manifest["source_commit"], second_manifest["source_commit"])
            first_objects = {item["key"]: item["sha256"] for item in first_manifest["objects"]}
            second_objects = {item["key"]: item["sha256"] for item in second_manifest["objects"]}
            self.assertEqual(first_objects, second_objects)
            self.assertIn("catalog/index.json", first_objects)
            self.assertIn("ota/channels/stable/index.json", first_objects)
            self.assertIn("pointers/catalog.json", first_objects)
            self.assertTrue((Path(first) / "bundle" / "bundle-manifest.json").is_file())

    def test_requested_sequence_cannot_be_below_source_sequence(self) -> None:
        module = builder_module()
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                module.build(Path(temp) / "bundle", -1, "stable")

    def test_bundle_manifest_is_valid_json(self) -> None:
        module = builder_module()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "bundle"
            module.build(output, 3, "canary")
            data = json.loads((output / "bundle-manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(data["channel"], "canary")
            self.assertEqual(data["sequence"], 3)
            self.assertGreater(len(data["objects"]), 0)

    def test_bootstrap_public_only_excludes_trust_and_fixture_data(self) -> None:
        module = builder_module()
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "bundle"
            manifest = module.build(output, 8, "all", bootstrap_public_only=True)
            self.assertTrue(manifest["bootstrap_public_only"])
            self.assertEqual(manifest["channel"], "all")
            self.assertEqual(json.loads((output / "catalog/index.json").read_bytes()), {
                "api_version": "store.cheesesec.com/v1",
                "catalog_sequence": 8,
                "releases": [],
                "withdrawals": [],
            })
            for channel in module.CHANNELS:
                index = json.loads((output / f"ota/channels/{channel}/index.json").read_bytes())
                self.assertEqual(index, {
                    "api_version": "ota.cheesesec.com/v1",
                    "index_sequence": 8,
                    "mode": "pull-only",
                    "releases": [],
                })
                pointer = json.loads((output / f"pointers/ota/{channel}.json").read_bytes())
                self.assertEqual(pointer["channel"], channel)
                self.assertEqual(pointer["sequence"], 8)
                self.assertTrue((output / pointer["key"]).is_file())
            keys = {item["key"] for item in manifest["objects"]}
            self.assertIn("policy/endpoints.json", keys)
            self.assertIn("schema/crp-v1/manifest.schema.json", keys)
            self.assertIn("schema/store-v1/catalog.schema.json", keys)
            for item in manifest["objects"]:
                self.assertNotIn("trust-roots.json", item["key"])
                self.assertNotIn("source-registry.json", item["key"])
                self.assertNotIn("revocations.json", item["key"])
                self.assertNotIn("resources/", item["key"])
                self.assertNotIn("examples/", item["key"])
                self.assertNotIn(b"official-demo-", (output / item["file"]).read_bytes())

    def test_bootstrap_public_only_is_deterministic(self) -> None:
        module = builder_module()
        with tempfile.TemporaryDirectory() as temp:
            first = Path(temp) / "first"
            second = Path(temp) / "second"
            first_manifest = module.build(first, 9, "all", bootstrap_public_only=True)
            second_manifest = module.build(second, 9, "all", bootstrap_public_only=True)
            self.assertEqual(first_manifest, second_manifest)
            self.assertEqual((first / "bundle-manifest.json").read_bytes(),
                             (second / "bundle-manifest.json").read_bytes())
            for item in first_manifest["objects"]:
                self.assertEqual((first / item["file"]).read_bytes(),
                                 (second / item["file"]).read_bytes())

    def test_bootstrap_refuses_existing_releases_or_withdrawals(self) -> None:
        for source, field in (
            ("catalog/index.json", "releases"),
            ("catalog/index.json", "withdrawals"),
            ("ota/index.json", "releases"),
        ):
            with self.subTest(source=source, field=field):
                module = builder_module()
                original_load = module.load_json

                def nonempty_index(relative):
                    value = original_load(relative)
                    if relative == source:
                        value[field] = [{"fixture": "must-not-be-published-or-hidden"}]
                    return value

                with tempfile.TemporaryDirectory() as temp, mock.patch.object(
                    module, "load_json", side_effect=nonempty_index
                ):
                    output = Path(temp) / "bundle"
                    with self.assertRaisesRegex(ValueError, "bootstrap.*empty"):
                        module.build(output, 10, "all", bootstrap_public_only=True)
                    self.assertFalse(output.exists())

    def test_normal_bundle_keeps_existing_policy_and_single_channel_behavior(self) -> None:
        module = builder_module()
        with tempfile.TemporaryDirectory() as temp:
            manifest = module.build(Path(temp) / "bundle", 11, "dev")
            self.assertNotIn("bootstrap_public_only", manifest)
            keys = {item["key"] for item in manifest["objects"]}
            self.assertIn("policy/trust-roots.json", keys)
            self.assertIn("policy/source-registry.json", keys)
            self.assertIn("policy/revocations.json", keys)
            self.assertIn("ota/channels/dev/index.json", keys)
            self.assertNotIn("ota/channels/stable/index.json", keys)


if __name__ == "__main__":
    unittest.main()
