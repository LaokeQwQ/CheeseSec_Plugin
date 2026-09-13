#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
