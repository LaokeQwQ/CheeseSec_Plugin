from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from scripts.verify_offline_import import verify_offline_package


class OfflineImportTests(unittest.TestCase):
    def test_preflight_accepts_signed_example_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            package = root / "demo.crp"
            with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("manifest.json", (Path(__file__).parents[1] / "examples/crp-v1/manifest.json").read_bytes())
                archive.writestr("artifact/payload.txt", (Path(__file__).parents[1] / "examples/crp-v1/artifact/payload.txt").read_bytes())
                archive.writestr("signatures/manifest.json", (Path(__file__).parents[1] / "examples/crp-v1/signatures/manifest.json").read_bytes())
            for name in ("trust-roots.json", "source-registry.json", "revocations.json"):
                source = Path(__file__).parents[1] / "policy" / name
                (root / name).write_bytes(source.read_bytes())
            result = verify_offline_package(package, root / "trust-roots.json", root / "source-registry.json", root / "revocations.json")
            self.assertEqual(result["network_requests"], 0)
            self.assertEqual(result["trust_level"], "official")
            self.assertFalse(result["staged"])

    def test_preflight_accepts_exact_three_entry_archive_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            package = root / "demo.crp"
            with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("manifest.json", json.dumps({"source": "offline"}))
                archive.writestr("artifact/payload.txt", b"payload")
                archive.writestr("signatures/manifest.json", "[]")
            roots = root / "trust-roots.json"
            sources = root / "sources.json"
            revocations = root / "revocations.json"
            roots.write_text(json.dumps({"roots": []}), encoding="utf-8")
            sources.write_text(json.dumps({"sources": [{"source": "offline", "source_root": "offline-root", "trust_level": "test"}]}), encoding="utf-8")
            revocations.write_text(json.dumps({"events": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "empty signature"):
                verify_offline_package(package, roots, sources, revocations)

    def test_preflight_rejects_extra_archive_entry(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            package = root / "bad.crp"
            with zipfile.ZipFile(package, "w") as archive:
                archive.writestr("manifest.json", "{}")
                archive.writestr("artifact/payload.txt", b"payload")
                archive.writestr("signatures/manifest.json", "[]")
                archive.writestr("provenance/statement.json", "{}")
            files = []
            for name in ("trust.json", "sources.json", "revocations.json"):
                path = root / name
                path.write_text("[]", encoding="utf-8")
                files.append(path)
            with self.assertRaises(ValueError):
                verify_offline_package(package, *files)
