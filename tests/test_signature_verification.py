from __future__ import annotations

import base64
import copy
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.signature_verifier import verify_signature_set


ROOT = Path(__file__).resolve().parents[1]


class SignatureVerificationTests(unittest.TestCase):
    def _inputs(self) -> tuple[bytes, bytes, dict[str, object], list[dict[str, object]], list[dict[str, object]]]:
        manifest_path = ROOT / "examples/crp-v1/manifest.json"
        signature_path = ROOT / "examples/crp-v1/signatures/manifest.json"
        roots = json.loads((ROOT / "policy/trust-roots.json").read_text(encoding="utf-8"))
        sources = json.loads((ROOT / "policy/source-registry.json").read_text(encoding="utf-8"))
        revocations = json.loads((ROOT / "policy/revocations.json").read_text(encoding="utf-8"))
        return manifest_path.read_bytes(), signature_path.read_bytes(), roots, sources, revocations

    def test_example_signatures_verify_against_manifest_and_official_root(self) -> None:
        manifest, signatures, roots, sources, revocations = self._inputs()
        result = verify_signature_set(
            manifest,
            signatures,
            roots,
            sources,
            revocations,
            now=datetime(2026, 2, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(result["trust_level"], "official")
        self.assertEqual(result["source_root"], "vendor-root-v1")
        self.assertEqual(len(result["valid_key_ids"]), 2)

    def test_empty_signature_set_is_rejected(self) -> None:
        manifest, _signatures, roots, sources, revocations = self._inputs()
        with self.assertRaisesRegex(ValueError, "empty signature"):
            verify_signature_set(manifest, b"[]", roots, sources, revocations)

    def test_expired_root_is_rejected(self) -> None:
        manifest, signatures, roots, sources, revocations = self._inputs()
        expired = copy.deepcopy(roots)
        expired["roots"][0]["valid_until"] = "2026-01-01T00:00:00Z"
        expired["roots"][1]["valid_until"] = "2026-01-01T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "outside key validity"):
            verify_signature_set(
                manifest,
                signatures,
                expired,
                sources,
                revocations,
                now=datetime(2026, 2, 1, tzinfo=timezone.utc),
            )

    def test_source_root_mismatch_is_rejected(self) -> None:
        manifest, signatures, roots, sources, revocations = self._inputs()
        mismatched = copy.deepcopy(roots)
        for root in mismatched["roots"]:
            root["source_root"] = "attacker-root"
        with self.assertRaisesRegex(ValueError, "source root"):
            verify_signature_set(
                manifest,
                signatures,
                mismatched,
                sources,
                revocations,
                now=datetime(2026, 2, 1, tzinfo=timezone.utc),
            )

    def test_signature_value_must_be_ed25519_length(self) -> None:
        manifest, _signatures, roots, sources, revocations = self._inputs()
        signatures = json.dumps(
            [
                {
                    "key_id": "official-demo-1",
                    "algorithm": "ed25519",
                    "value": base64.b64encode(b"short").decode(),
                    "source_root": "vendor-root-v1",
                    "trust_level": "official",
                    "release_sequence": 1,
                    "manifest_sha256": "75ad97aecb15e3dd842bf32dd7a71c8f9e6bbe55fb7200b37c8efbe6643e4216",
                    "signed_at": "2026-01-15T00:00:00Z",
                    "expires_at": "2028-01-01T00:00:00Z",
                }
            ]
        ).encode()
        with self.assertRaisesRegex(ValueError, "64-byte"):
            verify_signature_set(manifest, signatures, roots, sources, revocations)


if __name__ == "__main__":
    unittest.main()
