from __future__ import annotations

import base64
import copy
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts.signature_verifier import (
    _go_time_string,
    _signature_signing_bytes,
    _timestamp_nanoseconds,
    verify_signature_set,
)


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

    def test_signature_payload_matches_crp_v1_signing_envelope(self) -> None:
        manifest, signatures_bytes, _roots, _sources, _revocations = self._inputs()
        value = json.loads(manifest)
        signature = json.loads(signatures_bytes)[0]
        expected = (
            b"cheesewaf-crp-signature-v1\n"
            b'{"manifest":{"api_version":"crp.cheesewaf.io/v1","kind":"CheeseWAFResourcePackage",'
            b'"name":"demo","plugin_id":"demo","version":"1.0.0","namespace":"official/demo",'
            b'"publisher":"example","source":"offline","source_root":"vendor-root-v1",'
            b'"release_sequence":1,"digests":{"md5":"","sha1":"","sha256":""},'
            b'"artifact":{"name":"payload.txt","size":16,"digests":{"md5":"289440fb0fd416e276e3e56ca8d3381b",'
            b'"sha1":"a3ff74bc19323703a1c46830fafebbf24b39d62c",'
            b'"sha256":"f9a4a659b12d21729d3ad297151fbf77c3e0519ea6fddc68a139c8945c01925d"}}},'
            b'"key_id":"official-demo-1","algorithm":"ed25519","signed_at":"2026-01-15T00:00:00Z"}'
        )
        self.assertEqual(_signature_signing_bytes(value, signature), expected)

        plugin_only = copy.deepcopy(value)
        del plugin_only["name"]
        self.assertIn(b'"name":"","plugin_id":"demo"', _signature_signing_bytes(plugin_only, signature))

    def test_signer_identity_and_timestamp_are_cryptographically_bound(self) -> None:
        manifest, signatures_bytes, roots, sources, revocations = self._inputs()
        original = json.loads(signatures_bytes)
        for field, value in (("key_id", "official-demo-3"), ("signed_at", "2026-01-16T00:00:00Z")):
            mutated = copy.deepcopy(original)
            mutated[0][field] = value
            with self.assertRaisesRegex(ValueError, "Ed25519 signature verification failed"):
                verify_signature_set(
                    manifest,
                    json.dumps(mutated).encode(),
                    roots,
                    sources,
                    revocations,
                    now=datetime(2026, 2, 1, tzinfo=timezone.utc),
                )

    def test_signed_at_is_required_by_crp_v1(self) -> None:
        manifest, signatures_bytes, roots, sources, revocations = self._inputs()
        signatures = json.loads(signatures_bytes)
        del signatures[0]["signed_at"]
        with self.assertRaisesRegex(ValueError, "signed_at: timestamp is required"):
            verify_signature_set(
                manifest,
                json.dumps(signatures).encode(),
                roots,
                sources,
                revocations,
                now=datetime(2026, 2, 1, tzinfo=timezone.utc),
            )

    def test_signature_time_comparisons_preserve_nanoseconds(self) -> None:
        first = _timestamp_nanoseconds("2026-02-01T00:00:00.000000001Z", "first")
        second = _timestamp_nanoseconds("2026-02-01T00:00:00.000000002Z", "second")
        self.assertEqual(second - first, 1)
        self.assertEqual(
            _go_time_string("2026-02-01T01:00:00.123456700+01:00", "timestamp"),
            "2026-02-01T00:00:00.1234567Z",
        )

        manifest, signatures_bytes, roots, sources, revocations = self._inputs()
        signatures = json.loads(signatures_bytes)
        signatures[0]["signed_at"] = "2026-02-01T00:00:00.000000001Z"
        with self.assertRaisesRegex(ValueError, "is from the future"):
            verify_signature_set(
                manifest,
                json.dumps(signatures).encode(),
                roots,
                sources,
                revocations,
                now=datetime(2026, 2, 1, tzinfo=timezone.utc),
            )

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
                    "signed_at": "2026-01-15T00:00:00Z",
                }
            ]
        ).encode()
        with self.assertRaisesRegex(ValueError, "64-byte"):
            verify_signature_set(manifest, signatures, roots, sources, revocations)

    def test_crp_v1_signature_rejects_publication_provenance_fields(self) -> None:
        manifest, signatures_bytes, roots, sources, revocations = self._inputs()
        signatures = json.loads(signatures_bytes)
        signatures[0]["source_root"] = "vendor-root-v1"
        with self.assertRaisesRegex(ValueError, "outside CRP v1"):
            verify_signature_set(
                manifest,
                json.dumps(signatures).encode(),
                roots,
                sources,
                revocations,
                now=datetime(2026, 2, 1, tzinfo=timezone.utc),
            )


if __name__ == "__main__":
    unittest.main()
