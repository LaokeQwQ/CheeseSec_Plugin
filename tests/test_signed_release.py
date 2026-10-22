import argparse
import base64
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from build_signed_release import build, canonical, digests, validate


class SignedReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="cheesesec-release-test-")
        cls.directory = Path(cls.temporary.name)
        cls.now = datetime.now(timezone.utc).replace(microsecond=0)
        stamp = lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ")
        roots = []
        cls.keys = []
        for index in range(3):
            key_id = f"release-test-{index}"
            path = cls.directory / (key_id + ".pem")
            subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(path)], check=True, capture_output=True)
            path.chmod(0o600)
            public = subprocess.check_output(["openssl", "pkey", "-in", str(path), "-pubout", "-outform", "DER"])[-32:]
            roots.append({"key_id": key_id, "algorithm": "ed25519", "public_key": base64.b64encode(public).decode(), "trust_level": "official", "source_root": "test-formal-root", "status": "active", "valid_from": stamp(cls.now - timedelta(days=1)), "valid_until": stamp(cls.now + timedelta(days=365))})
            cls.keys.append(f"{key_id}={path}")
        documents = {
            "trust-roots": {"api_version": "store.cheesesec.com/v1", "roots": roots},
            "source-registry": {"api_version": "store.cheesesec.com/v1", "sources": [{"source": "official", "source_root": "test-formal-root", "trust_level": "official"}]},
            "revocations": {"api_version": "store.cheesesec.com/v1", "snapshot_sequence": 1, "events": []},
            "previous-catalog": {"api_version": "store.cheesesec.com/v1", "catalog_sequence": 1, "releases": [], "withdrawals": []},
            "review": {"review_id": "test-review", "decision": "approved", "reviewers": ["unit-test-review"], "checks": ["test fixture only"], "source_commit": "a" * 40, "artifact_sha256": __import__("hashlib").sha256(b"test executable fixture\n").hexdigest()},
            "provenance": {"source_commit": "a" * 40, "description": "Unit-test executable fixture", "compatibility": ["unit-test only"]},
            "descriptor": {"api_version": "crp.cheesewaf.io/v1", "descriptor_id": "hello-release-test", "plugin_id": "hello-test", "version": "0.1.0", "namespace": "official/hello-test", "source": "official", "source_root": "test-formal-root", "runtime": "sidecar", "capabilities": ["health"], "resources": {"cpu_milli": 100, "memory_bytes": 67108864, "pids": 32}, "metadata": {"request_path": "asynchronous", "initial_mode": "observe", "egress": "deny", "activation_owner": "control-plane"}},
        }
        for name, value in documents.items():
            (cls.directory / (name + ".json")).write_bytes(canonical(value))
        (cls.directory / "hello-test").write_bytes(b"test executable fixture\n")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def args(self, destination):
        return argparse.Namespace(output=str(self.directory / destination), artifact=str(self.directory / "hello-test"), source_commit="a" * 40,
            previous_catalog=str(self.directory / "previous-catalog.json"), trust_roots=str(self.directory / "trust-roots.json"), source_registry=str(self.directory / "source-registry.json"), revocations=str(self.directory / "revocations.json"), review=str(self.directory / "review.json"), descriptor=str(self.directory / "descriptor.json"), provenance=str(self.directory / "provenance.json"),
            plugin_id="hello-test", namespace="official/hello-test", version="0.1.0", source="official", source_root="test-formal-root", publisher="CheeseSec", sequence=1,
            signed_at=self.now.strftime("%Y-%m-%dT%H:%M:%SZ"), key=self.keys[:2])

    def test_real_signatures_and_reproducible_archive(self):
        first = build(self.args("valid-first"))
        second = build(self.args("valid-second"))
        self.assertEqual(first["crp"], second["crp"])
        self.assertTrue(validate(self.directory / "valid-first")["verified"])

    def test_threshold_failure_creates_no_output(self):
        args = self.args("threshold")
        args.key = args.key[:1]
        with self.assertRaisesRegex(ValueError, "threshold"):
            build(args)
        self.assertFalse(Path(args.output).exists())

    def test_unreviewed_input_rejected(self):
        path = self.directory / "unreviewed.json"
        path.write_bytes(canonical({"decision": "draft"}))
        args = self.args("unreviewed")
        args.review = str(path)
        with self.assertRaisesRegex(ValueError, "review"):
            build(args)

    def test_mutated_archive_rejected(self):
        args = self.args("tampered")
        result = build(args)
        relative = result["crp"]["resource_url"].removeprefix("https://res.cheesesec.com/")
        archive = Path(args.output) / "resources" / "resources" / relative
        archive.write_bytes(archive.read_bytes() + b"tamper")
        with self.assertRaisesRegex(ValueError, "digest"):
            validate(args.output)

    def test_unsafe_private_key_mode_rejected(self):
        args = self.args("insecure-key")
        key = self.directory / "insecure.pem"
        key.write_bytes((self.directory / "release-test-0.pem").read_bytes())
        key.chmod(0o644)
        args.key = ["release-test-0=" + str(key), self.keys[1]]
        with self.assertRaisesRegex(ValueError, "mode"):
            build(args)

    def change_object(self, bundle_path, key, value):
        path = Path(bundle_path)
        manifest_path = path / "bundle-manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        item = next(item for item in manifest["objects"] if item["key"] == key)
        data = canonical(value)
        (path / item["file"]).write_bytes(data)
        item["size"], item["sha256"] = len(data), digests(data)["sha256"]
        manifest_path.write_bytes(canonical(manifest))

    def test_validate_also_requires_three_distinct_official_roots(self):
        args = self.args("removed-root")
        build(args)
        policy = json.loads((self.directory / "trust-roots.json").read_bytes())
        policy["roots"] = policy["roots"][:2]
        self.change_object(args.output, "policy/trust-roots.json", policy)
        with self.assertRaisesRegex(ValueError, "three active"):
            validate(args.output)

    def test_review_must_bind_the_actual_artifact(self):
        args = self.args("wrong-review-artifact")
        review = json.loads((self.directory / "review.json").read_bytes())
        review["artifact_sha256"] = "0" * 64
        path = self.directory / "wrong-review-artifact.json"
        path.write_bytes(canonical(review))
        args.review = str(path)
        with self.assertRaisesRegex(ValueError, "artifact SHA-256"):
            build(args)

    def test_previous_snapshot_bytes_are_preserved_without_canonicalization(self):
        args = self.args("noncanonical-previous")
        raw = json.dumps({"withdrawals": [], "releases": [], "catalog_sequence": 1, "api_version": "store.cheesesec.com/v1"}, indent=4).encode()
        path = self.directory / "noncanonical-previous.json"
        path.write_bytes(raw)
        args.previous_catalog = str(path)
        build(args)
        self.assertEqual((Path(args.output) / "previous-catalog.json").read_bytes(), raw)
        self.assertTrue(validate(args.output)["verified"])

    def test_record_cannot_understate_real_signature_threshold(self):
        args = self.args("false-threshold-evidence")
        build(args)
        path = Path(args.output)
        catalog = json.loads((path / "index/catalog/index.json").read_bytes())
        catalog["releases"][-1]["signature_evidence"]["required_signatures"] = 1
        self.change_object(path, "catalog/index.json", catalog)
        self.change_object(path, "indexes/catalog/seq-00000000000000000002.json", catalog)
        pointer = {"sequence": 2, "key": "indexes/catalog/seq-00000000000000000002.json", "sha256": digests(canonical(catalog))["sha256"]}
        self.change_object(path, "pointers/catalog.json", pointer)
        with self.assertRaisesRegex(ValueError, "actual|real verification"):
            validate(path)


if __name__ == "__main__":
    unittest.main()
