"""Tests for Phase 3 modules: revocation, rotation, FIPS mode, differential privacy, attestation"""

import time
import unittest
from abir_guard.revocation import RevocationList, RevocationReason
from abir_guard.rotation import KeyRotationManager, KeyMetadata
from abir_guard.fips_mode import FIPSValidator, FIPSEncryptor, FIPSModeError
from abir_guard.differential_privacy import (
    LaplaceNoise,
    DifferentialEntropyCollector,
    SpectreMeltdownDefender,
)
from abir_guard.attestation import IntegrityProof, AttestationVerifier


class TestRevocation(unittest.TestCase):
    def test_revoke_and_check(self):
        crl = RevocationList()
        self.assertFalse(crl.is_revoked("agent-1"))

        crl.revoke("agent-1", RevocationReason.COMPROMISED, "admin", "Key leaked")
        self.assertTrue(crl.is_revoked("agent-1"))
        self.assertFalse(crl.is_revoked("agent-2"))

    def test_integrity(self):
        crl = RevocationList()
        crl.revoke("key-1", RevocationReason.ROTATED, "system", "routine")
        self.assertTrue(crl.verify_integrity())

    def test_export_import(self):
        crl = RevocationList(b"test-key-32-bytes-12345678")
        crl.revoke("key-1", RevocationReason.RETIRED, "admin", "")
        exported = crl.export()
        imported = RevocationList.load(exported, b"test-key-32-bytes-12345678")
        self.assertTrue(imported.is_revoked("key-1"))

    def test_list_revoked(self):
        crl = RevocationList()
        crl.revoke("k1", RevocationReason.COMPROMISED)
        crl.revoke("k2", RevocationReason.POLICY)
        revoked = crl.list_revoked()
        self.assertEqual(len(revoked), 2)


class TestKeyRotation(unittest.TestCase):
    def test_usage_based_rotation(self):
        manager = KeyRotationManager(default_max_operations=5)
        manager.register_key("test-key")

        for _ in range(5):
            manager.record_usage("test-key", "encrypt")

        self.assertTrue(manager.needs_rotation("test-key"))

    def test_no_rotation_under_limit(self):
        manager = KeyRotationManager(default_max_operations=10)
        manager.register_key("test-key")

        for _ in range(3):
            manager.record_usage("test-key", "encrypt")

        self.assertFalse(manager.needs_rotation("test-key"))

    def test_expire_key(self):
        manager = KeyRotationManager()
        manager.register_key("old-key")
        manager.expire_key("old-key", "new-key")

        meta = manager.get_metadata("old-key")
        self.assertTrue(meta.is_expired)
        self.assertEqual(meta.rotated_to, "new-key")

    def test_list_keys(self):
        manager = KeyRotationManager()
        manager.register_key("key-a")
        manager.register_key("key-b")
        keys = manager.list_keys()
        self.assertEqual(len(keys), 2)

    def test_get_expiring_keys(self):
        manager = KeyRotationManager(default_max_lifetime=1)  # 1 second
        manager.register_key("short-lived")
        time.sleep(0.5)
        expiring = manager.get_expiring_keys(warning_seconds=1)
        self.assertIn("short-lived", expiring)


class TestFIPSMode(unittest.TestCase):
    def test_valid_aes_key(self):
        key = b"\x00" * 32  # 256 bits
        FIPSValidator.validate_aes_key(key)  # Should not raise

    def test_short_aes_key(self):
        key = b"\x00" * 16  # 128 bits
        with self.assertRaises(FIPSModeError):
            FIPSValidator.validate_aes_key(key)

    def test_valid_nonce(self):
        nonce = b"\x00" * 12  # 96 bits
        FIPSValidator.validate_nonce(nonce)  # Should not raise

    def test_invalid_nonce(self):
        nonce = b"\x00" * 8
        with self.assertRaises(FIPSModeError):
            FIPSValidator.validate_nonce(nonce)

    def test_approved_hash(self):
        FIPSValidator.validate_hash_algorithm("sha256")
        FIPSValidator.validate_hash_algorithm("sha3_512")

    def test_unapproved_hash(self):
        with self.assertRaises(FIPSModeError):
            FIPSValidator.validate_hash_algorithm("md5")

    def test_fips_encryptor(self):
        encryptor = FIPSEncryptor()
        key = b"\x00" * 32
        plaintext = b"hello world"

        result = encryptor.encrypt(plaintext, key)
        self.assertIn("nonce", result)
        self.assertIn("ciphertext", result)
        self.assertIn("auth_tag", result)

        decrypted = encryptor.decrypt(
            result["ciphertext"],
            result["auth_tag"],
            result["nonce"],
            key,
        )
        self.assertEqual(decrypted, plaintext)

    def test_fips_key_derivation(self):
        encryptor = FIPSEncryptor()
        secret = b"\x00" * 32
        derived = encryptor.derive_key(secret, b"test-info")
        self.assertEqual(len(derived), 32)


class TestDifferentialPrivacy(unittest.TestCase):
    def test_laplace_noise(self):
        noise = LaplaceNoise(epsilon=0.5)
        samples = [noise.sample() for _ in range(100)]
        # Samples should be non-zero (with high probability)
        non_zero = sum(1 for s in samples if abs(s) > 0.001)
        self.assertGreater(non_zero, 50)

    def test_entropy_collection(self):
        collector = DifferentialEntropyCollector(epsilon=0.5, sample_count=10)
        entropy = collector.collect()
        self.assertEqual(len(entropy), 32)

    def test_constant_time_compare(self):
        self.assertTrue(SpectreMeltdownDefender.constant_time_compare(b"hello", b"hello"))
        self.assertFalse(SpectreMeltdownDefender.constant_time_compare(b"hello", b"world"))
        self.assertFalse(SpectreMeltdownDefender.constant_time_compare(b"short", b"longer"))


class TestAttestation(unittest.TestCase):
    def test_proof_computation(self):
        proof = IntegrityProof()
        proof.compute("test-challenge")
        self.assertTrue(proof.verify())

    def test_proof_tampering(self):
        proof = IntegrityProof()
        proof.compute("test-challenge")
        proof.challenge = "tampered"
        self.assertFalse(proof.verify())

    def test_verifier(self):
        verifier = AttestationVerifier()
        challenge = verifier.generate_challenge()

        proof = IntegrityProof()
        proof.compute(challenge)

        result = verifier.verify_proof(proof.to_dict())
        self.assertTrue(result)

    def test_environment_check(self):
        verifier = AttestationVerifier()
        warnings = verifier.check_environment_sanity()
        # Should return a list (may or may not have warnings depending on env)
        self.assertIsInstance(warnings, list)


if __name__ == "__main__":
    unittest.main()
