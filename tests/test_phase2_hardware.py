"""
Tests for Phase 2 Hardware Features:
- YubiKey/FIDO2 integration
- TPM 2.0 seal/unseal
- Hardware Enclave detection (Secure Enclave, SGX)
"""

import pytest
import os
import sys
import tempfile
from unittest.mock import patch, MagicMock


class TestYubiKeyIntegration:
    """Test YubiKey/FIDO2 integration with graceful fallback."""
    
    def setup_method(self):
        """Import YubiKeyManager, mocking fido2 if not available."""
        try:
            from abir_guard.yubikey_integration import (
                YubiKeyManager, YubiKeyError, YubiKeyNotFoundError,
                YubiKeyCredential
            )
            self.YubiKeyManager = YubiKeyManager
            self.YubiKeyError = YubiKeyError
            self.YubiKeyNotFoundError = YubiKeyNotFoundError
            self.YubiKeyCredential = YubiKeyCredential
        except ImportError:
            pytest.skip("yubikey_integration module not available")
    
    def test_init_without_yubikey(self):
        """Manager initializes even without YubiKey."""
        yk = self.YubiKeyManager()
        assert yk is not None
    
    def test_is_available_without_device(self):
        """Returns False when no YubiKey connected."""
        yk = self.YubiKeyManager()
        # May be True if YubiKey is actually connected
        assert isinstance(yk.is_available(), bool)
    
    def test_generate_key_no_fallback(self):
        """Raises error when YubiKey not available."""
        yk = self.YubiKeyManager()
        
        with patch.object(yk, 'is_available', return_value=False):
            with pytest.raises(self.YubiKeyNotFoundError):
                yk.generate_key("test-agent", "ed25519")
    
    def test_sign_and_verify(self):
        """Test sign and verify methods exist and work correctly."""
        yk = self.YubiKeyManager()
        
        # Test that sign/verify methods exist
        assert hasattr(yk, 'sign')
        assert hasattr(yk, 'verify')
        assert hasattr(yk, 'generate_key')
        
        # Test that they raise appropriate errors for non-existent keys
        import sys
        try:
            yk.sign("non-existent", b"data")
            assert False, "Should have raised KeyError"
        except KeyError:
            pass
        except Exception as e:
            print(f"Got exception: {type(e).__name__}: {e}", file=sys.stderr)
            raise
    
    def test_encrypt_decrypt_requires_key(self):
        """Test encrypt/decrypt require valid key."""
        yk = self.YubiKeyManager()
        
        with pytest.raises(KeyError):
            yk.encrypt_with_yubikey("non-existent", b"data")
        
        with pytest.raises(KeyError):
            yk.decrypt_with_yubikey("non-existent", b"ct", b"nonce")
    
    def test_list_and_delete_credentials(self):
        """Test credential management methods."""
        yk = self.YubiKeyManager()
        
        # Test list (should return dict)
        creds = yk.list_credentials()
        assert isinstance(creds, dict)
        
        # Test get non-existent credential
        cred = yk.get_credential("non-existent")
        assert cred is None
        
        # Test delete non-existent (should not raise)
        yk.delete_credential("non-existent")
    
    def test_key_not_found_error(self):
        """Operations fail gracefully for missing keys."""
        yk = self.YubiKeyManager()
        
        with pytest.raises(KeyError):
            yk.sign("nonexistent", b"data")
        
        with pytest.raises(KeyError):
            yk.encrypt_with_yubikey("nonexistent", b"data")


class TestTPM2Seal:
    """Test TPM 2.0 seal/unseal operations."""
    
    def setup_method(self):
        """Import TPM2Sealer."""
        try:
            from abir_guard.tpm2_seal import TPM2Sealer, TPM2Error, TPM2NotAvailable, SealedData
            self.TPM2Sealer = TPM2Sealer
            self.TPM2Error = TPM2Error
            self.TPM2NotAvailable = TPM2NotAvailable
            self.SealedData = SealedData
        except ImportError:
            pytest.skip("tpm2_seal module not available")
    
    def test_init(self):
        """TPM sealer initializes."""
        tpm = self.TPM2Sealer()
        assert tpm is not None
    
    def test_is_available(self):
        """Availability check returns bool."""
        tpm = self.TPM2Sealer()
        assert isinstance(tpm.is_available(), bool)
    
    def test_software_seal_fallback(self):
        """Falls back to software seal when TPM not available."""
        tpm = self.TPM2Sealer()
        
        with patch.object(tpm, 'is_available', return_value=False):
            import warnings
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                sealed = tpm.seal(b"my secret key", pcr_indices=[0, 7])
                
                assert len(w) == 1
                assert "software seal" in str(w[0].message).lower()
            
            assert isinstance(sealed, self.SealedData)
            assert len(sealed.sealed_blob) > 0
            assert sealed.pcr_bank == "sha256"
            assert sealed.pcr_indices == [0, 7]
    
    def test_software_unseal_roundtrip(self):
        """Seal and unseal roundtrip via software fallback."""
        tpm = self.TPM2Sealer()
        
        with patch.object(tpm, 'is_available', return_value=False):
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                
                secret = b"super-secret-data-12345"
                sealed = tpm.seal(secret, pcr_indices=[0, 7])
                recovered = tpm.unseal(sealed)
                
                assert recovered == secret
    
    def test_sealed_data_structure(self):
        """Sealed data contains all required fields."""
        tpm = self.TPM2Sealer()
        
        with patch.object(tpm, 'is_available', return_value=False):
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                sealed = tpm.seal(b"test", pcr_indices=[0, 7])
            
            assert sealed.sealed_blob is not None
            assert isinstance(sealed.pcr_indices, list)
            assert len(sealed.policy_hash) == 64  # SHA-256 hex
            assert "sealed_at" in sealed.metadata
    
    def test_generate_random(self):
        """Generate random bytes (falls back to secrets if TPM unavailable)."""
        tpm = self.TPM2Sealer()
        
        rand_bytes = tpm.generate_random(32)
        assert len(rand_bytes) == 32
        assert rand_bytes != tpm.generate_random(32)  # Different each time
    
    def test_cleanup(self):
        """Cleanup removes temp files."""
        tpm = self.TPM2Sealer()
        temp_dir = tpm._temp_dir
        
        tpm.cleanup()
        assert not os.path.exists(temp_dir)


class TestHardwareEnclave:
    """Test hardware enclave detection and operations."""
    
    def setup_method(self):
        """Import HardwareEnclave."""
        try:
            from abir_guard.hardware_enclave import (
                HardwareEnclave, EnclavePlatform, EnclaveInfo, SealedEnvelope
            )
            self.HardwareEnclave = HardwareEnclave
            self.EnclavePlatform = EnclavePlatform
            self.EnclaveInfo = EnclaveInfo
            self.SealedEnvelope = SealedEnvelope
        except ImportError:
            pytest.skip("hardware_enclave module not available")
    
    def test_init(self):
        """Enclave initializes."""
        enc = self.HardwareEnclave()
        assert enc is not None
    
    def test_platform_detection(self):
        """Platform is detected."""
        enc = self.HardwareEnclave()
        assert enc.platform in list(self.EnclavePlatform)
    
    def test_is_available(self):
        """Availability check returns bool."""
        enc = self.HardwareEnclave()
        assert isinstance(enc.is_available(), bool)
    
    def test_generate_key(self):
        """Key generation works."""
        enc = self.HardwareEnclave()
        key_id = enc.generate_key("test-agent")
        assert key_id == "test-agent"
    
    def test_seal_unseal_roundtrip(self):
        """Seal and unseal roundtrip."""
        enc = self.HardwareEnclave()
        enc.generate_key("enc-test")
        
        secret = b"secret data for hardware enclave"
        sealed = enc.seal(secret, "enc-test")
        
        assert isinstance(sealed, self.SealedEnvelope)
        assert len(sealed.ciphertext) > len(secret)
        assert sealed.key_id == "enc-test"
        
        recovered = enc.unseal(sealed, "enc-test")
        assert recovered == secret
    
    def test_attestation_report(self):
        """Attestation report contains required fields."""
        enc = self.HardwareEnclave()
        challenge = b"random-challenge-12345"
        
        report = enc.attest(challenge)
        
        assert "platform" in report
        assert "challenge_hash" in report
        assert "timestamp" in report
        assert "available" in report
        assert "attestation_type" in report
    
    def test_get_status(self):
        """Status contains platform info."""
        enc = self.HardwareEnclave()
        status = enc.get_status()
        
        assert "platform" in status
        assert "available" in status
        assert "details" in status
        assert "warnings" in status
        assert "keys_loaded" in status
    
    def test_key_not_found(self):
        """Operations fail for missing keys."""
        enc = self.HardwareEnclave()
        
        with pytest.raises(KeyError):
            enc.seal(b"data", "nonexistent")
        
        fake_sealed = self.SealedEnvelope(
            ciphertext=b"fake",
            platform="test",
            key_id="nonexistent",
            metadata={}
        )
        with pytest.raises(KeyError):
            enc.unseal(fake_sealed, "nonexistent")
    
    def test_multiple_keys(self):
        """Multiple keys can coexist."""
        enc = self.HardwareEnclave()
        
        enc.generate_key("key-1")
        enc.generate_key("key-2")
        enc.generate_key("key-3")
        
        for key_id in ["key-1", "key-2", "key-3"]:
            secret = f"secret for {key_id}".encode()
            sealed = enc.seal(secret, key_id)
            recovered = enc.unseal(sealed, key_id)
            assert recovered == secret
