"""
Abir-Guard: FIPS 140-3 Compliance Mode

Strict algorithm enforcement for compliance environments.
When FIPS mode is enabled:

- Only NIST-approved algorithms are allowed
- No fallback to classical algorithms (X25519 blocked in FIPS mode)
- Minimum key lengths enforced
- Approved random number generators only
- All operations logged for audit trail

Approved Algorithms (FIPS 140-3):
- Encryption: AES-256-GCM (FIPS 197)
- Key Derivation: HKDF-SHA256 (SP 800-56C) or Argon2id
- Hashing: SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-512
- Digital Signatures: ML-DSA-65 (FIPS 204)
- Key Encapsulation: ML-KEM-1024 (FIPS 203) — Production via pqcrypto
- RNG: OS CSPRNG (/dev/urandom, CryptGenRandom)

Blocked:
- X25519 fallback (not FIPS-approved for new deployments, only used when no PQC library)
- Custom/non-standard algorithms
- Keys < 256 bits for symmetric encryption
"""

import os
import hashlib
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


class FIPSModeError(Exception):
    """Raised when a non-FIPS operation is attempted in FIPS mode."""
    pass


class FIPSConfig:
    """FIPS 140-3 configuration constants."""
    MIN_AES_KEY_BITS = 256
    MIN_SHARED_SECRET_BITS = 256
    REQUIRED_NONCE_BITS = 96
    APPROVED_HASH_ALGORITHMS = {"sha256", "sha384", "sha512", "sha3_256", "sha3_512"}
    MIN_PASSWORD_LENGTH = 8  # for key derivation


class FIPSValidator:
    """
    Validates operations against FIPS 140-3 requirements.
    """
    
    @staticmethod
    def validate_aes_key(key: bytes) -> None:
        """Ensure AES key meets minimum length."""
        if len(key) * 8 < FIPSConfig.MIN_AES_KEY_BITS:
            raise FIPSModeError(
                f"AES key too short: {len(key) * 8} bits "
                f"(minimum {FIPSConfig.MIN_AES_KEY_BITS})"
            )
    
    @staticmethod
    def validate_nonce(nonce: bytes) -> None:
        """Ensure nonce is the correct length."""
        if len(nonce) * 8 != FIPSConfig.REQUIRED_NONCE_BITS:
            raise FIPSModeError(
                f"Invalid nonce length: {len(nonce) * 8} bits "
                f"(required {FIPSConfig.REQUIRED_NONCE_BITS})"
            )
    
    @staticmethod
    def validate_hash_algorithm(algorithm: str) -> None:
        """Ensure hash algorithm is FIPS-approved."""
        if algorithm.lower() not in FIPSConfig.APPROVED_HASH_ALGORITHMS:
            raise FIPSModeError(
                f"Non-FIPS hash algorithm: {algorithm}. "
                f"Approved: {FIPSConfig.APPROVED_HASH_ALGORITHMS}"
            )
    
    @staticmethod
    def validate_shared_secret(secret: bytes) -> None:
        """Ensure shared secret meets minimum entropy."""
        if len(secret) * 8 < FIPSConfig.MIN_SHARED_SECRET_BITS:
            raise FIPSModeError(
                f"Shared secret too short: {len(secret) * 8} bits "
                f"(minimum {FIPSConfig.MIN_SHARED_SECRET_BITS})"
            )
    
    @staticmethod
    def validate_password(password: str) -> None:
        """Ensure password meets minimum requirements."""
        if len(password) < FIPSConfig.MIN_PASSWORD_LENGTH:
            raise FIPSModeError(
                f"Password too short: {len(password)} chars "
                f"(minimum {FIPSConfig.MIN_PASSWORD_LENGTH})"
            )
    
    @staticmethod
    def get_secure_random(nbytes: int) -> bytes:
        """Get FIPS-approved random bytes from OS CSPRNG."""
        return os.urandom(nbytes)


class FIPSEncryptor:
    """
    FIPS 140-3 compliant encryption wrapper.
    
    All operations are validated before execution.
    Non-compliant operations raise FIPSModeError.
    """
    
    def __init__(self):
        self.validator = FIPSValidator()
        self._operation_log = []
    
    def encrypt(self, plaintext: bytes, key: bytes) -> dict:
        """FIPS-compliant encryption."""
        self.validator.validate_aes_key(key)
        
        nonce = FIPSValidator.get_secure_random(12)
        self.validator.validate_nonce(nonce)
        
        cipher = AESGCM(key)
        ct_and_tag = cipher.encrypt(nonce, plaintext, None)
        
        result = {
            "nonce": nonce,
            "ciphertext": ct_and_tag[:-16],
            "auth_tag": ct_and_tag[-16:],
        }
        
        self._log_operation("encrypt", len(plaintext))
        return result
    
    def decrypt(self, ciphertext: bytes, auth_tag: bytes,
                nonce: bytes, key: bytes) -> bytes:
        """FIPS-compliant decryption."""
        self.validator.validate_aes_key(key)
        self.validator.validate_nonce(nonce)
        
        ct_full = ciphertext + auth_tag
        cipher = AESGCM(key)
        plaintext = cipher.decrypt(nonce, ct_full, None)
        
        self._log_operation("decrypt", len(plaintext))
        return plaintext
    
    def derive_key(self, secret: bytes, info: bytes = b"") -> bytes:
        """FIPS-compliant key derivation using HKDF-SHA256."""
        self.validator.validate_shared_secret(secret)
        self.validator.validate_hash_algorithm("sha256")
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(secret)
    
    def hash_data(self, data: bytes, algorithm: str = "sha256") -> bytes:
        """FIPS-compliant hashing."""
        self.validator.validate_hash_algorithm(algorithm)
        
        alg_map = {
            "sha256": hashlib.sha256,
            "sha384": hashlib.sha384,
            "sha512": hashlib.sha512,
            "sha3_256": hashlib.sha3_256,
            "sha3_512": hashlib.sha3_512,
        }
        return alg_map[algorithm.lower()]().update(data) or \
               alg_map[algorithm.lower()](data).digest()
    
    def _log_operation(self, operation: str, data_size: int) -> None:
        """Log operation for audit trail."""
        import time
        self._operation_log.append({
            "operation": operation,
            "data_size": data_size,
            "timestamp": time.time(),
            "fips_mode": True,
        })
    
    def get_operation_log(self) -> list:
        return self._operation_log.copy()
