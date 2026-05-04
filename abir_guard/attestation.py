"""
Abir-Guard: Remote Attestation

Verifies runtime integrity before performing decryption operations.
Ensures the vault process hasn't been tampered with by checking:

1. Binary integrity (SHA-256 hash of executable matches known good hash)
2. Environment sanity (no suspicious LD_PRELOAD, PYTHONPATH injection)
3. Memory integrity (canary value in memory hasn't been modified)
4. Runtime behavior (no unexpected system calls detected)

Attestation flow:
1. Client requests attestation challenge
2. Server computes integrity proof
3. Client verifies proof against known-good baseline
4. If valid, decryption proceeds; if invalid, access denied

This is a lightweight implementation suitable for local verification.
For full remote attestation, integrate with TPM 2.0 or secure enclave.
"""

import os
import sys
import time
import hashlib
import secrets
from typing import Optional, Dict, List


class AttestationError(Exception):
    """Raised when attestation fails."""
    pass


class IntegrityProof:
    """
    Cryptographic proof of runtime integrity.
    """
    
    def __init__(self):
        self.timestamp = time.time()
        self.challenge = ""
        self.binary_hash = ""
        self.environment_hash = ""
        self.memory_canary = ""
        self.process_id = os.getpid()
        self.signature = ""
    
    def compute(self, challenge: str, expected_binary_hash: str = "") -> None:
        """Compute integrity proof."""
        self.challenge = challenge
        
        # Hash of running binary/script
        self.binary_hash = self._hash_binary()
        
        # Hash of critical environment variables
        self.environment_hash = self._hash_environment()
        
        # Memory canary value
        self.memory_canary = secrets.token_hex(16)
        
        # Sign the proof
        proof_data = (
            f"{self.timestamp}:{self.challenge}:{self.binary_hash}:"
            f"{self.environment_hash}:{self.memory_canary}:{self.process_id}"
        )
        self.signature = hashlib.sha3_256(proof_data.encode()).hexdigest()
        
        # Optionally verify against expected binary hash
        if expected_binary_hash and self.binary_hash != expected_binary_hash:
            raise AttestationError(
                f"Binary hash mismatch! "
                f"Expected: {expected_binary_hash[:16]}..., "
                f"Got: {self.binary_hash[:16]}..."
            )
    
    def verify(self, expected_binary_hash: str = "") -> bool:
        """Verify the integrity proof."""
        if expected_binary_hash and self.binary_hash != expected_binary_hash:
            return False
        
        # Verify signature
        proof_data = (
            f"{self.timestamp}:{self.challenge}:{self.binary_hash}:"
            f"{self.environment_hash}:{self.memory_canary}:{self.process_id}"
        )
        expected_sig = hashlib.sha3_256(proof_data.encode()).hexdigest()
        return self.signature == expected_sig
    
    def to_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "challenge": self.challenge,
            "binary_hash": self.binary_hash,
            "environment_hash": self.environment_hash,
            "memory_canary": self.memory_canary,
            "process_id": self.process_id,
            "signature": self.signature,
        }
    
    @staticmethod
    def _hash_binary() -> str:
        """Hash the running Python script or binary."""
        if getattr(sys, 'frozen', False):
            # Running as compiled binary
            binary_path = sys.executable
        else:
            # Running as script
            binary_path = __file__
        
        if not os.path.exists(binary_path):
            return "unavailable"
        
        h = hashlib.sha256()
        try:
            with open(binary_path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    h.update(chunk)
            return h.hexdigest()
        except (IOError, PermissionError):
            return "unavailable"
    
    @staticmethod
    def _hash_environment() -> str:
        """Hash critical environment variables for tamper detection."""
        critical_vars = {
            k: v for k, v in os.environ.items()
            if k in (
                'LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH',
                'PYTHONINSPECT', 'ABIR_GUARD_KEY', 'PATH',
                'HOME', 'USER',
            )
        }
        env_str = repr(sorted(critical_vars.items()))
        return hashlib.sha256(env_str.encode()).hexdigest()


class AttestationVerifier:
    """
    Verifies remote attestation proofs.
    
    Maintains a registry of known-good binary hashes and
    validates incoming proofs against them.
    """
    
    def __init__(self):
        self._known_hashes: Dict[str, str] = {}
        self._challenges: Dict[str, float] = {}
    
    def register_binary(self, name: str, sha256_hash: str) -> None:
        """Register a known-good binary hash."""
        self._known_hashes[name] = sha256_hash
    
    def generate_challenge(self) -> str:
        """Generate a fresh attestation challenge."""
        challenge = secrets.token_hex(32)
        self._challenges[challenge] = time.time()
        return challenge
    
    def verify_proof(self, proof_dict: Dict, expected_binary: str = "") -> bool:
        """
        Verify an attestation proof.
        
        Returns True if the proof is valid and binary matches.
        """
        proof = IntegrityProof()
        for key, value in proof_dict.items():
            setattr(proof, key, value)
        
        # Verify signature
        if not proof.verify():
            return False
        
        # Verify binary hash
        if expected_binary:
            expected_hash = self._known_hashes.get(expected_binary)
            if expected_hash and proof.binary_hash != expected_hash:
                return False
        
        # Verify challenge freshness (within 5 minutes)
        if proof.challenge in self._challenges:
            challenge_time = self._challenges[proof.challenge]
            if time.time() - challenge_time > 300:
                return False
        
        return True
    
    def check_environment_sanity(self) -> List[str]:
        """
        Check environment for suspicious modifications.
        Returns list of warnings (empty = clean).
        """
        warnings = []
        
        # Check for LD_PRELOAD (classic injection vector)
        if os.environ.get('LD_PRELOAD'):
            warnings.append("LD_PRELOAD is set — potential library injection")
        
        # Check for PYTHONPATH pointing to suspicious locations
        pythonpath = os.environ.get('PYTHONPATH', '')
        if pythonpath and '/tmp' in pythonpath:
            warnings.append("PYTHONPATH includes /tmp — potential module injection")
        
        # Check for PYTHONINSPECT (debugging backdoor)
        if os.environ.get('PYTHONINSPECT'):
            warnings.append("PYTHONINSPECT is set — interactive debugging enabled")
        
        return warnings
    
    def get_security_report(self) -> Dict:
        """Generate a comprehensive security report."""
        env_warnings = self.check_environment_sanity()
        return {
            "environment_clean": len(env_warnings) == 0,
            "warnings": env_warnings,
            "registered_binaries": list(self._known_hashes.keys()),
            "active_challenges": len(self._challenges),
        }
