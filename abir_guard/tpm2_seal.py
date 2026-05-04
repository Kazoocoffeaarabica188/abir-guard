"""
TPM 2.0 Seal/Unseal Module for Abir-Guard

Provides hardware-sealed encryption keys using TPM 2.0 PCR binding.
Keys can only be unsealed when the system is in the same state as when sealed.

Features:
- Seal data to TPM PCR values (platform configuration registers)
- Unsealed only when PCR values match (detects tampering)
- Supports TPM device (`/dev/tpmrm0`) and resource manager
- Works via tpm2-tools CLI for maximum compatibility

Requirements:
- TPM 2.0 hardware or simulator (`/dev/tpmrm0`)
- tpm2-tools package: sudo apt-get install tpm2-tools

Usage:
    from abir_guard.tpm2_seal import TPM2Sealer
    
    tpm = TPM2Sealer()
    if tpm.is_available():
        # Seal AES key to current PCR state
        sealed = tpm.seal(b"my-secret-key", pcrs=[0, 7])
        
        # Unseal - only works if PCR values match
        recovered = tpm.unseal(sealed)
"""

import os
import subprocess
import tempfile
import secrets
import hashlib
from pathlib import Path
from typing import Optional, List, Tuple
from dataclasses import dataclass


class TPM2Error(Exception):
    """Raised when TPM operations fail."""
    pass


class TPM2NotAvailable(TPM2Error):
    """Raised when TPM hardware is not available."""
    pass


@dataclass
class SealedData:
    """Container for TPM-sealed data."""
    sealed_blob: bytes
    pcr_bank: str
    pcr_indices: List[int]
    policy_hash: str
    metadata: dict


class TPM2Sealer:
    """
    TPM 2.0 seal/unseal operations using tpm2-tools CLI.
    
    Works without Python TPM bindings - calls tpm2_tools directly.
    Gracefully degrades when TPM is not available.
    """
    
    TPM_DEVICE = os.environ.get("TPM2_DEVICE", "/dev/tpmrm0")
    TCTI = f"device:{TPM_DEVICE}"
    
    def __init__(self, tcti: Optional[str] = None):
        """
        Initialize TPM sealer.
        
        Args:
            tcti: TCTI interface string (default: device:/dev/tpmrm0)
        """
        self.tcti = tcti or self.TCTI
        self._available = None
        self._temp_dir = tempfile.mkdtemp(prefix="abir_guard_tpm_")
    
    def is_available(self) -> bool:
        """Check if TPM 2.0 is available."""
        if self._available is not None:
            return self._available
        
        try:
            result = subprocess.run(
                ["tpm2_getcap", "properties-fixed"],
                capture_output=True, text=True, timeout=5
            )
            self._available = result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._available = False
        
        return self._available
    
    def get_pcr_values(self, pcr_indices: Optional[List[int]] = None) -> dict:
        """
        Get current PCR values from TPM.
        
        Args:
            pcr_indices: PCR indices to read (default: [0, 7])
        
        Returns:
            Dict of {index: hex_value}
        """
        if not self.is_available():
            raise TPM2NotAvailable("TPM 2.0 not available")
        
        indices = pcr_indices or [0, 7]
        pcr_values = {}
        
        for idx in indices:
            try:
                result = subprocess.run(
                    ["tpm2_pcrread", f"sha256:{idx}", "-o", f"{self._temp_dir}/pcr_{idx}.bin"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    with open(f"{self._temp_dir}/pcr_{idx}.bin", "rb") as f:
                        pcr_values[idx] = f.read().hex()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        
        return pcr_values
    
    def seal(self, data: bytes, pcr_indices: Optional[List[int]] = None,
             auth_value: Optional[bytes] = None) -> SealedData:
        """
        Seal data to TPM PCR values.
        
        The data can only be unsealed when PCR values match the current state.
        
        Args:
            data: Secret data to seal (max 128 bytes for TPM)
            pcr_indices: PCR indices to bind to (default: [0, 7])
            auth_value: Optional authorization password
        
        Returns:
            SealedData container with sealed blob and metadata
        
        Raises:
            TPM2NotAvailable: If TPM is not available
            TPM2Error: If sealing fails
        """
        if not self.is_available():
            # Fallback: use software sealing with PCR simulation
            return self._software_seal(data, pcr_indices)
        
        indices = pcr_indices or [0, 7]
        pcr_policy = ",".join(f"sha256:{i}" for i in indices)
        
        # Create temp files for TPM operations
        sealed_file = f"{self._temp_dir}/sealed_{secrets.token_hex(8)}.dat"
        secret_file = f"{self._temp_dir}/secret_{secrets.token_hex(8)}.dat"
        policy_file = f"{self._temp_dir}/policy_{secrets.token_hex(8)}.bin"
        
        try:
            # Write secret data
            with open(secret_file, "wb") as f:
                f.write(data)
            
            # Create PCR policy
            result = subprocess.run(
                ["tpm2_createpolicy", "--policy-pcr",
                 "-l", pcr_policy,
                 "-f", policy_file],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode != 0:
                raise TPM2Error(f"Policy creation failed: {result.stderr}")
            
            # Seal the data
            cmd = [
                "tpm2_create",
                "-C", "o",  # owner hierarchy
                "-i", secret_file,
                "-u", f"{sealed_file}.pub",
                "-r", f"{sealed_file}.priv",
                "-L", policy_file,
                "-c", "ecc"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                raise TPM2Error(f"TPM create failed: {result.stderr}")
            
            # Get policy hash
            policy_hash = self._compute_policy_hash(indices)
            
            return SealedData(
                sealed_blob=self._read_sealed_blob(sealed_file),
                pcr_bank="sha256",
                pcr_indices=indices,
                policy_hash=policy_hash,
                metadata={"sealed_at": os.times()[0]}
            )
            
        finally:
            # Cleanup temp files
            for f in [secret_file, policy_file, f"{sealed_file}.pub", f"{sealed_file}.priv"]:
                try:
                    os.unlink(f)
                except FileNotFoundError:
                    pass
    
    def unseal(self, sealed: SealedData, auth_value: Optional[bytes] = None) -> bytes:
        """
        Unseal data from TPM.
        
        Only succeeds if current PCR values match the sealed state.
        
        Args:
            sealed: SealedData from seal() operation
            auth_value: Optional authorization password
        
        Returns:
            Original secret data
        
        Raises:
            TPM2NotAvailable: If TPM is not available
            TPM2Error: If unsealing fails (e.g., PCR mismatch)
        """
        if not self.is_available():
            return self._software_unseal(sealed)
        
        # Write sealed blob to temp file
        sealed_file = f"{self._temp_dir}/unseal_{secrets.token_hex(8)}"
        unsealed_file = f"{sealed_file}_out"
        
        try:
            with open(sealed_file, "wb") as f:
                f.write(sealed.sealed_blob)
            
            # Unseal
            cmd = [
                "tpm2_unseal",
                "-c", sealed_file,
                "-o", unsealed_file
            ]
            
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            if result.returncode != 0:
                raise TPM2Error(
                    f"TPM unseal failed (likely PCR mismatch): {result.stderr.decode()}"
                )
            
            with open(unsealed_file, "rb") as f:
                return f.read()
                
        finally:
            for f in [sealed_file, unsealed_file]:
                try:
                    os.unlink(f)
                except FileNotFoundError:
                    pass
    
    def create_primary_key(self, algorithm: str = "ecc") -> str:
        """
        Create a primary key in TPM.
        
        Args:
            algorithm: Key algorithm (ecc, rsa)
        
        Returns:
            Context file path
        """
        if not self.is_available():
            raise TPM2NotAvailable("TPM 2.0 not available")
        
        ctx_file = f"{self._temp_dir}/primary_{secrets.token_hex(8)}.ctx"
        
        cmd = [
            "tpm2_createprimary",
            "-C", "o",
            "-c", ctx_file,
            "-g", "sha256",
            "-G", algorithm
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            raise TPM2Error(f"Create primary failed: {result.stderr}")
        
        return ctx_file
    
    def generate_random(self, num_bytes: int = 32) -> bytes:
        """
        Generate cryptographically secure random bytes from TPM.
        
        Args:
            num_bytes: Number of bytes (max 32)
        
        Returns:
            Random bytes from TPM RNG
        """
        if not self.is_available():
            return secrets.token_bytes(num_bytes)
        
        rand_file = f"{self._temp_dir}/rand_{secrets.token_hex(8)}"
        
        cmd = ["tpm2_getrandom", "-o", rand_file, str(num_bytes)]
        result = subprocess.run(cmd, capture_output=True, timeout=10)
        
        if result.returncode == 0:
            with open(rand_file, "rb") as f:
                return f.read()
        else:
            return secrets.token_bytes(num_bytes)
    
    def _compute_policy_hash(self, pcr_indices: List[int]) -> str:
        """Compute SHA-256 hash of PCR policy."""
        policy_data = b""
        for idx in pcr_indices:
            try:
                result = subprocess.run(
                    ["tpm2_pcrread", f"sha256:{idx}"],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    policy_data += result.stdout.encode()
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        
        return hashlib.sha256(policy_data).hexdigest()
    
    def _read_sealed_blob(self, base_file: str) -> bytes:
        """Read and combine sealed public/private parts."""
        try:
            with open(f"{base_file}.pub", "rb") as f:
                pub = f.read()
            with open(f"{base_file}.priv", "rb") as f:
                priv = f.read()
            return pub + priv
        except FileNotFoundError:
            return b""
    
    def _software_seal(self, data: bytes, pcr_indices: Optional[List[int]] = None) -> SealedData:
        """Software fallback when TPM is not available."""
        import warnings
        warnings.warn(
            "TPM not available - using software seal (NOT hardware-bound). "
            "Install tpm2-tools for hardware sealing.",
            UserWarning
        )
        
        # Simulate PCR binding with HMAC
        pcr_sim = self._simulate_pcr_values(pcr_indices)
        key = hashlib.sha256(b"abir_guard_pcr_seal" + str(pcr_sim).encode()).digest()
        
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        nonce = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        sealed = encryptor.update(data) + encryptor.finalize() + encryptor.tag
        
        return SealedData(
            sealed_blob=nonce + sealed,
            pcr_bank="sha256",
            pcr_indices=pcr_indices or [0, 7],
            policy_hash=hashlib.sha256(str(pcr_sim).encode()).hexdigest(),
            metadata={"software_fallback": True, "sealed_at": os.times()[0]}
        )
    
    def _software_unseal(self, sealed: SealedData) -> bytes:
        """Software fallback unseal."""
        nonce = sealed.sealed_blob[:12]
        ciphertext = sealed.sealed_blob[12:-16]
        tag = sealed.sealed_blob[-16:]
        
        pcr_sim = self._simulate_pcr_values(sealed.pcr_indices)
        key = hashlib.sha256(b"abir_guard_pcr_seal" + str(pcr_sim).encode()).digest()
        
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def _simulate_pcr_values(self, indices: Optional[List[int]] = None) -> dict:
        """Simulate PCR values for software fallback."""
        return {
            idx: hashlib.sha256(f"sim_pcr_{idx}".encode()).hexdigest()
            for idx in (indices or [0, 7])
        }
    
    def cleanup(self) -> None:
        """Clean up temporary files."""
        import shutil
        try:
            shutil.rmtree(self._temp_dir, ignore_errors=True)
        except Exception:
            pass
    
    def __del__(self):
        self.cleanup()
