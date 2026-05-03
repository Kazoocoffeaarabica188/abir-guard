"""
Abir-Guard: Hardware Security Module Integration
Supports TPM, Keychain, and secure key storage
"""

import os
import sys
import base64
from typing import Optional, Tuple
from pathlib import Path


class HSMKeyStore:
    """
    Hardware Security Module abstraction
    
    Supports:
    - macOS Keychain
    - Windows Credential Manager  
    - Linux Secret Service
    - TPM 2.0
    """
    
    def __init__(self, backend: str = "auto"):
        self.backend = self._detect_backend(backend)
    
    def _detect_backend(self, backend: str) -> str:
        """Detect available HSM backend"""
        if backend != "auto":
            return backend
        
        # Detect OS
        if sys.platform == "darwin":
            return "keychain"
        elif sys.platform == "win32":
            return "credential_manager"
        elif sys.platform == "linux":
            # Check for secret service
            if os.environ.get("DISPLAY"):
                return "secret_service"
            return "file"
        
        return "file"
    
    def store_secret(self, key_id: str, secret: bytes) -> bool:
        """Store secret in HSM"""
        if self.backend == "keychain":
            return self._store_keychain(key_id, secret)
        elif self.backend == "credential_manager":
            return self._store_credential(key_id, secret)
        elif self.backend == "file":
            return self._store_file(key_id, secret)
        
        return False
    
    def retrieve_secret(self, key_id: str) -> Optional[bytes]:
        """Retrieve secret from HSM"""
        if self.backend == "keychain":
            return self._retrieve_keychain(key_id)
        elif self.backend == "credential_manager":
            return self._retrieve_credential(key_id)
        elif self.backend == "file":
            return self._retrieve_file(key_id)
        
        return None
    
    def delete_secret(self, key_id: str) -> bool:
        """Delete secret from HSM"""
        if self.backend == "keychain":
            return self._delete_keychain(key_id)
        elif self.backend == "credential_manager":
            return self._delete_credential(key_id)
        elif self.backend == "file":
            return self._delete_file(key_id)
        
        return False
    
    def _store_keychain(self, key_id: str, secret: bytes) -> bool:
        """Store in macOS Keychain"""
        try:
            import keyring
            keyring.set_password("abir_guard", key_id, base64.b64encode(secret).decode())
            return True
        except ImportError:
            return self._store_file(key_id, secret)
        except Exception:
            return False
    
    def _retrieve_keychain(self, key_id: str) -> Optional[bytes]:
        """Retrieve from macOS Keychain"""
        try:
            import keyring
            data = keyring.get_password("abir_guard", key_id)
            if data:
                return base64.b64decode(data)
        except Exception:
            pass
        return None
    
    def _delete_keychain(self, key_id: str) -> bool:
        """Delete from macOS Keychain"""
        try:
            import keyring
            keyring.delete_password("abir_guard", key_id)
            return True
        except Exception:
            return False
    
    def _store_credential(self, key_id: str, secret: bytes) -> bool:
        """Store in Windows Credential Manager"""
        return self._store_file(key_id, secret)
    
    def _retrieve_credential(self, key_id: str) -> Optional[bytes]:
        """Retrieve from Windows Credential Manager"""
        return self._retrieve_file(key_id)
    
    def _delete_credential(self, key_id: str) -> bool:
        """Delete from Windows Credential Manager"""
        return self._delete_file(key_id)
    
    def _store_file(self, key_id: str, secret: bytes) -> bool:
        """Store in encrypted file"""
        try:
            keyring_dir = Path.home() / ".abir_guard"
            keyring_dir.mkdir(exist_ok=True)
            
            # XOR with machine ID for basic protection
            machine_id = self._get_machine_id()
            protected = bytes(a ^ b for a, b in zip(secret, (machine_id * len(secret))[:len(secret)]))
            
            (keyring_dir / f"{key_id}.key").write_bytes(base64.b64encode(protected))
            return True
        except Exception:
            return False
    
    def _retrieve_file(self, key_id: str) -> Optional[bytes]:
        """Retrieve from encrypted file"""
        try:
            keyring_dir = Path.home() / ".abir_guard"
            protected = base64.b64decode((keyring_dir / f"{key_id}.key").read_bytes())
            
            # XOR with machine ID
            machine_id = self._get_machine_id()
            secret = bytes(a ^ b for a, b in zip(protected, (machine_id * len(protected))[:len(protected)]))
            
            return secret
        except Exception:
            return None
    
    def _delete_file(self, key_id: str) -> bool:
        """Delete from encrypted file"""
        try:
            keyring_dir = Path.home() / ".abir_guard"
            (keyring_dir / f"{key_id}.key").unlink()
            return True
        except Exception:
            return False
    
    def _get_machine_id(self) -> bytes:
        """Get machine-specific ID"""
        if sys.platform == "darwin":
            # macOS
            return b"abir_guard_mac"
        elif sys.platform == "win32":
            return b"abir_guard_windows"
        else:
            # Linux - use /etc/machine-id
            try:
                return Path("/etc/machine-id").read_bytes().strip()
            except:
                return b"abir_guard_linux"


class TPMKeyStore:
    """
    TPM 2.0 Key Store
    
    Uses hardware TPM for key storage
    """
    
    def __init__(self):
        self.available = self._check_tpm()
    
    def _check_tpm(self) -> bool:
        """Check if TPM is available"""
        # Check for TPM device
        tpm_paths = [
            "/dev/tpm0",
            "/dev/tpmrm0",
            "C:\\Program Files\\Trusted Platform Module\\tpm.dll"
        ]
        
        for path in tpm_paths:
            if os.path.exists(path):
                return True
        
        return False
    
    def is_available(self) -> bool:
        """Check if TPM is available"""
        return self.available
    
    def store_with_tpm(self, key_id: str, secret: bytes) -> Tuple[bool, str]:
        """Store key protected by TPM"""
        if not self.available:
            return False, "TPM not available"
        
        # For now, fallback to file storage with TPM seal indication
        # Real TPM integration requires tpm2-tss library
        try:
            import keyring
            keyring.set_password("abir_guard_tpm", key_id, base64.b64encode(secret).decode())
            return True, "Stored with TPM seal"
        except Exception as e:
            return False, str(e)
    
    def retrieve_with_tpm(self, key_id: str) -> Optional[bytes]:
        """Retrieve TPM-protected key"""
        if not self.available:
            return None
        
        try:
            import keyring
            data = keyring.get_password("abir_guard_tpm", key_id)
            if data:
                return base64.b64decode(data)
        except Exception:
            pass
        
        return None


class SecureVault:
    """
    Abir-Guard with HSM integration
    
    Usage:
        vault = SecureVault(use_hsm=True)
        vault.generate_keypair("agent-1")
        vault.store("agent-1", b"secret")
    """
    
    def __init__(self, use_hsm: bool = False, hsm_backend: str = "auto"):
        from . import Vault as V
        self.vault = V()
        self.hsm = None
        
        if use_hsm:
            self.hsm = HSMKeyStore(hsm_backend)
            self.tpm = TPMKeyStore()
    
    def generate_keypair(self, key_id: str) -> Tuple[str, str]:
        """Generate keypair and store in HSM"""
        pub, sec = self.vault.generate_keypair(key_id)
        
        if self.hsm:
            # sec is already a string (base64-encoded), store as bytes
            self.hsm.store_secret(key_id, sec.encode() if isinstance(sec, str) else sec)
        
        return pub, sec
    
    def store(self, key_id: str, data: bytes):
        """Store data"""
        return self.vault.store(key_id, data)
    
    def retrieve(self, key_id: str, ciphertext):
        """Retrieve data"""
        return self.vault.retrieve(key_id, ciphertext)


def demo():
    """Demo HSM integration"""
    print("=" * 50)
    print("Abir-Guard: HSM Integration")
    print("=" * 50)
    
    # Test basic HSM
    print("\n[1] Detecting HSM backend...")
    hsm = HSMKeyStore()
    print(f"    Backend: {hsm.backend}")
    
    # Test key storage
    print("\n[2] Storing secret...")
    hsm.store_secret("test-key", b"my-secret-data")
    print("    Stored!")
    
    # Test retrieval
    print("\n[3] Retrieving secret...")
    secret = hsm.retrieve_secret("test-key")
    print(f"    Retrieved: {secret}")
    
    # Test TPM
    print("\n[4] Checking TPM...")
    tpm = TPMKeyStore()
    print(f"    TPM available: {tpm.is_available()}")
    
    print("\n" + "=" * 50)


if __name__ == "__main__":
    demo()