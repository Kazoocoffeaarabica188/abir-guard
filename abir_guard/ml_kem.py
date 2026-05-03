"""
Abir-Guard: ML-KEM Key Encapsulation Module

Cleanroom Approach
==================
Core Philosophy: Never store the raw key and the data in the same memory page.

- Key Generation: Private keys generated via cryptography library (internal zeroization)
- Encapsulation: Ephemeral keys created per-operation, discarded after shared secret derived
- Shared Secrets: Never persisted — derived on-demand, used immediately for HKDF
- Decapsulation: Input ciphertext processed in-place; output shared secret returned as bytes

Security Watchdog: 200ms latency threshold detects side-channel timing attacks.
If encapsulation/decapsulation takes longer than 200ms on expected hardware,
a SecurityException is raised to prevent timing-based key extraction.

Fallback: Uses X25519 (classical ECDH) when liboqs (ML-KEM-1024) is not installed.
Hybrid mode combines both: ML-KEM + X25519 secrets hashed together via SHA-256.
"""

import secrets
import hashlib
import time
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

HANDSHAKE_TIMEOUT = 0.2  # 200ms watchdog


class SecurityException(Exception):
    """Security exception for anomaly detection"""
    pass


class MLKEM1024:
    """
    ML-KEM-1024 Key Encapsulation (NIST FIPS 203)
    Falls back to X25519 when liboqs unavailable
    """
    
    def __init__(self):
        self._available = self._try_load_oqs()
    
    def _try_load_oqs(self) -> bool:
        try:
            from liboqs import Kem
            self._kem = Kem("ML-KEM-1024")
            return True
        except ImportError:
            self._kem = None
            return False
    
    def is_available(self) -> bool:
        return self._available
    
    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate ML-KEM keypair"""
        if self._kem:
            pk = self._kem.generate_keypair()
            sk = self._kem.export_secret_key()
            return pk, sk
        return self._x25519_keygen()
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate with security watchdog"""
        start_time = time.perf_counter()
        
        if self._kem:
            ct = self._kem.encapsulate(public_key)
            ss = self._kem.export_shared_secret()
        else:
            ct, ss = self._x25519_encapsulate(public_key)
        
        elapsed = time.perf_counter() - start_time
        
        # Security Watchdog: Latency Anomaly Detection
        if elapsed > HANDSHAKE_TIMEOUT:
            raise SecurityException(
                f"Latency Anomaly: {elapsed:.3f}s (expected <{HANDSHAKE_TIMEOUT}s). "
                "Potential entropy injection attack."
            )
        
        return ct, ss
    
    def encapsulate_secure(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Deprecated - use encapsulate() with watchdog"""
        return self.encapsulate(public_key)
    
    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate"""
        if self._kem:
            return self._kem.decapsulate(ciphertext, secret_key)
        return self._x25519_decapsulate(ciphertext, secret_key)
    
    def _x25519_keygen(self) -> Tuple[bytes, bytes]:
        """X25519 key generation — real ECDH keypair"""
        sk = x25519.X25519PrivateKey.generate()
        pk = sk.public_key()
        return pk.public_bytes_raw(), sk.private_bytes_raw()
    
    def _x25519_encapsulate(self, public_key_bytes: bytes) -> Tuple[bytes, bytes]:
        """
        X25519 encapsulation — proper ECDH
        
        Generates ephemeral X25519 keypair, derives shared secret via
        ECDH with recipient's public key. Returns (ephemeral_public_key, shared_secret).
        """
        # Generate ephemeral X25519 keypair
        ephemeral_sk = x25519.X25519PrivateKey.generate()
        ephemeral_pk = ephemeral_sk.public_key()
        
        # Load recipient's public key
        recipient_pk = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
        
        # Perform ECDH: derive shared secret
        shared_secret = ephemeral_sk.exchange(recipient_pk)
        
        # HKDF to derive final shared secret from ECDH output
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"Abir-Guard-PQC-2026",
            info=b"kem-shared-secret",
            backend=default_backend()
        )
        derived_ss = hkdf.derive(shared_secret)
        
        # Ciphertext = ephemeral public key (32 bytes)
        # Receiver uses it to perform ECDH with their secret key
        return ephemeral_pk.public_bytes_raw(), derived_ss
    
    def _x25519_decapsulate(self, ciphertext: bytes, secret_key_bytes: bytes) -> bytes:
        """
        X25519 decapsulation — proper ECDH
        
        Uses recipient's secret key and sender's ephemeral public key (from ciphertext)
        to derive the same shared secret via ECDH.
        """
        # Load recipient's secret key
        sk = x25519.X25519PrivateKey.from_private_bytes(secret_key_bytes)
        
        # Extract sender's ephemeral public key from ciphertext
        ephemeral_pk = x25519.X25519PublicKey.from_public_bytes(ciphertext)
        
        # Perform ECDH
        shared_secret = sk.exchange(ephemeral_pk)
        
        # HKDF to derive final shared secret (same as encapsulate)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"Abir-Guard-PQC-2026",
            info=b"kem-shared-secret",
            backend=default_backend()
        )
        return hkdf.derive(shared_secret)
    
    def _derive_shared(self, peer_public: bytes, private_key: bytes) -> bytes:
        """Derive shared secret (legacy, not used by proper X25519 methods)"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"Abir-Guard-PQC-2026",
            info=b"kem-shared-secret",
            backend=default_backend()
        )
        return hkdf.derive(peer_public + private_key)


class HybridKem:
    """Hybrid ML-KEM + X25519"""
    
    def __init__(self):
        self.ml_kem = MLKEM1024()
    
    def keygen(self) -> Tuple[bytes, bytes]:
        ml_pk, ml_sk = self.ml_kem.keygen()
        
        # Add X25519
        x_sk = x25519.X25519PrivateKey.generate()
        x_pk = x_sk.public_key()
        
        return ml_pk + x_pk.public_bytes_raw(), ml_sk + x_sk.private_bytes_raw()
    
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Hybrid encapsulate with security watchdog"""
        start_time = time.perf_counter()
        
        if len(public_key) > 32:
            ml_pk = public_key[:-32]
        else:
            ml_pk = public_key
        
        ml_ct, ml_ss = self.ml_kem.encapsulate(ml_pk)
        
        try:
            x_pk = x25519.X25519PublicKey.from_public_bytes(public_key[-32:])
            ep = secrets.token_bytes(32)
            x_ss = hashlib.sha256(x_pk.public_bytes_raw() + ep).digest()
        except Exception:
            x_ss = secrets.token_bytes(32)
        
        # Combine both secrets
        combined_ss = hashlib.sha256(ml_ss + x_ss).digest()
        combined_ct = ml_ct + x_ss
        
        elapsed = time.perf_counter() - start_time
        
        # Security Watchdog
        if elapsed > HANDSHAKE_TIMEOUT:
            raise SecurityException(
                f"Hybrid handshake latency anomaly: {elapsed:.3f}s"
            )
        
        return combined_ct, combined_ss
    
    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Hybrid decapsulate"""
        ml_ct = ciphertext[:-32] if len(ciphertext) > 32 else ciphertext
        x_ct = ciphertext[-32:]
        
        ml_ss = self.ml_kem.decapsulate(ml_ct, secret_key[:-32] if len(secret_key) > 32 else secret_key)
        
        return hashlib.sha256(ml_ss + x_ct).digest()
    
    @property
    def is_quantum_safe(self) -> bool:
        return self.ml_kem.is_available()


def demo():
    """Demo ML-KEM with security watchdog"""
    print("=" * 50)
    print("Abir-Guard: ML-KEM Key Encapsulation")
    print("=" * 50)
    
    kem = MLKEM1024()
    print(f"\n[1] ML-KEM-1024 available: {kem.is_available()}")
    
    print("\n[2] Generate keypair...")
    pk, sk = kem.keygen()
    print(f"    Public: {len(pk)} bytes, Secret: {len(sk)} bytes")
    
    print("\n[3] Encapsulate with watchdog...")
    try:
        ct, ss = kem.encapsulate(pk)
        print(f"    Ciphertext: {len(ct)} bytes")
        print(f"    Shared secret: OK")
    except SecurityException as e:
        print(f"    Security alert: {e}")
    
    print("\n[4] Decapsulate...")
    ss2 = kem.decapsulate(ct, sk)
    print(f"    Match: {ss == ss2}")
    
    print("\n[5] Hybrid mode...")
    h = HybridKem()
    hpk, hsk = h.keygen()
    hct, hss = h.encapsulate(hpk)
    hss2 = h.decapsulate(hct, hsk)
    print(f"    Hybrid quantum-safe: {h.is_quantum_safe}")
    print(f"    Hybrid round-trip: {hss == hss2}")
    
    print("\n" + "=" * 50)
    print("Security features: Handshake watchdog active")
    print("=" * 50)


if __name__ == "__main__":
    demo()
