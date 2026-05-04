"""
Abir-Guard: Automatic Key Rotation

Implements time-based and usage-based key rotation policies.
Keys are automatically flagged for rotation when:
- Their age exceeds the maximum lifetime
- Their usage count exceeds the maximum operations limit

Rotation is a two-phase process:
1. Mark key as "expiring" — still usable for decryption
2. Mark key as "expired" — decryption still allowed, encryption blocked
3. Generate new keypair and migrate encrypted data
"""

import time
from typing import Optional, Dict, List
from dataclasses import dataclass, field


@dataclass
class KeyMetadata:
    """Metadata tracked for each key."""
    key_id: str
    created_at: float = field(default_factory=time.time)
    last_used_at: float = 0.0
    encrypt_count: int = 0
    decrypt_count: int = 0
    max_lifetime_seconds: float = 0.0  # 0 = no time limit
    max_operations: int = 0  # 0 = no usage limit
    is_expired: bool = False
    rotated_to: str = ""  # key_id of replacement key
    
    def record_encrypt(self):
        self.encrypt_count += 1
        self.last_used_at = time.time()
    
    def record_decrypt(self):
        self.decrypt_count += 1
        self.last_used_at = time.time()
    
    @property
    def total_operations(self) -> int:
        return self.encrypt_count + self.decrypt_count
    
    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at
    
    def should_expire(self) -> bool:
        """Check if key should be rotated based on policy."""
        if self.max_lifetime_seconds > 0 and self.age_seconds > self.max_lifetime_seconds:
            return True
        if self.max_operations > 0 and self.total_operations >= self.max_operations:
            return True
        return False


class KeyRotationManager:
    """
    Manages key rotation policies and tracks key lifecycle.
    
    Policies:
    - Time-based: Keys expire after N seconds
    - Usage-based: Keys expire after N operations
    - Both can be combined (whichever triggers first)
    """
    
    def __init__(
        self,
        default_max_lifetime: float = 0.0,  # seconds, 0 = unlimited
        default_max_operations: int = 0,    # operations, 0 = unlimited
    ):
        self._metadata: Dict[str, KeyMetadata] = {}
        self._default_max_lifetime = default_max_lifetime
        self._default_max_operations = default_max_operations
    
    def register_key(self, key_id: str, max_lifetime: float = None,
                     max_operations: int = None) -> KeyMetadata:
        """Register a new key with rotation policy."""
        meta = KeyMetadata(
            key_id=key_id,
            max_lifetime_seconds=(
                max_lifetime if max_lifetime is not None
                else self._default_max_lifetime
            ),
            max_operations=(
                max_operations if max_operations is not None
                else self._default_max_operations
            ),
        )
        self._metadata[key_id] = meta
        return meta
    
    def record_usage(self, key_id: str, operation: str = "encrypt"):
        """Record key usage for rotation tracking."""
        if key_id in self._metadata:
            meta = self._metadata[key_id]
            if operation == "encrypt":
                meta.record_encrypt()
            elif operation == "decrypt":
                meta.record_decrypt()
    
    def needs_rotation(self, key_id: str) -> bool:
        """Check if a key needs rotation."""
        if key_id not in self._metadata:
            return False
        return self._metadata[key_id].should_expire()
    
    def expire_key(self, key_id: str, rotated_to: str = ""):
        """Mark a key as expired."""
        if key_id in self._metadata:
            self._metadata[key_id].is_expired = True
            self._metadata[key_id].rotated_to = rotated_to
    
    def get_metadata(self, key_id: str) -> Optional[KeyMetadata]:
        """Get key metadata."""
        return self._metadata.get(key_id)
    
    def list_keys(self) -> List[Dict]:
        """List all keys with rotation status."""
        result = []
        for key_id, meta in self._metadata.items():
            result.append({
                "key_id": key_id,
                "age_seconds": round(meta.age_seconds, 1),
                "total_operations": meta.total_operations,
                "encrypt_count": meta.encrypt_count,
                "decrypt_count": meta.decrypt_count,
                "is_expired": meta.is_expired,
                "needs_rotation": meta.should_expire(),
                "rotated_to": meta.rotated_to or "",
                "max_lifetime": meta.max_lifetime_seconds,
                "max_operations": meta.max_operations,
            })
        return result
    
    def get_expiring_keys(self, warning_seconds: float = 3600) -> List[str]:
        """Get keys that will expire within the warning window."""
        expiring = []
        for key_id, meta in self._metadata.items():
            if meta.is_expired:
                continue
            if meta.max_lifetime_seconds > 0:
                remaining = meta.max_lifetime_seconds - meta.age_seconds
                if remaining <= warning_seconds:
                    expiring.append(key_id)
        return expiring
