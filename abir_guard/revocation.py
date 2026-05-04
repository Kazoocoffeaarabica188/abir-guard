"""
Abir-Guard: Key Revocation / Blacklist (CRL-style mechanism)

Implements a Certificate Revocation List (CRL) for agent keys.
Allows marking keys as compromised/revoked, preventing their use
for encryption or decryption operations.

Revocation reasons:
- compromised: Key material suspected exposed
- rotated: Key replaced by newer key (routine rotation)
- retired: Agent decommissioned
- policy: Security policy violation
"""

import time
import json
import hashlib
import hmac
from enum import Enum
from typing import Optional, Dict, List
from dataclasses import dataclass, asdict


class RevocationReason(Enum):
    COMPROMISED = "compromised"
    ROTATED = "rotated"
    RETIRED = "retired"
    POLICY = "policy"


@dataclass
class RevocationEntry:
    key_id: str
    reason: str
    timestamp: float
    revoked_by: str = ""
    details: str = ""


class RevocationList:
    """
    Tamper-evident Certificate Revocation List.
    
    Uses HMAC-SHA256 signatures to detect tampering.
    Each entry is signed with a revocation key.
    """
    
    def __init__(self, revocation_key: bytes = None):
        self._revocation_key = revocation_key or self._generate_key()
        self._entries: List[RevocationEntry] = []
        self._signature: str = ""
    
    @staticmethod
    def _generate_key() -> bytes:
        import secrets
        return secrets.token_bytes(32)
    
    def _compute_signature(self) -> str:
        """Compute HMAC signature over all entries."""
        data = json.dumps(
            [asdict(e) for e in self._entries],
            sort_keys=True
        ).encode()
        return hmac.new(
            self._revocation_key,
            data,
            hashlib.sha256
        ).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify CRL hasn't been tampered with."""
        if not self._signature:
            return True
        return hmac.compare_digest(
            self._signature,
            self._compute_signature()
        )
    
    def revoke(self, key_id: str, reason: RevocationReason,
               revoked_by: str = "", details: str = "") -> None:
        """Add a key to the revocation list."""
        entry = RevocationEntry(
            key_id=key_id,
            reason=reason.value,
            timestamp=time.time(),
            revoked_by=revoked_by,
            details=details,
        )
        self._entries.append(entry)
        self._signature = self._compute_signature()
    
    def is_revoked(self, key_id: str) -> bool:
        """Check if a key is revoked."""
        return any(e.key_id == key_id for e in self._entries)
    
    def get_entry(self, key_id: str) -> Optional[RevocationEntry]:
        """Get revocation details for a key."""
        for entry in self._entries:
            if entry.key_id == key_id:
                return entry
        return None
    
    def list_revoked(self) -> List[Dict]:
        """List all revoked keys."""
        return [asdict(e) for e in self._entries]
    
    def export(self) -> str:
        """Export CRL as signed JSON."""
        return json.dumps({
            "version": 1,
            "entries": [asdict(e) for e in self._entries],
            "signature": self._signature,
            "exported_at": time.time(),
        }, indent=2)
    
    @classmethod
    def load(cls, crl_json: str, revocation_key: bytes) -> "RevocationList":
        """Import CRL from JSON."""
        data = json.loads(crl_json)
        crl = cls(revocation_key)
        crl._entries = [
            RevocationEntry(**e) for e in data["entries"]
        ]
        crl._signature = data["signature"]
        if not crl.verify_integrity():
            raise ValueError("CRL integrity check failed — tampering detected")
        return crl
