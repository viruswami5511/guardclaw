"""
GuardClaw GEF: Genesis Records.

GenesisRecord and AgentRegistration are signed using canonical_json_encode.
They are emitted as the FIRST envelope in a GEFLedger via:
    ledger.emit(EventType.GENESIS, record.to_dict())
    ledger.emit(EventType.AGENT_REGISTRATION, reg.to_dict())
"""

import uuid
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict

from guardclaw.core.crypto import Ed25519KeyManager, canonical_json_encode
from guardclaw.core.observers import utc_now


# ─────────────────────────────────────────────────────────────
# GenesisRecord
# ─────────────────────────────────────────────────────────────

@dataclass
class GenesisRecord:
    """Root-of-trust record. Must be the first entry in any GEF ledger."""

    genesis_id:      str
    ledger_name:     str
    timestamp:       str   # GEF format: YYYY-MM-DDTHH:MM:SS.mmmZ
    created_by:      str
    root_public_key: str
    purpose:         str
    jurisdiction:    Optional[str] = None
    metadata:        Dict[str, Any] = field(default_factory=dict)
    signature:       Optional[str] = None

    @classmethod
    def create(
        cls,
        ledger_name: str,
        created_by: str,
        root_key_manager: Ed25519KeyManager,
        purpose: str,
        jurisdiction: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "GenesisRecord":
        record = cls(
            genesis_id=      f"genesis-{uuid.uuid4()}",
            ledger_name=     ledger_name,
            timestamp=       utc_now(),
            created_by=      created_by,
            root_public_key= root_key_manager.public_key_hex(),
            purpose=         purpose,
            jurisdiction=    jurisdiction,
            metadata=        metadata or {},
        )
        # Sign over canonical bytes of the record (excluding signature)
        d = asdict(record)
        d.pop("signature")
        record.signature = root_key_manager.sign(canonical_json_encode(d))
        return record

    def verify(self, root_key_manager: Ed25519KeyManager) -> bool:
        """Verify the genesis record signature."""
        if not self.signature:
            return False
        d = asdict(self)
        d.pop("signature")
        return root_key_manager.verify(canonical_json_encode(d), self.signature)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GenesisRecord":
        return cls(**data)


# ─────────────────────────────────────────────────────────────
# AgentRegistration
# ─────────────────────────────────────────────────────────────

@dataclass
class AgentRegistration:
    """Agent registration. Signed by the delegating (root) key."""

    agent_id:         str
    agent_name:       str
    timestamp:        str   # GEF format
    registered_by:    str
    agent_public_key: str
    capabilities:     List[str]
    valid_from:       str
    valid_until:      str
    metadata:         Dict[str, Any] = field(default_factory=dict)
    signature:        Optional[str] = None

    @classmethod
    def create(
        cls,
        agent_id: str,
        agent_name: str,
        registered_by: str,
        delegating_key_manager: Ed25519KeyManager,
        agent_key_manager: Ed25519KeyManager,
        capabilities: List[str],
        valid_from: str,
        valid_until: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "AgentRegistration":
        record = cls(
            agent_id=         agent_id,
            agent_name=       agent_name,
            timestamp=        utc_now(),
            registered_by=    registered_by,
            agent_public_key= agent_key_manager.public_key_hex(),
            capabilities=     capabilities,
            valid_from=       valid_from,
            valid_until=      valid_until,
            metadata=         metadata or {},
        )
        d = asdict(record)
        d.pop("signature")
        record.signature = delegating_key_manager.sign(canonical_json_encode(d))
        return record

    def verify(self, delegating_key_manager: Ed25519KeyManager) -> bool:
        if not self.signature:
            return False
        d = asdict(self)
        d.pop("signature")
        return delegating_key_manager.verify(canonical_json_encode(d), self.signature)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentRegistration":
        return cls(**data)


# ─────────────────────────────────────────────────────────────
# KeyDelegation (payload-only — no standalone signature)
# ─────────────────────────────────────────────────────────────

@dataclass
class KeyDelegation:
    """Key delegation record. Carried as payload in a GEF envelope."""

    delegation_id:  str
    timestamp:      str
    delegating_key: str
    delegated_key:  str
    capabilities:   List[str]
    valid_from:     str
    valid_until:    str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyDelegation":
        return cls(**data)
