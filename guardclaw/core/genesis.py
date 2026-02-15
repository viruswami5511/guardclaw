"""
GuardClaw Phase 2: Genesis (MINIMAL STUB)

This is a reference implementation for Phase 5 testing.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field, asdict

from guardclaw.core.crypto import Ed25519KeyManager, canonical_json_encode


@dataclass
class GenesisRecord:
    """Genesis record (ledger initialization)."""
    
    genesis_id: str
    ledger_name: str
    timestamp: str
    created_by: str
    root_public_key: str
    purpose: str
    jurisdiction: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None
    
    @classmethod
    def create(
        cls,
        ledger_name: str,
        created_by: str,
        root_key_manager: Ed25519KeyManager,
        purpose: str,
        jurisdiction: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "GenesisRecord":
        """Create and sign genesis record."""
        
        genesis_id = f"genesis-{uuid.uuid4()}"
        timestamp = datetime.now(timezone.utc).isoformat()
        
        record = cls(
            genesis_id=genesis_id,
            ledger_name=ledger_name,
            timestamp=timestamp,
            created_by=created_by,
            root_public_key=root_key_manager.public_key_hex(),
            purpose=purpose,
            jurisdiction=jurisdiction,
            metadata=metadata or {}
        )
        
        # Sign
        record_dict = asdict(record)
        record_dict.pop('signature')
        canonical_bytes = canonical_json_encode(record_dict)
        record.signature = root_key_manager.sign(canonical_bytes)
        
        return record
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GenesisRecord":
        """Load from dictionary."""
        return cls(**data)


@dataclass
class AgentRegistration:
    """Agent registration record."""
    
    agent_id: str
    agent_name: str
    timestamp: str
    registered_by: str
    agent_public_key: str
    capabilities: List[str]
    valid_from: str
    valid_until: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None
    
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
        metadata: Optional[Dict[str, Any]] = None
    ) -> "AgentRegistration":
        """Create and sign agent registration."""
        
        timestamp = datetime.now(timezone.utc).isoformat()
        
        record = cls(
            agent_id=agent_id,
            agent_name=agent_name,
            timestamp=timestamp,
            registered_by=registered_by,
            agent_public_key=agent_key_manager.public_key_hex(),
            capabilities=capabilities,
            valid_from=valid_from,
            valid_until=valid_until,
            metadata=metadata or {}
        )
        
        # Sign with delegating key (root key)
        record_dict = asdict(record)
        record_dict.pop('signature')
        canonical_bytes = canonical_json_encode(record_dict)
        record.signature = delegating_key_manager.sign(canonical_bytes)
        
        return record
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentRegistration":
        """Load from dictionary."""
        return cls(**data)


@dataclass
class KeyDelegation:
    """Key delegation record (stub)."""
    
    delegation_id: str
    timestamp: str
    delegating_key: str
    delegated_key: str
    capabilities: List[str]
    valid_from: str
    valid_until: str
    signature: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyDelegation":
        return cls(**data)
