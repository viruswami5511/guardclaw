"""
GuardClaw Phase 3: Negative Proof & Liveness Tracking

Answers the question: WHAT didn't happen?

Courts hate missing data. Phase 3 makes "I don't know" provable.

Types of negative proof:
1. Heartbeat: Proof the system is alive
2. Tombstone: Explicit marker for expected-but-missing records
3. Failure-to-Report: System detected a failure to report
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
import uuid

from guardclaw.core.crypto import (
    Ed25519KeyManager,
    canonical_json_encode,
    canonical_hash
)


@dataclass
class HeartbeatRecord:
    """
    Heartbeat Record - Proof of system liveness.
    
    Periodic heartbeats prove:
    - System is operational
    - No records were lost
    - Continuous operation timeline
    
    If heartbeat stops → system failure is detectable.
    """
    
    heartbeat_id: str
    sequence_number: int  # Monotonically increasing
    timestamp: datetime
    system_state: str  # "operational", "degraded", "maintenance"
    expected_next_heartbeat: datetime
    previous_heartbeat_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""  # Ed25519 signature by system key
    
    @staticmethod
    def create(
        sequence_number: int,
        system_key_manager: Ed25519KeyManager,
        system_state: str = "operational",
        heartbeat_interval: timedelta = timedelta(hours=1),
        previous_heartbeat_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "HeartbeatRecord":
        """
        Create a heartbeat record.
        
        Args:
            sequence_number: Monotonic sequence number
            system_key_manager: System's key manager
            system_state: System status
            heartbeat_interval: Expected time until next heartbeat
            previous_heartbeat_id: ID of previous heartbeat (chain)
            metadata: Additional metadata
            
        Returns:
            Signed HeartbeatRecord
        """
        heartbeat_id = f"heartbeat-{sequence_number:06d}-{uuid.uuid4()}"
        now = datetime.now(timezone.utc)
        
        record = HeartbeatRecord(
            heartbeat_id=heartbeat_id,
            sequence_number=sequence_number,
            timestamp=now,
            system_state=system_state,
            expected_next_heartbeat=now + heartbeat_interval,
            previous_heartbeat_id=previous_heartbeat_id,
            metadata=metadata or {}
        )
        
        # Sign the heartbeat
        record.sign(system_key_manager)
        
        return record
    
    def to_dict_for_signing(self) -> Dict[str, Any]:
        """Get dictionary representation for signing (excludes signature)."""
        return {
            "heartbeat_id": self.heartbeat_id,
            "sequence_number": self.sequence_number,
            "timestamp": self.timestamp.isoformat(),
            "system_state": self.system_state,
            "expected_next_heartbeat": self.expected_next_heartbeat.isoformat(),
            "previous_heartbeat_id": self.previous_heartbeat_id,
            "metadata": self.metadata
        }
    
    def sign(self, key_manager: Ed25519KeyManager) -> None:
        """Sign the heartbeat record."""
        canonical_bytes = canonical_json_encode(self.to_dict_for_signing())
        self.signature = key_manager.sign(canonical_bytes)
    
    def hash(self) -> str:
        """Compute deterministic hash of heartbeat."""
        return canonical_hash(self.to_dict_for_signing())
    
    def verify_signature(self, public_key_hex: str) -> bool:
        """Verify the heartbeat signature."""
        if not self.signature:
            return False
        
        key_manager = Ed25519KeyManager.from_public_key(public_key_hex)
        canonical_bytes = canonical_json_encode(self.to_dict_for_signing())
        
        try:
            return key_manager.verify(canonical_bytes, self.signature)
        except Exception:
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Full dictionary representation (includes signature)."""
        d = self.to_dict_for_signing()
        d["signature"] = self.signature
        return d
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HeartbeatRecord":
        """Reconstruct HeartbeatRecord from dictionary."""
        return cls(
            heartbeat_id=data["heartbeat_id"],
            sequence_number=data["sequence_number"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            system_state=data["system_state"],
            expected_next_heartbeat=datetime.fromisoformat(data["expected_next_heartbeat"]),
            previous_heartbeat_id=data.get("previous_heartbeat_id"),
            metadata=data.get("metadata", {}),
            signature=data.get("signature", "")
        )


@dataclass
class TombstoneRecord:
    """
    Tombstone Record - Explicit failure marker.
    
    Marks an expected record that never arrived:
    - Expected authorization that was denied
    - Expected execution that failed
    - Expected settlement that couldn't complete
    
    This makes "didn't happen" auditable.
    """
    
    tombstone_id: str
    expected_record_type: str  # "authorization", "execution", "settlement"
    expected_record_id: str  # What was expected
    expected_at: datetime
    failure_reason: str
    failure_category: str  # "denied", "timeout", "error", "cancelled"
    detected_at: datetime
    context: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""  # Ed25519 signature by system key
    
    @staticmethod
    def create(
        expected_record_type: str,
        expected_record_id: str,
        failure_reason: str,
        failure_category: str,
        system_key_manager: Ed25519KeyManager,
        expected_at: Optional[datetime] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> "TombstoneRecord":
        """
        Create a tombstone record.
        
        Args:
            expected_record_type: Type of record that was expected
            expected_record_id: ID of expected record
            failure_reason: Why it didn't happen
            failure_category: Category of failure
            system_key_manager: System's key manager
            expected_at: When it was expected
            context: Additional context
            
        Returns:
            Signed TombstoneRecord
        """
        tombstone_id = f"tombstone-{uuid.uuid4()}"
        
        record = TombstoneRecord(
            tombstone_id=tombstone_id,
            expected_record_type=expected_record_type,
            expected_record_id=expected_record_id,
            expected_at=expected_at or datetime.now(timezone.utc),
            failure_reason=failure_reason,
            failure_category=failure_category,
            detected_at=datetime.now(timezone.utc),
            context=context or {}
        )
        
        # Sign the tombstone
        record.sign(system_key_manager)
        
        return record
    
    def to_dict_for_signing(self) -> Dict[str, Any]:
        """Get dictionary representation for signing (excludes signature)."""
        return {
            "tombstone_id": self.tombstone_id,
            "expected_record_type": self.expected_record_type,
            "expected_record_id": self.expected_record_id,
            "expected_at": self.expected_at.isoformat(),
            "failure_reason": self.failure_reason,
            "failure_category": self.failure_category,
            "detected_at": self.detected_at.isoformat(),
            "context": self.context
        }
    
    def sign(self, key_manager: Ed25519KeyManager) -> None:
        """Sign the tombstone record."""
        canonical_bytes = canonical_json_encode(self.to_dict_for_signing())
        self.signature = key_manager.sign(canonical_bytes)
    
    def hash(self) -> str:
        """Compute deterministic hash of tombstone."""
        return canonical_hash(self.to_dict_for_signing())
    
    def verify_signature(self, public_key_hex: str) -> bool:
        """Verify the tombstone signature."""
        if not self.signature:
            return False
        
        key_manager = Ed25519KeyManager.from_public_key(public_key_hex)
        canonical_bytes = canonical_json_encode(self.to_dict_for_signing())
        
        try:
            return key_manager.verify(canonical_bytes, self.signature)
        except Exception:
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Full dictionary representation (includes signature)."""
        d = self.to_dict_for_signing()
        d["signature"] = self.signature
        return d
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TombstoneRecord":
        """Reconstruct TombstoneRecord from dictionary."""
        return cls(
            tombstone_id=data["tombstone_id"],
            expected_record_type=data["expected_record_type"],
            expected_record_id=data["expected_record_id"],
            expected_at=datetime.fromisoformat(data["expected_at"]),
            failure_reason=data["failure_reason"],
            failure_category=data["failure_category"],
            detected_at=datetime.fromisoformat(data["detected_at"]),
            context=data.get("context", {}),
            signature=data.get("signature", "")
        )


@dataclass
class AdminActionRecord:
    """
    Admin Action Record - System administration audit trail.
    
    Logs privileged operations:
    - Key rotations
    - Configuration changes
    - System upgrades
    - Access control modifications
    
    Separation of duties:
    - Issuer (policy)
    - Executor (runtime)
    - Settler (settlement)
    - Administrator (system)
    """
    
    action_id: str
    admin_key_id: str  # Public key hex of admin
    admin_identity: str  # Human identifier
    action_type: str  # "key_rotation", "config_change", "upgrade", "access_grant"
    action_details: Dict[str, Any]
    performed_at: datetime
    affected_components: list[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    signature: str = ""  # Ed25519 signature by admin key
    
    @staticmethod
    def create(
        admin_key_manager: Ed25519KeyManager,
        admin_identity: str,
        action_type: str,
        action_details: Dict[str, Any],
        affected_components: Optional[list[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "AdminActionRecord":
        """
        Create an admin action record.
        
        Args:
            admin_key_manager: Admin's key manager
            admin_identity: Human identifier of admin
            action_type: Type of admin action
            action_details: Details of the action
            affected_components: Which components were affected
            metadata: Additional metadata
            
        Returns:
            Signed AdminActionRecord
        """
        action_id = f"admin-{uuid.uuid4()}"
        
        record = AdminActionRecord(
            action_id=action_id,
            admin_key_id=admin_key_manager.public_key_hex(),
            admin_identity=admin_identity,
            action_type=action_type,
            action_details=action_details,
            performed_at=datetime.now(timezone.utc),
            affected_components=affected_components or [],
            metadata=metadata or {}
        )
        
        # Sign the admin action
        record.sign(admin_key_manager)
        
        return record
    
    def to_dict_for_signing(self) -> Dict[str, Any]:
        """Get dictionary representation for signing (excludes signature)."""
        return {
            "action_id": self.action_id,
            "admin_key_id": self.admin_key_id,
            "admin_identity": self.admin_identity,
            "action_type": self.action_type,
            "action_details": self.action_details,
            "performed_at": self.performed_at.isoformat(),
            "affected_components": sorted(self.affected_components),  # Deterministic
            "metadata": self.metadata
        }
    
    def sign(self, key_manager: Ed25519KeyManager) -> None:
        """Sign the admin action record."""
        canonical_bytes = canonical_json_encode(self.to_dict_for_signing())
        self.signature = key_manager.sign(canonical_bytes)
    
    def hash(self) -> str:
        """Compute deterministic hash of admin action."""
        return canonical_hash(self.to_dict_for_signing())
    
    def verify_signature(self, public_key_hex: Optional[str] = None) -> bool:
        """Verify the admin action signature."""
        if not self.signature:
            return False
        
        key_hex = public_key_hex or self.admin_key_id
        key_manager = Ed25519KeyManager.from_public_key(key_hex)
        canonical_bytes = canonical_json_encode(self.to_dict_for_signing())
        
        try:
            return key_manager.verify(canonical_bytes, self.signature)
        except Exception:
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Full dictionary representation (includes signature)."""
        d = self.to_dict_for_signing()
        d["signature"] = self.signature
        return d
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AdminActionRecord":
        """Reconstruct AdminActionRecord from dictionary."""
        return cls(
            action_id=data["action_id"],
            admin_key_id=data["admin_key_id"],
            admin_identity=data["admin_identity"],
            action_type=data["action_type"],
            action_details=data["action_details"],
            performed_at=datetime.fromisoformat(data["performed_at"]),
            affected_components=data.get("affected_components", []),
            metadata=data.get("metadata", {}),
            signature=data.get("signature", "")
        )
