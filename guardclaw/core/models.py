"""
GuardClaw Core Data Models - Phase 3 Extended

Phase 3 Extensions:
- AuthorizationProof: Added policy_anchor, trigger_context, intent_reference
- ExecutionReceipt: Added context_manifest_hash
- SettlementRecord: Enhanced with causality tracking
- All Phase 2 crypto intact (NO MODIFICATIONS)
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional
import uuid

from guardclaw.core.crypto import (
    Ed25519KeyManager,
    canonical_json_encode,
    canonical_hash
)
from guardclaw.core.causality import TriggerContext, IntentReference


@dataclass
class ActionRequest:
    """
    Action Request - User's requested action.
    
    Phase 3: Unchanged (foundation)
    """
    action_type: str
    target: str
    parameters: Dict[str, Any]
    requested_by: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    intent: str = ""
    context: Dict[str, Any] = field(default_factory=dict)
    
    def hash(self) -> str:
        """Compute deterministic hash (excludes timestamp for consistency)."""
        return canonical_hash({
            "action_type": self.action_type,
            "target": self.target,
            "parameters": self.parameters,
            "requested_by": self.requested_by,
            "intent": self.intent
        })
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "action_type": self.action_type,
            "target": self.target,
            "parameters": self.parameters,
            "requested_by": self.requested_by,
            "timestamp": self.timestamp.isoformat(),
            "intent": self.intent,
            "context": self.context
        }
    
    @staticmethod
    def validate(data: Dict[str, Any]) -> bool:
        """Validate action request has required fields."""
        required = ["action_type", "target", "parameters", "requested_by"]
        return all(field in data for field in required)


@dataclass
class AuthorizationProof:
    """
    Authorization Proof - Policy decision with cryptographic signature.
    
    Phase 2: Ed25519 signing, hash binding
    Phase 3: Policy anchor, trigger context, intent reference
    """
    proof_id: str
    action: ActionRequest
    decision: str
    reason: str
    policy_version: str
    issued_at: datetime
    expires_at: datetime
    issuer: str
    
    # Phase 3: Non-Repudiation & Causality
    policy_anchor_hash: str = ""  # Hash of policy that made this decision
    approver_key_id: str = ""  # Who "turned the key" (delegated authority)
    trigger_context: Optional[Dict[str, Any]] = None  # What caused this authorization?
    intent_reference: Optional[Dict[str, Any]] = None  # Link to user intent
    organizational_context: Dict[str, Any] = field(default_factory=dict)
    
    signature: str = ""  # Phase 2: Ed25519 signature
    
    def to_dict_for_signing(self) -> Dict[str, Any]:
        """
        Get dictionary representation for signing (excludes signature).
        Phase 2: LOCKED - Do not modify
        """
        return {
            "proof_id": self.proof_id,
            "action": self.action.to_dict(),
            "decision": self.decision,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "issuer": self.issuer,
            # Phase 3 additions
            "policy_anchor_hash": self.policy_anchor_hash,
            "approver_key_id": self.approver_key_id,
            "trigger_context": self.trigger_context,
            "intent_reference": self.intent_reference,
            "organizational_context": self.organizational_context
        }
    
    def sign(self, key_manager: Ed25519KeyManager) -> None:
        """
        Sign the proof using Ed25519.
        Phase 2: LOCKED - Do not modify
        """
        canonical_bytes = canonical_json_encode(self.to_dict_for_signing())
        self.signature = key_manager.sign(canonical_bytes)
    
    def hash(self) -> str:
        """
        Compute deterministic hash of proof (for binding).
        Phase 2: LOCKED - Do not modify
        """
        return canonical_hash(self.to_dict_for_signing())
    
    def verify_signature(self, public_key_hex: str) -> bool:
        """
        Verify the proof signature.
        Phase 2: LOCKED - Do not modify
        """
        if not self.signature:
            return False
        
        key_manager = Ed25519KeyManager.from_public_key(public_key_hex)
        canonical_bytes = canonical_json_encode(self.to_dict_for_signing())
        
        try:
            return key_manager.verify(canonical_bytes, self.signature)
        except Exception:
            return False
    
    def is_expired(self) -> bool:
        """Check if proof has expired."""
        return datetime.now(timezone.utc) > self.expires_at
    
    def verify_action_match(self, action: ActionRequest) -> bool:
        """Verify that action matches the authorized action."""
        return self.action.hash() == action.hash()
    
    def to_dict(self) -> Dict[str, Any]:
        """Full dictionary representation (includes signature)."""
        d = self.to_dict_for_signing()
        d["signature"] = self.signature
        return d
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthorizationProof":
        """Reconstruct AuthorizationProof from dictionary."""
        action_data = data["action"]
        action = ActionRequest(
            action_type=action_data["action_type"],
            target=action_data["target"],
            parameters=action_data["parameters"],
            requested_by=action_data["requested_by"],
            timestamp=datetime.fromisoformat(action_data["timestamp"]),
            intent=action_data.get("intent", ""),
            context=action_data.get("context", {})
        )
        
        return cls(
            proof_id=data["proof_id"],
            action=action,
            decision=data["decision"],
            reason=data["reason"],
            policy_version=data["policy_version"],
            issued_at=datetime.fromisoformat(data["issued_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            issuer=data["issuer"],
            policy_anchor_hash=data.get("policy_anchor_hash", ""),
            approver_key_id=data.get("approver_key_id", ""),
            trigger_context=data.get("trigger_context"),
            intent_reference=data.get("intent_reference"),
            organizational_context=data.get("organizational_context", {}),
            signature=data.get("signature", "")
        )


@dataclass
class ExecutionReceipt:
    """
    Execution Receipt - Proof of execution with cryptographic binding.
    
    Phase 2: proof_hash binding, Ed25519 signing
    Phase 3: context_manifest_hash (what data was used)
    """
    receipt_id: str
    proof_id: str
    executed_at: datetime
    executor: str
    success: bool
    result: Optional[Any] = None
    error: Optional[str] = None
    
    # Phase 2: Hash binding
    proof_hash: str = ""  # Cryptographic binding to proof
    
    # Phase 3: Context tracking
    context_manifest_hash: str = ""  # Hash of data used for execution
    execution_duration_ms: Optional[int] = None
    
    signature: str = ""  # Phase 2: Ed25519 signature
    
    def to_dict_for_signing(self) -> Dict[str, Any]:
        """
        Get dictionary representation for signing (excludes signature).
        Phase 2: LOCKED - Do not modify structure
        """
        return {
            "receipt_id": self.receipt_id,
            "proof_id": self.proof_id,
            "executed_at": self.executed_at.isoformat(),
            "executor": self.executor,
            "success": self.success,
            "result": self.result,
            "error": self.error,
            "proof_hash": self.proof_hash,
            # Phase 3 additions
            "context_manifest_hash": self.context_manifest_hash,
            "execution_duration_ms": self.execution_duration_ms
        }
    
    def sign(self, key_manager: Ed25519KeyManager) -> None:
        """
        Sign the receipt using Ed25519.
        Phase 2: LOCKED - Do not modify
        """
        canonical_bytes = canonical_json_encode(self.to_dict_for_signing())
        self.signature = key_manager.sign(canonical_bytes)
    
    def hash(self) -> str:
        """
        Compute deterministic hash of receipt (for binding).
        Phase 2: LOCKED - Do not modify
        """
        return canonical_hash(self.to_dict_for_signing())
    
    def verify_signature(self, public_key_hex: str) -> bool:
        """
        Verify the receipt signature.
        Phase 2: LOCKED - Do not modify
        """
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
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionReceipt":
        """Reconstruct ExecutionReceipt from dictionary."""
        return cls(
            receipt_id=data["receipt_id"],
            proof_id=data["proof_id"],
            executed_at=datetime.fromisoformat(data["executed_at"]),
            executor=data["executor"],
            success=data["success"],
            result=data.get("result"),
            error=data.get("error"),
            proof_hash=data.get("proof_hash", ""),
            context_manifest_hash=data.get("context_manifest_hash", ""),
            execution_duration_ms=data.get("execution_duration_ms"),
            signature=data.get("signature", "")
        )


@dataclass
class SettlementRecord:
    """
    Settlement Record - Verification that execution matched authorization.
    
    Phase 2: proof_hash + receipt_hash binding, Ed25519 signing
    Phase 3: Enhanced verification metadata
    """
    settlement_id: str
    proof_id: str
    receipt_id: str
    settled_at: datetime
    settler: str
    verification_result: str
    verification_details: Dict[str, Any]
    
    # Phase 2: Hash binding
    proof_hash: str = ""  # Binding to proof
    receipt_hash: str = ""  # Binding to receipt
    
    # Phase 3: Enhanced tracking
    verification_trace: Dict[str, Any] = field(default_factory=dict)  # Audit trail of checks
    
    signature: str = ""  # Phase 2: Ed25519 signature
    
    def to_dict_for_signing(self) -> Dict[str, Any]:
        """
        Get dictionary representation for signing (excludes signature).
        Phase 2: LOCKED - Do not modify structure
        """
        return {
            "settlement_id": self.settlement_id,
            "proof_id": self.proof_id,
            "receipt_id": self.receipt_id,
            "settled_at": self.settled_at.isoformat(),
            "settler": self.settler,
            "verification_result": self.verification_result,
            "verification_details": self.verification_details,
            "proof_hash": self.proof_hash,
            "receipt_hash": self.receipt_hash,
            # Phase 3 additions
            "verification_trace": self.verification_trace
        }
    
    def sign(self, key_manager: Ed25519KeyManager) -> None:
        """
        Sign the settlement using Ed25519.
        Phase 2: LOCKED - Do not modify
        """
        canonical_bytes = canonical_json_encode(self.to_dict_for_signing())
        self.signature = key_manager.sign(canonical_bytes)
    
    def hash(self) -> str:
        """
        Compute deterministic hash of settlement.
        Phase 2: LOCKED - Do not modify
        """
        return canonical_hash(self.to_dict_for_signing())
    
    def verify_signature(self, public_key_hex: str) -> bool:
        """
        Verify the settlement signature.
        Phase 2: LOCKED - Do not modify
        """
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
    def from_dict(cls, data: Dict[str, Any]) -> "SettlementRecord":
        """Reconstruct SettlementRecord from dictionary."""
        return cls(
            settlement_id=data["settlement_id"],
            proof_id=data["proof_id"],
            receipt_id=data["receipt_id"],
            settled_at=datetime.fromisoformat(data["settled_at"]),
            settler=data["settler"],
            verification_result=data["verification_result"],
            verification_details=data["verification_details"],
            proof_hash=data.get("proof_hash", ""),
            receipt_hash=data.get("receipt_hash", ""),
            verification_trace=data.get("verification_trace", {}),
            signature=data.get("signature", "")
        )


def utc_now() -> datetime:
    """Get current UTC time with timezone."""
    return datetime.now(timezone.utc)
