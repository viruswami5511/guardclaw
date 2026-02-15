"""
Compatibility layer for Phase 1 components - Updated for Phase 2.

CRYPTO INVARIANT: Sign canonical bytes, NOT hashes.
"""

import yaml
import json
import uuid
import hashlib
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Optional
from dataclasses import replace

from guardclaw.core.models import (
    AuthorizationProof, 
    ActionRequest, 
    DecisionType,
    SettlementRecord,
    SettlementState,
    ExecutionReceipt
)
from guardclaw.core.crypto import Ed25519KeyManager, KeyManager, canonical_json_encode


class PolicyEngine:
    """Simple PolicyEngine for Phase 1/2 testing."""
    
    def __init__(self, policy_config: dict, key_manager):
        """Initialize policy engine."""
        self.policy_config = policy_config
        self.key_manager = key_manager
        self.default_decision = policy_config.get('default_decision', 'DENY')
    
    @classmethod
    def from_yaml(cls, policy_file: Path, key_manager):
        """Load policy from YAML file."""
        with open(policy_file, 'r') as f:
            policy_config = yaml.safe_load(f)
        return cls(policy_config, key_manager)
    
    def authorize(self, action_request: ActionRequest) -> AuthorizationProof:
        """
        Authorize an action request.
        
        CRYPTO RULE: Signs canonical bytes, NOT hash.
        """
        decision = DecisionType.ALLOW if self.default_decision == "ALLOW" else DecisionType.DENY
        
        # Calculate policy hash for V1 compatibility
        policy_str = json.dumps(self.policy_config, sort_keys=True)
        policy_hash = hashlib.sha256(policy_str.encode()).hexdigest()
        
        # Create proof WITHOUT signature first
        proof = AuthorizationProof(
            proof_id=f"proof-{uuid.uuid4()}",
            action_id=action_request.action_id,
            agent_id=action_request.agent_id,
            decision=decision,
            allowed_action_type=action_request.action_type,
            allowed_target=action_request.target_resource,
            allowed_operation=action_request.operation,
            reason=f"Policy default: {self.default_decision}",
            matched_rule_id=None,
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            issuer_id="policy-engine",
            policy_id=self.policy_config.get('name', 'phase1-policy'),
            policy_version=self.policy_config.get('version', '1.0'),
            policy_hash=policy_hash,
            signature=""
        )
        
        # Sign the proof using CANONICAL BYTES (not hash)
        canonical_bytes = canonical_json_encode(proof.to_dict_for_signing())
        signature = self.key_manager.sign(canonical_bytes)
        
        proof = replace(proof, signature=signature)
        
        return proof


class SettlementEngine:
    """Simple SettlementEngine for Phase 1/2 testing."""
    
    def __init__(self, ledger, key_manager):
        """Initialize settlement engine."""
        self.ledger = ledger
        self.key_manager = key_manager
    
    def settle(self, proof: AuthorizationProof, receipt: ExecutionReceipt) -> SettlementRecord:
        """
        Settle proof against receipt.
        
        CRYPTO RULE: Signs canonical bytes, NOT hash.
        """
        # Check if execution matched authorization
        mismatch = (
            proof.allowed_action_type != receipt.observed_action_type or
            proof.allowed_target != receipt.observed_target or
            proof.allowed_operation != receipt.observed_operation
        )
        
        if mismatch:
            final_state = SettlementState.SETTLED_MISMATCH
            reason = "Execution did not match authorization"
        elif receipt.status == "SUCCESS":
            final_state = SettlementState.SETTLED_SUCCESS
            reason = "Execution matched authorization and succeeded"
        elif receipt.status in ["FAILURE", "DENIED", "EXPIRED"]:
            final_state = SettlementState.SETTLED_FAILURE
            reason = f"Execution matched authorization but {receipt.status.lower()}"
        else:
            final_state = SettlementState.SETTLED_MISMATCH
            reason = f"Unknown status: {receipt.status}"
        
        # Calculate hashes for binding (Phase 2)
        proof_hash = proof.hash()
        receipt_hash = receipt.hash()
        
        # Create settlement without signature
        settlement = SettlementRecord(
            settlement_id=f"settlement-{uuid.uuid4()}",
            proof_id=proof.proof_id,
            proof_hash=proof_hash,
            receipt_id=receipt.receipt_id,
            receipt_hash=receipt_hash,
            final_state=final_state,
            reason=reason,
            settled_at=datetime.now(timezone.utc),
            settler_id="settlement-engine",
            signature=""
        )
        
        # Sign the settlement using CANONICAL BYTES (not hash)
        canonical_bytes = canonical_json_encode(settlement.to_dict_for_signing())
        signature = self.key_manager.sign(canonical_bytes)
        
        settlement = replace(settlement, signature=signature)
        
        # Append to ledger
        self.ledger.append_settlement(settlement)
        
        return settlement


class Ledger:
    """Simple Ledger for Phase 1/2 testing."""
    
    def __init__(self, ledger_path: Path, key_manager):
        """Initialize ledger."""
        self.ledger_path = Path(ledger_path)
        self.key_manager = key_manager
        self.entries = []
        
        if self.ledger_path.exists():
            with open(self.ledger_path, 'r') as f:
                data = json.load(f)
                self.entries = data.get('entries', [])
    
    @classmethod
    def load_or_create(cls, ledger_path: Path, key_manager):
        """Load existing ledger or create new one."""
        return cls(ledger_path, key_manager)
    
    def append_authorization(self, proof: AuthorizationProof):
        """Append authorization to ledger."""
        entry = {
            "entry_type": "authorization",
            "data": proof.to_dict()
        }
        self.entries.append(entry)
        self.save()
    
    def append_settlement(self, settlement: SettlementRecord):
        """Append settlement to ledger."""
        entry = {
            "entry_type": "settlement",
            "data": settlement.to_dict()
        }
        self.entries.append(entry)
        self.save()
    
    def save(self):
        """Save ledger to disk."""
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.ledger_path, 'w') as f:
            json.dump({"entries": self.entries}, f, indent=2, default=str)
