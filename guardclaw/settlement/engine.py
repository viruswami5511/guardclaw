"""
Settlement engine for comparing authorization proofs and execution receipts.
"""

from datetime import datetime, timezone
from typing import Optional
import uuid

from guardclaw.core.models import (
    AuthorizationProof,
    ExecutionReceipt,
    SettlementRecord,
    SettlementState,
    DecisionType,
    utc_now,
)
from guardclaw.core.crypto import Ed25519KeyManager, canonical_json_encode
from guardclaw.ledger.ledger import Ledger


class SettlementEngine:
    """
    Phase 2 Settlement Engine with Ed25519 signing and hash binding.
    
    Compares authorization proofs against execution receipts to detect:
    - Unauthorized executions
    - Mismatched actions
    - Expired proofs
    - Invalid signatures
    """
    
    def __init__(self, ledger: Ledger, key_manager: Ed25519KeyManager):
        """
        Initialize settlement engine.
        
        Args:
            ledger: Ledger to read from and write to
            key_manager: Ed25519KeyManager for signing settlements
        """
        self.ledger = ledger
        self.key_manager = key_manager
        self.settler_id = "settlement-engine"
    
    def settle(
        self,
        proof: AuthorizationProof,
        receipt: ExecutionReceipt,
    ) -> SettlementRecord:
        """
        Settle a proof-receipt pair.
        
        Args:
            proof: Authorization proof
            receipt: Execution receipt
            
        Returns:
            Signed settlement record
        """
        # Determine final state and reason
        final_state, reason = self._evaluate_settlement(proof, receipt)
        
        # Create settlement record
        settlement = SettlementRecord(
            settlement_id=f"settlement-{uuid.uuid4()}",
            proof_id=proof.proof_id,
            proof_hash=proof.hash(),  # Hash binding
            receipt_id=receipt.receipt_id,
            receipt_hash=receipt.hash(),  # Hash binding
            final_state=final_state,
            reason=reason,
            settled_at=utc_now(),
            settler_id=self.settler_id,
        )
        
        # Sign settlement with Ed25519
        settlement_data = settlement.to_dict_for_signing()
        canonical_bytes = canonical_json_encode(settlement_data)
        signature = self.key_manager.sign(canonical_bytes)
        
        # Create final settlement with signature
        settlement = SettlementRecord(
            settlement_id=settlement.settlement_id,
            proof_id=settlement.proof_id,
            proof_hash=settlement.proof_hash,
            receipt_id=settlement.receipt_id,
            receipt_hash=settlement.receipt_hash,
            final_state=settlement.final_state,
            reason=settlement.reason,
            settled_at=settlement.settled_at,
            settler_id=settlement.settler_id,
            signature=signature,
        )
        
        # Append to ledger
        self.ledger.append_settlement(settlement)
        
        return settlement
    
    def _evaluate_settlement(
        self,
        proof: AuthorizationProof,
        receipt: ExecutionReceipt,
    ) -> tuple[SettlementState, str]:
        """
        Evaluate settlement state and reason.
        
        Returns:
            (final_state, reason)
        """
        # Check proof expiration
        if proof.is_expired():
            return (
                SettlementState.SETTLED_PROOF_EXPIRED,
                f"Proof expired at {proof.expires_at}",
            )
        
        # Check if proof denied
        if proof.decision != DecisionType.ALLOW:
            return (
                SettlementState.SETTLED_UNAUTHORIZED,
                f"Proof decision was {proof.decision.value}, not ALLOW",
            )
        
        # Check hash binding (receipt must reference proof)
        expected_proof_hash = proof.hash()
        if receipt.proof_hash != expected_proof_hash:
            return (
                SettlementState.SETTLED_HASH_MISMATCH,
                f"Receipt proof_hash mismatch: expected {expected_proof_hash}, got {receipt.proof_hash}",
            )
        
        # Check proof-receipt binding (proof_id)
        if receipt.proof_id != proof.proof_id:
            return (
                SettlementState.SETTLED_UNAUTHORIZED,
                f"Receipt proof_id {receipt.proof_id} does not match proof {proof.proof_id}",
            )
        
        # Check action type match
        if receipt.observed_action_type != proof.allowed_action_type:
            return (
                SettlementState.SETTLED_ACTION_MISMATCH,
                f"Action type mismatch: proof allowed {proof.allowed_action_type.value}, "
                f"receipt observed {receipt.observed_action_type.value}",
            )
        
        # Check target match
        if receipt.observed_target != proof.allowed_target:
            return (
                SettlementState.SETTLED_ACTION_MISMATCH,
                f"Target mismatch: proof allowed '{proof.allowed_target}', "
                f"receipt observed '{receipt.observed_target}'",
            )
        
        # Check operation match
        if receipt.observed_operation != proof.allowed_operation:
            return (
                SettlementState.SETTLED_ACTION_MISMATCH,
                f"Operation mismatch: proof allowed '{proof.allowed_operation}', "
                f"receipt observed '{receipt.observed_operation}'",
            )
        
        # Check execution status
        if receipt.status == "SUCCESS":
            return (
                SettlementState.SETTLED_SUCCESS,
                "Execution matched authorization and succeeded",
            )
        else:
            return (
                SettlementState.SETTLED_EXECUTION_FAILED,
                f"Execution failed: {receipt.error_message or 'unknown error'}",
            )
    
    def get_settlement_stats(self) -> dict:
        """
        Get settlement statistics from ledger.
        
        Returns:
            Dict with settlement counts by state
        """
        settlements = self.ledger.get_entries_by_type("settlement")
        
        stats = {
            "total": len(settlements),
            "by_state": {},
        }
        
        for entry in settlements:
            settlement = SettlementRecord.from_dict(entry["data"])
            state = settlement.final_state.value
            stats["by_state"][state] = stats["by_state"].get(state, 0) + 1
        
        return stats
