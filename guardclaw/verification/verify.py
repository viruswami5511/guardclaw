"""
GuardClaw Verification Module - Phase 3 Extended

Phase 2: Cryptographic verification (LOCKED)
Phase 3: Authority chain verification (NEW)
"""

from dataclasses import dataclass
from typing import List, Tuple, Dict, Any, Optional


from guardclaw.core.models import AuthorizationProof, ExecutionReceipt, SettlementRecord
from guardclaw.core.crypto import Ed25519KeyManager, canonical_json_encode


@dataclass
class VerificationResult:
    """Result of a verification check."""
    valid: bool
    component: str
    message: str
    details: Dict[str, Any] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "valid": self.valid,
            "component": self.component,
            "message": self.message,
            "details": self.details or {}
        }


# ============================================================================
# PHASE 2 VERIFICATION (LOCKED - DO NOT MODIFY)
# ============================================================================

def verify_proof_signature(proof: AuthorizationProof, issuer_public_key: str) -> bool:
    """
    Verify authorization proof signature.
    Phase 2: LOCKED
    """
    return proof.verify_signature(issuer_public_key)


def verify_receipt_signature(receipt: ExecutionReceipt, executor_public_key: str) -> bool:
    """
    Verify execution receipt signature.
    Phase 2: LOCKED
    """
    return receipt.verify_signature(executor_public_key)


def verify_settlement_signature(settlement: SettlementRecord, settler_public_key: str) -> bool:
    """
    Verify settlement record signature.
    Phase 2: LOCKED
    """
    return settlement.verify_signature(settler_public_key)


def verify_proof_receipt_binding(proof: AuthorizationProof, receipt: ExecutionReceipt) -> bool:
    """
    Verify cryptographic binding between proof and receipt.
    Phase 2: LOCKED
    """
    return receipt.proof_hash == proof.hash()


def verify_receipt_settlement_binding(receipt: ExecutionReceipt, settlement: SettlementRecord) -> bool:
    """
    Verify cryptographic binding between receipt and settlement.
    Phase 2: LOCKED
    """
    return settlement.receipt_hash == receipt.hash()


def verify_proof_settlement_binding(proof: AuthorizationProof, settlement: SettlementRecord) -> bool:
    """
    Verify cryptographic binding between proof and settlement.
    Phase 2: LOCKED
    """
    return settlement.proof_hash == proof.hash()


def verify_complete_chain(
    proof: AuthorizationProof,
    receipt: ExecutionReceipt,
    settlement: SettlementRecord,
    issuer_public_key: str,
    executor_public_key: str,
    settler_public_key: str
) -> Tuple[bool, List[VerificationResult]]:
    """
    Verify complete Proof → Receipt → Settlement chain.
    Phase 2: LOCKED
    
    Args:
        proof: Authorization proof
        receipt: Execution receipt
        settlement: Settlement record
        issuer_public_key: Issuer's public key (hex)
        executor_public_key: Executor's public key (hex)
        settler_public_key: Settler's public key (hex)
        
    Returns:
        (all_valid, list_of_results)
    """
    results = []
    
    # 1. Verify proof signature
    proof_sig_valid = verify_proof_signature(proof, issuer_public_key)
    results.append(VerificationResult(
        valid=proof_sig_valid,
        component="AuthorizationProof",
        message="Signature verified successfully" if proof_sig_valid else "Signature verification failed"
    ))
    
    # 2. Verify receipt signature
    receipt_sig_valid = verify_receipt_signature(receipt, executor_public_key)
    results.append(VerificationResult(
        valid=receipt_sig_valid,
        component="ExecutionReceipt",
        message="Signature verified successfully" if receipt_sig_valid else "Signature verification failed"
    ))
    
    # 3. Verify settlement signature
    settlement_sig_valid = verify_settlement_signature(settlement, settler_public_key)
    results.append(VerificationResult(
        valid=settlement_sig_valid,
        component="SettlementRecord",
        message="Signature verified successfully" if settlement_sig_valid else "Signature verification failed"
    ))
    
    # 4. Verify proof-receipt binding
    proof_receipt_binding = verify_proof_receipt_binding(proof, receipt)
    results.append(VerificationResult(
        valid=proof_receipt_binding,
        component="ProofReceiptBinding",
        message="Receipt is cryptographically bound to proof" if proof_receipt_binding else "Binding verification failed"
    ))
    
    # 5. Verify receipt-settlement binding
    receipt_settlement_binding = verify_receipt_settlement_binding(receipt, settlement)
    results.append(VerificationResult(
        valid=receipt_settlement_binding,
        component="ReceiptSettlementBinding",
        message="Settlement is cryptographically bound to receipt" if receipt_settlement_binding else "Binding verification failed"
    ))
    
    # 6. Verify proof-settlement binding
    proof_settlement_binding = verify_proof_settlement_binding(proof, settlement)
    results.append(VerificationResult(
        valid=proof_settlement_binding,
        component="ProofSettlementBinding",
        message="Settlement is bound to proof" if proof_settlement_binding else "Binding verification failed"
    ))
    
    all_valid = all(r.valid for r in results)
    
    return all_valid, results


# ============================================================================
# PHASE 3 VERIFICATION (NEW)
# ============================================================================

def verify_policy_anchor(proof: AuthorizationProof, expected_policy_hash: str) -> bool:
    """
    Verify that proof was issued under a specific policy.
    Phase 3: NEW
    
    Args:
        proof: Authorization proof
        expected_policy_hash: Expected policy hash
        
    Returns:
        True if policy anchor matches
    """
    return proof.policy_anchor_hash == expected_policy_hash


def verify_trigger_context(proof: AuthorizationProof) -> Tuple[bool, str]:
    """
    Verify that proof has valid trigger context.
    Phase 3: NEW
    
    Args:
        proof: Authorization proof
        
    Returns:
        (is_valid, message)
    """
    if not proof.trigger_context:
        return False, "Proof missing trigger context"
    
    required_fields = ["trigger_id", "trigger_type", "trigger_hash"]
    for field in required_fields:
        if field not in proof.trigger_context:
            return False, f"Trigger context missing required field: {field}"
    
    return True, "Trigger context valid"


def verify_intent_reference(proof: AuthorizationProof) -> Tuple[bool, str]:
    """
    Verify that proof has valid intent reference.
    Phase 3: NEW
    
    Args:
        proof: Authorization proof
        
    Returns:
        (is_valid, message)
    """
    if not proof.intent_reference:
        return False, "Proof missing intent reference"
    
    required_fields = ["intent_id", "intent_type", "intent_hash"]
    for field in required_fields:
        if field not in proof.intent_reference:
            return False, f"Intent reference missing required field: {field}"
    
    return True, "Intent reference valid"


def verify_context_manifest(receipt: ExecutionReceipt) -> Tuple[bool, str]:
    """
    Verify that receipt has context manifest hash.
    Phase 3: NEW
    
    Args:
        receipt: Execution receipt
        
    Returns:
        (is_valid, message)
    """
    if not receipt.context_manifest_hash:
        return False, "Receipt missing context manifest hash"
    
    return True, "Context manifest hash present"


def verify_complete_chain_with_authority(
    proof: AuthorizationProof,
    receipt: ExecutionReceipt,
    settlement: SettlementRecord,
    issuer_public_key: str,
    executor_public_key: str,
    settler_public_key: str,
    expected_policy_hash: Optional[str] = None
) -> Tuple[bool, List[VerificationResult]]:
    """
    Verify complete chain with Phase 3 authority checks.
    
    Args:
        proof: Authorization proof
        receipt: Execution receipt
        settlement: Settlement record
        issuer_public_key: Issuer's public key (hex)
        executor_public_key: Executor's public key (hex)
        settler_public_key: Settler's public key (hex)
        expected_policy_hash: Optional expected policy hash
        
    Returns:
        (all_valid, list_of_results)
    """
    # Start with Phase 2 verification
    all_valid, results = verify_complete_chain(
        proof, receipt, settlement,
        issuer_public_key, executor_public_key, settler_public_key
    )
    
    # Add Phase 3 checks
    
    # 1. Policy anchor
    if expected_policy_hash:
        policy_anchor_valid = verify_policy_anchor(proof, expected_policy_hash)
        results.append(VerificationResult(
            valid=policy_anchor_valid,
            component="PolicyAnchor",
            message="Policy anchor matches" if policy_anchor_valid else "Policy anchor mismatch"
        ))
        all_valid = all_valid and policy_anchor_valid
    
    # 2. Trigger context
    trigger_valid, trigger_msg = verify_trigger_context(proof)
    results.append(VerificationResult(
        valid=trigger_valid,
        component="TriggerContext",
        message=trigger_msg
    ))
    # Not critical - warning only
    
    # 3. Intent reference
    intent_valid, intent_msg = verify_intent_reference(proof)
    results.append(VerificationResult(
        valid=intent_valid,
        component="IntentReference",
        message=intent_msg
    ))
    # Not critical - warning only
    
    # 4. Context manifest
    context_valid, context_msg = verify_context_manifest(receipt)
    results.append(VerificationResult(
        valid=context_valid,
        component="ContextManifest",
        message=context_msg
    ))
    # Not critical - warning only
    
    return all_valid, results


def check_proof_expiry(proof: AuthorizationProof) -> Tuple[bool, str]:
    """Check if proof has expired."""
    if proof.is_expired():
        return False, f"Proof expired at {proof.expires_at.isoformat()}"
    return True, "Proof not expired"


def batch_verify(
    items: List[Tuple[Any, str]],
    verify_func
) -> List[VerificationResult]:
    """
    Batch verify multiple items.
    
    Args:
        items: List of (item, public_key) tuples
        verify_func: Verification function
        
    Returns:
        List of VerificationResult
    """
    results = []
    for item, public_key in items:
        valid = verify_func(item, public_key)
        results.append(VerificationResult(
            valid=valid,
            component=type(item).__name__,
            message="Verified" if valid else "Verification failed"
        ))
    return results
