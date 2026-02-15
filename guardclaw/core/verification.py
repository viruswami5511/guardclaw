"""
Offline Verification Core - Phase 2

CRYPTO INVARIANT: Verify canonical bytes, NOT hashes.
Hashes are for binding, signatures are over canonical bytes.
"""

from typing import Dict, Optional, Tuple
from datetime import datetime, timezone

from guardclaw.core.models import (
    AuthorizationProof,
    ExecutionReceipt,
    SettlementRecord,
)
from guardclaw.core.crypto import Ed25519KeyManager, canonical_json_encode


class VerificationError(Exception):
    """Raised when verification fails."""
    pass


class VerificationResult:
    """Result of a verification operation."""
    
    def __init__(
        self,
        valid: bool,
        record_type: str,
        record_id: str,
        reason: str = "",
        details: Dict = None
    ):
        self.valid = valid
        self.record_type = record_type
        self.record_id = record_id
        self.reason = reason
        self.details = details or {}
        self.verified_at = datetime.now(timezone.utc)
    
    def __repr__(self) -> str:
        status = "VALID" if self.valid else "INVALID"
        return f"VerificationResult({status}, {self.record_type}, {self.record_id})"
    
    def to_dict(self) -> dict:
        """Export verification result."""
        return {
            "valid": self.valid,
            "record_type": self.record_type,
            "record_id": self.record_id,
            "reason": self.reason,
            "details": self.details,
            "verified_at": self.verified_at.isoformat()
        }


# ============================================================================
# CORE VERIFICATION FUNCTIONS
# ============================================================================

def verify_proof_signature(
    proof: AuthorizationProof,
    public_key_hex: str
) -> VerificationResult:
    """
    Verify the cryptographic signature on an authorization proof.
    
    CRYPTO RULE: Verifies canonical bytes, NOT hash.
    """
    try:
        key_manager = Ed25519KeyManager.from_public_key_hex(public_key_hex)
        
        # Get canonical bytes for verification
        canonical_bytes = canonical_json_encode(proof.to_dict_for_signing())
        
        # Verify signature over canonical bytes
        is_valid = key_manager.verify(canonical_bytes, proof.signature)
        
        if is_valid:
            return VerificationResult(
                valid=True,
                record_type="AuthorizationProof",
                record_id=proof.proof_id,
                reason="Signature verified successfully",
                details={
                    "issuer_id": proof.issuer_id,
                    "issued_at": proof.issued_at.isoformat(),
                    "policy_id": proof.policy_id
                }
            )
        else:
            return VerificationResult(
                valid=False,
                record_type="AuthorizationProof",
                record_id=proof.proof_id,
                reason="Signature verification failed",
                details={"issuer_id": proof.issuer_id}
            )
    
    except Exception as e:
        return VerificationResult(
            valid=False,
            record_type="AuthorizationProof",
            record_id=proof.proof_id,
            reason=f"Verification error: {str(e)}"
        )


def verify_receipt_signature(
    receipt: ExecutionReceipt,
    public_key_hex: str
) -> VerificationResult:
    """
    Verify the cryptographic signature on an execution receipt.
    
    CRYPTO RULE: Verifies canonical bytes, NOT hash.
    """
    try:
        key_manager = Ed25519KeyManager.from_public_key_hex(public_key_hex)
        
        # Get canonical bytes for verification
        canonical_bytes = canonical_json_encode(receipt.to_dict_for_signing())
        
        is_valid = key_manager.verify(canonical_bytes, receipt.signature)
        
        if is_valid:
            return VerificationResult(
                valid=True,
                record_type="ExecutionReceipt",
                record_id=receipt.receipt_id,
                reason="Signature verified successfully",
                details={
                    "executor_id": receipt.executor_id,
                    "executed_at": receipt.executed_at.isoformat(),
                    "status": receipt.status
                }
            )
        else:
            return VerificationResult(
                valid=False,
                record_type="ExecutionReceipt",
                record_id=receipt.receipt_id,
                reason="Signature verification failed"
            )
    
    except Exception as e:
        return VerificationResult(
            valid=False,
            record_type="ExecutionReceipt",
            record_id=receipt.receipt_id,
            reason=f"Verification error: {str(e)}"
        )


def verify_settlement_signature(
    settlement: SettlementRecord,
    public_key_hex: str
) -> VerificationResult:
    """
    Verify the cryptographic signature on a settlement record.
    
    CRYPTO RULE: Verifies canonical bytes, NOT hash.
    """
    try:
        key_manager = Ed25519KeyManager.from_public_key_hex(public_key_hex)
        
        # Get canonical bytes for verification
        canonical_bytes = canonical_json_encode(settlement.to_dict_for_signing())
        
        is_valid = key_manager.verify(canonical_bytes, settlement.signature)
        
        if is_valid:
            return VerificationResult(
                valid=True,
                record_type="SettlementRecord",
                record_id=settlement.settlement_id,
                reason="Signature verified successfully",
                details={
                    "settler_id": settlement.settler_id,
                    "settled_at": settlement.settled_at.isoformat(),
                    "final_state": settlement.final_state.value
                }
            )
        else:
            return VerificationResult(
                valid=False,
                record_type="SettlementRecord",
                record_id=settlement.settlement_id,
                reason="Signature verification failed"
            )
    
    except Exception as e:
        return VerificationResult(
            valid=False,
            record_type="SettlementRecord",
            record_id=settlement.settlement_id,
            reason=f"Verification error: {str(e)}"
        )


# ============================================================================
# HASH BINDING VERIFICATION (Phase 2)
# ============================================================================

def verify_proof_receipt_binding(
    proof: AuthorizationProof,
    receipt: ExecutionReceipt
) -> VerificationResult:
    """Verify that a receipt is cryptographically bound to a proof."""
    try:
        actual_proof_hash = proof.hash()
        
        if receipt.proof_hash == actual_proof_hash:
            return VerificationResult(
                valid=True,
                record_type="ProofReceiptBinding",
                record_id=f"{proof.proof_id}->{receipt.receipt_id}",
                reason="Receipt is cryptographically bound to proof",
                details={
                    "proof_hash": actual_proof_hash,
                    "proof_id": proof.proof_id,
                    "receipt_id": receipt.receipt_id
                }
            )
        else:
            return VerificationResult(
                valid=False,
                record_type="ProofReceiptBinding",
                record_id=f"{proof.proof_id}->{receipt.receipt_id}",
                reason="Receipt proof_hash does not match proof",
                details={
                    "expected_hash": actual_proof_hash,
                    "receipt_hash": receipt.proof_hash
                }
            )
    
    except Exception as e:
        return VerificationResult(
            valid=False,
            record_type="ProofReceiptBinding",
            record_id=f"{proof.proof_id}->{receipt.receipt_id}",
            reason=f"Binding verification error: {str(e)}"
        )


def verify_receipt_settlement_binding(
    receipt: ExecutionReceipt,
    settlement: SettlementRecord
) -> VerificationResult:
    """Verify that a settlement is cryptographically bound to a receipt."""
    try:
        actual_receipt_hash = receipt.hash()
        
        if settlement.receipt_hash == actual_receipt_hash:
            return VerificationResult(
                valid=True,
                record_type="ReceiptSettlementBinding",
                record_id=f"{receipt.receipt_id}->{settlement.settlement_id}",
                reason="Settlement is cryptographically bound to receipt",
                details={
                    "receipt_hash": actual_receipt_hash,
                    "receipt_id": receipt.receipt_id,
                    "settlement_id": settlement.settlement_id
                }
            )
        else:
            return VerificationResult(
                valid=False,
                record_type="ReceiptSettlementBinding",
                record_id=f"{receipt.receipt_id}->{settlement.settlement_id}",
                reason="Settlement receipt_hash does not match receipt",
                details={
                    "expected_hash": actual_receipt_hash,
                    "settlement_hash": settlement.receipt_hash
                }
            )
    
    except Exception as e:
        return VerificationResult(
            valid=False,
            record_type="ReceiptSettlementBinding",
            record_id=f"{receipt.receipt_id}->{settlement.settlement_id}",
            reason=f"Binding verification error: {str(e)}"
        )


def verify_complete_chain(
    proof: AuthorizationProof,
    receipt: ExecutionReceipt,
    settlement: SettlementRecord,
    issuer_public_key: str,
    executor_public_key: str,
    settler_public_key: str
) -> Tuple[bool, list]:
    """Verify the complete chain: Proof → Receipt → Settlement."""
    results = []
    
    # 1. Verify proof signature
    results.append(verify_proof_signature(proof, issuer_public_key))
    
    # 2. Verify receipt signature
    results.append(verify_receipt_signature(receipt, executor_public_key))
    
    # 3. Verify settlement signature
    results.append(verify_settlement_signature(settlement, settler_public_key))
    
    # 4. Verify proof-receipt binding
    results.append(verify_proof_receipt_binding(proof, receipt))
    
    # 5. Verify receipt-settlement binding
    results.append(verify_receipt_settlement_binding(receipt, settlement))
    
    # 6. Verify proof-settlement binding
    if settlement.proof_hash == proof.hash():
        results.append(VerificationResult(
            valid=True,
            record_type="ProofSettlementBinding",
            record_id=f"{proof.proof_id}->{settlement.settlement_id}",
            reason="Settlement is bound to proof"
        ))
    else:
        results.append(VerificationResult(
            valid=False,
            record_type="ProofSettlementBinding",
            record_id=f"{proof.proof_id}->{settlement.settlement_id}",
            reason="Settlement proof_hash does not match proof"
        ))
    
    all_valid = all(r.valid for r in results)
    return all_valid, results


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================

def verify_from_json(
    record_json: dict,
    record_type: str,
    public_key_hex: str
) -> VerificationResult:
    """Verify a record from JSON representation."""
    if record_type.lower() in ["proof", "authorizationproof"]:
        proof = AuthorizationProof.from_dict(record_json)
        return verify_proof_signature(proof, public_key_hex)
    
    elif record_type.lower() in ["receipt", "executionreceipt"]:
        receipt = ExecutionReceipt.from_dict(record_json)
        return verify_receipt_signature(receipt, public_key_hex)
    
    elif record_type.lower() in ["settlement", "settlementrecord"]:
        settlement = SettlementRecord.from_dict(record_json)
        return verify_settlement_signature(settlement, public_key_hex)
    
    else:
        raise ValueError(f"Unknown record type: {record_type}")


def check_proof_expiry(proof: AuthorizationProof) -> VerificationResult:
    """Check if a proof has expired."""
    now = datetime.now(timezone.utc)
    
    if proof.is_expired(now):
        return VerificationResult(
            valid=False,
            record_type="AuthorizationProof",
            record_id=proof.proof_id,
            reason=f"Proof expired at {proof.expires_at.isoformat()}",
            details={
                "expired_at": proof.expires_at.isoformat(),
                "checked_at": now.isoformat()
            }
        )
    else:
        return VerificationResult(
            valid=True,
            record_type="AuthorizationProof",
            record_id=proof.proof_id,
            reason="Proof is not expired",
            details={
                "expires_at": proof.expires_at.isoformat(),
                "checked_at": now.isoformat()
            }
        )


def batch_verify_proofs(
    proofs: list[AuthorizationProof],
    public_key_hex: str
) -> Tuple[int, int, list]:
    """Verify multiple proofs in batch."""
    results = []
    valid_count = 0
    
    for proof in proofs:
        result = verify_proof_signature(proof, public_key_hex)
        results.append(result)
        if result.valid:
            valid_count += 1
    
    return valid_count, len(proofs), results
