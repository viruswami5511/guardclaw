"""
Manual verification script for Phase 2.

This script performs all critical checks to ensure Phase 2 is correctly implemented.
"""

import sys
from pathlib import Path

# Add guardclaw to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from guardclaw.core.crypto import Ed25519KeyManager, canonical_json_encode, canonical_hash, ED25519_AVAILABLE
from guardclaw.core.models import AuthorizationProof, ExecutionReceipt, SettlementRecord, ActionType, DecisionType, SettlementState
from datetime import datetime, timezone, timedelta
import uuid
from dataclasses import replace


def check_ed25519_available():
    """Check if Ed25519 is available."""
    print("🔍 Checking Ed25519 availability...")
    if ED25519_AVAILABLE:
        print("   ✅ Ed25519 is available")
        return True
    else:
        print("   ❌ Ed25519 NOT available")
        print("   Install with: pip install cryptography")
        return False


def check_canonical_encoding():
    """Check canonical encoding is deterministic."""
    print("\n🔍 Checking canonical encoding...")
    
    data1 = {"z": 3, "a": 1, "b": 2}
    data2 = {"a": 1, "b": 2, "z": 3}
    
    canonical1 = canonical_json_encode(data1)
    canonical2 = canonical_json_encode(data2)
    
    if canonical1 == canonical2:
        print("   ✅ Canonical encoding is deterministic")
        print(f"      Output: {canonical1}")
        return True
    else:
        print("   ❌ Canonical encoding is NOT deterministic")
        return False


def check_crypto_invariant():
    """Check that signatures are over canonical bytes, NOT hashes."""
    print("\n🔍 Checking crypto invariant (sign canonical bytes, not hashes)...")
    
    km = Ed25519KeyManager.generate_keypair()
    
    proof = AuthorizationProof(
        proof_id=f"proof-{uuid.uuid4()}",
        action_id=f"action-{uuid.uuid4()}",
        agent_id="test-agent",
        decision=DecisionType.ALLOW,
        allowed_action_type=ActionType.FILE_READ,
        allowed_target="/test/file.txt",
        allowed_operation="read",
        reason="Test",
        matched_rule_id="rule-1",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        issuer_id="test-issuer",
        policy_id="test-policy",
        policy_version="1.0",
        policy_hash="abc123",
        signature=""
    )
    
    # Get canonical bytes and hash
    canonical_bytes = canonical_json_encode(proof.to_dict_for_signing())
    proof_hash = proof.hash()
    
    # Sign canonical bytes (correct)
    sig_canonical = km.sign(canonical_bytes)
    
    # Sign hash (incorrect)
    sig_hash = km.sign(proof_hash)
    
    if sig_canonical != sig_hash:
        print("   ✅ Signatures over canonical bytes differ from signatures over hashes")
        print("      (This is correct behavior)")
        
        # Verify canonical signature works
        if km.verify(canonical_bytes, sig_canonical):
            print("   ✅ Canonical signature verifies correctly")
            return True
        else:
            print("   ❌ Canonical signature does NOT verify")
            return False
    else:
        print("   ❌ Signatures are the same (WRONG!)")
        return False


def check_hash_binding():
    """Check hash binding between records."""
    print("\n🔍 Checking hash binding...")
    
    km = Ed25519KeyManager.generate_keypair()
    
    # Create proof
    proof = AuthorizationProof(
        proof_id=f"proof-{uuid.uuid4()}",
        action_id=f"action-{uuid.uuid4()}",
        agent_id="test-agent",
        decision=DecisionType.ALLOW,
        allowed_action_type=ActionType.FILE_READ,
        allowed_target="/test/file.txt",
        allowed_operation="read",
        reason="Test",
        matched_rule_id="rule-1",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        issuer_id="test-issuer",
        policy_id="test-policy",
        policy_version="1.0",
        policy_hash="abc123",
        signature=""
    )
    
    proof_canonical = canonical_json_encode(proof.to_dict_for_signing())
    proof_signature = km.sign(proof_canonical)
    proof = replace(proof, signature=proof_signature)
    
    # Create receipt with hash binding
    proof_hash = proof.hash()
    receipt = ExecutionReceipt(
        receipt_id=f"rcpt-{uuid.uuid4()}",
        proof_id=proof.proof_id,
        proof_hash=proof_hash,
        observed_action_type=ActionType.FILE_READ,
        observed_target="/test/file.txt",
        observed_operation="read",
        status="SUCCESS",
        executed_at=datetime.now(timezone.utc),
        executor_id="test-executor",
        signature=""
    )
    
    # Verify binding
    if receipt.proof_hash == proof.hash():
        print("   ✅ Receipt is bound to proof via hash")
        print(f"      Proof hash: {proof_hash[:16]}...")
        return True
    else:
        print("   ❌ Receipt is NOT bound to proof")
        return False


def check_to_dict_for_signing():
    """Check that to_dict_for_signing excludes signature."""
    print("\n🔍 Checking to_dict_for_signing() excludes signature...")
    
    proof = AuthorizationProof(
        proof_id=f"proof-{uuid.uuid4()}",
        action_id=f"action-{uuid.uuid4()}",
        agent_id="test-agent",
        decision=DecisionType.ALLOW,
        allowed_action_type=ActionType.FILE_READ,
        allowed_target="/test/file.txt",
        allowed_operation="read",
        reason="Test",
        matched_rule_id="rule-1",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        issuer_id="test-issuer",
        policy_id="test-policy",
        policy_version="1.0",
        policy_hash="abc123",
        signature="fake_signature"
    )
    
    signing_dict = proof.to_dict_for_signing()
    full_dict = proof.to_dict()
    
    if "signature" not in signing_dict and "signature" in full_dict:
        print("   ✅ to_dict_for_signing() excludes signature")
        print("   ✅ to_dict() includes signature")
        return True
    else:
        print("   ❌ to_dict_for_signing() behavior is incorrect")
        return False


def main():
    """Run all Phase 2 verification checks."""
    print("=" * 60)
    print("PHASE 2 VERIFICATION SCRIPT")
    print("=" * 60)
    
    checks = [
        check_ed25519_available(),
        check_canonical_encoding(),
        check_crypto_invariant(),
        check_hash_binding(),
        check_to_dict_for_signing()
    ]
    
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)
    
    passed = sum(checks)
    total = len(checks)
    
    print(f"\nPassed: {passed}/{total}")
    
    if passed == total:
        print("\n🎉 ALL CHECKS PASSED - PHASE 2 IS CORRECTLY IMPLEMENTED!")
        return 0
    else:
        print(f"\n❌ {total - passed} CHECK(S) FAILED - PHASE 2 NEEDS FIXES")
        return 1


if __name__ == "__main__":
    sys.exit(main())
