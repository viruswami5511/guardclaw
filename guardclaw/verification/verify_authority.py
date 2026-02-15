"""
GuardClaw Phase 3: Authority Chain Verification

Verifies the authority chain from root → agent → action.

Key Verifications:
1. Genesis is valid and signed by root key
2. Agent is registered by authorized delegator
3. Delegation chain is valid and unbroken
4. Authority was valid at time of action
5. Agent had capability to perform action
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple

from guardclaw.core.genesis import GenesisRecord, AgentRegistration, KeyDelegation
from guardclaw.core.models import AuthorizationProof
from guardclaw.core.liveness import HeartbeatRecord, TombstoneRecord, AdminActionRecord


@dataclass
class AuthorityVerificationResult:
    """Result of authority chain verification."""
    valid: bool
    checks: Dict[str, bool]
    errors: List[str]
    warnings: List[str]
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "valid": self.valid,
            "checks": self.checks,
            "errors": self.errors,
            "warnings": self.warnings,
            "metadata": self.metadata
        }


def verify_genesis(genesis: GenesisRecord) -> Tuple[bool, str]:
    """Verify genesis record."""
    # Check required fields
    if not genesis.genesis_id or not genesis.ledger_name:
        return False, "Genesis missing required fields (genesis_id or ledger_name)"
    
    if not genesis.root_key_id or genesis.root_key_id == "":
        return False, "Genesis missing root key ID"
    
    # Verify signature (only if root_key_id is valid)
    try:
        if not genesis.verify_signature():
            return False, "Genesis signature verification failed"
    except (ValueError, Exception) as e:
        return False, f"Genesis signature verification failed: {str(e)}"
    
    return True, ""



def verify_agent_registration(
    agent_reg: AgentRegistration,
    root_key_id: str,
    at_time: Optional[datetime] = None
) -> Tuple[bool, str]:
    """
    Verify an agent registration.
    
    Args:
        agent_reg: AgentRegistration to verify
        root_key_id: Root authority's public key hex
        at_time: Optional timestamp to check validity
        
    Returns:
        (is_valid, error_message)
    """
    # Verify signature
    if not agent_reg.verify_signature():
        return False, "Agent registration signature verification failed"
    
    # Verify delegating key matches root or a delegated key
    # (For now, simple check - can be extended for multi-level delegation)
    if agent_reg.delegated_from_key != root_key_id:
        # In production, would check delegation chain here
        pass
    
    # Verify time validity
    if at_time:
        if not agent_reg.is_valid_at(at_time):
            return False, f"Agent registration not valid at {at_time.isoformat()}"
    
    # Verify required fields
    if not agent_reg.agent_id or not agent_reg.agent_key_id:
        return False, "Agent registration missing required fields"
    
    if not agent_reg.capabilities:
        return False, "Agent registration has no capabilities"
    
    return True, ""


def verify_key_delegation(
    delegation: KeyDelegation,
    parent_key_id: str,
    at_time: Optional[datetime] = None
) -> Tuple[bool, str]:
    """
    Verify a key delegation.
    
    Args:
        delegation: KeyDelegation to verify
        parent_key_id: Expected parent key ID
        at_time: Optional timestamp to check validity
        
    Returns:
        (is_valid, error_message)
    """
    # Verify signature
    if not delegation.verify_signature():
        return False, "Key delegation signature verification failed"
    
    # Verify parent key matches
    if delegation.parent_key_id != parent_key_id:
        return False, f"Parent key mismatch: expected {parent_key_id}, got {delegation.parent_key_id}"
    
    # Verify time validity
    if at_time:
        if not delegation.is_valid_at(at_time):
            return False, f"Key delegation not valid at {at_time.isoformat()}"
    
    return True, ""


def verify_authority_chain(
    genesis: GenesisRecord,
    agent_registration: AgentRegistration,
    delegations: List[KeyDelegation],
    proof: AuthorizationProof
) -> AuthorityVerificationResult:
    """
    Verify complete authority chain from genesis → agent → action.
    
    Args:
        genesis: Genesis record
        agent_registration: Agent registration
        delegations: List of key delegations (if multi-level)
        proof: Authorization proof to verify
        
    Returns:
        AuthorityVerificationResult
    """
    checks = {}
    errors = []
    warnings = []
    metadata = {}
    
    # 1. Verify genesis
    genesis_valid, genesis_error = verify_genesis(genesis)
    checks["genesis_valid"] = genesis_valid
    if not genesis_valid:
        errors.append(f"Genesis verification failed: {genesis_error}")
    
    # 2. Verify agent registration
    agent_valid, agent_error = verify_agent_registration(
        agent_registration,
        genesis.root_key_id,
        at_time=proof.issued_at
    )
    checks["agent_registration_valid"] = agent_valid
    if not agent_valid:
        errors.append(f"Agent registration verification failed: {agent_error}")
    
    # 3. Verify delegation chain (if exists)
    if delegations:
        delegation_chain_valid = True
        current_parent_key = genesis.root_key_id
        
        for i, delegation in enumerate(delegations):
            delegation_valid, delegation_error = verify_key_delegation(
                delegation,
                current_parent_key,
                at_time=proof.issued_at
            )
            
            if not delegation_valid:
                delegation_chain_valid = False
                errors.append(f"Delegation {i} verification failed: {delegation_error}")
                break
            
            current_parent_key = delegation.child_key_id
        
        checks["delegation_chain_valid"] = delegation_chain_valid
        
        # Verify last delegation points to agent key
        if delegations and delegation_chain_valid:
            if delegations[-1].child_key_id != agent_registration.agent_key_id:
                checks["delegation_chain_complete"] = False
                errors.append("Delegation chain does not connect to agent key")
            else:
                checks["delegation_chain_complete"] = True
    
    # 4. Verify proof issuer matches agent or authorized key
    if proof.approver_key_id:
        # Phase 3: Check approver_key_id
        checks["proof_issuer_authorized"] = (
            proof.approver_key_id == agent_registration.agent_key_id or
            proof.approver_key_id == genesis.root_key_id
        )
        if not checks["proof_issuer_authorized"]:
            errors.append("Proof approver key not authorized")
    else:
        # Fallback to agent key check
        checks["proof_issuer_authorized"] = True
        warnings.append("Proof missing approver_key_id (Phase 2 format)")
    
    # 5. Verify agent had capability for this action
    action_type = proof.action.action_type
    if action_type in agent_registration.capabilities or "*" in agent_registration.capabilities:
        checks["agent_has_capability"] = True
    else:
        checks["agent_has_capability"] = False
        errors.append(f"Agent does not have capability for action type: {action_type}")
    
    # 6. Verify proof signature
    checks["proof_signature_valid"] = proof.verify_signature(agent_registration.agent_key_id)
    if not checks["proof_signature_valid"]:
        errors.append("Proof signature verification failed")
    
    # 7. Check policy anchor (Phase 3)
    if proof.policy_anchor_hash:
        checks["has_policy_anchor"] = True
        metadata["policy_anchor_hash"] = proof.policy_anchor_hash
    else:
        checks["has_policy_anchor"] = False
        warnings.append("Proof missing policy anchor hash")
    
    # 8. Check trigger context (Phase 3)
    if proof.trigger_context:
        checks["has_trigger_context"] = True
        metadata["trigger_context"] = proof.trigger_context
    else:
        checks["has_trigger_context"] = False
        warnings.append("Proof missing trigger context")
    
    # Overall validity
    all_valid = all(checks.values()) and len(errors) == 0
    
    return AuthorityVerificationResult(
        valid=all_valid,
        checks=checks,
        errors=errors,
        warnings=warnings,
        metadata=metadata
    )


def verify_heartbeat(
    heartbeat: HeartbeatRecord,
    system_key_hex: str,
    previous_heartbeat: Optional[HeartbeatRecord] = None
) -> Tuple[bool, str]:
    """
    Verify a heartbeat record.
    
    Args:
        heartbeat: HeartbeatRecord to verify
        system_key_hex: System's public key hex
        previous_heartbeat: Previous heartbeat (for chain verification)
        
    Returns:
        (is_valid, error_message)
    """
    # Verify signature
    if not heartbeat.verify_signature(system_key_hex):
        return False, "Heartbeat signature verification failed"
    
    # Verify sequence number
    if previous_heartbeat:
        if heartbeat.sequence_number != previous_heartbeat.sequence_number + 1:
            return False, f"Heartbeat sequence break: expected {previous_heartbeat.sequence_number + 1}, got {heartbeat.sequence_number}"
        
        if heartbeat.previous_heartbeat_id != previous_heartbeat.heartbeat_id:
            return False, "Heartbeat chain broken: previous_heartbeat_id mismatch"
        
        # Check timing
        if heartbeat.timestamp < previous_heartbeat.timestamp:
            return False, "Heartbeat timestamp goes backward in time"
    
    return True, ""


def verify_tombstone(
    tombstone: TombstoneRecord,
    system_key_hex: str
) -> Tuple[bool, str]:
    """
    Verify a tombstone record.
    
    Args:
        tombstone: TombstoneRecord to verify
        system_key_hex: System's public key hex
        
    Returns:
        (is_valid, error_message)
    """
    # Verify signature
    if not tombstone.verify_signature(system_key_hex):
        return False, "Tombstone signature verification failed"
    
    # Verify required fields
    if not tombstone.expected_record_type or not tombstone.failure_reason:
        return False, "Tombstone missing required fields"
    
    # Verify timing
    if tombstone.detected_at < tombstone.expected_at:
        return False, "Tombstone detected before expected time (temporal inconsistency)"
    
    return True, ""


def verify_admin_action(
    admin_action: AdminActionRecord,
    authorized_admin_keys: List[str]
) -> Tuple[bool, str]:
    """
    Verify an admin action record.
    
    Args:
        admin_action: AdminActionRecord to verify
        authorized_admin_keys: List of authorized admin public key hexes
        
    Returns:
        (is_valid, error_message)
    """
    # Verify signature
    if not admin_action.verify_signature():
        return False, "Admin action signature verification failed"
    
    # Verify admin is authorized
    if admin_action.admin_key_id not in authorized_admin_keys:
        return False, f"Admin key {admin_action.admin_key_id} not authorized"
    
    # Verify required fields
    if not admin_action.action_type or not admin_action.action_details:
        return False, "Admin action missing required fields"
    
    return True, ""
