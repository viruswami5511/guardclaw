"""
Policy engine for GuardClaw.

ALIGNED TO: models.py v1.1 canonical schema

PROTOCOL INVARIANT: Validation order matters for explainability and efficiency.
Order: Issuer → Expiration → Signature (fastest to slowest, clearest to most opaque)

UPDATED: Now includes policy metadata in authorization proofs for audit trail.
"""

import uuid
from datetime import timedelta
from typing import Tuple, Optional, Dict, Any

from guardclaw.core.models import (
    ActionRequest,
    AuthorizationProof,
    DecisionType,
    utc_now,
)
from guardclaw.core.crypto import SigningKey
from guardclaw.ledger.ledger import Ledger
from guardclaw.policy.rules import Rule, RuleAction


class Policy:
    """
    A policy is a collection of rules that determine authorization decisions.
    """
    
    def __init__(
        self,
        policy_id: str,
        version: str,
        rules: list[Rule],
        default_decision: DecisionType = DecisionType.DENY,
    ):
        self.policy_id = policy_id
        self.version = version
        self.rules = sorted(rules, key=lambda r: r.priority, reverse=True)
        self.default_decision = default_decision
    
    @property
    def policy_hash(self) -> str:
        """Generate deterministic hash of policy for versioning."""
        import hashlib
        import json
        
        data = {
            "policy_id": self.policy_id,
            "version": self.version,
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "priority": r.priority,
                    "conditions": [
                        {
                            "field": c.field,
                            "operator": c.operator.value,
                            "value": c.value,
                        }
                        for c in r.conditions
                    ],
                    "action": {
                        "decision": r.action.decision.value,
                        "reason": r.action.reason,
                    },
                }
                for r in self.rules
            ],
            "default_decision": self.default_decision.value,
        }
        
        json_str = json.dumps(data, sort_keys=True)
        return hashlib.sha256(json_str.encode()).hexdigest()
    
    def evaluate(
        self,
        action: ActionRequest,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[DecisionType, str, Optional[str]]:
        """
        Evaluate an action against policy rules.
        
        Returns:
            (decision, reason, matched_rule_id)
        """
        if context is None:
            context = {}
        
        # Build evaluation context
        eval_context = {
            "action_type": action.action_type.value,
            "agent_id": action.agent_id,
            "target_resource": action.target_resource,
            "operation": action.operation,
            **context,
        }
        
        # Evaluate rules in priority order
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            if rule.matches(eval_context):
                return (
                    rule.action.decision,
                    rule.action.reason,
                    rule.rule_id,
                )
        
        # No rule matched - use default
        return (
            self.default_decision,
            f"No matching rule, default {self.default_decision.value}",
            None,
        )
    
    @staticmethod
    def from_dict(data: dict) -> "Policy":
        """Load policy from dictionary."""
        rules = [Rule.from_dict(r) for r in data.get("rules", [])]
        
        default_decision = DecisionType.DENY
        if "default_decision" in data:
            default_decision = DecisionType(data["default_decision"])
        
        return Policy(
            policy_id=data["name"],
            version=data["version"],
            rules=rules,
            default_decision=default_decision,
        )


class PolicyEngine:
    """
    Policy Decision Point (PDP) - evaluates actions and issues proofs.
    
    CONFORMED TO: AuthorizationProof canonical schema v1.1
    UPDATED: Now embeds policy metadata in proofs for complete audit trail.
    """
    
    def __init__(
        self,
        policy: Policy,
        ledger: Ledger,
        signing_key: SigningKey,
        instance_id: str,
    ):
        self.policy = policy
        self.ledger = ledger
        self.signing_key = signing_key
        self.instance_id = instance_id
        self._decision_count = {"ALLOW": 0, "DENY": 0}
    
    def authorize(
        self,
        action: ActionRequest,
        ttl_seconds: int = 300,
    ) -> AuthorizationProof:
        """
        Evaluate action and issue authorization proof.
        
        CANONICAL COMPLIANCE: Emits AuthorizationProof matching models.py exactly.
        UPDATED: Includes policy_id, policy_version, policy_hash for audit trail.
        """
        # Build context for history-aware decisions
        context = self._build_context(action)
        
        # Evaluate policy
        decision, reason, matched_rule_id = self.policy.evaluate(action, context)
        
        # Track stats
        self._decision_count[decision.value] = self._decision_count.get(decision.value, 0) + 1
        
        # Generate proof (CONFORMED TO CANONICAL SCHEMA v1.1)
        proof_id = str(uuid.uuid4())
        issued_at = utc_now()
        expires_at = issued_at + timedelta(seconds=ttl_seconds)
        
        proof = AuthorizationProof(
            proof_id=proof_id,
            action_id=action.action_id,
            agent_id=action.agent_id,
            decision=decision,
            allowed_action_type=action.action_type,
            allowed_target=action.target_resource,
            allowed_operation=action.operation,
            reason=reason,
            matched_rule_id=matched_rule_id,
            issued_at=issued_at,
            expires_at=expires_at,
            issuer_id=self.instance_id,
            policy_id=self.policy.policy_id,           # NEW: Policy metadata
            policy_version=self.policy.version,         # NEW: Policy version
            policy_hash=self.policy.policy_hash,        # NEW: Policy hash
        )
        
        # Sign proof
        proof_hash = proof.hash()
        signature = self.signing_key.sign(proof_hash)
        
        signed_proof = AuthorizationProof(
            proof_id=proof.proof_id,
            action_id=proof.action_id,
            agent_id=proof.agent_id,
            decision=proof.decision,
            allowed_action_type=proof.allowed_action_type,
            allowed_target=proof.allowed_target,
            allowed_operation=proof.allowed_operation,
            reason=proof.reason,
            matched_rule_id=proof.matched_rule_id,
            issued_at=proof.issued_at,
            expires_at=proof.expires_at,
            issuer_id=proof.issuer_id,
            policy_id=proof.policy_id,
            policy_version=proof.policy_version,
            policy_hash=proof.policy_hash,
            signature=signature,
        )
        
        # Record in ledger
        self.ledger.append_authorization(signed_proof)
        
        return signed_proof
    
    def validate_proof(self, proof: AuthorizationProof) -> Tuple[bool, str]:
        """
        Validate an authorization proof.
        
        PROTOCOL INVARIANT: Validation order for clarity and efficiency.
        1. Issuer check (structural, fast)
        2. Expiration check (temporal, fast)
        3. Signature check (cryptographic, slow)
        """
        # Check issuer FIRST (fast structural check, clear error message)
        if proof.issuer_id != self.instance_id:
            return False, f"Wrong issuer (expected {self.instance_id}, got {proof.issuer_id})"
        
        # Check expiration SECOND (fast temporal check)
        if proof.is_expired():
            return False, "Proof has expired"
        
        # Check signature LAST (slow cryptographic verification)
        proof_hash = proof.hash()
        if not self.signing_key.verify(proof_hash, proof.signature):
            return False, "Invalid signature"
        
        return True, "Valid"
    
    def _build_context(self, action: ActionRequest) -> Dict[str, Any]:
        """Build context for history-aware policy decisions."""
        context = {}
        
        # Get recent actions by this agent
        recent_entries = self.ledger.get_entries_by_type("authorization")
        agent_history = [
            e for e in recent_entries[-100:]
            if e.data.get("agent_id") == action.agent_id
        ]
        
        context["agent_recent_action_count"] = len(agent_history)
        context["agent_recent_denials"] = sum(
            1 for e in agent_history
            if e.data.get("decision") == "DENY"
        )
        
        return context
    
    def get_policy_stats(self) -> dict:
        """Get policy evaluation statistics."""
        return {
            "policy_id": self.policy.policy_id,
            "policy_version": self.policy.version,
            "policy_hash": self.policy.policy_hash,
            "total_decisions": sum(self._decision_count.values()),
            "decisions_by_type": self._decision_count.copy(),
            "rule_count": len(self.policy.rules),
        }
