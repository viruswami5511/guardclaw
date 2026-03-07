"""
guardclaw/core/proofs.py

AuthorizationProof and ExecutionReceipt for GuardClaw runtime.
Separated from models.py to preserve GEF protocol contract lock.
"""

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

from guardclaw.core.action_types import ActionType


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class SettlementState(str, Enum):
    SETTLED_SUCCESS = "SETTLED_SUCCESS"
    SETTLED_FAILURE = "SETTLED_FAILURE"
    SETTLEMENT_VIOLATION = "SETTLEMENT_VIOLATION"


@dataclass
class AuthorizationProof:
    proof_id: str
    agent_id: str
    decision: Decision
    allowed_action_type: ActionType
    allowed_target: str
    allowed_operation: str
    issued_at: str
    expires_at: str
    reason: str = ""

    def is_expired(self) -> bool:
        exp = datetime.fromisoformat(self.expires_at.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) > exp

    def hash(self) -> str:
        data = json.dumps({
            "proof_id": self.proof_id,
            "agent_id": self.agent_id,
            "decision": self.decision.value,
            "allowed_action_type": self.allowed_action_type,
            "allowed_target": self.allowed_target,
            "allowed_operation": self.allowed_operation,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

    @classmethod
    def allow(cls, agent_id: str, action_type: ActionType,
              target: str, operation: str) -> "AuthorizationProof":
        now = datetime.now(timezone.utc)
        return cls(
            proof_id=f"proof-{uuid.uuid4()}",
            agent_id=agent_id,
            decision=Decision.ALLOW,
            allowed_action_type=action_type,
            allowed_target=target,
            allowed_operation=operation,
            issued_at=now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z",
            expires_at=now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z",
        )


@dataclass
class ExecutionReceipt:
    receipt_id: str
    proof_id: str
    proof_hash: str
    observed_action_type: ActionType
    observed_target: str
    observed_operation: str
    status: str
    executed_at: str
    executor_id: str
    error_message: Optional[str] = None
    signature: Optional[str] = None

    def to_dict_for_signing(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "proof_id": self.proof_id,
            "proof_hash": self.proof_hash,
            "observed_action_type": str(self.observed_action_type),
            "observed_target": self.observed_target,
            "observed_operation": self.observed_operation,
            "status": self.status,
            "executed_at": self.executed_at,
            "executor_id": self.executor_id,
            "error_message": self.error_message,
        }


@dataclass
class Settlement:
    settlement_id: str
    proof_id: str
    receipt_id: str
    final_state: SettlementState
    reason: str = ""
