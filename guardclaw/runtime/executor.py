"""
Execution engine for tool/function calls with authorization.
"""

from typing import Any, Callable
from datetime import datetime, timezone
from dataclasses import dataclass
import uuid

from guardclaw.core.models import (
    AuthorizationProof,
    ExecutionReceipt,
    ActionType,
    utc_now,
)
from guardclaw.core.exceptions import AuthorizationError
from guardclaw.core.crypto import Ed25519KeyManager


# Add ExecutionError for backward compatibility
class ExecutionError(Exception):
    """Raised when execution fails."""
    pass


@dataclass
class ExecutionResult:
    """Result of executing a tool."""
    receipt: ExecutionReceipt
    result: Any
    error: Exception | None = None


class ToolExecutor:
    """
    Executes tools/functions with authorization checking.
    
    Phase 2: Now uses Ed25519KeyManager for signing receipts.
    """
    
    def __init__(self, executor_id: str, key_manager: Ed25519KeyManager):
        """
        Initialize executor.
        
        Args:
            executor_id: Unique identifier for this executor
            key_manager: Ed25519KeyManager for signing receipts
        """
        self.executor_id = executor_id
        self.key_manager = key_manager
    
    def execute(
        self,
        tool_func: Callable,
        args: tuple,
        kwargs: dict,
        proof: AuthorizationProof,
    ) -> ExecutionResult:
        """
        Execute a tool with authorization proof.
        
        Args:
            tool_func: Function to execute
            args: Positional arguments
            kwargs: Keyword arguments
            proof: Authorization proof
            
        Returns:
            ExecutionResult with receipt and result
        """
        # Verify proof allows execution
        if proof.decision.value != "ALLOW":
            raise AuthorizationError(
                f"Cannot execute: proof decision is {proof.decision.value}"
            )
        
        # Check expiration
        if proof.is_expired():
            raise AuthorizationError(
                f"Cannot execute: proof expired at {proof.expires_at}"
            )
        
        # Execute function
        status = "SUCCESS"
        error_message = None
        error = None
        result = None
        
        try:
            result = tool_func(*args, **kwargs)
        except Exception as e:
            status = "FAILURE"
            error_message = str(e)
            error = e
        
        # Create receipt
        receipt = ExecutionReceipt(
            receipt_id=f"rcpt-{uuid.uuid4()}",
            proof_id=proof.proof_id,
            proof_hash=proof.hash(),  # Hash binding to proof
            observed_action_type=proof.allowed_action_type,
            observed_target=proof.allowed_target,
            observed_operation=proof.allowed_operation,
            status=status,
            executed_at=utc_now(),
            executor_id=self.executor_id,
            error_message=error_message,
        )
        
        # Sign receipt with Ed25519
        receipt_data = receipt.to_dict_for_signing()
        from guardclaw.core.crypto import canonical_json_encode
        canonical_bytes = canonical_json_encode(receipt_data)
        signature = self.key_manager.sign(canonical_bytes)
        
        # Create final receipt with signature
        receipt = ExecutionReceipt(
            receipt_id=receipt.receipt_id,
            proof_id=receipt.proof_id,
            proof_hash=receipt.proof_hash,
            observed_action_type=receipt.observed_action_type,
            observed_target=receipt.observed_target,
            observed_operation=receipt.observed_operation,
            status=receipt.status,
            executed_at=receipt.executed_at,
            executor_id=receipt.executor_id,
            error_message=receipt.error_message,
            signature=signature,
        )
        
        return ExecutionResult(
            receipt=receipt,
            result=result,
            error=error,
        )
