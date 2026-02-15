"""
GuardClaw Execution Wrapper - The Structural Choke Point.

This is the most critical component in GuardClaw. It ensures that
no tool can be executed without going through authorization,
execution, receipt generation, settlement, and ledger recording.

CRITICAL INVARIANT: Settlement ALWAYS runs, even on execution failure.
Removing this wrapper breaks accountability provability.
"""

from typing import Callable, Any, TypeVar, ParamSpec
from functools import wraps
from datetime import datetime, timezone
import uuid

from guardclaw.core.models import ActionRequest, ActionType
from guardclaw.runtime.context import RuntimeContext
from guardclaw.runtime.executor import ToolExecutor, ExecutionError


P = ParamSpec('P')
R = TypeVar('R')


class WrapperError(Exception):
    """Raised when wrapper encounters a violation."""
    pass


class ExecutionWrapper:
    """
    The execution wrapper - GuardClaw's structural choke point.
    
    This class ensures that every tool execution goes through:
    1. Authorization (PolicyEngine)
    2. Execution (ToolExecutor)
    3. Receipt generation (automatic, ALWAYS)
    4. Settlement (SettlementEngine, ALWAYS)
    5. Ledger recording (append-only)
    
    CRITICAL: Removing this wrapper breaks accountability provability
    within a GuardClaw-managed runtime.
    """
    
    def __init__(self, context: RuntimeContext):
        """
        Initialize execution wrapper.
        
        Args:
            context: Runtime context with all components
        """
        self.context = context
        # CRITICAL: Executor is private - user code cannot access it
        self._executor = ToolExecutor(
            executor_id=context.executor_id,
            key_manager=context.key_manager
        )
    
    def protect(
        self,
        action_type: ActionType,
        target_resource: str,
        operation: str,
        agent_id: str = "default-agent"
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        """
        Decorator to protect a tool with GuardClaw.
        
        Usage:
            @wrapper.protect(
                action_type=ActionType.FILE_DELETE,
                target_resource="/tmp/data.txt",
                operation="delete"
            )
            def delete_file(path: str):
                os.remove(path)
        
        Args:
            action_type: Type of action being performed
            target_resource: Resource being accessed
            operation: Specific operation
            agent_id: ID of agent requesting action
            
        Returns:
            Decorator function
        """
        def decorator(func: Callable[P, R]) -> Callable[P, R]:
            @wraps(func)
            def wrapper_func(*args: P.args, **kwargs: P.kwargs) -> R:
                # Create action request
                action_request = ActionRequest(
                    action_id=f"action-{uuid.uuid4()}",
                    agent_id=agent_id,
                    action_type=action_type,
                    target_resource=target_resource,
                    operation=operation,
                    intent=f"{operation} on {target_resource}",
                    context={},
                    requested_at=datetime.now(timezone.utc)
                )
                
                return self._execute_protected(
                    func=func,
                    args=args,
                    kwargs=kwargs,
                    action_request=action_request
                )
            
            return wrapper_func
        return decorator
    
    def _execute_protected(
        self,
        func: Callable,
        args: tuple,
        kwargs: dict,
        action_request: ActionRequest
    ) -> Any:
        """
        Internal execution logic with guaranteed settlement.
        
        CRITICAL INVARIANT: Settlement ALWAYS runs, even on failure.
        
        Args:
            func: Function to execute
            args: Positional arguments
            kwargs: Keyword arguments
            action_request: Action request for authorization
            
        Returns:
            Execution result
            
        Raises:
            WrapperError: If authorization denied or settlement violated
        """
        # STEP 1: Request Authorization
        proof = self.context.policy_engine.authorize(action_request)
        
        # STEP 2: Execute Tool (always generates receipt)
        exec_result = self._executor.execute(
            tool_func=func,
            args=args,
            kwargs=kwargs,
            proof=proof
        )
        
        # STEP 3: Settlement (ALWAYS runs, regardless of execution outcome)
        settlement = self.context.settlement_engine.settle(
            proof=proof,
            receipt=exec_result.receipt
        )
        
        # STEP 4: Validate settlement outcome
        # Note: SETTLED_FAILURE is acceptable (authorized action failed)
        acceptable_states = ["SETTLED_SUCCESS", "SETTLED_FAILURE"]
        
        if settlement.final_state.value not in acceptable_states:
            raise WrapperError(
                f"Settlement violation detected: {settlement.final_state.value} - {settlement.reason}"
            )
        
        # STEP 5: If execution failed, raise error (after settlement)
        if not exec_result.success:
            raise WrapperError(
                f"Execution failed: {exec_result.error}"
            )
        
        # STEP 6: Return successful result
        return exec_result.result
    
    def execute_with_explicit_request(
        self,
        func: Callable,
        args: tuple,
        kwargs: dict,
        action_request: ActionRequest
    ) -> Any:
        """
        Execute a function with explicit action request.
        
        This is the non-decorator version for dynamic execution.
        Settlement is guaranteed to run.
        
        Args:
            func: Function to execute
            args: Positional arguments
            kwargs: Keyword arguments
            action_request: Explicit action request
            
        Returns:
            Execution result
        """
        return self._execute_protected(func, args, kwargs, action_request)
    
    def __repr__(self) -> str:
        return f"ExecutionWrapper(executor={self.context.executor_id!r})"
