"""
GuardClaw Phase 5: Tool Wrapper Adapter

Purpose:
- Observe tool/function execution WITHOUT controlling it
- Wrap arbitrary Python callables
- Capture execution, result, or failure
- Preserve original behavior exactly

Design Principles:
- Zero blocking
- Zero behavior modification
- Zero framework coupling
- Observer failure must NOT affect tool execution

This is the most common integration path.
This is how GuardClaw becomes invisible.
"""

from typing import Callable, Any, Optional, Dict
from datetime import datetime, timezone
import functools
import hashlib
import json

from guardclaw.core.observers import Observer


class ToolObserver:
    """
    Observational wrapper for tool execution.
    
    This wraps a callable (tool/function) and emits:
    - EXECUTION event before call
    - RESULT event on success
    - FAILURE event on exception
    
    IMPORTANT:
    - Tool behavior is NEVER modified
    - Exceptions propagate normally
    - Observer failure does not affect execution
    """
    
    def __init__(
        self,
        tool_name: str,
        subject_id: str,
        observer: Optional[Observer] = None
    ):
        """
        Initialize tool observer.
        
        Args:
            tool_name: Logical tool name (e.g. "file:delete")
            subject_id: Agent or system invoking the tool
            observer: Observer instance (creates new if None)
        """
        self.tool_name = tool_name
        self.subject_id = subject_id
        self.observer = observer or Observer()
    
    def wrap(self, tool_fn: Callable) -> Callable:
        """
        Wrap a tool/function with observation.
        
        Args:
            tool_fn: Callable to wrap
        
        Returns:
            Wrapped callable with identical behavior
        """
        
        @functools.wraps(tool_fn)
        def wrapped(*args, **kwargs):
            execution_time = self._utc_now()  # Capture ONCE at start
            execution_event_id = None
            
            # 1️⃣ Observe execution attempt
            try:
                event = self.observer.observe_execution(
                    subject_id=self.subject_id,
                    action=self.tool_name,
                    execution_timestamp=execution_time,  # Use captured time
                    context_hash=self._hash_inputs(args, kwargs)
                )
                execution_event_id = event.event_id
            except Exception:
                # Observer failure MUST NOT affect execution
                execution_event_id = None
            
            # 2️⃣ Execute tool (unmodified)
            try:
                result = tool_fn(*args, **kwargs)
                
                # 3️⃣ Observe result
                try:
                    self.observer.observe_result(
                        subject_id=self.subject_id,
                        action=self.tool_name,
                        result_hash=self._hash_result(result),
                        execution_timestamp=execution_time,  # FIXED: Use captured time
                        correlation_id=execution_event_id,
                        metadata={"result_type": type(result).__name__}
                    )
                except Exception:
                    pass  # Observer failure ignored
                
                return result
            
            except Exception as e:
                # 4️⃣ Observe failure
                try:
                    self.observer.observe_failure(
                        subject_id=self.subject_id,
                        action=self.tool_name,
                        failure_reason=str(e),
                        execution_timestamp=execution_time,  # FIXED: Use captured time
                        correlation_id=execution_event_id,
                        metadata={"error_type": type(e).__name__}
                    )
                except Exception:
                    pass  # Observer failure ignored
                
                # IMPORTANT: re-raise original exception
                raise
        
        return wrapped
    
    def _utc_now(self) -> str:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc).isoformat()
    
    def _hash_inputs(self, args: tuple, kwargs: dict) -> str:
        """
        Hash tool inputs (privacy-safe).
        
        Never store raw inputs.
        """
        try:
            payload = {
                "args": [str(a) for a in args],  # Convert to strings
                "kwargs": {k: str(v) for k, v in kwargs.items()}
            }
            payload_str = json.dumps(payload, sort_keys=True)
            return hashlib.sha256(payload_str.encode()).hexdigest()
        except Exception:
            return "hash_error"
    
    def _hash_result(self, result: Any) -> str:
        """
        Hash tool result (privacy-safe).
        
        Never store raw outputs.
        """
        try:
            return hashlib.sha256(str(result).encode()).hexdigest()
        except Exception:
            return "hash_error"
    
    def stop(self) -> None:
        """Stop observer gracefully."""
        self.observer.stop(reason=f"Tool observer stopped: {self.tool_name}")


# Convenience decorator-style API
def observe_tool(
    tool_name: str,
    subject_id: str,
    observer: Optional[Observer] = None
):
    """
    Decorator to observe a tool/function.
    
    Usage:
        @observe_tool("file:delete", subject_id="agent-001")
        def delete_file(path):
            ...
    
    Args:
        tool_name: Logical tool name
        subject_id: Agent/system invoking tool
        observer: Optional observer
    
    Returns:
        Decorated function
    """
    tool_observer = ToolObserver(
        tool_name=tool_name,
        subject_id=subject_id,
        observer=observer
    )
    
    def decorator(fn: Callable) -> Callable:
        return tool_observer.wrap(fn)
    
    return decorator
