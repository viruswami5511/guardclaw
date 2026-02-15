"""
GuardClaw Phase 5: Generic Agent Observer

Thin observational wrapper for generic Python agents.

Design:
- Framework-agnostic
- Non-blocking
- Passive observation
- No control flow modification

Usage:
    from guardclaw.adapters import GenericAgentObserver
    
    observer = GenericAgentObserver(agent_id="agent-001")
    
    # Wrap agent loop
    observer.observe_intent(user_command)
    result = agent.execute(command)
    observer.observe_result(result)
"""

from guardclaw.core.emitter import get_global_emitter
from typing import Any, Optional, Dict, Callable
from datetime import datetime, timezone

from guardclaw.core.observers import Observer


class GenericAgentObserver:
    """
    Generic agent observer.
    
    Wraps any Python agent with GuardClaw observation.
    
    Key Properties:
    - Thin wrapper (minimal overhead)
    - Non-blocking (async emission)
    - No agent modification required
    - Failure-safe (agent runs even if observer fails)
    
    Example:
        observer = GenericAgentObserver("agent-001")
        
        # Observe intent
        observer.observe_intent("Delete old logs")
        
        # Agent executes (unmodified)
        result = agent.execute("rm /tmp/*.log")
        
        # Observe result
        observer.observe_result(result)
    """
    
    def __init__(
        self,
        agent_id: str,
        observer: Optional[Observer] = None
    ):
        """
        Initialize generic agent observer.
        
        Args:
            agent_id: Agent identifier
            observer: Observer instance (creates new if None)
        """
        self.agent_id = agent_id
        self.observer = observer or Observer()
        self.current_execution_id: Optional[str] = None
    
    def observe_intent(
        self,
        intent: str,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Observe user/system intent.
        
        Args:
            intent: Intent description
            context: Optional context
        
        Returns:
            Event ID (for correlation)
        """
        execution_time = self._utc_now()
        
        event = self.observer.observe_intent(
            subject_id=self.agent_id,
            intent_description=intent,
            execution_timestamp=execution_time,
            context_hash=self._hash_context(context) if context else None,
            metadata=context or {}
        )
        
        self.current_execution_id = event.event_id
        return event.event_id
    
    def observe_action(
        self,
        action: str,
        correlation_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Observe agent action execution.
        
        Args:
            action: Action description
            correlation_id: Link to authorization proof
            context: Optional context
        
        Returns:
            Event ID
        """
        execution_time = self._utc_now()
        
        event = self.observer.observe_execution(
            subject_id=self.agent_id,
            action=action,
            execution_timestamp=execution_time,
            correlation_id=correlation_id or self.current_execution_id,
            context_hash=self._hash_context(context) if context else None,
            metadata=context or {}
        )
        
        self.current_execution_id = event.event_id
        return event.event_id
    
    def observe_result(
        self,
        result: Any,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Observe action result.
        
        Args:
            result: Action result (hashed, never stored raw)
            correlation_id: Link to execution event
        
        Returns:
            Event ID
        """
        execution_time = self._utc_now()
        
        event = self.observer.observe_result(
            subject_id=self.agent_id,
            action="result",
            result_hash=self._hash_result(result),
            execution_timestamp=execution_time,
            correlation_id=correlation_id or self.current_execution_id,
            metadata={"result_type": type(result).__name__}
        )
        
        return event.event_id
    
    def observe_failure(
        self,
        error: Exception,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Observe action failure.
        
        Args:
            error: Exception that occurred
            correlation_id: Link to execution event
        
        Returns:
            Event ID
        """
        execution_time = self._utc_now()
        
        event = self.observer.observe_failure(
            subject_id=self.agent_id,
            action="execution",
            failure_reason=str(error),
            execution_timestamp=execution_time,
            correlation_id=correlation_id or self.current_execution_id,
            metadata={"error_type": type(error).__name__}
        )
        
        return event.event_id
    
    def observe_delegation(
        self,
        delegated_to: str,
        action: str,
        correlation_id: Optional[str] = None
    ) -> str:
        """
        Observe task delegation.
        
        Args:
            delegated_to: Agent receiving delegation
            action: Action being delegated
            correlation_id: Link to original request
        
        Returns:
            Event ID
        """
        execution_time = self._utc_now()
        
        event = self.observer.observe_delegation(
            subject_id=self.agent_id,
            delegated_to=delegated_to,
            action=action,
            execution_timestamp=execution_time,
            correlation_id=correlation_id or self.current_execution_id
        )
        
        return event.event_id
    
    def _utc_now(self) -> str:
        """Get current UTC timestamp."""
        return datetime.now(timezone.utc).isoformat()
    
    def _hash_context(self, context: Dict[str, Any]) -> str:
        """Hash context (privacy-safe)."""
        import hashlib
        import json
        
        context_str = json.dumps(context, sort_keys=True)
        return hashlib.sha256(context_str.encode()).hexdigest()
    
    def _hash_result(self, result: Any) -> str:
        """Hash result (never store raw)."""
        import hashlib
        
        result_str = str(result)
        return hashlib.sha256(result_str.encode()).hexdigest()
    
    def stop(self) -> None:
        """Stop observer gracefully."""
        self.observer.stop(reason=f"Agent {self.agent_id} stopped")


# Convenience function
def observe_agent_loop(
    agent_id: str,
    agent_callable: Callable,
    *args,
    **kwargs
) -> Any:
    """
    Observe a generic agent loop (decorator-style).
    
    Usage:
        result = observe_agent_loop(
            agent_id="agent-001",
            agent_callable=agent.run,
            task="Delete old logs"
        )
    
    Args:
        agent_id: Agent identifier
        agent_callable: Agent function to call
        *args, **kwargs: Arguments to pass to agent
    
    Returns:
        Agent return value
    """
    observer = GenericAgentObserver(agent_id=agent_id)
    
    # Observe intent (use first arg as intent if available)
    intent = args[0] if args else "Agent execution"
    observer.observe_intent(str(intent))
    
    try:
        # Execute agent
        result = agent_callable(*args, **kwargs)
        
        # Observe result
        observer.observe_result(result)
        
        return result
    
    except Exception as e:
        # Observe failure
        observer.observe_failure(e)
        raise
    
    finally:
        # Stop observer
        observer.stop()
