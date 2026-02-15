"""
GuardClaw Phase 5: Observer System

Complete observer implementation with strict replay protection.
Phase 5.1: Nonce is REQUIRED (no backward compatibility)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any, Callable
from datetime import datetime, timezone
import secrets


class EventType(Enum):
    """Types of observable events."""
    INTENT = "intent"
    EXECUTION = "execution"
    RESULT = "result"
    FAILURE = "failure"
    DELEGATION = "delegation"
    HEARTBEAT = "heartbeat"


@dataclass
class ObservationEvent:
    """
    Observable event from agent.
    
    Phase 5.1: Nonce is REQUIRED for all events (v0.1.0 protocol)
    """
    event_id: str
    timestamp: str
    event_type: EventType
    subject_id: str  # Who did this
    action: str
    nonce: str = field(default_factory=lambda: secrets.token_hex(16))  # REQUIRED
    correlation_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for signing.
        
        Phase 5.1: Nonce is ALWAYS included (required field)
        """
        data = {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "subject_id": self.subject_id,
            "action": self.action,
            "nonce": self.nonce  # Always included
        }
        
        # Optional fields
        if self.correlation_id:
            data["correlation_id"] = self.correlation_id
        
        if self.metadata:
            data["metadata"] = self.metadata
        
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ObservationEvent":
        """
        Reconstruct from dictionary.
        
        Phase 5.1: STRICT validation - nonce is required
        """
        # Validate nonce is present
        if "nonce" not in data:
            raise ValueError(
                "Invalid event: 'nonce' field is required in GuardClaw v0.1.0 protocol. "
                "This event appears to be from a pre-release or incompatible version."
            )
        
        # Validate nonce type
        if not isinstance(data["nonce"], str):
            raise ValueError(
                f"Invalid event: 'nonce' must be a string, got {type(data['nonce']).__name__}"
            )
        
        # Validate nonce length
        if len(data["nonce"]) != 32:
            raise ValueError(
                f"Invalid event: 'nonce' must be 32 hex characters, got {len(data['nonce'])}"
            )
        
        # Validate nonce is valid hex (GPT's improvement)
        try:
            bytes.fromhex(data["nonce"])
        except ValueError:
            raise ValueError(
                f"Invalid event: 'nonce' must be valid hexadecimal string, "
                f"got '{data['nonce'][:8]}...'"
            )
        
        return cls(
            event_id=data["event_id"],
            timestamp=data["timestamp"],
            event_type=EventType(data["event_type"]),
            subject_id=data["subject_id"],
            action=data["action"],
            nonce=data["nonce"],  # Required
            correlation_id=data.get("correlation_id"),
            metadata=data.get("metadata")
        )


class Observer:
    """
    Observer base class for monitoring agent actions.
    
    Observers hook into agent lifecycle and emit events to the evidence emitter.
    """
    
    def __init__(self, observer_id: str):
        self.observer_id = observer_id
        self._emitter = None
    
    def set_emitter(self, emitter):
        """Set the evidence emitter for this observer."""
        self._emitter = emitter
    
    def observe(self, event: ObservationEvent) -> None:
        """
        Observe an event.
        
        Override this method to add custom observation logic.
        """
        if self._emitter:
            self._emitter.emit(event)
    
    def on_intent(self, agent_id: str, intent: str, context: Optional[Dict] = None) -> None:
        """Called when agent declares intent."""
        event = ObservationEvent(
            event_id=generate_event_id(),
            timestamp=utc_now(),
            event_type=EventType.INTENT,
            subject_id=agent_id,
            action=intent,
            metadata=context or {}
        )
        self.observe(event)
    
    def on_execution(self, agent_id: str, action: str, context: Optional[Dict] = None) -> None:
        """Called when agent executes action."""
        event = ObservationEvent(
            event_id=generate_event_id(),
            timestamp=utc_now(),
            event_type=EventType.EXECUTION,
            subject_id=agent_id,
            action=action,
            metadata=context or {}
        )
        self.observe(event)
    
    def on_result(self, agent_id: str, action: str, result: Any, context: Optional[Dict] = None) -> None:
        """Called when action completes successfully."""
        event = ObservationEvent(
            event_id=generate_event_id(),
            timestamp=utc_now(),
            event_type=EventType.RESULT,
            subject_id=agent_id,
            action=action,
            metadata={
                "result": str(result),
                **(context or {})
            }
        )
        self.observe(event)
    
    def on_failure(self, agent_id: str, action: str, error: str, context: Optional[Dict] = None) -> None:
        """Called when action fails."""
        event = ObservationEvent(
            event_id=generate_event_id(),
            timestamp=utc_now(),
            event_type=EventType.FAILURE,
            subject_id=agent_id,
            action=action,
            metadata={
                "error": error,
                **(context or {})
            }
        )
        self.observe(event)
    
    def on_delegation(self, agent_id: str, delegated_to: str, action: str, context: Optional[Dict] = None) -> None:
        """Called when agent delegates to another agent."""
        event = ObservationEvent(
            event_id=generate_event_id(),
            timestamp=utc_now(),
            event_type=EventType.DELEGATION,
            subject_id=agent_id,
            action=action,
            metadata={
                "delegated_to": delegated_to,
                **(context or {})
            }
        )
        self.observe(event)
    
    def on_heartbeat(self, agent_id: str, status: str = "alive") -> None:
        """Called periodically to indicate agent is still active."""
        event = ObservationEvent(
            event_id=generate_event_id(),
            timestamp=utc_now(),
            event_type=EventType.HEARTBEAT,
            subject_id=agent_id,
            action="heartbeat",
            metadata={"status": status}
        )
        self.observe(event)


class FunctionObserver(Observer):
    """
    Observer that wraps a function to monitor its execution.
    
    Automatically generates intent, execution, and result/failure events.
    """
    
    def __init__(self, observer_id: str, subject_id: str):
        super().__init__(observer_id)
        self.subject_id = subject_id
    
    def wrap(self, func: Callable) -> Callable:
        """
        Wrap a function to observe its execution.
        
        Returns a wrapper function that emits events before/after execution.
        """
        def wrapper(*args, **kwargs):
            # Emit intent
            self.on_intent(
                agent_id=self.subject_id,
                intent=f"call_{func.__name__}",
                context={
                    "function": func.__name__,
                    "args_count": len(args),
                    "kwargs_count": len(kwargs)
                }
            )
            
            # Emit execution
            self.on_execution(
                agent_id=self.subject_id,
                action=f"execute_{func.__name__}"
            )
            
            try:
                # Execute function
                result = func(*args, **kwargs)
                
                # Emit result
                self.on_result(
                    agent_id=self.subject_id,
                    action=f"execute_{func.__name__}",
                    result=result
                )
                
                return result
            
            except Exception as e:
                # Emit failure
                self.on_failure(
                    agent_id=self.subject_id,
                    action=f"execute_{func.__name__}",
                    error=str(e)
                )
                raise
        
        return wrapper


def utc_now() -> str:
    """Return current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).isoformat()


def generate_event_id() -> str:
    """Generate unique event ID."""
    return f"event-{secrets.token_hex(12)}"
