"""
GuardClaw Phase 3: Context & Causality Tracking

Answers the question: WHY did this action happen?

Every action in GuardClaw Phase 3 MUST track:
- trigger_hash: What input caused this action?
- context_manifest_hash: What data was used for the decision?
- intent_reference: Link to user prompt/command/signal

This enables distinction between:
- User instruction vs AI hallucination
- External manipulation vs internal failure
- Expected behavior vs anomaly
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
import uuid

from guardclaw.core.crypto import canonical_hash, canonical_json_encode


@dataclass
class TriggerContext:
    """
    Trigger Context - What caused this action?
    
    Privacy-safe: Stores HASHES of inputs, not raw data.
    
    Enables auditors to:
    - Verify an action was triggered by a specific input
    - Detect unauthorized triggers
    - Trace causality chains
    """
    
    trigger_id: str
    trigger_type: str  # "user_command", "api_request", "scheduled_task", "external_signal"
    trigger_hash: str  # SHA-256 hash of trigger content
    triggered_at: datetime
    source: str  # Where did the trigger come from?
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @staticmethod
    def from_user_command(command: str, source: str = "user") -> "TriggerContext":
        """Create trigger context from user command."""
        trigger_id = f"trigger-{uuid.uuid4()}"
        trigger_hash = canonical_hash({"command": command})
        
        return TriggerContext(
            trigger_id=trigger_id,
            trigger_type="user_command",
            trigger_hash=trigger_hash,
            triggered_at=datetime.now(timezone.utc),
            source=source
        )
    
    @staticmethod
    def from_api_request(request_data: Dict[str, Any], source: str) -> "TriggerContext":
        """Create trigger context from API request."""
        trigger_id = f"trigger-{uuid.uuid4()}"
        trigger_hash = canonical_hash(request_data)
        
        return TriggerContext(
            trigger_id=trigger_id,
            trigger_type="api_request",
            trigger_hash=trigger_hash,
            triggered_at=datetime.now(timezone.utc),
            source=source,
            metadata={"endpoint": request_data.get("endpoint", "unknown")}
        )
    
    @staticmethod
    def from_scheduled_task(task_name: str) -> "TriggerContext":
        """Create trigger context from scheduled task."""
        trigger_id = f"trigger-{uuid.uuid4()}"
        trigger_hash = canonical_hash({"task": task_name})
        
        return TriggerContext(
            trigger_id=trigger_id,
            trigger_type="scheduled_task",
            trigger_hash=trigger_hash,
            triggered_at=datetime.now(timezone.utc),
            source="scheduler",
            metadata={"task_name": task_name}
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "trigger_id": self.trigger_id,
            "trigger_type": self.trigger_type,
            "trigger_hash": self.trigger_hash,
            "triggered_at": self.triggered_at.isoformat(),
            "source": self.source,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TriggerContext":
        """Reconstruct from dictionary."""
        return cls(
            trigger_id=data["trigger_id"],
            trigger_type=data["trigger_type"],
            trigger_hash=data["trigger_hash"],
            triggered_at=datetime.fromisoformat(data["triggered_at"]),
            source=data["source"],
            metadata=data.get("metadata", {})
        )


@dataclass
class ContextManifest:
    """
    Context Manifest - What data was used to make a decision?
    
    Privacy-safe: Stores hashes and schemas, not raw data.
    
    Enables auditors to:
    - Verify what data influenced a decision
    - Detect data manipulation
    - Replay decisions with original context
    """
    
    manifest_id: str
    created_at: datetime
    data_sources: List[Dict[str, Any]]  # List of data sources with hashes
    schema_version: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @staticmethod
    def create(
        data_sources: List[Dict[str, Any]],
        schema_version: str = "3.0.0",
        metadata: Optional[Dict[str, Any]] = None
    ) -> "ContextManifest":
        """
        Create a context manifest.
        
        Args:
            data_sources: List of data sources, each with:
                - source_name: str
                - source_type: str
                - data_hash: str (hash of data used)
                - accessed_at: datetime
            schema_version: Schema version
            metadata: Additional metadata
            
        Returns:
            ContextManifest
        """
        manifest_id = f"manifest-{uuid.uuid4()}"
        
        return ContextManifest(
            manifest_id=manifest_id,
            created_at=datetime.now(timezone.utc),
            data_sources=data_sources,
            schema_version=schema_version,
            metadata=metadata or {}
        )
    
    def hash(self) -> str:
        """Compute hash of context manifest."""
        return canonical_hash({
            "manifest_id": self.manifest_id,
            "created_at": self.created_at.isoformat(),
            "data_sources": self.data_sources,
            "schema_version": self.schema_version
        })
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "manifest_id": self.manifest_id,
            "created_at": self.created_at.isoformat(),
            "data_sources": self.data_sources,
            "schema_version": self.schema_version,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContextManifest":
        """Reconstruct from dictionary."""
        return cls(
            manifest_id=data["manifest_id"],
            created_at=datetime.fromisoformat(data["created_at"]),
            data_sources=data["data_sources"],
            schema_version=data["schema_version"],
            metadata=data.get("metadata", {})
        )


@dataclass
class IntentReference:
    """
    Intent Reference - Link to original user intent.
    
    Enables tracing from action back to user prompt/command.
    """
    
    intent_id: str
    intent_type: str  # "user_prompt", "api_call", "scheduled", "autonomous"
    intent_hash: str  # Hash of intent content
    recorded_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @staticmethod
    def from_prompt(prompt: str, metadata: Optional[Dict[str, Any]] = None) -> "IntentReference":
        """Create intent reference from user prompt."""
        intent_id = f"intent-{uuid.uuid4()}"
        intent_hash = canonical_hash({"prompt": prompt})
        
        return IntentReference(
            intent_id=intent_id,
            intent_type="user_prompt",
            intent_hash=intent_hash,
            recorded_at=datetime.now(timezone.utc),
            metadata=metadata or {}
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "intent_id": self.intent_id,
            "intent_type": self.intent_type,
            "intent_hash": self.intent_hash,
            "recorded_at": self.recorded_at.isoformat(),
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IntentReference":
        """Reconstruct from dictionary."""
        return cls(
            intent_id=data["intent_id"],
            intent_type=data["intent_type"],
            intent_hash=data["intent_hash"],
            recorded_at=datetime.fromisoformat(data["recorded_at"]),
            metadata=data.get("metadata", {})
        )
