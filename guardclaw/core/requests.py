"""
guardclaw/core/requests.py

ActionRequest and related runtime request types.
Separated from models.py to preserve GEF protocol contract lock.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional

from guardclaw.core.action_types import ActionType


@dataclass
class ActionRequest:
    """Represents a request by an agent to perform an action."""
    action_id:       str
    agent_id:        str
    action_type:     ActionType
    target_resource: str
    operation:       str
    intent:          str
    context:         Dict[str, Any]
    requested_at:    datetime
    metadata:        Dict[str, Any] = field(default_factory=dict)