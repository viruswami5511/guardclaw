"""
guardclaw/core/action_types.py

ActionType enum for GuardClaw wrapper, demos, and runtime executor.
Separate from models.py to preserve GEF protocol contract lock.
"""

from enum import Enum


class ActionType(str, Enum):
    """Action classification for GuardClaw agent wrappers."""
    INTENT       = "intent"
    EXECUTION    = "execution"
    RESULT       = "result"
    FAILURE      = "failure"
    FILE_READ    = "file_read"
    FILE_WRITE   = "file_write"
    FILE_DELETE  = "file_delete"
    TOOL_CALL    = "tool_call"
    ADMIN_ACTION = "admin_action"