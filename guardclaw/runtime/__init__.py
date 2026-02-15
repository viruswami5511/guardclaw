"""
GuardClaw Runtime - Execution wrapper and context management.

This module provides the structural choke point that makes
bypassing GuardClaw impossible within a managed runtime.
"""

from guardclaw.runtime.context import RuntimeContext
from guardclaw.runtime.executor import ToolExecutor, ExecutionResult

__all__ = [
    "RuntimeContext",
    "ToolExecutor",
    "ExecutionResult",
]
