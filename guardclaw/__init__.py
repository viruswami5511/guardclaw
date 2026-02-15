"""
GuardClaw: Cryptographic Accountability for AI Agents

Phase 5: Runtime Observers + Async Emission + Replay
"""

__version__ = "0.5.0"

from guardclaw.core.modes import init_ghost_mode, init_strict_mode
from guardclaw.core.observers import Observer
from guardclaw.core.emitter import EvidenceEmitter, init_global_emitter
from guardclaw.adapters import GenericAgentObserver, observe_tool

__all__ = [
    "init_ghost_mode",
    "init_strict_mode",
    "Observer",
    "EvidenceEmitter",
    "init_global_emitter",
    "GenericAgentObserver",
    "observe_tool",
]
