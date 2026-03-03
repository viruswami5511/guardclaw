"""
guardclaw/core/emitter.py

Global ledger helpers for GuardClaw.

GEFLedger lives in guardclaw.core.ledger — that is the canonical implementation.
This module exists solely for:
    1. Global singleton helpers (init_global_ledger / get_global_ledger)
    2. Backward-compatible deprecated shims (EvidenceEmitter)

Do NOT add ledger write logic here. All write logic belongs in core/ledger.py.

GEF-SPEC-1.0 aligned.
"""

import warnings
from typing import Optional

from guardclaw.core.ledger import GEFLedger
from guardclaw.core.crypto import Ed25519KeyManager


# ── Global Singleton ──────────────────────────────────────────────────────────

_global_ledger: Optional[GEFLedger] = None


def init_global_ledger(
    key_manager:  Ed25519KeyManager,
    agent_id:     str,
    ledger_path:  str = ".guardclaw/ledger",
    mode:         str = "strict",
) -> GEFLedger:
    """
    Initialize and return the process-wide GEFLedger instance.

    Safe to call multiple times — replaces the previous in-memory instance.
    Previous ledger files are preserved on disk.

    Args:
        key_manager:  Ed25519KeyManager instance for signing.
        agent_id:     String identifier for this agent/process.
        ledger_path:  Directory where ledger.jsonl will be written.
        mode:         "strict" (default, fsync every entry) or "ghost" (in-memory only).

    Returns:
        The initialized GEFLedger instance.
    """
    global _global_ledger
    _global_ledger = GEFLedger(
        key_manager=key_manager,
        agent_id=agent_id,
        ledger_path=ledger_path,
        mode=mode,
    )
    return _global_ledger


def get_global_ledger() -> Optional[GEFLedger]:
    """
    Return the process-wide GEFLedger instance.

    Returns None if init_global_ledger() has not been called yet.
    """
    return _global_ledger


# ── Deprecated Shims ──────────────────────────────────────────────────────────
# These exist only to prevent ImportError on old installs.
# Will be removed in v0.6.0.


class EvidenceEmitter:
    """
    DEPRECATED — violates GEF Section 7.1.

    EvidenceEmitter used deferred batch signing. Signatures did not exist
    when emit() returned — a direct violation of the GEF signing contract.

    Migration: use GEFLedger instead.

        # Old (broken):
        emitter = EvidenceEmitter(...)
        emitter.emit(...)

        # New (correct):
        ledger = GEFLedger(key_manager=key, agent_id="my-agent", ledger_path=".guardclaw")
        ledger.emit(RecordType.EXECUTION, payload={"task": "run"})

    Will be removed in v0.6.0.
    """

    def __init__(self, *args, **kwargs):
        warnings.warn(
            "EvidenceEmitter is deprecated and violates GEF Section 7.1 "
            "(signature must exist before emit() returns). "
            "Use guardclaw.core.ledger.GEFLedger instead. "
            "Will be removed in v0.6.0.",
            DeprecationWarning,
            stacklevel=2,
        )


def init_global_emitter(*args, **kwargs) -> None:
    """
    DEPRECATED — use init_global_ledger() instead.

    Will be removed in v0.6.0.
    """
    warnings.warn(
        "init_global_emitter() is deprecated. "
        "Use guardclaw.core.emitter.init_global_ledger() instead. "
        "Will be removed in v0.6.0.",
        DeprecationWarning,
        stacklevel=2,
    )
