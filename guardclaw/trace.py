"""
guardclaw/trace.py

@trace decorator — zero-friction entry point for GuardClaw.

Usage:
    import guardclaw

    @guardclaw.trace(agent_id="my-agent")
    def run_pipeline(query: str) -> str:
        return model(query)

Behavior:
    - If a global ledger already exists: uses it without modification.
    - If no ledger exists: auto-initializes one at .guardclaw/ledger.gef
      using an in-memory Ed25519 key, then prints the Noisy Birth message
      ONCE per process.
    - Records every call as RecordType.EXECUTION.
    - Records failures as RecordType.FAILURE and re-raises — @trace is transparent.
    - Does NOT print after every call. Only prints on first auto-init.

GEF-SPEC-1.0 aligned.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import Any, Callable

from guardclaw.core.emitter import (
    get_global_ledger,
    has_global_ledger,
    init_global_ledger,
)
from guardclaw.core.models import RecordType
from guardclaw.core.time import gef_timestamp


# ── Module-level state ────────────────────────────────────────

_BIRTH_ANNOUNCED: bool = False
_DEFAULT_LEDGER_DIR: str = ".guardclaw"


# ── Path display helper ───────────────────────────────────────

def _display_path(p: str) -> str:
    """Return path relative to cwd for readability. Falls back to absolute."""
    try:
        return str(Path(p).relative_to(Path.cwd()))
    except Exception:
        return p


# ── Noisy Birth — fires exactly once per process ─────────────

def _announce_birth(ledger_path: str) -> None:
    global _BIRTH_ANNOUNCED
    if _BIRTH_ANNOUNCED:
        return
    _BIRTH_ANNOUNCED = True
    dp = _display_path(ledger_path)
    print(f"\n🛡️  GuardClaw: Accountability Ledger created at {dp}\n")
    print(f"  Verify:   guardclaw verify {dp}")
    print(f"  Export:   guardclaw export {dp}\n")


# ── Safe serialization ────────────────────────────────────────

def _safe_serialize(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return str(value)


# ── Auto-init ─────────────────────────────────────────────────

def _get_or_init_ledger(agent_id: str):
    """
    Return the active global ledger, or auto-initialize one.
    Never overrides an existing ledger.
    """
    if has_global_ledger():
        return get_global_ledger(), False  # (ledger, did_init)

    from guardclaw.core.crypto import Ed25519KeyManager
    km = Ed25519KeyManager.generate()
    ledger = init_global_ledger(
        key_manager=km,
        agent_id=agent_id,
        ledger_path=_DEFAULT_LEDGER_DIR,
    )
    return ledger, True  # (ledger, did_init)


# ── @trace decorator ──────────────────────────────────────────

def trace(agent_id: str) -> Callable:
    """
    Decorator that records function calls as GEF entries.

    Args:
        agent_id: Identity string for this agent/process.

    Example:
        @guardclaw.trace(agent_id="researcher-v1")
        def search(query: str) -> dict:
            return api.search(query)
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            ledger, did_init = _get_or_init_ledger(agent_id)

            if did_init:
                _announce_birth(ledger.get_path())

            # FIX: agent_id removed from payload — ledger owns identity.
            # Use module+name for attribution instead.
            try:
                result = fn(*args, **kwargs)

                ledger.emit(
                    record_type=RecordType.EXECUTION,
                    payload={
                        "action":    fn.__name__,
                        "module":    fn.__module__,
                        "input":     _safe_serialize({"args": args, "kwargs": kwargs}),
                        "output":    _safe_serialize(result),
                        "status":    "success",
                        "timestamp": gef_timestamp(),
                    },
                )
                return result

            except Exception as exc:
                ledger.emit(
                    record_type=RecordType.FAILURE,
                    payload={
                        "action":    fn.__name__,
                        "module":    fn.__module__,
                        "input":     _safe_serialize({"args": args, "kwargs": kwargs}),
                        "error":     type(exc).__name__,
                        "message":   str(exc),
                        "status":    "failure",
                        "timestamp": gef_timestamp(),
                    },
                )
                raise  # always re-raise — @trace is transparent

        return wrapper
    return decorator