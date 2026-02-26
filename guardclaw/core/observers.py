"""
guardclaw/core/observers.py

GEF-native observer helpers.

REMOVED (permanently):
    ObservationEvent   — replaced by ExecutionEnvelope
    EventType enum     — replaced by RecordType constants in models.py
    utc_now()          — replaced by gef_timestamp() in core/time.py

Observer calls ledger.emit(record_type, payload) directly.
The ledger constructs the ExecutionEnvelope and signs it.
"""

import secrets
from typing import Any, Callable, Dict, Optional

from guardclaw.core.models import RecordType
from guardclaw.core.time import gef_timestamp  # noqa: F401 — re-exported for convenience


def generate_record_id() -> str:
    """Generate a unique GEF record ID."""
    return f"gef-{secrets.token_hex(12)}"


# ─────────────────────────────────────────────────────────────
# Observer
# ─────────────────────────────────────────────────────────────

class Observer:
    """
    GEF-native observer.

    Each on_* method calls ledger.emit(record_type, payload).
    The ledger creates the ExecutionEnvelope, sets causal_hash,
    signs it, and appends it — all atomically.

    No batching. No deferred signing. No ObservationEvent.
    """

    def __init__(self, agent_id: str, ledger=None):
        self.agent_id = agent_id
        self._ledger  = ledger

    def set_ledger(self, ledger) -> None:
        """Bind a GEFLedger. Must be called before any on_* method."""
        self._ledger = ledger

    def _emit(self, record_type: str, payload: Dict[str, Any]) -> None:
        if self._ledger is None:
            raise RuntimeError(
                "Observer has no GEFLedger bound. Call set_ledger() first."
            )
        payload = dict(payload)
        payload.setdefault("agent_id", self.agent_id)
        self._ledger.emit(record_type, payload)

    def on_intent(self, intent: str, context: Optional[Dict] = None) -> None:
        self._emit(RecordType.INTENT, {
            "intent":  intent,
            "context": context or {},
        })

    def on_execution(self, action: str, context: Optional[Dict] = None) -> None:
        self._emit(RecordType.EXECUTION, {
            "action":  action,
            "context": context or {},
        })

    def on_result(self, action: str, result: Any,
                  context: Optional[Dict] = None) -> None:
        self._emit(RecordType.RESULT, {
            "action":  action,
            "result":  str(result),
            "context": context or {},
        })

    def on_failure(self, action: str, error: str,
                   context: Optional[Dict] = None) -> None:
        self._emit(RecordType.FAILURE, {
            "action":  action,
            "error":   error,
            "context": context or {},
        })

    def on_delegation(self, delegated_to: str, action: str,
                      context: Optional[Dict] = None) -> None:
        self._emit(RecordType.DELEGATION, {
            "delegated_to": delegated_to,
            "action":       action,
            "context":      context or {},
        })

    def on_heartbeat(self, status: str = "alive") -> None:
        self._emit(RecordType.HEARTBEAT, {"status": status})

    def on_tool_call(self, tool_name: str, inputs: Dict[str, Any],
                     context: Optional[Dict] = None) -> None:
        self._emit(RecordType.TOOL_CALL, {
            "tool_name": tool_name,
            "inputs":    inputs,
            "context":   context or {},
        })


# ─────────────────────────────────────────────────────────────
# FunctionObserver
# ─────────────────────────────────────────────────────────────

class FunctionObserver(Observer):
    """
    Wraps a Python callable with GEF observation.
    Emits intent → execution → result/failure as atomic GEF envelopes.
    """

    def wrap(self, func: Callable) -> Callable:
        obs = self

        def wrapper(*args, **kwargs):
            obs.on_intent(
                intent=f"call_{func.__name__}",
                context={
                    "function":     func.__name__,
                    "args_count":   len(args),
                    "kwargs_count": len(kwargs),
                },
            )
            obs.on_execution(action=f"execute_{func.__name__}")
            try:
                result = func(*args, **kwargs)
                obs.on_result(action=f"execute_{func.__name__}", result=result)
                return result
            except Exception as e:
                obs.on_failure(
                    action=f"execute_{func.__name__}",
                    error=str(e),
                )
                raise

        return wrapper
