"""
guardclaw/integrations/langchain.py

GuardClaw callback handler for LangChain.

Usage:
    from guardclaw.integrations.langchain import GuardClawCallbackHandler

    handler = GuardClawCallbackHandler(agent_id="my-chain")
    chain.run(query, callbacks=[handler])

Requires:
    pip install guardclaw[langchain]

Records:
    on_llm_start    → RecordType.EXECUTION  (intent)
    on_llm_end      → RecordType.RESULT     (result)
    on_llm_error    → RecordType.FAILURE    (failure)
    on_tool_start   → RecordType.TOOL_CALL  (tool invocation)
    on_tool_end     → RecordType.RESULT     (tool result)
    on_tool_error   → RecordType.FAILURE    (tool failure)

GEF-SPEC-1.0 aligned.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Union

try:
    from langchain_core.callbacks.base import BaseCallbackHandler
    from langchain_core.outputs import LLMResult
except ImportError:
    try:
        from langchain.callbacks.base import BaseCallbackHandler
        from langchain.schema import LLMResult
    except ImportError:
        raise ImportError(
            "LangChain is required for GuardClawCallbackHandler.\n"
            "Install with: pip install guardclaw[langchain]"
        )

from guardclaw.core.emitter import get_global_ledger
from guardclaw.core.models import RecordType
from guardclaw.core.time import gef_timestamp


def _safe(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return str(value)


class GuardClawCallbackHandler(BaseCallbackHandler):
    """
    Minimal LangChain callback handler that records executions into
    a GuardClaw GEF ledger.

    Requires an active global ledger. Raises RuntimeError immediately
    if no ledger is active — no silent failure.
    """

    def __init__(self, agent_id: str) -> None:
        super().__init__()
        self.agent_id = agent_id
        # FIX: fail loudly at construction time, not silently at call time.
        ledger = get_global_ledger()
        if ledger is None:
            raise RuntimeError(
                "GuardClaw: No active ledger. "
                "Call init_global_ledger() or use @trace before "
                "instantiating GuardClawCallbackHandler."
            )

    def _ledger(self):
        return get_global_ledger()

    def _emit(self, record_type: RecordType, payload: Dict[str, Any]) -> None:
        ledger = self._ledger()
        if ledger is None:
            raise RuntimeError(
                "GuardClaw: Ledger became unavailable. "
                "Do not call set_global_ledger(None) while a handler is active."
            )
        ledger.emit(record_type=record_type, payload=payload)

    # ── LLM hooks ──────────────────────────────────────────────

    def on_llm_start(
        self,
        serialized: Dict[str, Any],
        prompts: List[str],
        **kwargs: Any,
    ) -> None:
        self._emit(RecordType.EXECUTION, {
            "action_id": str(uuid.uuid4()),
            "action":    "llm.start",
            "model":     _safe(serialized.get("name", serialized.get("id", "unknown"))),
            "input":     _safe(prompts),
            "timestamp": gef_timestamp(),
        })

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        self._emit(RecordType.RESULT, {
            "action_id":  str(uuid.uuid4()),
            "action":     "llm.end",
            "output":     _safe(response.generations),
            "llm_output": _safe(response.llm_output),
            "timestamp":  gef_timestamp(),
        })

    def on_llm_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        **kwargs: Any,
    ) -> None:
        self._emit(RecordType.FAILURE, {
            "action_id": str(uuid.uuid4()),
            "action":    "llm.error",
            "error":     type(error).__name__,
            "message":   str(error),
            "timestamp": gef_timestamp(),
        })

    # ── Tool hooks ─────────────────────────────────────────────

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        **kwargs: Any,
    ) -> None:
        self._emit(RecordType.TOOL_CALL, {
            "action_id": str(uuid.uuid4()),
            "action":    "tool.start",
            "tool":      _safe(serialized.get("name", "unknown")),
            "input":     _safe(input_str),
            "timestamp": gef_timestamp(),
        })

    def on_tool_end(self, output: str, **kwargs: Any) -> None:
        self._emit(RecordType.RESULT, {
            "action_id": str(uuid.uuid4()),
            "action":    "tool.end",
            "output":    _safe(output),
            "timestamp": gef_timestamp(),
        })

    def on_tool_error(
        self,
        error: Union[Exception, KeyboardInterrupt],
        **kwargs: Any,
    ) -> None:
        self._emit(RecordType.FAILURE, {
            "action_id": str(uuid.uuid4()),
            "action":    "tool.error",
            "error":     type(error).__name__,
            "message":   str(error),
            "timestamp": gef_timestamp(),
        })