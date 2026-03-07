"""
guardclaw/adapters/langchain.py

LangChain callback adapter for GuardClaw.

Install:
    pip install guardclaw[langchain]

Usage:
    from guardclaw.adapters.langchain import GuardClawCallbackHandler

    handler = GuardClawCallbackHandler(agent_id="my-agent")
    agent.run("task", callbacks=[handler])
"""

import sys

try:
    # LangChain <= 0.1.x
    from langchain.callbacks.base import BaseCallbackHandler
except Exception:
    try:
        # LangChain >= 0.2.x
        from langchain_core.callbacks.base import BaseCallbackHandler
    except Exception:
        raise ImportError(
            "LangChain is required for this adapter.\n"
            "Install with: pip install langchain"
        )

from guardclaw.api import record_action


MAX_PAYLOAD = 1000


def _truncate(value) -> str:
    """Convert value to string and truncate to prevent large payloads."""
    return str(value)[:MAX_PAYLOAD]


def _safe_metadata(metadata: dict) -> dict:
    """Ensure metadata values are safe and truncated."""
    return {k: _truncate(v) for k, v in metadata.items()}


class GuardClawCallbackHandler(BaseCallbackHandler):
    """
    LangChain callback handler that records tool and LLM activity
    into the GuardClaw ledger as signed ExecutionEnvelope entries.
    """

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self._current_tool = None

    def _record(self, action: str, result: str, metadata: dict):
        """
        Record an action to GuardClaw.

        Never crashes the agent runtime.
        Logs errors to stderr if audit logging fails.
        """
        try:
            safe = _safe_metadata(metadata)

            safe["framework"] = "langchain"
            safe["adapter"] = "guardclaw"

            record_action(
                agent_id=self.agent_id,
                action=action,
                result=result,
                metadata=safe,
            )

        except Exception as e:
            print(f"[GuardClaw] adapter error: {e}", file=sys.stderr)

    # -------------------------
    # Tool lifecycle events
    # -------------------------

    def on_tool_start(self, serialized, input_str, **kwargs):

        tool_name = "unknown_tool"
        if isinstance(serialized, dict):
            tool_name = serialized.get("name", "unknown_tool")

        self._current_tool = tool_name

        self._record(
            action=tool_name,
            result="STARTED",
            metadata={
                "event": "tool_start",
                "input": _truncate(input_str),
                "run_id": kwargs.get("run_id", ""),
                "parent_run_id": kwargs.get("parent_run_id", ""),
            },
        )

    def on_tool_end(self, output, **kwargs):

        self._record(
            action=self._current_tool or "unknown_tool",
            result="SUCCESS",
            metadata={
                "event": "tool_end",
                "output": _truncate(output),
                "run_id": kwargs.get("run_id", ""),
                "parent_run_id": kwargs.get("parent_run_id", ""),
            },
        )

        self._current_tool = None

    def on_tool_error(self, error, **kwargs):

        self._record(
            action=self._current_tool or "unknown_tool",
            result="ERROR",
            metadata={
                "event": "tool_error",
                "error": _truncate(error),
                "run_id": kwargs.get("run_id", ""),
                "parent_run_id": kwargs.get("parent_run_id", ""),
            },
        )

        self._current_tool = None

    # -------------------------
    # LLM lifecycle events
    # -------------------------

    def on_llm_start(self, serialized, prompts, **kwargs):

        model_name = "unknown_llm"
        if isinstance(serialized, dict):
            model_name = serialized.get("name", "unknown_llm")

        prompt = ""
        if prompts and isinstance(prompts, (list, tuple)):
            prompt = prompts[0]

        self._record(
            action=model_name,
            result="STARTED",
            metadata={
                "event": "llm_start",
                "prompt": _truncate(prompt),
                "run_id": kwargs.get("run_id", ""),
                "parent_run_id": kwargs.get("parent_run_id", ""),
            },
        )

    def on_llm_end(self, response, **kwargs):

        completion = ""

        try:
            completion = response.generations[0][0].text
        except Exception:
            completion = str(response)

        self._record(
            action="llm_response",
            result="SUCCESS",
            metadata={
                "event": "llm_end",
                "completion": _truncate(completion),
                "run_id": kwargs.get("run_id", ""),
                "parent_run_id": kwargs.get("parent_run_id", ""),
            },
        )