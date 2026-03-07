"""
guardclaw/mcp/proxy.py

GuardClaw MCP Proxy — framework-agnostic tool interception layer.

Intercepts tool execution and records cryptographically signed
INTENT → RESULT / FAILURE entries into the GuardClaw ledger.

Supports:
- Sync and async tools
- Dispatcher style (proxy.call)
- Wrapper style (proxy.wrap_tool)
- Automatic schema generation from Python functions
- OpenAI / Claude tool calling compatibility
"""

import sys
import uuid
import inspect
import asyncio
import functools
from typing import Any, Callable, Dict, Optional

from guardclaw.api import record_action

MAX_PAYLOAD = 1000


# ------------------------------------------------
# Helpers
# ------------------------------------------------

def _truncate(value) -> str:
    """Convert any value to string and truncate."""
    try:
        return str(value)[:MAX_PAYLOAD]
    except Exception:
        return repr(value)[:MAX_PAYLOAD]


def _safe_metadata(metadata: dict) -> dict:
    """Ensure metadata values are safe, truncated strings."""
    return {k: _truncate(v) for k, v in metadata.items()}


def _schema_from_function(func: Callable) -> dict:
    """
    Generate OpenAI-compatible tool schema from Python function signature.
    All parameters are treated as strings for simplicity.
    """
    sig = inspect.signature(func)

    properties = {}
    required = []

    for name, param in sig.parameters.items():
        if name == "self":
            continue

        properties[name] = {"type": "string"}

        if param.default is inspect._empty:
            required.append(name)

    return {
        "type": "function",
        "function": {
            "name": func.__name__,
            "description": func.__doc__ or func.__name__,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        },
    }


def _normalize_payload(args, kwargs):
    """
    Normalize arguments into a payload dict.

    - If first arg is a dict, treat it as the payload base.
    - Merge kwargs on top.
    - If args are non-dict, store them under 'args'.
    """
    if args and isinstance(args[0], dict):
        payload = dict(args[0])
    else:
        payload = {}

    payload.update(kwargs)

    if args and not isinstance(args[0], dict):
        payload["args"] = args

    return payload


# ------------------------------------------------
# Main Proxy
# ------------------------------------------------

class GuardClawMCPProxy:
    """
    Framework-agnostic tool interception proxy.

    Records INTENT before execution and RESULT/FAILURE after,
    producing a cryptographically signed audit trail for every
    tool call regardless of the underlying framework.
    """

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self._tools: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------
    # Tool Registration
    # ------------------------------------------------

    def register_tool(
        self,
        name: str,
        func: Callable,
        description: str = None,
        schema: dict = None,
    ) -> None:
        """
        Register a tool with the proxy.

        Args:
            name:        Tool identifier used in call()
            func:        Callable (sync or async)
            description: Human-readable description
            schema:      OpenAI-compatible tool schema
        """
        if name in self._tools:
            raise ValueError(f"Tool '{name}' already registered.")

        self._tools[name] = {
            "func": func,
            "description": description or name,
            "schema": schema or _schema_from_function(func),
        }

    # ------------------------------------------------
    # Logging
    # ------------------------------------------------

    def _log(self, action: str, result: str, metadata: dict, run_id: str) -> None:
        """Safe logging — never crashes agent runtime."""
        try:
            safe = _safe_metadata(metadata)
            safe.update({
                "framework": "mcp",
                "adapter": "guardclaw",
                "run_id": run_id,
            })

            record_action(
                agent_id=self.agent_id,
                action=action,
                result=result,
                metadata=safe,
            )

        except Exception as e:
            print(f"[GuardClaw] MCP logging error: {e}", file=sys.stderr)

    # ------------------------------------------------
    # Execution Pipeline
    # ------------------------------------------------

    async def _execute_async(
        self,
        tool_name: str,
        func: Callable,
        payload: dict,
        run_id: str,
    ) -> Any:
        """
        Unified async execution pipeline.

        INTENT → EXECUTE → RESULT / FAILURE
        """
        # 1) INTENT
        self._log(
            action=tool_name,
            result="INTENT",
            metadata={
                "event": "tool_intent",
                "payload": _truncate(repr(payload)),
            },
            run_id=run_id,
        )

        # 2) EXECUTE
        try:
            if inspect.iscoroutinefunction(func):
                output = await func(**payload)
            else:
                output = func(**payload)

            # 3) RESULT
            self._log(
                action=tool_name,
                result="RESULT",
                metadata={
                    "event": "tool_result",
                    "output": _truncate(output),
                },
                run_id=run_id,
            )

            return output

        except Exception as exc:
            # 4) FAILURE
            self._log(
                action=tool_name,
                result="FAILURE",
                metadata={
                    "event": "tool_failure",
                    "error": _truncate(exc),
                },
                run_id=run_id,
            )
            raise

    # ------------------------------------------------
    # Dispatcher
    # ------------------------------------------------

    def call(
        self,
        tool_name: str,
        payload: Optional[Dict] = None,
        run_id: Optional[str] = None,
        **kwargs,
    ) -> Any:
        """
        Dispatch a tool call through the audit pipeline.

        Supports both:
            proxy.call("search", {"query": "AI"})
            proxy.call("search", query="AI")
        """
        if tool_name not in self._tools:
            raise KeyError(f"Tool '{tool_name}' not registered.")

        func = self._tools[tool_name]["func"]

        merged = dict(payload or {})
        merged.update(kwargs)

        run_id = run_id or str(uuid.uuid4())

        coro = self._execute_async(tool_name, func, merged, run_id)

        if inspect.iscoroutinefunction(func):
            # Caller can await this
            return coro

        # Sync execution path: run coroutine safely
        try:
            loop = asyncio.get_running_loop()

            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result()

        except RuntimeError:
            # No running loop
            return asyncio.run(coro)

    # ------------------------------------------------
    # Tool Wrapper
    # ------------------------------------------------

    def wrap_tool(
        self,
        func: Callable,
        name: str = None,
        description: str = None,
        run_id: str = None,
    ) -> Callable:
        """
        Wrap a function so every call is automatically audited.

        Preserves original function signature for framework compatibility.
        """
        tool_name = name or f"wrapped_{func.__name__}"

        if tool_name not in self._tools:
            self.register_tool(tool_name, func, description)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            payload = _normalize_payload(args, kwargs)
            rid = run_id or kwargs.pop("run_id", None)
            return self.call(tool_name, payload, run_id=rid)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            payload = _normalize_payload(args, kwargs)
            rid = run_id or kwargs.pop("run_id", None) or str(uuid.uuid4())
            return await self._execute_async(tool_name, func, payload, rid)

        return async_wrapper if inspect.iscoroutinefunction(func) else sync_wrapper

    # ------------------------------------------------
    # Schema Export
    # ------------------------------------------------

    def get_tool_schemas(self) -> list:
        """Export all registered tools as OpenAI-compatible schemas."""
        return [meta["schema"] for meta in self._tools.values()]

    # ------------------------------------------------
    # Introspection
    # ------------------------------------------------

    def list_tools(self) -> list:
        """Return list of registered tool names."""
        return list(self._tools.keys())

    def __repr__(self) -> str:
        return f"GuardClawMCPProxy(agent_id={self.agent_id!r}, tools={self.list_tools()})"
