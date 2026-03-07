"""
guardclaw/mcp/proxy.py

GuardClaw MCP Proxy — framework-agnostic tool interception layer.

Intercepts tool execution and records cryptographically signed
INTENT → RESULT / FAILURE entries into the GuardClaw ledger.

Supports:
    - Sync and async tools
    - Dispatcher style (proxy.call)
    - Wrapper style (proxy.wrap_tool)
    - LLM tool schema export

Usage:
    from guardclaw.mcp import GuardClawMCPProxy
    from guardclaw import init_global_ledger, Ed25519KeyManager

    km = Ed25519KeyManager.generate()
    init_global_ledger(key_manager=km, agent_id="agent-1")

    proxy = GuardClawMCPProxy(agent_id="agent-1")
    proxy.register_tool("search", search_fn, description="Search the web")

    result = proxy.call("search", query="AI safety")
"""

import sys
import uuid
import inspect
import asyncio
import functools
from typing import Any, Callable, Dict, Optional

from guardclaw.api import record_action

MAX_PAYLOAD = 1000


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _truncate(value) -> str:
    """Convert any value to string and truncate."""
    try:
        return str(value)[:MAX_PAYLOAD]
    except Exception:
        return repr(value)[:MAX_PAYLOAD]


def _safe_metadata(metadata: dict) -> dict:
    """Ensure all metadata values are truncated strings."""
    return {k: _truncate(v) for k, v in metadata.items()}


def _default_schema(name: str, description: str) -> dict:
    """Fallback OpenAI-compatible tool schema."""
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description or name,
            "parameters": {
                "type": "object",
                "properties": {},
                "required": [],
            },
        },
    }


# ─────────────────────────────────────────────
# Main Class
# ─────────────────────────────────────────────

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

    # ─────────────────────────────────────────
    # Tool Registration
    # ─────────────────────────────────────────

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
            description: Human-readable description for audit logs
            schema:      OpenAI-compatible tool schema (auto-generated if None)
        """
        if name in self._tools:
            raise ValueError(f"Tool '{name}' already registered.")
        self._tools[name] = {
            "func": func,
            "description": description or name,
            "schema": schema or _default_schema(name, description or name),
        }

    # ─────────────────────────────────────────
    # Logging
    # ─────────────────────────────────────────

    def _log(
        self,
        action: str,
        result: str,
        metadata: dict,
        run_id: str,
    ) -> None:
        """Safe logging — never crashes agent runtime."""
        try:
            safe = _safe_metadata(metadata)
            safe.update({
                "framework": "mcp",
                "adapter":   "guardclaw",
                "run_id":    run_id,
            })
            record_action(
                agent_id=self.agent_id,
                action=action,
                result=result,
                metadata=safe,
            )
        except Exception as e:
            print(f"[GuardClaw] MCP logging error: {e}", file=sys.stderr)

    # ─────────────────────────────────────────
    # Core Execution Pipeline
    # ─────────────────────────────────────────

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
        # 1. Log INTENT — forensic guarantee before execution
        self._log(
            action=tool_name,
            result="INTENT",
            metadata={
                "event": "tool_intent",
                "payload": _truncate(repr(payload)),
            },
            run_id=run_id,
        )

        # 2. Execute
        try:
            if inspect.iscoroutinefunction(func):
                output = await func(**payload)
            else:
                output = func(**payload)

            # 3. Log RESULT
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
            # 4. Log FAILURE — re-raise so caller behaves normally
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

    # ─────────────────────────────────────────
    # Style A — Dispatcher
    # ─────────────────────────────────────────

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

        Args:
            tool_name: Registered tool name
            payload:   Dict of tool arguments (optional)
            run_id:    Trace ID for grouping related calls
        """
        if tool_name not in self._tools:
            raise KeyError(f"Tool '{tool_name}' not registered.")

        # Normalize payload — merge dict + kwargs
        merged = dict(payload or {})
        merged.update(kwargs)

        run_id = run_id or str(uuid.uuid4())
        func = self._tools[tool_name]["func"]

        coro = self._execute_async(tool_name, func, merged, run_id)

        if inspect.iscoroutinefunction(func):
            # Caller can await this
            return coro
        else:
            # Run sync tools via event loop
            try:
                loop = asyncio.get_running_loop()
                # In a running loop (e.g. async app) run in a separate thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, coro)
                    return future.result()
            except RuntimeError:
                # No running loop, safe to run directly
                return asyncio.run(coro)

    # ─────────────────────────────────────────
    # Style B — Tool Wrapper
    # ─────────────────────────────────────────

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

        Example:
            search = proxy.wrap_tool(search_fn)
            search(query="AI")  # automatically logged
        """
        tool_name = name or f"wrapped_{func.__name__}"
        if tool_name not in self._tools:
            self.register_tool(tool_name, func, description)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            payload = kwargs.copy()
            if args:
                payload["args"] = args
            rid = run_id or kwargs.pop("run_id", None)
            return self.call(tool_name, payload, run_id=rid)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            payload = kwargs.copy()
            if args:
                payload["args"] = args
            rid = run_id or kwargs.pop("run_id", None) or str(uuid.uuid4())
            return await self._execute_async(tool_name, func, payload, rid)

        return async_wrapper if inspect.iscoroutinefunction(func) else sync_wrapper

    # ─────────────────────────────────────────
    # Schema Export
    # ─────────────────────────────────────────

    def get_tool_schemas(self) -> list:
        """
        Export all registered tools as OpenAI-compatible schemas.

        Example:
            tools = proxy.get_tool_schemas()
            client.chat(..., tools=tools)
        """
        return [meta["schema"] for meta in self._tools.values()]

    # ─────────────────────────────────────────
    # Introspection
    # ─────────────────────────────────────────

    def list_tools(self) -> list:
        """Return list of registered tool names."""
        return list(self._tools.keys())

    def __repr__(self) -> str:
        return (
            f"GuardClawMCPProxy("
            f"agent_id={self.agent_id!r}, "
            f"tools={self.list_tools()})"
        )
