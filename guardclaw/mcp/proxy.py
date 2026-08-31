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
from typing import Any, Callable, Dict, Optional, Union, List

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


def _normalize_payload(args, kwargs, func: Optional[Callable] = None) -> dict:
    """
    Normalize arguments into a payload dict.

    - If func is provided, bind arguments to parameter names.
    - If first arg is a dict, treat it as the payload base.
    - Merge kwargs on top.
    - If args are non-dict, store them under 'args'.
    """
    if func is not None:
        try:
            sig = inspect.signature(func)
            bound = sig.bind(*args, **kwargs)
            bound.apply_defaults()
            return dict(bound.arguments)
        except Exception:
            pass

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
                if "args" in payload and len(payload) == 1:
                    output = await func(*payload["args"])
                else:
                    output = await func(**payload)
            else:
                if "args" in payload and len(payload) == 1:
                    output = func(*payload["args"])
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
            payload = _normalize_payload(args, kwargs, func=func)
            rid = run_id or kwargs.pop("run_id", None)
            return self.call(tool_name, payload, run_id=rid)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            payload = _normalize_payload(args, kwargs, func=func)
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


# ------------------------------------------------
# JSON-RPC 2.0 Stdio Stream Interceptor
# ------------------------------------------------

def run_stdio_mcp_proxy(
    cmd: Union[str, list],
    agent_id: str = "mcp-agent",
    ledger_path: Optional[str] = None,
) -> None:
    """
    Run a transparent stdio JSON-RPC reverse proxy in front of an MCP server.
    Intercepts and cryptographically signs all 'tools/call' requests and responses.
    """
    import subprocess
    import json
    import threading
    from guardclaw.core.crypto import Ed25519KeyManager
    from guardclaw.core.ledger import GEFLedger
    from guardclaw.core.models import RecordType

    key = Ed25519KeyManager.generate()
    lp = ledger_path or ".guardclaw"
    ledger = GEFLedger(key_manager=key, agent_id=agent_id, ledger_path=lp)

    proc_args = cmd if isinstance(cmd, list) else cmd.split()
    proc = subprocess.Popen(
        proc_args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )

    pending_calls: Dict[Any, Dict[str, Any]] = {}
    pending_lock = threading.Lock()

    def client_to_server():
        try:
            for line in sys.stdin:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    msg = json.loads(line_str)
                    if isinstance(msg, dict) and msg.get("method") == "tools/call":
                        req_id = msg.get("id")
                        params = msg.get("params", {})
                        tool_name = params.get("name", "unknown_tool")
                        args = params.get("arguments", {})

                        with pending_lock:
                            pending_calls[req_id] = {
                                "tool_name": tool_name,
                                "arguments": args,
                                "run_id": str(uuid.uuid4()),
                            }

                        ledger.emit(
                            record_type=RecordType.TOOL_CALL,
                            payload={
                                "tool": tool_name,
                                "arguments": args,
                                "request_id": str(req_id),
                                "event": "mcp_tool_intent",
                            },
                        )
                except Exception:
                    pass

                if proc.stdin:
                    proc.stdin.write(line)
                    proc.stdin.flush()
        except Exception:
            pass
        finally:
            if proc.stdin:
                try:
                    proc.stdin.close()
                except Exception:
                    pass

    def server_to_client():
        try:
            if proc.stdout:
                for line in proc.stdout:
                    line_str = line.strip()
                    if line_str:
                        try:
                            msg = json.loads(line_str)
                            if isinstance(msg, dict) and "id" in msg:
                                req_id = msg["id"]
                                with pending_lock:
                                    call_info = pending_calls.pop(req_id, None)

                                if call_info:
                                    tool_name = call_info["tool_name"]
                                    if "error" in msg:
                                        ledger.emit(
                                            record_type=RecordType.FAILURE,
                                            payload={
                                                "tool": tool_name,
                                                "error": msg["error"],
                                                "request_id": str(req_id),
                                                "event": "mcp_tool_error",
                                            },
                                        )
                                    else:
                                        ledger.emit(
                                            record_type=RecordType.TOOL_RESULT,
                                            payload={
                                                "tool": tool_name,
                                                "result": msg.get("result"),
                                                "request_id": str(req_id),
                                                "event": "mcp_tool_result",
                                            },
                                        )
                        except Exception:
                            pass

                    sys.stdout.write(line)
                    sys.stdout.flush()
        except Exception:
            pass

    t_client = threading.Thread(target=client_to_server, daemon=True)
    t_server = threading.Thread(target=server_to_client, daemon=True)

    t_client.start()
    t_server.start()

    proc.wait()
    t_server.join(timeout=1.0)

