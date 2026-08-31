"""
tests/test_mcp_proxy_live.py

Validates GuardClaw MCP Proxy tool wrapping, execution dispatch, schema generation,
and cryptographic evidence recording.
"""

import tempfile
from pathlib import Path

from guardclaw.mcp.proxy import GuardClawMCPProxy
from guardclaw.core.emitter import init_global_ledger
from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.replay import ReplayEngine


def test_mcp_proxy_tool_registration_and_execution():
    key = Ed25519KeyManager.generate()
    with tempfile.TemporaryDirectory() as td:
        init_global_ledger(key_manager=key, agent_id="mcp-test-agent", ledger_path=td)

        proxy = GuardClawMCPProxy(agent_id="mcp-test-agent")

        def add_numbers(a: int, b: int) -> int:
            """Add two numbers together."""
            return int(a) + int(b)

        proxy.register_tool("add_numbers", add_numbers, description="Adds two numbers")
        assert "add_numbers" in proxy.list_tools()

        schemas = proxy.get_tool_schemas()
        assert len(schemas) == 1
        assert schemas[0]["function"]["name"] == "add_numbers"

        # Dispatch call through proxy
        result = proxy.call("add_numbers", {"a": 10, "b": 32})
        assert result == 42

        # Verify emitted ledger
        ledger_file = Path(td) / "ledger.jsonl"
        summary = ReplayEngine(mode="strict", silent=True).stream_verify(ledger_file)
        assert summary.chain_valid is True
        assert summary.total_entries >= 2  # genesis + intent/result


def test_mcp_proxy_wrap_tool_decorator():
    key = Ed25519KeyManager.generate()
    with tempfile.TemporaryDirectory() as td:
        init_global_ledger(key_manager=key, agent_id="decorator-agent", ledger_path=td)
        proxy = GuardClawMCPProxy(agent_id="decorator-agent")

        @proxy.wrap_tool
        def multiply(x: int, y: int) -> int:
            return int(x) * int(y)

        res = multiply(6, 7)
        assert res == 42

        ledger_file = Path(td) / "ledger.jsonl"
        summary = ReplayEngine(mode="strict", silent=True).stream_verify(ledger_file)
        assert summary.chain_valid is True
