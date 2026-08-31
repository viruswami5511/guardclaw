"""
guardclaw/cli/mcp.py

guardclaw mcp-proxy — Universal Model Context Protocol (MCP) Audit Gateway
"""

from __future__ import annotations
from typing import Optional
import click

from guardclaw.mcp.proxy import run_stdio_mcp_proxy


@click.command(name="mcp-proxy")
@click.option(
    "--cmd",
    required=True,
    help="Command to launch the target MCP server (e.g. 'python server.py' or 'npx -y @mcp/server').",
)
@click.option(
    "--agent-id",
    default="mcp-agent",
    show_default=True,
    help="Agent identifier for ledger entries.",
)
@click.option(
    "--ledger-path",
    default=".guardclaw",
    show_default=True,
    help="Directory to write the cryptographic evidence ledger.",
)
def mcp_proxy_command(cmd: str, agent_id: str, ledger_path: str) -> None:
    """
    Run a transparent stdio JSON-RPC audit proxy in front of any MCP server.

    Intercepts all tool calls and responses, producing an Ed25519-signed,
    tamper-evident execution ledger with zero code modifications.
    """
    try:
        run_stdio_mcp_proxy(cmd=cmd, agent_id=agent_id, ledger_path=ledger_path)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
