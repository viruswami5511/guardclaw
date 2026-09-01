"""
guardclaw/cli/daemon.py

guardclaw daemon — Out-of-Process Signing Service CLI
"""

from __future__ import annotations
from pathlib import Path
import click

from guardclaw.daemon.service import GuardClawDaemon
from guardclaw.daemon.client import DaemonClient


@click.group(name="daemon")
def daemon_group() -> None:
    """Manage the isolated GuardClaw Out-of-Process Signing Daemon."""


@daemon_group.command(name="start")
@click.option("--ledger-path", "-l", default=".guardclaw", show_default=True, help="Path to write the ledger.")
@click.option("--agent-id", default="daemon-agent", show_default=True, help="Agent ID.")
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind address.")
@click.option("--port", "-p", default=9443, show_default=True, help="Port.")
def start_daemon_command(ledger_path: str, agent_id: str, host: str, port: int) -> None:
    """Start the GuardClaw signing daemon server."""
    daemon = GuardClawDaemon(
        ledger_path=Path(ledger_path),
        agent_id=agent_id,
        host=host,
        port=port,
    )
    click.echo(f"\n🚀 GuardClaw Signing Daemon listening on tcp://{host}:{port}")
    click.echo(f"  Agent ID   : {agent_id}")
    click.echo(f"  Ledger Path: {ledger_path}")
    click.echo(f"  Public Key : {daemon.key_provider.public_key_hex}\n")
    try:
        daemon.start(blocking=True)
    except KeyboardInterrupt:
        click.echo("\nStopping GuardClaw Daemon...")
        daemon.stop()


@daemon_group.command(name="status")
@click.option("--host", default="127.0.0.1", show_default=True, help="Daemon host.")
@click.option("--port", "-p", default=9443, show_default=True, help="Daemon port.")
def status_daemon_command(host: str, port: int) -> None:
    """Check status of a running GuardClaw daemon."""
    try:
        with DaemonClient(host=host, port=port, timeout=2.0) as client:
            info = client.ping()
            click.echo(f"\n✅ GuardClaw Daemon Status: {info['status'].upper()}")
            click.echo(f"  Uptime     : {info['uptime']:.2f}s")
            click.echo(f"  Agent ID   : {info['agent_id']}")
            click.echo(f"  Entries    : {info['entry_count']}")
            click.echo(f"  Public Key : {info['signer_public_key']}\n")
    except Exception as exc:
        click.echo(f"\n❌ Could not connect to daemon at {host}:{port}: {exc}\n")
        raise SystemExit(1)
