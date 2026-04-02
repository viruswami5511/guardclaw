"""
guardclaw/cli/__init__.py

GuardClaw CLI entry point.

Commands:
    guardclaw verify   Verify a GEF ledger or .gcbundle
    guardclaw export   Export a GEF ledger as a .gcbundle evidence artifact
"""

import click

from guardclaw.cli.verify import verify_command
from guardclaw.cli.export import export_command


@click.group()
@click.version_option(package_name="guardclaw")
def cli() -> None:
    """GuardClaw — Cryptographic Evidence Ledger for AI Agent Accountability."""


cli.add_command(verify_command)
cli.add_command(export_command)