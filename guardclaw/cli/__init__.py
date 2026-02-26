"""
guardclaw/cli/__init__.py

GuardClaw CLI — root Click command group.

This file is the sole entry point for the `guardclaw` terminal command.
It is registered in pyproject.toml as:

    [project.scripts]
    guardclaw = "guardclaw.cli:cli"

Adding a new command:
    1. Create guardclaw/cli/your_command.py with a @click.command()
    2. Import it here
    3. cli.add_command(your_command)
    That's it. No other files change.
"""

import click

from guardclaw.cli.verify import verify_command


@click.group()
@click.version_option(package_name="guardclaw")
def cli() -> None:
    """
    GuardClaw — GEF Protocol CLI.

    \b
    Commands:
      verify    Verify a GEF ledger — chain, signatures, schema.

    \b
    Quick start:
      guardclaw verify .guardclaw/ledger.jsonl
      guardclaw verify audit.jsonl --format json
      guardclaw verify audit.jsonl --export report.json
      guardclaw verify audit.jsonl --quiet && echo "clean"
    """
    pass


cli.add_command(verify_command)
