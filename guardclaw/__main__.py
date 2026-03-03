"""
guardclaw/__main__.py

Enables: python -m guardclaw

Delegates to the CLI entry point defined in guardclaw/cli/__init__.py.
Registered in pyproject.toml as: guardclaw = "guardclaw.cli:cli"
"""

from guardclaw.cli import cli

if __name__ == "__main__":
    cli()
