"""
guardclaw/cli/dossier.py

guardclaw dossier — Export Enterprise Compliance Dossier (EU AI Act & ISO 42001)
"""

from __future__ import annotations
from pathlib import Path
from typing import Optional
import click

from guardclaw.bundle.compliance import ComplianceDossierGenerator


@click.command(name="dossier")
@click.argument("ledger", type=click.Path(exists=True))
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    help="Output file path (e.g. compliance_dossier.html or compliance.json).",
)
@click.option(
    "--format", "fmt",
    type=click.Choice(["html", "json"], case_sensitive=False),
    default="html",
    show_default=True,
    help="Dossier format: self-contained HTML report or machine-readable JSON.",
)
def dossier_command(ledger: str, output: Optional[str], fmt: str) -> None:
    """
    Generate a certified EU AI Act Article 12 & ISO 42001 Compliance Dossier.
    """
    ledger_path = Path(ledger)
    out_path = Path(output) if output else ledger_path.parent / f"compliance_dossier.{fmt}"

    try:
        gen = ComplianceDossierGenerator(ledger_path)
        result_path = gen.export(out_path, format=fmt)
        status_msg = "✅ ALL INVARIANTS COMPLIANT" if gen.summary.chain_valid else "⚠️ CHAIN VIOLATIONS PRESENT"
        click.echo(f"\n{status_msg}")
        click.echo(f"Compliance Dossier Exported: {result_path}")
        if fmt == "html":
            click.echo(f"Open in browser: {result_path.resolve()}\n")
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc
