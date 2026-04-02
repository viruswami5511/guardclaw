"""
guardclaw/cli.py  —  v0.7.0

EXIT CODES:
    0  chain valid
    1  violations found
    2  pre-flight failure (missing / empty ledger)
"""
from __future__ import annotations

import json
from pathlib import Path

import click

from guardclaw.bundle.exporter import GEFBundleExporter, BundleExportError
from guardclaw.core.failure import FailureType, VerificationSummary
from guardclaw.core.replay import ReplayEngine
from guardclaw.core.summary import build_summary_from_engine


@click.group()
@click.version_option()
def cli():
    """GuardClaw — Cryptographic Evidence Ledger for AI Agent Accountability."""


@cli.command()
@click.argument("ledger", type=click.Path(exists=False, path_type=Path))
@click.option("--format", "output_format",
              type=click.Choice(["text", "json"]), default="text", show_default=True)
@click.option("--recover", is_flag=True, default=False,
              help="Recovery mode: certify valid prefix, emit boundary hash.")
@click.option("--quiet", is_flag=True)
def verify(ledger: Path, output_format: str, recover: bool, quiet: bool):
    """Verify a GEF ledger — chain integrity, signatures, schema."""
    mode = "recovery" if recover else "strict"
    try:
        engine  = ReplayEngine(mode=mode, parallel=True, silent=(quiet or output_format == "json"))
        summary: VerificationSummary = engine.stream_verify(ledger)
    except Exception as exc:
        raise click.ClickException(str(exc)) from exc

    # Pre-flight failure
    if not summary.chain_valid and summary.failure_type == FailureType.LEDGER_INVALID:
        if output_format == "json":
            click.echo(json.dumps(summary.to_dict(), indent=2))
        else:
            click.echo(f"ERROR: {summary.failure_type} — {summary.failure_detail}")
            click.echo(f"Ledger: {ledger}")
        raise SystemExit(2)

    # JSON output
    if output_format == "json":
        out = summary.to_dict()
        try:
            legacy = build_summary_from_engine(engine, ledger)
            out["_legacy_violations"] = legacy.get("violations", [])
        except Exception:
            pass
        click.echo(json.dumps(out, indent=2))
        raise SystemExit(0 if summary.chain_valid else 1)

    # Text output
    if not recover:
        click.echo(f"Ledger      : {ledger}")
        click.echo(f"Mode        : strict")
        click.echo(f"Entries     : {summary.total_entries}")
        click.echo(f"Chain valid : {summary.chain_valid}")
        if summary.chain_valid:
            click.echo("Result      : ✅ ALL ENTRIES VERIFIED")
        else:
            click.echo("Result      : ❌ VERIFICATION FAILED")
            click.echo(f"Failure at  : line {summary.failure_sequence} (0-indexed)")
            click.echo(f"Type        : {summary.failure_type}")
            click.echo(f"Detail      : {summary.failure_detail}")
    else:
        bar = "=" * 72
        click.echo(f"\n{bar}\nGuardClaw — Recovery Mode Verification\n{bar}")
        click.echo(f"  Ledger       : {ledger}")
        click.echo(f"  Total entries: {summary.total_entries}")
        if summary.chain_valid:
            click.echo("  Chain valid  : ✅ YES — full ledger intact")
        else:
            click.echo("  Chain valid  : ❌ NO\n")
            if summary.partial_integrity:
                click.echo("  ✅ PARTIAL INTEGRITY CERTIFIED")
                click.echo(f"  Verified count     : {summary.verified_count} entries")
                click.echo(f"  Boundary sequence  : {summary.boundary_sequence}")
                click.echo(f"  Boundary hash      : {summary.integrity_boundary_hash}")
                click.echo(f"\n  Entries 0–{summary.boundary_sequence} are cryptographically certified.")
            else:
                click.echo("  ⚠️  NO VALID PREFIX — failure at line 0")
            click.echo(f"\n  ❌ FAILURE DETECTED")
            click.echo(f"  Failure line   : {summary.failure_sequence} (0-indexed)")
            click.echo(f"  Failure type   : {summary.failure_type}")
            click.echo(f"  Failure detail : {summary.failure_detail}")
        click.echo(f"{bar}\n")

    raise SystemExit(0 if summary.chain_valid else 1)


@cli.command()
@click.argument("ledger", type=click.Path(exists=True, path_type=Path))
@click.option("--output", type=click.Path(path_type=Path), default=None)
def export(ledger: Path, output: Path | None):
    """Export a GEF ledger as a portable .gcbundle evidence artifact."""
    try:
        bundle_path = GEFBundleExporter(ledger).export(output)
    except (BundleExportError, FileNotFoundError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"\n✅ Export complete: {bundle_path}\nOpen report: {bundle_path / 'report.html'}\n")