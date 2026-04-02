"""
guardclaw/cli/export.py

guardclaw export — GEF Evidence Bundle CLI

Creates a .gcbundle folder from a .gef ledger.

Exit codes:
    0  Bundle created successfully
    1  Ledger is INVALID — bundle not created
    2  Error (file not found, parse failure, write error)
"""

import json
import sys
from pathlib import Path
from typing import Optional

import click

from guardclaw.bundle.exporter import GEFBundleExporter, BundleExportError


def _display_path(p: str) -> str:
    try:
        return str(Path(p).relative_to(Path.cwd()))
    except Exception:
        return p


@click.command(name="export")
@click.argument("ledger", type=click.Path(exists=True))
@click.option(
    "--output", "-o",
    type=click.Path(),
    default=None,
    metavar="PATH",
    help=(
        "Output path for the .gcbundle folder. "
        "Defaults to <ledger_stem>.gcbundle in the same directory. "
        "If PATH is an existing directory, the bundle is placed inside it."
    ),
)
@click.option(
    "--format", "fmt",
    type=click.Choice(["human", "json"], case_sensitive=False),
    default="human",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--quiet", "-q",
    is_flag=True,
    default=False,
    help="Suppress output. Use exit code only.",
)
@click.option(
    "--forensic",
    is_flag=True,
    default=False,
    help="Allow exporting a forensic bundle with only the verified prefix of a damaged ledger.",
)
def export_command(
    ledger: str,
    output: Optional[str],
    fmt: str,
    quiet: bool,
    forensic: bool,
) -> None:
    """
    Export a GEF ledger as a portable .gcbundle evidence artifact.

    By default, only fully valid ledgers are exported.
    Use --forensic to export a bundle containing only the cryptographically
    verified prefix of a damaged ledger.

    The bundle contains: ledger.gef, manifest.json, verification.json,
    public_key.json, report.html, and summary.json.

    \b
    Examples:
      guardclaw export .guardclaw/ledger.gef
      guardclaw export audit.gef --output case.gcbundle
      guardclaw export audit.gef --forensic --output case.gcbundle
      guardclaw export audit.gef --output ./evidence/ --format json
    """
    ledger_path = Path(ledger)
    output_path = Path(output) if output else None

    try:
        exporter = GEFBundleExporter(ledger_path=ledger_path)
        bundle_path = exporter.export(output=output_path, forensic=forensic)
    except FileNotFoundError as e:
        _emit_error(str(e), fmt, quiet)
        sys.exit(2)
    except BundleExportError as e:
        if not quiet:
            if fmt == "json":
                click.echo(json.dumps({
                    "guardclaw_export": {"success": False, "error": str(e)}
                }))
            else:
                click.echo(f"\n  ❌  EXPORT FAILED: {e}\n", err=True)
        sys.exit(1)
    except Exception as e:
        _emit_error(f"Unexpected error: {e}", fmt, quiet)
        sys.exit(2)

    if quiet:
        sys.exit(0)

    try:
        from guardclaw.bundle.models import BundleManifest, BundleVerification
        manifest = BundleManifest.from_path(bundle_path / "manifest.json")
        verification = BundleVerification.from_path(bundle_path / "verification.json")
    except Exception:
        manifest = None
        verification = None

    if fmt == "json":
        out = {
            "guardclaw_export": {
                "success": True,
                "bundle_path": str(bundle_path),
                "integrity_status": manifest.integrity_status if manifest else None,
                "entry_count": manifest.entry_count if manifest else None,
                "verified_entry_count": manifest.verified_entry_count if manifest else None,
                "total_entry_count": manifest.total_entry_count if manifest else None,
                "agent_id": manifest.agent_id if manifest else None,
                "ledger_sha256": manifest.ledger_sha256 if manifest else None,
                "ledger_size_bytes": manifest.ledger_size_bytes if manifest else None,
                "chain_head_hash": manifest.chain_head_hash if manifest else None,
                "chain_head_sequence": manifest.chain_head_sequence if manifest else None,
                "gef_bundle_version": manifest.gef_bundle_version if manifest else None,
                "failure_sequence": verification.failure_sequence if verification else None,
                "failure_type": verification.failure_type if verification else None,
                "integrity_boundary_hash": verification.integrity_boundary_hash if verification else None,
            }
        }
        click.echo(json.dumps(out, indent=2))
        sys.exit(0)

    dp = _display_path(str(bundle_path))
    click.echo()
    click.echo("  ══════════════════════════════════════════════════════════")
    click.echo("  GuardClaw  ·  GEF Evidence Bundle Export")
    click.echo("  ══════════════════════════════════════════════════════════")
    click.echo()

    if manifest and manifest.integrity_status == "PARTIAL":
        click.echo("  ⚠  PARTIAL INTEGRITY — FORENSIC BUNDLE CREATED")
    else:
        click.echo(f"  ✅  Bundle created: {dp}")
    click.echo()

    if manifest:
        click.echo(f"  {'Bundle path':<18}  {dp}")
        click.echo(f"  {'Integrity':<18}  {manifest.integrity_status}")
        click.echo(f"  {'Agent':<18}  {manifest.agent_id}")
        click.echo(f"  {'Entries':<18}  {manifest.entry_count:,}")
        click.echo(f"  {'Verified':<18}  {manifest.verified_entry_count:,}")
        click.echo(f"  {'Total seen':<18}  {manifest.total_entry_count:,}")
        click.echo(f"  {'Ledger SHA-256':<18}  {manifest.ledger_sha256[:32]}...")
        click.echo(f"  {'Size':<18}  {manifest.ledger_size_bytes:,} bytes")
        if manifest.chain_head_hash:
            short = manifest.chain_head_hash[:16] + "..." + manifest.chain_head_hash[-8:]
            click.echo(f"  {'Chain Head':<18}  {short}  [seq {manifest.chain_head_sequence}]")
        if manifest.first_entry_at:
            click.echo(f"  {'First entry':<18}  {manifest.first_entry_at}")
        if manifest.last_entry_at:
            click.echo(f"  {'Last entry':<18}  {manifest.last_entry_at}")

    if verification and manifest and manifest.integrity_status == "PARTIAL":
        click.echo(f"  {'Failure seq':<18}  {verification.failure_sequence}")
        click.echo(f"  {'Failure type':<18}  {verification.failure_type}")
        click.echo(f"  {'Boundary hash':<18}  {verification.integrity_boundary_hash}")
        click.echo("  This bundle contains only the cryptographically verified prefix.")
        if manifest.untrusted_ledger_file:
            click.echo(f"  {'Untrusted tail':<18}  {manifest.untrusted_ledger_file}")

    click.echo()
    click.echo("  Bundle contents:")
    file_names = [
        "ledger.gef",
        "manifest.json",
        "verification.json",
        "public_key.json",
        "summary.json",
        "report.html",
    ]
    if manifest and manifest.untrusted_ledger_file:
        file_names.append(manifest.untrusted_ledger_file)

    for f_name in file_names:
        fpath = bundle_path / f_name
        size = fpath.stat().st_size if fpath.exists() else 0
        click.echo(f"    {f_name:<26}  {size:>8,} bytes")

    click.echo()
    click.echo("  To verify:")
    click.echo(f"    guardclaw verify {dp}")
    click.echo()

    click.echo("  Share this bundle for independent verification:")
    click.echo(f"    guardclaw verify {dp}")
    click.echo("    pip install guardclaw")
    click.echo()

    sys.exit(0)


def _emit_error(msg: str, fmt: str, quiet: bool) -> None:
    if quiet:
        return
    if fmt == "json":
        click.echo(json.dumps({"guardclaw_export": {"success": False, "error": msg}}))
    else:
        click.echo(f"\n  ❌  ERROR: {msg}\n", err=True)