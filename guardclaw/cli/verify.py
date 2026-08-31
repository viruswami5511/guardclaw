"""
guardclaw/cli/verify.py

guardclaw verify — GEF Ledger Verification CLI
===============================================

The trust anchor for GEF ledgers. Usable by humans, CI systems,
auditors, and regulators.

Usage:
    guardclaw verify <ledger>                       Human output (default)
    guardclaw verify <ledger> --format json         Machine-readable JSON
    guardclaw verify <ledger> --format compact      One-line pipeline output
    guardclaw verify <ledger> --export report.json  Export full audit report
    guardclaw verify <ledger> --quiet               Exit code only
    guardclaw verify <ledger> --no-color            Disable ANSI

    guardclaw verify case.gcbundle                  Verify a .gcbundle folder

Exit codes (POSIX-standard, shell-scriptable):
    0  Ledger fully valid  (chain + signatures + schema)
    1  Ledger has violations
    2  Error  (file missing, malformed JSON, parse failure)

Extension note:
    .gef      is the recommended extension for GEF artifacts
    .jsonl    is also accepted — verification is content-based
    .gcbundle is a GuardClaw evidence bundle folder
"""

import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Optional, Tuple

import click

from guardclaw.core.replay import ReplayEngine
from guardclaw.core.failure import VerificationSummary
from guardclaw import canonical_json_encode


# ── GEF format detection (content-based, extension-agnostic) ─────────────────

def is_gef_format(data: dict) -> bool:
    return "signature" in data and "causal_hash" in data


def _detect_ledger_format(ledger_path: Path) -> Tuple[bool, bool]:
    is_recommended_ext = ledger_path.suffix.lower() == ".gef"
    try:
        with ledger_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                first_entry = json.loads(line)
                return is_gef_format(first_entry), is_recommended_ext
    except Exception:
        pass
    return False, is_recommended_ext


# ── Bundle detection ──────────────────────────────────────────────────────────

def _is_bundle(path: Path) -> bool:
    return (
        path.is_dir()
        and (path / "ledger.gef").exists()
        and (path / "manifest.json").exists()
    )


# ── ANSI color ────────────────────────────────────────────────────────────────

class _Color:
    _on: bool = True

    @classmethod
    def configure(cls, enabled: bool) -> None:
        cls._on = enabled and sys.stdout.isatty()

    @classmethod
    def green(cls, s: str) -> str:
        return f"\033[32m{s}\033[0m" if cls._on else s

    @classmethod
    def red(cls, s: str) -> str:
        return f"\033[31m{s}\033[0m" if cls._on else s

    @classmethod
    def yellow(cls, s: str) -> str:
        return f"\033[33m{s}\033[0m" if cls._on else s

    @classmethod
    def cyan(cls, s: str) -> str:
        return f"\033[36m{s}\033[0m" if cls._on else s

    @classmethod
    def bold(cls, s: str) -> str:
        return f"\033[1m{s}\033[0m" if cls._on else s

    @classmethod
    def dim(cls, s: str) -> str:
        return f"\033[2m{s}\033[0m" if cls._on else s


def _row_ok(label: str, value: str) -> str:
    return f"  {_Color.dim(f'{label:<16}')  }  {_Color.green('✅')}  {value}"

def _row_fail(label: str, value: str) -> str:
    return f"  {_Color.dim(f'{label:<16}')}  {_Color.red('❌')}  {value}"

def _row_info(label: str, value: str) -> str:
    return f"  {_Color.dim(f'{label:<16}')}     {_Color.dim(value)}"

def _row_warn(label: str, value: str) -> str:
    return f"  {_Color.dim(f'{label:<16}')}  {_Color.yellow('⚠️')}   {value}"


# ── CLI command ───────────────────────────────────────────────────────────────

@click.command(name="verify")
@click.argument("ledger", type=click.Path(exists=False))
@click.option(
    "--format", "fmt",
    type=click.Choice(["human", "json", "compact"], case_sensitive=False),
    default="human", show_default=True,
    help="Output format.",
)
@click.option(
    "--export", "export_path",
    type=click.Path(), default=None, metavar="PATH",
    help="Export full audit report to a JSON file.",
)
@click.option("--quiet", is_flag=True, default=False,
    help="Suppress all output. Use exit code only.")
@click.option("--no-color", is_flag=True, default=False,
    help="Disable ANSI color output.")
@click.option("--no-parallel", is_flag=True, default=False,
    help="Unused — kept for CLI backwards compatibility.")
def verify_command(
    ledger:       str,
    fmt:          str,
    export_path:  Optional[str],
    quiet:        bool,
    no_color:     bool,
    no_parallel:  bool,
) -> None:
    """
    Verify a GEF ledger — chain integrity, signatures, schema.

    LEDGER may be a .gef file, .jsonl file, or a .gcbundle folder.
    Verification is content-based — extension is not required to be .gef.

    \b
    Examples:
      guardclaw verify .guardclaw/ledger.gef
      guardclaw verify audit.gef --format json
      guardclaw verify case.gcbundle
      guardclaw verify audit.gef --quiet && echo "clean"
    """
    _Color.configure(not no_color)

    ledger_path = Path(ledger)

    # ── Bundle detection ──────────────────────────────────────
    bundle_mode = False
    bundle_root = None
    if ledger_path.exists() and _is_bundle(ledger_path):
        bundle_root = ledger_path
        ledger_path = ledger_path / "ledger.gef"
        bundle_mode = True

    # ── File check ────────────────────────────────────────────
    if not ledger_path.exists():
        _emit_error(f"Ledger not found: {ledger}", fmt, quiet)
        sys.exit(2)

    # ── Content-based GEF detection ───────────────────────────
    gef_detected, is_recommended_ext = _detect_ledger_format(ledger_path)
    ext_warning = gef_detected and not is_recommended_ext and not bundle_mode

    # ── Verify ────────────────────────────────────────────────
    file_mb = ledger_path.stat().st_size / (1024 * 1024)
    engine  = ReplayEngine(mode="strict", silent=True)
    t_start = time.perf_counter()

    summary: VerificationSummary = engine.stream_verify(ledger_path)

    t_elapsed = time.perf_counter() - t_start
    rate      = summary.total_entries / t_elapsed if t_elapsed > 0 else 0
    ledger_valid = summary.chain_valid

    # ── Export ────────────────────────────────────────────────
    if export_path:
        try:
            _export_report(summary, ledger_path, export_path)
        except Exception as e:
            if not quiet and fmt == "human":
                click.echo(_Color.yellow(f"\n  ⚠️   Export failed: {e}"), err=True)

    # ── Output ────────────────────────────────────────────────
    if quiet:
        sys.exit(0 if ledger_valid else 1)

    if fmt == "json":
        _output_json(
            summary, ledger_path, file_mb, t_elapsed, rate,
            export_path, ledger_valid, ext_warning,
        )
    elif fmt == "compact":
        _output_compact(summary, ledger_path, t_elapsed, rate, ledger_valid)
    else:
        _output_human(
            summary, ledger_path, file_mb, t_elapsed, rate,
            export_path, ledger_valid, ext_warning,
            bundle_mode, bundle_root,
        )

    sys.exit(0 if ledger_valid else 1)


# ── Export helper ─────────────────────────────────────────────────────────────

def _export_report(
    summary:      VerificationSummary,
    ledger_path:  Path,
    export_path:  str,
) -> None:
    out_path = Path(export_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "gef_replay_report": {
            "version":          "1.0",
            "ledger":           str(ledger_path),
            **summary.to_dict(),
        }
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


# ── Human output ──────────────────────────────────────────────────────────────

def _output_human(
    summary:        VerificationSummary,
    ledger_path:    Path,
    file_mb:        float,
    elapsed:        float,
    rate:           float,
    export_path:    Optional[str],
    ledger_valid:   bool,
    ext_warning:    bool,
    bundle_mode:    bool = False,
    bundle_root:    Optional[Path] = None,
) -> None:
    BAR_HEAVY = "═" * 68
    BAR_LIGHT = "─" * 68

    click.echo()
    click.echo(_Color.bold(f"  {BAR_HEAVY}"))
    click.echo(_Color.bold(  "  GuardClaw  ·  GEF Ledger Verification"))
    click.echo(_Color.bold(f"  {BAR_HEAVY}"))
    click.echo()

    # ── Bundle metadata ───────────────────────────────────────
    if bundle_mode and bundle_root is not None:
        try:
            from guardclaw.bundle.models import BundleManifest
            manifest = BundleManifest.from_path(bundle_root / "manifest.json")
            click.echo(_row_info("Bundle",  str(bundle_root)))
            click.echo(_row_info("Created", manifest.created_at))
            click.echo(_row_info("SHA-256", manifest.ledger_sha256[:32] + "..."))
            click.echo(_row_info("Size",    f"{manifest.ledger_size_bytes:,} bytes"))
            click.echo()
        except Exception:
            pass

    # ── File info ─────────────────────────────────────────────
    click.echo(_row_info("Ledger",
        str(ledger_path.name) if bundle_mode else str(ledger_path)
    ))
    click.echo(_row_info("Size",
        f"{file_mb:.2f} MB  ({summary.total_entries:,} entries)"
    ))

    if ext_warning:
        click.echo(_row_warn(
            "Extension",
            _Color.yellow(
                f"'{ledger_path.suffix}' — GEF content detected. "
                f"Rename to .gef for identity signalling."
            )
        ))

    click.echo()

    # ── Verification level banner ─────────────────────────────
    level = summary.verification_level
    if level == "FULLY_VALID":
        click.echo(_row_ok("Status", _Color.green("FULLY_VALID — complete chain verified")))
    elif level == "FULLY_VALID_INTERRUPTED":
        click.echo(_row_warn("Status", _Color.yellow("FULLY_VALID_INTERRUPTED — clean terminal state")))
    elif level == "PARTIALLY_VALID":
        click.echo(_row_warn("Status", _Color.yellow(f"PARTIALLY_VALID — trusted prefix: {summary.verified_count} entries")))
    elif level == "EMPTY":
        click.echo(_row_warn("Status", "EMPTY — no entries found"))
    else:
        click.echo(_row_fail("Status", _Color.red("INVALID — chain integrity compromised")))

    click.echo()

    # ── Verification checks ───────────────────────────────────
    total = summary.total_entries

    if summary.chain_valid:
        click.echo(_row_ok("Chain", "intact — all causal hashes valid"))
    else:
        click.echo(_row_fail("Chain", _Color.red(
            f"violation at line {summary.failure_sequence}  "
            f"[{summary.failure_type}]"
        )))

    if summary.invalid_signatures == 0:
        click.echo(_row_ok("Signatures", f"{summary.valid_signatures:,} / {total:,} valid"))
    else:
        click.echo(_row_fail("Signatures",
            f"{summary.valid_signatures:,} valid  "
            + _Color.red(f"{summary.invalid_signatures:,} INVALID")
        ))

    if summary.chain_valid:
        click.echo(_row_ok("Schema", "all entries conform to GEF-SPEC-v1.0"))
    elif summary.failure_type == "schema_violation":
        click.echo(_row_fail("Schema",
            _Color.red(f"{summary.failure_detail}  at line {summary.failure_sequence}")
        ))
    else:
        click.echo(_row_ok("Schema", "no schema violations detected"))

    if summary.chain_valid and total > 0:
        click.echo(_row_ok("Sequence", f"0 → {summary.verified_count - 1:,}  (no gaps)"))
    elif summary.failure_type == "chain_violation" and summary.failure_detail == "sequence_gap":
        click.echo(_row_fail("Sequence",
            _Color.red(f"gap at line {summary.failure_sequence}")
        ))
    elif total == 0:
        click.echo(_row_ok("Sequence", "empty ledger"))
    else:
        click.echo(_row_ok("Sequence", f"verified {summary.verified_count:,} entries"))

    click.echo()

    # ── Failure detail block ──────────────────────────────────
    if not summary.chain_valid:
        BAR = "─" * 68
        click.echo(f"  {BAR}")
        click.echo(
            f"  {_Color.bold(_Color.red('Failure Detail'))}"
        )
        click.echo(f"  {BAR}")
        click.echo(f"  {'Type':<18}  {_Color.red(summary.failure_type or '—')}")
        click.echo(f"  {'Detail':<18}  {_Color.yellow(summary.failure_detail or '—')}")
        click.echo(f"  {'At line':<18}  {summary.failure_sequence if summary.failure_sequence is not None else '—'}")
        click.echo(f"  {'Verified up to':<18}  {summary.verified_count:,} entries")
        if summary.integrity_boundary_hash:
            short = summary.integrity_boundary_hash[:16] + "..." + summary.integrity_boundary_hash[-8:]
            click.echo(f"  {'Boundary hash':<18}  {_Color.cyan(short)}")
        click.echo(f"  {BAR}")
        click.echo()

    # ── Timing ────────────────────────────────────────────────
    click.echo(_row_info("Verified",
        f"{elapsed:.3f}s  ·  {rate:,.0f} envelopes/sec"
    ))

    if export_path:
        click.echo(_row_info("Exported", export_path))

    click.echo()

    # ── Final verdict ─────────────────────────────────────────
    click.echo(f"  {BAR_LIGHT}")
    if ledger_valid:
        click.echo(_Color.green(_Color.bold(
            "  ✅  VALID  ·  0 violations  ·  ledger integrity confirmed"
        )))
    else:
        click.echo(_Color.red(_Color.bold(
            f"  ❌  INVALID  ·  {summary.failure_type}:{summary.failure_detail}"
            f"  ·  at line {summary.failure_sequence}"
        )))
    click.echo(f"  {BAR_LIGHT}")
    click.echo()


# ── JSON output ───────────────────────────────────────────────────────────────

def _output_json(
    summary:        VerificationSummary,
    ledger_path:    Path,
    file_mb:        float,
    elapsed:        float,
    rate:           float,
    export_path:    Optional[str],
    ledger_valid:   bool,
    ext_warning:    bool,
) -> None:
    out = {
        "guardclaw_verify": {
            "ledger":               str(ledger_path),
            "file_mb":              round(file_mb, 2),
            "elapsed_seconds":      round(elapsed, 3),
            "envelopes_per_second": int(rate),
            "export_path":          export_path,
            "extension_advisory": (
                f"GEF content detected in '{ledger_path.suffix}' file. "
                f"Rename to .gef for identity signalling."
            ) if ext_warning else None,
            **summary.to_dict(),
        }
    }
    click.echo(json.dumps(out, indent=2))


# ── Compact output ────────────────────────────────────────────────────────────

def _output_compact(
    summary:      VerificationSummary,
    ledger_path:  Path,
    elapsed:      float,
    rate:         float,
    ledger_valid: bool,
) -> None:
    status  = "VALID"   if ledger_valid else "INVALID"
    entries = summary.total_entries
    name    = ledger_path.name

    if ledger_valid:
        line = (
            _Color.green(f"{status:<8}") +
            f"  {name:<30}  {entries:>10,} entries  "
            f"0 violations  {elapsed:.3f}s  {rate:,.0f}/sec"
        )
    else:
        detail = f"{summary.failure_type}:{summary.failure_detail}"
        line = (
            _Color.red(f"{status:<8}") +
            f"  {name:<30}  {entries:>10,} entries  "
            f"{_Color.red(detail)}  "
            f"line {summary.failure_sequence}  "
            f"{elapsed:.3f}s  {rate:,.0f}/sec"
        )
    click.echo(line)


# ── Error output ──────────────────────────────────────────────────────────────

def _emit_error(msg: str, fmt: str, quiet: bool) -> None:
    if quiet:
        return
    if fmt == "json":
        click.echo(json.dumps({
            "guardclaw_verify": {
                "error":        msg,
                "chain_valid":  False,
                "ledger_valid": False,
            }
        }))
    else:
        click.echo(_Color.red(f"\n  ❌  ERROR: {msg}\n"), err=True)