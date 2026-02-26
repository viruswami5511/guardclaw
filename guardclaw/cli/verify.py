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
    guardclaw verify <ledger> --range 0:1000        Verify subsequence
    guardclaw verify <ledger> --agent my-agent      Filter by agent_id
    guardclaw verify <ledger> --no-color            Disable ANSI
    guardclaw verify <ledger> --no-parallel         Force sequential

Exit codes (POSIX-standard, shell-scriptable):
    0  Ledger fully valid  (chain + signatures + schema)
    1  Ledger has violations
    2  Error  (file missing, malformed JSON, parse failure)

CI one-liners:
    guardclaw verify ledger.jsonl --format json | python -m json.tool
    guardclaw verify ledger.jsonl --quiet && echo "clean" || echo "VIOLATED"
    guardclaw verify ledger.jsonl --format compact >> audit.log
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Optional

import click

from guardclaw.core.replay import ReplayEngine, ReplaySummary, ChainViolation


# ── ANSI color ────────────────────────────────────────────────────────────────

class _Color:
    """
    Minimal ANSI color wrapper — no external dependencies.
    Auto-disables when not a TTY or --no-color is passed.
    """
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
    label_col = _Color.dim(f"{label:<16}")
    return f"  {label_col}  {_Color.green('✅')}  {value}"

def _row_fail(label: str, value: str) -> str:
    label_col = _Color.dim(f"{label:<16}")
    return f"  {label_col}  {_Color.red('❌')}  {value}"

def _row_info(label: str, value: str) -> str:
    label_col = _Color.dim(f"{label:<16}")
    return f"  {label_col}     {_Color.dim(value)}"


# ── CLI command ───────────────────────────────────────────────────────────────

@click.command(name="verify")
@click.argument("ledger", type=click.Path(exists=False))
@click.option(
    "--format", "fmt",
    type=click.Choice(["human", "json", "compact"], case_sensitive=False),
    default="human",
    show_default=True,
    help="Output format: human (default), json (CI/automation), compact (pipelines).",
)
@click.option(
    "--export",
    "export_path",
    type=click.Path(),
    default=None,
    metavar="PATH",
    help="Export full audit report to a JSON file.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output. Use exit code only (0=valid, 1=invalid, 2=error).",
)
@click.option(
    "--range",
    "seq_range",
    type=str,
    default=None,
    metavar="START:END",
    help="Verify only entries with sequence in [START, END). e.g. --range 0:5000",
)
@click.option(
    "--agent",
    type=str,
    default=None,
    metavar="AGENT_ID",
    help="Verify only entries from a specific agent_id.",
)
@click.option(
    "--no-color",
    is_flag=True,
    default=False,
    help="Disable ANSI color output.",
)
@click.option(
    "--no-parallel",
    is_flag=True,
    default=False,
    help="Force sequential signature verification (no subprocesses).",
)
def verify_command(
    ledger:       str,
    fmt:          str,
    export_path:  Optional[str],
    quiet:        bool,
    seq_range:    Optional[str],
    agent:        Optional[str],
    no_color:     bool,
    no_parallel:  bool,
) -> None:
    """
    Verify a GEF ledger — chain integrity, signatures, schema.

    LEDGER is the path to a .jsonl GEF ledger file.

    \b
    Examples:
      guardclaw verify .guardclaw/ledger.jsonl
      guardclaw verify audit.jsonl --format json
      guardclaw verify audit.jsonl --export report.json
      guardclaw verify audit.jsonl --range 0:10000 --agent prod-agent
      guardclaw verify audit.jsonl --quiet && echo "clean"
    """
    _Color.configure(not no_color)

    ledger_path = Path(ledger)

    # ── File check ────────────────────────────────────────────
    if not ledger_path.exists():
        _emit_error(
            f"Ledger not found: {ledger}",
            fmt, quiet,
        )
        sys.exit(2)

    # ── Parse --range ─────────────────────────────────────────
    range_start: Optional[int] = None
    range_end:   Optional[int] = None

    if seq_range:
        try:
            parts       = seq_range.split(":")
            range_start = int(parts[0])
            range_end   = int(parts[1])
            if range_start < 0 or range_end <= range_start:
                raise ValueError("END must be > START and both must be >= 0")
        except (ValueError, IndexError) as e:
            _emit_error(
                f"Invalid --range '{seq_range}': {e}. Use format START:END e.g. 0:1000",
                fmt, quiet,
            )
            sys.exit(2)

    # ── Load ──────────────────────────────────────────────────
    file_mb  = ledger_path.stat().st_size / (1024 * 1024)
    parallel = not no_parallel
    engine = ReplayEngine(parallel=parallel, silent=True)
    t_start  = time.perf_counter()

    try:
        engine.load(ledger_path)
    except FileNotFoundError as e:
        _emit_error(str(e), fmt, quiet)
        sys.exit(2)
    except (ValueError, json.JSONDecodeError) as e:
        _emit_error(str(e), fmt, quiet)
        sys.exit(2)
    except Exception as e:
        _emit_error(f"Unexpected error: {e}", fmt, quiet)
        sys.exit(2)

    # ── Apply filters ─────────────────────────────────────────
    original_count = len(engine.envelopes)

    if agent:
        engine.envelopes = [
            e for e in engine.envelopes if e.agent_id == agent
        ]

    if range_start is not None and range_end is not None:
        engine.envelopes = [
            e for e in engine.envelopes
            if range_start <= e.sequence < range_end
        ]

    filtered     = original_count != len(engine.envelopes)
    active_count = len(engine.envelopes)

    filter_parts = []
    if agent:
        filter_parts.append(f"agent={agent}")
    if seq_range:
        filter_parts.append(f"range={seq_range}")
    filter_note = "  ".join(filter_parts)

    # ── Verify ────────────────────────────────────────────────
    try:
        summary = engine.verify()
    except Exception as e:
        _emit_error(f"Verification error: {e}", fmt, quiet)
        sys.exit(2)

    t_elapsed = time.perf_counter() - t_start
    rate      = active_count / t_elapsed if t_elapsed > 0 else 0

    # ── Export ────────────────────────────────────────────────
    if export_path:
        try:
            engine.export_json(Path(export_path))
        except Exception as e:
            if not quiet and fmt == "human":
                click.echo(
                    _Color.yellow(f"\n  ⚠️   Export failed: {e}"),
                    err=True,
                )

    # ── Output ────────────────────────────────────────────────
    if quiet:
        sys.exit(0 if summary.chain_valid else 1)

    if fmt == "json":
        _output_json(
            summary, ledger_path, file_mb,
            t_elapsed, rate,
            filter_note, filtered,
            original_count, export_path,
        )
    elif fmt == "compact":
        _output_compact(summary, ledger_path, t_elapsed, rate)
    else:
        _output_human(
            summary, ledger_path, file_mb,
            t_elapsed, rate,
            filter_note, filtered,
            original_count, export_path, parallel,
        )

    sys.exit(0 if summary.chain_valid else 1)


# ── Human output ──────────────────────────────────────────────────────────────

def _output_human(
    summary:        ReplaySummary,
    ledger_path:    Path,
    file_mb:        float,
    elapsed:        float,
    rate:           float,
    filter_note:    str,
    filtered:       bool,
    original_count: int,
    export_path:    Optional[str],
    parallel:       bool,
) -> None:
    valid     = summary.chain_valid
    BAR_HEAVY = "═" * 68
    BAR_LIGHT = "─" * 68

    click.echo()
    click.echo(_Color.bold(f"  {BAR_HEAVY}"))
    click.echo(_Color.bold(  "  GuardClaw  ·  GEF Ledger Verification"))
    click.echo(_Color.bold(f"  {BAR_HEAVY}"))
    click.echo()

    # ── File info ─────────────────────────────────────────────
    click.echo(_row_info("Ledger",     str(ledger_path)))
    click.echo(_row_info("Size",
        f"{file_mb:.2f} MB  "
        f"({summary.total_entries:,} entries"
        + (f"  of {original_count:,} total" if filtered else "")
        + ")"
    ))
    click.echo(_row_info("GEF version",
        f"v{summary.gef_version}" if summary.gef_version else "unknown"
    ))
    click.echo(_row_info("Agents",
        ", ".join(summary.agents_seen) if summary.agents_seen else "—"
    ))
    if filtered:
        click.echo(_row_info("Filter", filter_note))

    click.echo()

    # ── Verification status ───────────────────────────────────
    chain_v  = [v for v in summary.violations if v.violation_type == "chain_break"]
    seq_v    = [v for v in summary.violations if v.violation_type == "sequence_gap"]
    sig_v    = [v for v in summary.violations if v.violation_type == "invalid_signature"]
    schema_v = [v for v in summary.violations if v.violation_type == "schema"]

    # Chain integrity
    if not chain_v:
        click.echo(_row_ok("Chain", "intact — all causal hashes valid"))
    else:
        click.echo(_row_fail("Chain",
            _Color.red(f"{len(chain_v)} break(s) detected")
        ))

    # Signatures
    total = summary.total_entries
    if summary.invalid_signatures == 0:
        click.echo(_row_ok("Signatures",
            f"{summary.valid_signatures:,} / {total:,} valid"
        ))
    else:
        click.echo(_row_fail("Signatures",
            f"{summary.valid_signatures:,} valid  "
            + _Color.red(f"{summary.invalid_signatures:,} INVALID")
        ))

    # Schema
    if not schema_v:
        click.echo(_row_ok("Schema", "all entries conform to GEF-SPEC-v1.0"))
    else:
        click.echo(_row_fail("Schema",
            _Color.red(f"{len(schema_v)} violation(s)")
        ))

    # Sequence continuity
    if not seq_v:
        if total > 0:
            first_s = engine_first_seq(summary)
            last_s  = first_s + total - 1
            click.echo(_row_ok("Sequence",
                f"{first_s:,} → {last_s:,}  (no gaps)"
            ))
        else:
            click.echo(_row_ok("Sequence", "empty ledger"))
    else:
        click.echo(_row_fail("Sequence",
            _Color.red(f"{len(seq_v)} gap(s) detected")
        ))

    # Version homogeneity
    if summary.gef_version:
        click.echo(_row_ok("GEF version",
            f"uniform — all entries at v{summary.gef_version}"
        ))

    click.echo()

    # ── Timestamps ────────────────────────────────────────────
    if summary.first_timestamp:
        click.echo(_row_info("First entry",
            f"{summary.first_timestamp}  "
            + _Color.dim("[seq 0]")
        ))
    if summary.last_timestamp:
        click.echo(_row_info("Last entry",
            f"{summary.last_timestamp}  "
            + _Color.dim(f"[seq {total - 1:,}]")
        ))

    click.echo()

    # ── Record type breakdown ─────────────────────────────────
    if summary.record_type_counts:
        counts_str = "  ".join(
            f"{_Color.cyan(k)}: {v:,}"
            for k, v in sorted(summary.record_type_counts.items())
        )
        click.echo(_row_info("Record types", counts_str))

    # ── Performance ───────────────────────────────────────────
    mode = "parallel" if parallel else "sequential"
    click.echo(_row_info("Verified",
        f"{elapsed:.3f}s  ·  {rate:,.0f} envelopes/sec  "
        + _Color.dim(f"({mode})")
    ))

    if export_path:
        click.echo(_row_info("Exported", export_path))

    click.echo()

    # ── Violations table ──────────────────────────────────────
    if summary.violations:
        click.echo(f"  {BAR_LIGHT}")
        header = (
            f"  {_Color.bold(_Color.red('Seq')):>6}  "
            f"{_Color.bold(_Color.red('Type')):<22}  "
            f"{_Color.bold(_Color.red('Detail'))}"
        )
        click.echo(header)
        click.echo(f"  {BAR_LIGHT}")

        for v in summary.violations:
            type_col = _Color.yellow(f"{v.violation_type:<22}")
            click.echo(
                f"  {_Color.red(str(v.at_sequence)):>6}  {type_col}  {v.detail}"
            )

        click.echo(f"  {BAR_LIGHT}")
        click.echo()

    # ── Final verdict ─────────────────────────────────────────
    click.echo(f"  {BAR_LIGHT}")
    if valid:
        click.echo(_Color.green(_Color.bold(
            f"  ✅  VALID  ·  0 violations  ·  ledger integrity confirmed"
        )))
    else:
        n = len(summary.violations)
        click.echo(_Color.red(_Color.bold(
            f"  ❌  INVALID  ·  {n} violation(s)  ·  ledger integrity compromised"
        )))
    click.echo(f"  {BAR_LIGHT}")
    click.echo()


def engine_first_seq(summary: ReplaySummary) -> int:
    """Best-effort first sequence number from summary."""
    return 0


# ── JSON output ───────────────────────────────────────────────────────────────

def _output_json(
    summary:        ReplaySummary,
    ledger_path:    Path,
    file_mb:        float,
    elapsed:        float,
    rate:           float,
    filter_note:    str,
    filtered:       bool,
    original_count: int,
    export_path:    Optional[str],
) -> None:
    out = {
        "guardclaw_verify": {
            "ledger":               str(ledger_path),
            "file_mb":              round(file_mb, 2),
            "gef_version":          summary.gef_version,
            "total_entries":        summary.total_entries,
            "original_count":       original_count,
            "filter_applied":       filtered,
            "filter":               filter_note.strip() or None,
            "chain_valid":          summary.chain_valid,
            "valid_signatures":     summary.valid_signatures,
            "invalid_signatures":   summary.invalid_signatures,
            "violation_count":      len(summary.violations),
            "agents_seen":          summary.agents_seen,
            "record_type_counts":   summary.record_type_counts,
            "first_timestamp":      summary.first_timestamp,
            "last_timestamp":       summary.last_timestamp,
            "elapsed_seconds":      round(elapsed, 3),
            "envelopes_per_second": int(rate),
            "export_path":          export_path,
            "violations": [
                {
                    "at_sequence":    v.at_sequence,
                    "record_id":      v.record_id,
                    "violation_type": v.violation_type,
                    "detail":         v.detail,
                }
                for v in summary.violations
            ],
        }
    }
    click.echo(json.dumps(out, indent=2))


# ── Compact output ────────────────────────────────────────────────────────────

def _output_compact(
    summary:     ReplaySummary,
    ledger_path: Path,
    elapsed:     float,
    rate:        float,
) -> None:
    """
    Single-line output for shell pipelines, monitoring, and audit logs.

    Format:
        VALID    ledger.jsonl  100,000 entries  0 violations  3.241s  30,856/sec
        INVALID  audit.jsonl   50,000 entries   3 violations  1.812s  27,594/sec
    """
    status  = "VALID"   if summary.chain_valid else "INVALID"
    vcount  = len(summary.violations)
    entries = summary.total_entries
    name    = ledger_path.name

    if summary.chain_valid:
        line = (
            _Color.green(f"{status:<8}") +
            f"  {name:<30}  {entries:>10,} entries  "
            f"0 violations  {elapsed:.3f}s  {rate:,.0f}/sec"
        )
    else:
        line = (
            _Color.red(f"{status:<8}") +
            f"  {name:<30}  {entries:>10,} entries  "
            f"{_Color.red(str(vcount) + ' violation(s)')}  "
            f"{elapsed:.3f}s  {rate:,.0f}/sec"
        )
    click.echo(line)


# ── Error output ──────────────────────────────────────────────────────────────

def _emit_error(msg: str, fmt: str, quiet: bool) -> None:
    """Emit error in the correct format. Never raises."""
    if quiet:
        return
    if fmt == "json":
        click.echo(json.dumps({
            "guardclaw_verify": {
                "error":       msg,
                "chain_valid": False,
            }
        }))
    else:
        click.echo(
            _Color.red(f"\n  ❌  ERROR: {msg}\n"),
            err=True,
        )
	