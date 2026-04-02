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

from guardclaw.core.replay import ReplayEngine, ReplaySummary, ChainViolation
from guardclaw import canonical_json_encode


# ── GEF format detection (content-based, extension-agnostic) ─────────────────

def is_gef_format(data: dict) -> bool:
    """
    Detect whether a parsed JSONL entry is GEF-structured.
    Checks minimum required fields only — signature + causal_hash.
    """
    return "signature" in data and "causal_hash" in data


def _detect_ledger_format(ledger_path: Path) -> Tuple[bool, bool]:
    """
    Peek at the first non-empty line of the file and detect GEF format.

    Returns:
        (is_gef, is_recommended_ext)
    Never raises — returns (False, False) on any read/parse failure.
    """
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
    """
    Detect whether a path is a .gcbundle folder.
    Content-based: must be a directory containing ledger.gef + manifest.json.
    Extension (.gcbundle) is advisory, not required.
    """
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


# ── Head hash helper ──────────────────────────────────────────────────────────

def _compute_head_hash(engine: ReplayEngine) -> Tuple[Optional[str], Optional[int]]:
    """
    head_hash = hex(SHA-256(JCS(signing_surface(last_entry))))
    NOT last_entry.causal_hash — commits to current state, not previous.
    """
    if not engine.envelopes:
        return None, None
    try:
        last = engine.envelopes[-1]
        record_type = last.record_type
        if hasattr(record_type, "value"):
            record_type = record_type.value
        signing_surface = {
            "gef_version":       last.gef_version,
            "record_id":         last.record_id,
            "record_type":       record_type,
            "agent_id":          last.agent_id,
            "signer_public_key": last.signer_public_key,
            "sequence":          last.sequence,
            "nonce":             last.nonce,
            "timestamp":         last.timestamp,
            "causal_hash":       last.causal_hash,
            "payload":           last.payload,
        }
        canonical_bytes = canonical_json_encode(signing_surface)
        head_hash = hashlib.sha256(canonical_bytes).hexdigest()
        return head_hash, last.sequence
    except Exception:
        return None, None


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
@click.option(
    "--range", "seq_range",
    type=str, default=None, metavar="START:END",
    help="Verify only entries in [START, END).",
)
@click.option("--agent", type=str, default=None, metavar="AGENT_ID",
    help="Verify only entries from a specific agent_id.")
@click.option("--no-color", is_flag=True, default=False,
    help="Disable ANSI color output.")
@click.option("--no-parallel", is_flag=True, default=False,
    help="Force sequential signature verification.")
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
    # If path is a .gcbundle folder, redirect verify to inner ledger.gef.
    # Bundle metadata is shown as informational context in human output.
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

    # ── Parse --range ─────────────────────────────────────────
    range_start: Optional[int] = None
    range_end:   Optional[int] = None

    if seq_range:
        try:
            parts       = seq_range.split(":")
            range_start = int(parts[0])
            range_end   = int(parts[1])
            if range_start < 0 or range_end <= range_start:
                raise ValueError("END must be > START and both >= 0")
        except (ValueError, IndexError) as e:
            _emit_error(
                f"Invalid --range '{seq_range}': {e}. Use START:END e.g. 0:1000",
                fmt, quiet,
            )
            sys.exit(2)

    # ── Load ──────────────────────────────────────────────────
    file_mb  = ledger_path.stat().st_size / (1024 * 1024)
    parallel = not no_parallel
    engine   = ReplayEngine(parallel=parallel, silent=True)
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

    # ── Head hash BEFORE filtering ────────────────────────────
    head_hash, head_sequence = _compute_head_hash(engine)

    # ── Apply filters ─────────────────────────────────────────
    original_count = len(engine.envelopes)

    if agent:
        engine.envelopes = [e for e in engine.envelopes if e.agent_id == agent]

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
    ledger_valid = len(summary.violations) == 0

    # ── Export ────────────────────────────────────────────────
    if export_path:
        try:
            engine.export_json(Path(export_path))
        except Exception as e:
            if not quiet and fmt == "human":
                click.echo(_Color.yellow(f"\n  ⚠️   Export failed: {e}"), err=True)

    # ── Output ────────────────────────────────────────────────
    if quiet:
        sys.exit(0 if ledger_valid else 1)

    if fmt == "json":
        _output_json(
            summary, ledger_path, file_mb, t_elapsed, rate,
            filter_note, filtered, original_count, export_path,
            head_hash, head_sequence, ledger_valid, ext_warning,
        )
    elif fmt == "compact":
        _output_compact(summary, ledger_path, t_elapsed, rate, ledger_valid)
    else:
        _output_human(
            summary, ledger_path, file_mb, t_elapsed, rate,
            filter_note, filtered, original_count, export_path, parallel,
            head_hash, head_sequence, ledger_valid, ext_warning,
            bundle_mode, bundle_root,
        )

    sys.exit(0 if ledger_valid else 1)


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
    head_hash:      Optional[str],
    head_sequence:  Optional[int],
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

    # ── Bundle metadata (informational) ──────────────────────
    if bundle_mode and bundle_root is not None:
        try:
            from guardclaw.bundle.models import BundleManifest
            manifest = BundleManifest.from_path(bundle_root / "manifest.json")
            click.echo(_row_info("Bundle",   str(bundle_root)))
            click.echo(_row_info("Created",  manifest.created_at))
            click.echo(_row_info("SHA-256",  manifest.ledger_sha256[:32] + "..."))
            click.echo(_row_info("Size",     f"{manifest.ledger_size_bytes:,} bytes"))
            click.echo()
        except Exception:
            pass  # Bundle metadata is informational — never fail verify on it

    # ── File info ─────────────────────────────────────────────
    click.echo(_row_info("Ledger",
        str(ledger_path.name) if bundle_mode else str(ledger_path)
    ))
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
    if ext_warning:
        click.echo(_row_warn(
            "Extension",
            _Color.yellow(f"'{ledger_path.suffix}' — GEF content detected. "
                          f"Rename to .gef for identity signalling.")
        ))

    click.echo()

    # ── Verification status ───────────────────────────────────
    chain_v  = [v for v in summary.violations if v.violation_type == "chain_break"]
    seq_v    = [v for v in summary.violations if v.violation_type == "sequence_gap"]
    schema_v = [v for v in summary.violations if v.violation_type == "schema"]
    total    = summary.total_entries

    if not chain_v:
        click.echo(_row_ok("Chain", "intact — all causal hashes valid"))
    else:
        click.echo(_row_fail("Chain", _Color.red(f"{len(chain_v)} break(s) detected")))

    if summary.invalid_signatures == 0:
        click.echo(_row_ok("Signatures", f"{summary.valid_signatures:,} / {total:,} valid"))
    else:
        click.echo(_row_fail("Signatures",
            f"{summary.valid_signatures:,} valid  "
            + _Color.red(f"{summary.invalid_signatures:,} INVALID")
        ))

    if not schema_v:
        click.echo(_row_ok("Schema", "all entries conform to GEF-SPEC-v1.0"))
    else:
        click.echo(_row_fail("Schema", _Color.red(f"{len(schema_v)} violation(s)")))

    if not seq_v:
        if total > 0:
            click.echo(_row_ok("Sequence", f"0 → {total - 1:,}  (no gaps)"))
        else:
            click.echo(_row_ok("Sequence", "empty ledger"))
    else:
        click.echo(_row_fail("Sequence", _Color.red(f"{len(seq_v)} gap(s) detected")))

    if summary.gef_version:
        click.echo(_row_ok("GEF version",
            f"uniform — all entries at v{summary.gef_version}"
        ))

    click.echo()

    if summary.first_timestamp:
        click.echo(_row_info("First entry",
            f"{summary.first_timestamp}  " + _Color.dim("[seq 0]")
        ))
    if summary.last_timestamp:
        click.echo(_row_info("Last entry",
            f"{summary.last_timestamp}  " + _Color.dim(f"[seq {total - 1:,}]")
        ))

    if head_hash and head_sequence is not None:
        short = head_hash[:16] + "..." + head_hash[-8:]
        click.echo(_row_info("Chain Head",
            _Color.cyan(short) + _Color.dim(f"  [seq {head_sequence}]")
        ))
        click.echo(_row_info("",
            _Color.dim("hex(SHA-256(JCS(last_entry)))  ·  use for external anchoring")
        ))

    click.echo()

    if summary.record_type_counts:
        counts_str = "  ".join(
            f"{_Color.cyan(k)}: {v:,}"
            for k, v in sorted(summary.record_type_counts.items())
        )
        click.echo(_row_info("Record types", counts_str))

    mode = "parallel" if parallel else "sequential"
    click.echo(_row_info("Verified",
        f"{elapsed:.3f}s  ·  {rate:,.0f} envelopes/sec  "
        + _Color.dim(f"({mode})")
    ))

    if export_path:
        click.echo(_row_info("Exported", export_path))

    click.echo()

    if summary.violations:
        click.echo(f"  {BAR_LIGHT}")
        click.echo(
            f"  {_Color.bold(_Color.red('Seq')):>6}  "
            f"{_Color.bold(_Color.red('Type')):<22}  "
            f"{_Color.bold(_Color.red('Detail'))}"
        )
        click.echo(f"  {BAR_LIGHT}")
        for v in summary.violations:
            click.echo(
                f"  {_Color.red(str(v.at_sequence)):>6}  "
                f"{_Color.yellow(f'{v.violation_type:<22}')}  {v.detail}"
            )
        click.echo(f"  {BAR_LIGHT}")
        click.echo()

    click.echo(f"  {BAR_LIGHT}")
    if ledger_valid:
        click.echo(_Color.green(_Color.bold(
            "  ✅  VALID  ·  0 violations  ·  ledger integrity confirmed"
        )))
    else:
        n = len(summary.violations)
        click.echo(_Color.red(_Color.bold(
            f"  ❌  INVALID  ·  {n} violation(s)  ·  ledger integrity compromised"
        )))
    click.echo(f"  {BAR_LIGHT}")
    click.echo()


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
    head_hash:      Optional[str],
    head_sequence:  Optional[int],
    ledger_valid:   bool,
    ext_warning:    bool,
) -> None:
    out = {
        "guardclaw_verify": {
            "ledger":                 str(ledger_path),
            "file_mb":                round(file_mb, 2),
            "gef_version":            summary.gef_version,
            "total_entries":          summary.total_entries,
            "original_count":         original_count,
            "filter_applied":         filtered,
            "filter":                 filter_note.strip() or None,
            "ledger_valid":           ledger_valid,
            "chain_valid":            summary.chain_valid,
            "chain_head_hash":        head_hash,
            "chain_head_sequence":    head_sequence,
            "valid_signatures":       summary.valid_signatures,
            "invalid_signatures":     summary.invalid_signatures,
            "violation_count":        len(summary.violations),
            "agents_seen":            summary.agents_seen,
            "record_type_counts":     summary.record_type_counts,
            "first_timestamp":        summary.first_timestamp,
            "last_timestamp":         summary.last_timestamp,
            "elapsed_seconds":        round(elapsed, 3),
            "envelopes_per_second":   int(rate),
            "export_path":            export_path,
            "extension_advisory": (
                f"GEF content detected in '{ledger_path.suffix}' file. "
                f"Rename to .gef for identity signalling."
            ) if ext_warning else None,
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
    summary:      ReplaySummary,
    ledger_path:  Path,
    elapsed:      float,
    rate:         float,
    ledger_valid: bool,
) -> None:
    status  = "VALID"   if ledger_valid else "INVALID"
    vcount  = len(summary.violations)
    entries = summary.total_entries
    name    = ledger_path.name

    if ledger_valid:
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