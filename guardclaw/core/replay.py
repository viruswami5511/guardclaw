"""
guardclaw/core/replay.py

GEF Replay Engine — v0.2.0
Aligned to: GEF-SPEC-v1.0

Protocol Laws enforced here:
    1. Load    → ExecutionEnvelope.from_dict(line)  — no other deserialization
    2. Schema  → env.validate_schema()              — fail fast, no silent pass
    3. Chain   → env.verify_chain(prev)             — sequential (causal dependency)
    4. Sig     → env.verify_signature()             — parallel (independent per entry)
    5. Version → all envelopes must share gef_version (GEFVersionError if not)
    6. Nonce   → no two envelopes in a ledger may share a nonce (INV-29)

Performance architecture — TWO PHASES:
    Phase 1 (sequential): Chain + sequence + nonce uniqueness verification.
        MUST be sequential — each entry's causal_hash depends on the previous.
        Speed: ~50k/sec (hash comparison, no crypto)

    Phase 2 (parallel): Signature verification.
        EMBARRASSINGLY PARALLEL — each signature is independent.
        Uses ProcessPoolExecutor. Falls back to sequential on any error.
        Speed: N × 4,500/sec where N = CPU cores

    Target throughput with 4 cores:  ~12,000 envelopes/sec
    Target throughput with 8 cores:  ~25,000 envelopes/sec
    Python single-thread ceiling:     ~2,950 envelopes/sec (Ed25519 bound)
    Go/Rust implementation target:  ~200,000 envelopes/sec

silent mode:
    ReplayEngine(silent=True)  — suppresses the "✅ Loaded N envelopes" print.
    Used by the CLI (guardclaw verify) for clean formatted output.
    Tests and scripts use silent=False (default) to see load confirmation.

No custom dataclasses that mirror ExecutionEnvelope fields.
No local chain hash computation.
No local canonicalization.
No alternate field mapping.
"""

import json
import os
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from guardclaw.core.models import (
    ExecutionEnvelope,
    GEFVersionError,
    GEF_VERSION,
    SchemaValidationResult,
)


# ─────────────────────────────────────────────────────────────
# Module-level worker function
# MUST be at top level for ProcessPoolExecutor pickling.
# Inner functions and lambdas cannot be pickled on Windows.
# ─────────────────────────────────────────────────────────────

def _verify_sig_batch(
    batch: List[Tuple[Dict[str, Any], Optional[str], str, int]]
) -> List[Tuple[int, bool]]:
    """
    Verify a batch of envelope signatures in a subprocess.

    Module-level placement is required for ProcessPoolExecutor pickling.
    Do NOT move inside a class or function.

    Args:
        batch: List of (signing_dict, signature, pubkey_hex, sequence)
               All primitive/dict types — pickable across process boundaries.

    Returns:
        List of (sequence, is_valid)
    """
    from guardclaw.core.canonical import canonical_json_encode
    from guardclaw.core.crypto import Ed25519KeyManager

    results: List[Tuple[int, bool]] = []

    for signing_dict, signature, pubkey_hex, sequence in batch:
        if not signature:
            results.append((sequence, False))
            continue
        data = canonical_json_encode(signing_dict)
        ok   = Ed25519KeyManager.verify_detached(data, signature, pubkey_hex)
        results.append((sequence, ok))

    return results


# ─────────────────────────────────────────────────────────────
# Tuning constants
# ─────────────────────────────────────────────────────────────

# Only use parallel verification above this count.
# Below this, process spawn overhead exceeds the crypto speedup.
_PARALLEL_THRESHOLD = 2_000

# Batches per worker × CPU count = total batches.
# Too small: IPC overhead dominates. Too large: poor load balancing.
_BATCH_SIZE_PER_WORKER_MULTIPLIER = 4


# ─────────────────────────────────────────────────────────────
# Result / Summary Types
# ─────────────────────────────────────────────────────────────

@dataclass
class ChainViolation:
    """A single detected violation in the ledger."""
    at_sequence:    int
    record_id:      str
    violation_type: str   # "schema" | "chain_break" | "invalid_signature" | "sequence_gap"
    detail:         str


@dataclass
class ReplaySummary:
    """Aggregate result of a full ledger verification pass."""
    total_entries:      int
    chain_valid:        bool
    violations:         List[ChainViolation]
    valid_signatures:   int
    invalid_signatures: int
    record_type_counts: Dict[str, int]
    agents_seen:        List[str]
    gef_version:        Optional[str]
    first_timestamp:    Optional[str]
    last_timestamp:     Optional[str]


# ─────────────────────────────────────────────────────────────
# Replay Engine
# ─────────────────────────────────────────────────────────────

class ReplayEngine:
    """
    GEF-native replay engine with parallel signature verification.

    Usage:
        engine = ReplayEngine()
        engine.load(Path(".guardclaw/ledger.jsonl"))
        summary = engine.verify()
        engine.print_timeline()
        engine.export_json(Path("replay_out.json"))

    Parallel mode (default):
        Signature verification is parallelized using ProcessPoolExecutor.
        Chain/sequence verification remains sequential (causal dependency).

    Disable parallel:
        engine = ReplayEngine(parallel=False)

    Silent mode (for CLI use):
        engine = ReplayEngine(silent=True)
        Suppresses the "✅ Loaded N envelopes" confirmation print.
        Use this in guardclaw verify to keep formatted output clean.
        Tests and scripts should use silent=False (default).

    Internal state:
        self.envelopes  — List[ExecutionEnvelope], sorted by sequence
        self.violations — populated by verify()

    ALL verification logic delegates to ExecutionEnvelope methods.
    This file contains ZERO chain hash computation.
    This file contains ZERO canonicalization.
    """

    def __init__(self, parallel: bool = True, silent: bool = False):
        self.envelopes:    List[ExecutionEnvelope] = []
        self.violations:   List[ChainViolation]    = []
        self._ledger_path: Optional[Path]          = None
        self._parallel:    bool                    = parallel
        self._silent:      bool                    = silent

    # ── Load ──────────────────────────────────────────────────

    def load(self, ledger_path: Path) -> None:
        """
        Load a GEF ledger JSONL file.

        Each line is processed as:
            1. json.loads(line)
            2. ExecutionEnvelope.from_dict(data)   — THE ONLY deserialization path
            3. env.validate_schema()               — fail fast on schema violation

        After loading all lines:
            4. Sort by sequence
            5. Enforce gef_version homogeneity     — GEFVersionError if mixed

        Raises:
            FileNotFoundError — ledger file does not exist
            ValueError        — malformed JSON or schema violation
            GEFVersionError   — mixed gef_version values in one ledger
        """
        ledger_path       = Path(ledger_path)
        self._ledger_path = ledger_path
        self.envelopes    = []
        self.violations   = []

        if not ledger_path.exists():
            raise FileNotFoundError(f"GEF ledger not found: {ledger_path}")

        with open(ledger_path, "r", encoding="utf-8") as f:
            for line_num, raw in enumerate(f, 1):
                raw = raw.strip()
                if not raw:
                    continue

                # Step 1 — JSON parse
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError as e:
                    raise ValueError(
                        f"Malformed JSON at ledger line {line_num}: {e}"
                    ) from e

                # Step 2 — Deserialize via THE ONLY path
                try:
                    env = ExecutionEnvelope.from_dict(data)
                except KeyError as e:
                    raise ValueError(
                        f"Missing required GEF field at line {line_num}: {e}"
                    ) from e

                # Step 3 — Schema validation: fail fast
                schema = env.validate_schema()
                if not schema:
                    raise ValueError(
                        f"GEF schema violation at line {line_num} "
                        f"(record_id={data.get('record_id', '?')}): "
                        f"{schema.errors}"
                    )

                self.envelopes.append(env)

        # Step 4 — Sort by sequence (ledger should already be ordered; be safe)
        self.envelopes.sort(key=lambda e: e.sequence)

        # Step 5 — Enforce version homogeneity (CONTRACT 6)
        if self.envelopes:
            versions = {e.gef_version for e in self.envelopes}
            if len(versions) > 1:
                raise GEFVersionError(
                    f"Ledger '{ledger_path.name}' contains mixed gef_version "
                    f"values: {sorted(versions)}. All envelopes in a single "
                    f"ledger must share identical gef_version."
                )

        # Confirmation print — suppressed in CLI (silent=True), shown in tests
        if not self._silent:
            print(
                f"✅  Loaded {len(self.envelopes)} GEF envelopes "
                f"from '{ledger_path.name}'"
            )

    # ── Verify — Two-Phase ────────────────────────────────────

    def verify(self) -> ReplaySummary:
        """
        Full verification pass over all loaded envelopes.

        TWO PHASES:

        Phase 1 — Sequential (chain + sequence + nonce uniqueness):
            Must be sequential — causal_hash depends on the previous entry.
            Per entry:
                1. verify_sequence(i)     — monotonic gap check
                2. env.verify_chain(prev) — causal_hash integrity
                3. nonce uniqueness       — INV-29: no two entries share a nonce

        Phase 2 — Parallel (signature verification):
            Signatures are independent — embarrassingly parallel.
            Uses ProcessPoolExecutor with batching.
            Falls back to sequential on any error.

        Returns ReplaySummary with full violation list.
        """
        self.violations = []

        if not self.envelopes:
            return self._empty_summary()

        # ── Phase 1: Sequential chain + sequence + nonce ──────
        chain_violations: List[ChainViolation] = []
        seen_nonces:      Set[str]             = set()   # INV-29 enforcement

        for i, env in enumerate(self.envelopes):
            prev = self.envelopes[i - 1] if i > 0 else None

            # ── 1a. Sequence gap check ─────────────────────────
            if not env.verify_sequence(i):
                chain_violations.append(ChainViolation(
                    at_sequence=    i,
                    record_id=      env.record_id,
                    violation_type= "sequence_gap",
                    detail=(
                        f"Expected sequence {i}, got {env.sequence}"
                    ),
                ))

            # ── 1b. Causal hash integrity ──────────────────────
            if not env.verify_chain(prev):
                expected = env.expected_causal_hash_from(prev)
                chain_violations.append(ChainViolation(
                    at_sequence=    env.sequence,
                    record_id=      env.record_id,
                    violation_type= "chain_break",
                    detail=(
                        f"causal_hash mismatch: "
                        f"expected ...{expected[-12:]}, "
                        f"got ...{env.causal_hash[-12:]}"
                    ),
                ))

            # ── 1c. Nonce uniqueness (INV-29) ──────────────────
            if env.nonce in seen_nonces:
                chain_violations.append(ChainViolation(
                    at_sequence=    env.sequence,
                    record_id=      env.record_id,
                    violation_type= "schema",
                    detail=(
                        f"Duplicate nonce '{env.nonce}' at sequence "
                        f"{env.sequence} — nonces MUST be unique per "
                        f"ledger (GEF-SPEC-1.0 INV-29)"
                    ),
                ))
            seen_nonces.add(env.nonce)
            # ── end INV-29 ─────────────────────────────────────

        # ── Phase 2: Parallel signature verification ──────────
        use_parallel = (
            self._parallel
            and len(self.envelopes) >= _PARALLEL_THRESHOLD
        )

        if use_parallel:
            sig_results = self._verify_signatures_parallel()
        else:
            sig_results = self._verify_signatures_sequential()

        # ── Combine violations ────────────────────────────────
        sig_violations: List[ChainViolation] = []
        valid_sigs   = 0
        invalid_sigs = 0

        for env in self.envelopes:
            ok = sig_results.get(env.sequence, False)
            if ok:
                valid_sigs += 1
            else:
                invalid_sigs += 1
                sig_violations.append(ChainViolation(
                    at_sequence=    env.sequence,
                    record_id=      env.record_id,
                    violation_type= "invalid_signature",
                    detail=(
                        f"Signature invalid "
                        f"(signer: {env.signer_public_key[:16]}...)"
                    ),
                ))

        self.violations = chain_violations + sig_violations

        counts: Dict[str, int] = defaultdict(int)
        for env in self.envelopes:
            counts[env.record_type] += 1

        return ReplaySummary(
            total_entries=      len(self.envelopes),
            chain_valid=        len(self.violations) == 0,
            violations=         list(self.violations),
            valid_signatures=   valid_sigs,
            invalid_signatures= invalid_sigs,
            record_type_counts= dict(counts),
            agents_seen=        sorted({e.agent_id for e in self.envelopes}),
            gef_version=        self.envelopes[0].gef_version,
            first_timestamp=    self.envelopes[0].timestamp,
            last_timestamp=     self.envelopes[-1].timestamp,
        )

    # ── Parallel Signature Verification ──────────────────────

    def _verify_signatures_parallel(self) -> Dict[int, bool]:
        """
        Verify all signatures in parallel using ProcessPoolExecutor.

        Strategy:
            Split envelopes into batches.
            Each subprocess receives a batch of (signing_dict, sig, pubkey, seq).
            Only pickable primitives — no ExecutionEnvelope objects cross the
            process boundary.

        Falls back to _verify_signatures_sequential() on ANY error:
            Windows spawn issues, pickle failures, OS resource limits.

        Returns:
            dict mapping sequence → is_valid
        """
        n_workers  = min(os.cpu_count() or 4, 8)
        batch_size = max(
            500,
            len(self.envelopes) // (n_workers * _BATCH_SIZE_PER_WORKER_MULTIPLIER),
        )

        all_data: List[Tuple[Dict, Optional[str], str, int]] = [
            (
                env.to_signing_dict(),
                env.signature,
                env.signer_public_key,
                env.sequence,
            )
            for env in self.envelopes
        ]

        batches = [
            all_data[i : i + batch_size]
            for i in range(0, len(all_data), batch_size)
        ]

        results: Dict[int, bool] = {}

        try:
            with ProcessPoolExecutor(max_workers=n_workers) as executor:
                for batch_result in executor.map(_verify_sig_batch, batches):
                    for seq, ok in batch_result:
                        results[seq] = ok

        except Exception:
            # Parallel failed — fall back to sequential silently.
            results = self._verify_signatures_sequential()

        return results

    def _verify_signatures_sequential(self) -> Dict[int, bool]:
        """
        Sequential signature verification — fallback and small-ledger path.
        """
        return {
            env.sequence: env.verify_signature()
            for env in self.envelopes
        }

    # ── Print Timeline ────────────────────────────────────────

    def print_timeline(self, max_entries: Optional[int] = None) -> None:
        """
        Pretty-print a human-readable timeline to stdout.

        Calls verify() internally. Does not modify engine state.

        Args:
            max_entries: If set, only the first N entries are shown.
                         Summary stats always reflect the full ledger.
        """
        if not self.envelopes:
            print("⚠️   No GEF envelopes loaded.")
            return

        summary = self.verify()
        bar     = "=" * 80

        print(f"\n{bar}")
        print("📋  GuardClaw GEF Replay Timeline")
        print(bar)
        print(f"  Ledger      : {self._ledger_path or 'in-memory'}")
        print(f"  GEF Version : {summary.gef_version}")
        print(f"  Entries     : {summary.total_entries:,}")
        print(f"  Chain       : {'✅ VALID' if summary.chain_valid else '❌ VIOLATED'}")
        print(f"  Valid sigs  : {summary.valid_signatures:,}")
        print(f"  Invalid sigs: {summary.invalid_signatures:,}")
        print(f"  Agents      : {', '.join(summary.agents_seen)}")
        print(f"  First entry : {summary.first_timestamp}")
        print(f"  Last entry  : {summary.last_timestamp}")
        print()

        to_show = (
            self.envelopes[:max_entries] if max_entries else self.envelopes
        )

        for env in to_show:
            prev       = self.envelopes[env.sequence - 1] if env.sequence > 0 else None
            sig_icon   = "✅" if env.verify_signature()  else "❌"
            chain_icon = "🔗" if env.verify_chain(prev) else "⛓️‍💥"

            print(f"  [{env.sequence:04d}] {env.timestamp}  {env.record_type}")
            print(f"         record_id   : {env.record_id}")
            print(f"         agent_id    : {env.agent_id}")
            print(f"         nonce       : {env.nonce[:16]}...")
            print(f"         causal_hash : ...{env.causal_hash[-12:]}")
            print(f"         sig {sig_icon}  chain {chain_icon}")
            print()

        if max_entries and len(self.envelopes) > max_entries:
            print(f"  ... and {len(self.envelopes) - max_entries:,} more entries not shown")
            print()

        if summary.violations:
            print(f"{'─' * 80}")
            print(f"❌  {len(summary.violations)} VIOLATION(S) DETECTED:")
            print(f"{'─' * 80}")
            for v in summary.violations:
                print(
                    f"  [seq {v.at_sequence:04d}] "
                    f"{v.violation_type.upper():20s} | "
                    f"{v.detail}"
                )
            print(f"{'─' * 80}")
        else:
            print(f"{'─' * 80}")
            print("✅  All entries verified — chain intact, all signatures valid.")
            print(f"{'─' * 80}")

        print()

    # ── Export JSON ───────────────────────────────────────────

    def export_json(self, output_path: Path) -> None:
        """
        Export full replay summary as a JSON audit report.

        Use for:
            CI artifact storage, regulatory audit submission,
            cross-tool verification, external forensic review.

        Calls verify() internally. Does not modify engine state.

        Args:
            output_path: Destination path. Parent directories created if missing.

        Raises:
            RuntimeError — no envelopes loaded
        """
        if not self.envelopes:
            raise RuntimeError(
                "No envelopes loaded. Call load() before export_json()."
            )

        summary     = self.verify()
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        report = {
            "gef_replay_report": {
                "version":            "1.0",
                "ledger":             str(self._ledger_path or "in-memory"),
                "total_entries":      summary.total_entries,
                "chain_valid":        summary.chain_valid,
                "valid_signatures":   summary.valid_signatures,
                "invalid_signatures": summary.invalid_signatures,
                "gef_version":        summary.gef_version,
                "first_timestamp":    summary.first_timestamp,
                "last_timestamp":     summary.last_timestamp,
                "agents_seen":        summary.agents_seen,
                "record_type_counts": summary.record_type_counts,
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

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        if not self._silent:
            print(f"📄  Replay report exported to: {output_path}")

    # ── Internal ──────────────────────────────────────────────

    def _empty_summary(self) -> ReplaySummary:
        """Return a clean empty summary for a zero-entry ledger."""
        return ReplaySummary(
            total_entries=      0,
            chain_valid=        True,
            violations=         [],
            valid_signatures=   0,
            invalid_signatures= 0,
            record_type_counts= {},
            agents_seen=        [],
            gef_version=        None,
            first_timestamp=    None,
            last_timestamp=     None,
        )
