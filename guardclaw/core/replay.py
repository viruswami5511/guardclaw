"""
guardclaw/core/replay.py

GEF Replay Engine - v0.3.1
Aligned to: GEF-SPEC-v1.0

Protocol Laws enforced here:
    1. Load    -> ExecutionEnvelope.from_dict(line)  -- no other deserialization
    2. Schema  -> env.validate_schema()              -- fail fast, no silent pass
    3. Chain   -> env.verify_chain(prev)             -- sequential (causal dependency)
    4. Sig     -> env.verify_signature()             -- parallel (independent per entry)
    5. Version -> all envelopes must share gef_version (GEFVersionError if not)
    6. Nonce   -> no two envelopes in a ledger may share a nonce (INV-29)
    7. Order   -> file position order must match sequence order (v0.2.1)
    8. Agent   -> all envelopes in one ledger must share the same agent_id (v0.2.1)

Performance architecture -- THREE MODES:
    Mode 1 -- verify()             O(N) memory, parallel sigs
    Mode 2 -- stream_verify()      O(1) memory, line-by-line, no file load
    Mode 3 -- stream_verify_fast() O(1) memory + checkpoint resume

CHANGE LOG:
    v0.3.1 -- Distinguish invalid_signature_encoding vs invalid_signature
              in all three verification paths. Requires models.verify_signature()
              to return (bool, str).
"""

import json
import os
import time
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


# -----------------------------------------------------------------
# Module-level worker -- MUST be top-level for ProcessPoolExecutor
# -----------------------------------------------------------------

def _verify_sig_batch(
    batch: List[Tuple[Dict[str, Any], Optional[str], str, int]]
) -> List[Tuple[int, bool, str]]:
    """
    Verify a batch of envelope signatures in a subprocess.
    Returns list of (sequence, ok, reason).
        reason: "" = valid, "encoding" = bad base64url, "mismatch" = bad bytes
    """
    from guardclaw.core.canonical import canonical_json_encode
    from guardclaw.core.crypto import Ed25519KeyManager

    results: List[Tuple[int, bool, str]] = []
    for signing_dict, signature, pubkey_hex, sequence in batch:
        if not signature:
            results.append((sequence, False, "mismatch"))
            continue
        try:
            Ed25519KeyManager._decode_strict_base64url_signature(signature)
        except ValueError:
            results.append((sequence, False, "encoding"))
            continue
        data = canonical_json_encode(signing_dict)
        ok = Ed25519KeyManager.verify_detached(data, signature, pubkey_hex)
        results.append((sequence, ok, "" if ok else "mismatch"))
    return results


# -----------------------------------------------------------------
# Internal helper
# -----------------------------------------------------------------

def _sig_violation(env: "ExecutionEnvelope", reason: str) -> "ChainViolation":
    if reason == "encoding":
        return ChainViolation(
            at_sequence=env.sequence,
            record_id=env.record_id,
            violation_type="invalid_signature_encoding",
            detail=(
                "Signature encoding invalid -- non-canonical base64url "
                "(signer: " + env.signer_public_key[:16] + "...)"
            ),
        )
    return ChainViolation(
        at_sequence=env.sequence,
        record_id=env.record_id,
        violation_type="invalid_signature",
        detail=(
            "Signature bytes invalid "
            "(signer: " + env.signer_public_key[:16] + "...)"
        ),
    )


# -----------------------------------------------------------------
# Tuning constants
# -----------------------------------------------------------------

_PARALLEL_THRESHOLD               = 2_000
_BATCH_SIZE_PER_WORKER_MULTIPLIER = 4
_STREAM_PROGRESS_INTERVAL         = 100_000


# -----------------------------------------------------------------
# Result / Summary Types
# -----------------------------------------------------------------

@dataclass
class ChainViolation:
    at_sequence:    int
    record_id:      str
    violation_type: str
    detail:         str


@dataclass
class ReplaySummary:
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


# -----------------------------------------------------------------
# Replay Engine
# -----------------------------------------------------------------

class ReplayEngine:
    """
    GEF-native replay engine -- streaming, parallel, checkpoint-aware.

    Usage (full load + verify):
        engine = ReplayEngine()
        engine.load(Path("ledger.jsonl"))
        summary = engine.verify()

    Usage (O(1) streaming):
        engine = ReplayEngine(silent=True)
        summary = engine.stream_verify(Path("ledger.jsonl"))

    Usage (checkpoint resume):
        engine = ReplayEngine(silent=True)
        summary = engine.stream_verify_fast(Path("ledger.jsonl"), key_hex)
    """

    def __init__(self, parallel: bool = True, silent: bool = False):
        self.envelopes:     List[ExecutionEnvelope]    = []
        self.violations:    List[ChainViolation]       = []
        self._ledger_path:  Optional[Path]             = None
        self._parallel:     bool                       = parallel
        self._silent:       bool                       = silent
        self._out_of_order: List[Tuple[int, int, str]] = []

    # -- Load ----------------------------------------------------------

    def load(self, ledger_path: Path) -> None:
        ledger_path       = Path(ledger_path)
        self._ledger_path = ledger_path
        self.envelopes    = []
        self.violations   = []
        self._out_of_order = []

        if not ledger_path.exists():
            raise FileNotFoundError(f"GEF ledger not found: {ledger_path}")

        with open(ledger_path, "r", encoding="utf-8") as f:
            for line_num, raw in enumerate(f, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError as e:
                    raise ValueError(
                        f"Malformed JSON at ledger line {line_num}: {e}"
                    ) from e
                try:
                    env = ExecutionEnvelope.from_dict(data)
                except KeyError as e:
                    raise ValueError(
                        f"Missing required GEF field at line {line_num}: {e}"
                    ) from e
                schema = env.validate_schema()
                if not schema:
                    raise ValueError(
                        f"GEF schema violation at line {line_num} "
                        f"(record_id={data.get('record_id', '?')}): "
                        f"{schema.errors}"
                    )
                self.envelopes.append(env)

        self._out_of_order = [
            (file_pos, env.sequence, env.record_id)
            for file_pos, env in enumerate(self.envelopes)
            if env.sequence != file_pos
        ]

        self.envelopes.sort(key=lambda e: e.sequence)

        if self.envelopes:
            versions = {e.gef_version for e in self.envelopes}
            if len(versions) > 1:
                raise GEFVersionError(
                    f"Ledger '{ledger_path.name}' contains mixed gef_version "
                    f"values: {sorted(versions)}. All envelopes in a single "
                    f"ledger must share identical gef_version."
                )

        if not self._silent:
            print(
                f"Loaded {len(self.envelopes):,} GEF envelopes "
                f"from '{ledger_path.name}'"
            )

    # -- Verify --------------------------------------------------------

    def verify(self) -> ReplaySummary:
        self.violations = []

        if not self.envelopes:
            return self._empty_summary()

        chain_violations: List[ChainViolation] = []
        seen_nonces:      Set[str]             = set()

        for file_pos, actual_seq, rec_id in self._out_of_order:
            chain_violations.append(ChainViolation(
                at_sequence=actual_seq,
                record_id=rec_id,
                violation_type="sequence_order",
                detail=(
                    f"File position {file_pos} has sequence {actual_seq} -- "
                    f"entry reorder detected."
                ),
            ))

        for i, env in enumerate(self.envelopes):
            prev = self.envelopes[i - 1] if i > 0 else None

            if not env.verify_sequence(i):
                chain_violations.append(ChainViolation(
                    at_sequence=i,
                    record_id=env.record_id,
                    violation_type="sequence_gap",
                    detail=f"Expected sequence {i}, got {env.sequence}",
                ))

            if not env.verify_chain(prev):
                expected = env.expected_causal_hash_from(prev)
                chain_violations.append(ChainViolation(
                    at_sequence=env.sequence,
                    record_id=env.record_id,
                    violation_type="chain_break",
                    detail=(
                        f"causal_hash mismatch: "
                        f"expected ...{expected[-12:]}, "
                        f"got ...{env.causal_hash[-12:]}"
                    ),
                ))

            if env.nonce in seen_nonces:
                chain_violations.append(ChainViolation(
                    at_sequence=env.sequence,
                    record_id=env.record_id,
                    violation_type="schema",
                    detail=(
                        f"Duplicate nonce '{env.nonce}' at sequence "
                        f"{env.sequence} (INV-29)"
                    ),
                ))
            seen_nonces.add(env.nonce)

        if self.envelopes:
            expected_agent = self.envelopes[0].agent_id
            for env in self.envelopes[1:]:
                if env.agent_id != expected_agent:
                    chain_violations.append(ChainViolation(
                        at_sequence=env.sequence,
                        record_id=env.record_id,
                        violation_type="mixed_agent_id",
                        detail=(
                            f"agent_id changed from '{expected_agent}' to "
                            f"'{env.agent_id}' at sequence {env.sequence}."
                        ),
                    ))
                    break

        use_parallel = (
            self._parallel and len(self.envelopes) >= _PARALLEL_THRESHOLD
        )
        sig_results = (
            self._verify_signatures_parallel()
            if use_parallel
            else self._verify_signatures_sequential()
        )

        sig_violations: List[ChainViolation] = []
        valid_sigs   = 0
        invalid_sigs = 0

        for env in self.envelopes:
            ok, reason = sig_results.get(env.sequence, (False, "mismatch"))
            if ok:
                valid_sigs += 1
            else:
                invalid_sigs += 1
                sig_violations.append(_sig_violation(env, reason))

        self.violations = chain_violations + sig_violations

        counts: Dict[str, int] = defaultdict(int)
        for env in self.envelopes:
            counts[env.record_type] += 1

        return ReplaySummary(
            total_entries=len(self.envelopes),
            chain_valid=len(self.violations) == 0,
            violations=list(self.violations),
            valid_signatures=valid_sigs,
            invalid_signatures=invalid_sigs,
            record_type_counts=dict(counts),
            agents_seen=sorted({e.agent_id for e in self.envelopes}),
            gef_version=self.envelopes[0].gef_version,
            first_timestamp=self.envelopes[0].timestamp,
            last_timestamp=self.envelopes[-1].timestamp,
        )

    # -- Stream Verify -------------------------------------------------

    def stream_verify(self, ledger_path: Path) -> ReplaySummary:
        ledger_path = Path(ledger_path)

        if not ledger_path.exists():
            raise FileNotFoundError(f"GEF ledger not found: {ledger_path}")

        violations:  List[ChainViolation]        = []
        seen_nonces: Set[str]                    = set()
        prev:        Optional[ExecutionEnvelope] = None
        gef_version: Optional[str]               = None
        valid_sigs   = 0
        invalid_sigs = 0
        total        = 0
        counts:      Dict[str, int]              = defaultdict(int)
        agents:      Set[str]                    = set()
        first_ts:    Optional[str]               = None
        last_ts:     Optional[str]               = None
        t_start      = time.time()

        with open(ledger_path, "r", encoding="utf-8") as f:
            for line_num, raw in enumerate(f, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError:
                    violations.append(ChainViolation(
                        at_sequence=total, record_id="?",
                        violation_type="schema",
                        detail=f"Malformed JSON at line {line_num}",
                    ))
                    continue
                try:
                    env = ExecutionEnvelope.from_dict(data)
                except KeyError as e:
                    violations.append(ChainViolation(
                        at_sequence=total,
                        record_id=data.get("record_id", "?"),
                        violation_type="schema",
                        detail=f"Missing field at line {line_num}: {e}",
                    ))
                    continue

                if gef_version is None:
                    gef_version = env.gef_version
                elif env.gef_version != gef_version:
                    violations.append(ChainViolation(
                        at_sequence=env.sequence, record_id=env.record_id,
                        violation_type="schema",
                        detail=f"gef_version mismatch: {env.gef_version} != {gef_version}",
                    ))

                if env.sequence != total:
                    violations.append(ChainViolation(
                        at_sequence=total, record_id=env.record_id,
                        violation_type="sequence_gap",
                        detail=f"Expected sequence {total}, got {env.sequence}",
                    ))

                if not env.verify_chain(prev):
                    expected = env.expected_causal_hash_from(prev)
                    violations.append(ChainViolation(
                        at_sequence=env.sequence, record_id=env.record_id,
                        violation_type="chain_break",
                        detail=(
                            f"causal_hash mismatch: "
                            f"expected ...{expected[-12:]}, "
                            f"got ...{env.causal_hash[-12:]}"
                        ),
                    ))

                if env.nonce in seen_nonces:
                    violations.append(ChainViolation(
                        at_sequence=env.sequence, record_id=env.record_id,
                        violation_type="schema",
                        detail=f"Duplicate nonce '{env.nonce}' (INV-29)",
                    ))
                seen_nonces.add(env.nonce)

                sig_ok, sig_reason = env.verify_signature()
                if sig_ok:
                    valid_sigs += 1
                else:
                    invalid_sigs += 1
                    violations.append(_sig_violation(env, sig_reason))

                counts[env.record_type] += 1
                agents.add(env.agent_id)
                if first_ts is None:
                    first_ts = env.timestamp
                last_ts = env.timestamp
                total  += 1
                prev    = env

                if not self._silent and total % _STREAM_PROGRESS_INTERVAL == 0:
                    elapsed = time.time() - t_start
                    rate = total / elapsed if elapsed > 0 else 0
                    print(
                        f"  stream_verify: {total:,} entries "
                        f"({rate:,.0f} eps) violations: {len(violations)}"
                    )

        if not self._silent:
            elapsed = time.time() - t_start
            rate = total / elapsed if elapsed > 0 else 0
            print(
                f"stream_verify complete: {total:,} entries "
                f"in {elapsed:.1f}s ({rate:,.0f} eps) "
                f"violations: {len(violations)}"
            )

        return ReplaySummary(
            total_entries=total,
            chain_valid=len(violations) == 0,
            violations=violations,
            valid_signatures=valid_sigs,
            invalid_signatures=invalid_sigs,
            record_type_counts=dict(counts),
            agents_seen=sorted(agents),
            gef_version=gef_version,
            first_timestamp=first_ts,
            last_timestamp=last_ts,
        )

    # -- Stream Verify Fast --------------------------------------------

    def stream_verify_fast(
        self,
        ledger_path: Path,
        public_key_hex: str,
    ) -> ReplaySummary:
        from guardclaw.core.checkpoint import load_latest_checkpoint

        ledger_path = Path(ledger_path)
        ckpt_info   = load_latest_checkpoint(ledger_path, public_key_hex)

        if not ckpt_info:
            if not self._silent:
                print("  No valid checkpoint -- falling back to full stream_verify")
            return self.stream_verify(ledger_path)

        ckpt, num_ckpts = ckpt_info

        if not self._silent:
            print(
                f"  Checkpoint #{num_ckpts} found: "
                f"seq {ckpt.sequence:,}, offset {ckpt.file_offset:,} bytes"
            )
            print(
                f"  Seeking to offset -- "
                f"skipping {ckpt.sequence:,} verified entries"
            )

        violations:  List[ChainViolation]        = []
        seen_nonces: Set[str]                    = set()
        prev:        Optional[ExecutionEnvelope] = None
        gef_version: Optional[str]               = None
        valid_sigs   = 0
        invalid_sigs = 0
        total        = 0
        counts:      Dict[str, int]              = defaultdict(int)
        agents:      Set[str]                    = set()
        first_ts:    Optional[str]               = None
        last_ts:     Optional[str]               = None
        t_start      = time.time()

        with open(ledger_path, "r", encoding="utf-8") as f:
            f.seek(ckpt.file_offset)
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    data = json.loads(raw)
                    env  = ExecutionEnvelope.from_dict(data)
                except Exception:
                    continue

                if gef_version is None:
                    gef_version = env.gef_version

                if not env.verify_chain(prev):
                    expected = env.expected_causal_hash_from(prev)
                    violations.append(ChainViolation(
                        at_sequence=env.sequence, record_id=env.record_id,
                        violation_type="chain_break",
                        detail=(
                            f"expected ...{expected[-12:]}, "
                            f"got ...{env.causal_hash[-12:]}"
                        ),
                    ))

                if env.nonce in seen_nonces:
                    violations.append(ChainViolation(
                        at_sequence=env.sequence, record_id=env.record_id,
                        violation_type="schema",
                        detail=f"Duplicate nonce '{env.nonce}' (INV-29)",
                    ))
                seen_nonces.add(env.nonce)

                sig_ok, sig_reason = env.verify_signature()
                if sig_ok:
                    valid_sigs += 1
                else:
                    invalid_sigs += 1
                    violations.append(_sig_violation(env, sig_reason))

                counts[env.record_type] += 1
                agents.add(env.agent_id)
                if first_ts is None:
                    first_ts = env.timestamp
                last_ts = env.timestamp
                total  += 1
                prev    = env

                if not self._silent and total % _STREAM_PROGRESS_INTERVAL == 0:
                    elapsed = time.time() - t_start
                    rate = total / elapsed if elapsed > 0 else 0
                    print(f"  delta verify: {total:,} new entries ({rate:,.0f} eps)")

        if not self._silent:
            elapsed = time.time() - t_start
            rate = total / elapsed if elapsed > 0 else 0
            print(
                f"stream_verify_fast complete: "
                f"{total:,} delta + {ckpt.sequence:,} checkpointed "
                f"= {ckpt.sequence + total:,} total | "
                f"{elapsed:.2f}s ({rate:,.0f} delta eps) "
                f"violations: {len(violations)}"
            )

        return ReplaySummary(
            total_entries=ckpt.sequence + total,
            chain_valid=len(violations) == 0,
            violations=violations,
            valid_signatures=ckpt.valid_sig_count + valid_sigs,
            invalid_signatures=invalid_sigs,
            record_type_counts=dict(counts),
            agents_seen=sorted(agents),
            gef_version=gef_version,
            first_timestamp=first_ts,
            last_timestamp=last_ts,
        )

    # -- Parallel Signature Helpers ------------------------------------

    def _verify_signatures_parallel(self) -> Dict[int, Tuple[bool, str]]:
        n_workers  = min(os.cpu_count() or 4, 8)
        batch_size = max(
            500,
            len(self.envelopes) // (
                n_workers * _BATCH_SIZE_PER_WORKER_MULTIPLIER
            ),
        )
        all_data = [
            (
                env.to_signing_dict(),
                env.signature,
                env.signer_public_key,
                env.sequence,
            )
            for env in self.envelopes
        ]
        batches = [
            all_data[i: i + batch_size]
            for i in range(0, len(all_data), batch_size)
        ]
        results: Dict[int, Tuple[bool, str]] = {}
        try:
            with ProcessPoolExecutor(max_workers=n_workers) as executor:
                for batch_result in executor.map(_verify_sig_batch, batches):
                    for seq, ok, reason in batch_result:
                        results[seq] = (ok, reason)
        except Exception:
            results = self._verify_signatures_sequential()
        return results

    def _verify_signatures_sequential(self) -> Dict[int, Tuple[bool, str]]:
        return {
            env.sequence: env.verify_signature()
            for env in self.envelopes
        }

    # -- Print Timeline ------------------------------------------------

    def print_timeline(self, max_entries: Optional[int] = None) -> None:
        if not self.envelopes:
            print("No GEF envelopes loaded.")
            return

        summary = self.verify()
        bar     = "=" * 80

        print("")
        print(bar)
        print("GuardClaw GEF Replay Timeline")
        print(bar)
        print(f"  Ledger      : {self._ledger_path or 'in-memory'}")
        print(f"  GEF Version : {summary.gef_version}")
        print(f"  Entries     : {summary.total_entries:,}")
        print(f"  Chain       : {'VALID' if summary.chain_valid else 'VIOLATED'}")
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
            prev      = self.envelopes[env.sequence - 1] if env.sequence > 0 else None
            sig_ok, _ = env.verify_signature()
            sig_icon  = "OK"   if sig_ok              else "FAIL"
            chn_icon  = "OK"   if env.verify_chain(prev) else "FAIL"

            print(f"  [{env.sequence:04d}] {env.timestamp}  {env.record_type}")
            print(f"         record_id   : {env.record_id}")
            print(f"         agent_id    : {env.agent_id}")
            print(f"         nonce       : {env.nonce[:16]}...")
            print(f"         causal_hash : ...{env.causal_hash[-12:]}")
            print(f"         sig:{sig_icon}  chain:{chn_icon}")
            print()

        if max_entries and len(self.envelopes) > max_entries:
            print(f"  ... and {len(self.envelopes) - max_entries:,} more entries not shown")
            print()

        if summary.violations:
            print("-" * 80)
            print(f"{len(summary.violations)} VIOLATION(S) DETECTED:")
            print("-" * 80)
            for v in summary.violations:
                print(
                    f"  [seq {v.at_sequence:04d}] "
                    f"{v.violation_type.upper():30s} | {v.detail}"
                )
            print("-" * 80)
        else:
            print("-" * 80)
            print("All entries verified -- chain intact, all signatures valid.")
            print("-" * 80)
        print()

    # -- Export JSON ---------------------------------------------------

    def export_json(self, output_path: Path) -> None:
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
            print(f"Replay report exported to: {output_path}")

    # -- Internal ------------------------------------------------------

    def _empty_summary(self) -> ReplaySummary:
        return ReplaySummary(
            total_entries=0,
            chain_valid=True,
            violations=[],
            valid_signatures=0,
            invalid_signatures=0,
            record_type_counts={},
            agents_seen=[],
            gef_version=None,
            first_timestamp=None,
            last_timestamp=None,
        )