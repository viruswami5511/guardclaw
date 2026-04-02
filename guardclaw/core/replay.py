"""
guardclaw/core/replay.py  —  GEF Replay Engine v0.7.2

CHANGES IN v0.7.2:
    FIX A  Genesis → CHAIN_VIOLATION (not LEDGER_INVALID)
           Reason: genesis check is runtime (after parse+schema+sig), not pre-flight
    FIX B  total_entries = entry_count (non-empty lines), not line_count
           Semantics: failure_sequence=line_num (physical truth), total_entries=real entries

FIELD SEMANTICS (locked):
    failure_sequence  = line_num   (0-indexed physical file line, truth source)
    total_entries     = entry_count (non-empty ledger entries processed)
    verified_count    = trusted prefix (entries that passed all checks)

VERIFICATION ORDER per line (LOCKED):
    1. JSON decode
    2. Schema (from_dict + validate_schema)
    3. Signature presence
    4. Signature encoding (base64url)
    5. Signature crypto (Ed25519)
    6. Genesis check (first entry only — CHAIN rule, not pre-flight)
    7. Sequence continuity
    8. GEF version consistency
    9. Causal hash
   10. Nonce uniqueness
"""

from __future__ import annotations

import json
import os
import time
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from guardclaw.core.failure import (
    FailureDetail, FailureType, VerificationSummary,
    ProtocolInvariantError, compute_boundary_hash, first_schema_error,
)
from guardclaw.core.models import (
    ExecutionEnvelope, GEFVersionError, GEF_VERSION,
    RecordType, SchemaValidationResult,
)


# ── Module-level worker for ProcessPoolExecutor ───────────────────────────────

def _verify_sig_batch(
    batch: List[Tuple[Dict[str, Any], Optional[str], str, int]]
) -> List[Tuple[int, bool, str]]:
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


_PARALLEL_THRESHOLD               = 2_000
_BATCH_SIZE_PER_WORKER_MULTIPLIER = 4
_STREAM_PROGRESS_INTERVAL         = 100_000


# ── Legacy result types (preserved for backward compat) ──────────────────────

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


# ── Replay Engine ─────────────────────────────────────────────────────────────

class ReplayEngine:

    def __init__(self, mode: str = "strict", parallel: bool = True, silent: bool = False):
        if mode not in ("strict", "recovery"):
            raise ValueError(f"mode must be 'strict' or 'recovery', got {mode!r}")
        self.mode           = mode
        self.envelopes:     List[ExecutionEnvelope]    = []
        self.violations:    List[ChainViolation]       = []
        self._ledger_path:  Optional[Path]             = None
        self._parallel:     bool                       = parallel
        self._silent:       bool                       = silent
        self._out_of_order: List[Tuple[int, int, str]] = []

    # ── PRIMARY API ───────────────────────────────────────────────────────────

    def stream_verify(self, ledger_path: Path) -> VerificationSummary:
        """O(1) memory streaming verify. Returns VerificationSummary."""
        ledger_path = Path(ledger_path)
        is_recovery = (self.mode == "recovery")

        if not ledger_path.exists():
            return VerificationSummary(
                total_entries=0, chain_valid=False,
                recovery_mode_active=is_recovery,
                failure_type=FailureType.LEDGER_INVALID,
                failure_detail=FailureDetail.FILE_NOT_FOUND,
            )
        if ledger_path.stat().st_size == 0:
            return VerificationSummary(
                total_entries=0, chain_valid=False,
                recovery_mode_active=is_recovery,
                failure_type=FailureType.LEDGER_INVALID,
                failure_detail=FailureDetail.EMPTY_LEDGER,
            )

        if self.mode == "strict":
            return self._stream_verify_strict(ledger_path)
        return self._stream_verify_recovery(ledger_path)

    # ── STRICT MODE ───────────────────────────────────────────────────────────

    def _stream_verify_strict(self, ledger_path: Path) -> VerificationSummary:
        prev:        Optional[ExecutionEnvelope] = None
        gef_version: Optional[str]               = None
        seen_nonces: Set[str]                    = set()
        verified      = 0
        entry_count   = 0   # FIX B: non-empty entries processed
        line_count    = 0   # internal: physical lines (for failure_sequence only)
        expected_seq  = 0

        with open(ledger_path, "r", encoding="utf-8") as f:
            for line_num, raw in enumerate(f):
                raw = raw.strip()
                if not raw:
                    continue

                entry_count += 1              # FIX B: count only real entries
                line_count = line_num + 1     # keep for failure_sequence correctness

                # Step 1: JSON
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError as exc:
                    return VerificationSummary(
                        total_entries=entry_count, chain_valid=False,
                        failure_sequence=line_num,
                        failure_type=FailureType.MALFORMED_JSON,
                        failure_detail=f"{FailureDetail.JSON_DECODE_ERROR}: {exc}",
                    )

                # Step 2: Schema
                try:
                    env = ExecutionEnvelope.from_dict(data)
                except KeyError as exc:
                    field = str(exc).strip("'\"")
                    return VerificationSummary(
                        total_entries=entry_count, chain_valid=False,
                        failure_sequence=line_num,
                        failure_type=FailureType.SCHEMA_VIOLATION,
                        failure_detail=FailureDetail.missing_field(field),
                    )
                schema = env.validate_schema()
                if not schema:
                    return VerificationSummary(
                        total_entries=entry_count, chain_valid=False,
                        failure_sequence=line_num,
                        failure_type=FailureType.SCHEMA_VIOLATION,
                        failure_detail=first_schema_error(schema.errors),
                    )

                # Step 3: Signature presence
                if not env.signature:
                    return VerificationSummary(
                        total_entries=entry_count, chain_valid=False,
                        failure_sequence=line_num,
                        failure_type=FailureType.SCHEMA_VIOLATION,
                        failure_detail=FailureDetail.MISSING_SIGNATURE,
                    )

                # Steps 4+5: Encoding + crypto
                sig_ok, sig_reason = env.verify_signature()
                if not sig_ok:
                    return VerificationSummary(
                        total_entries=entry_count, chain_valid=False,
                        failure_sequence=line_num,
                        failure_type=(
                            FailureType.SIGNATURE_ENCODING_INVALID
                            if sig_reason == "encoding"
                            else FailureType.SIGNATURE_INVALID
                        ),
                        failure_detail=(
                            FailureDetail.INVALID_BASE64URL
                            if sig_reason == "encoding"
                            else FailureDetail.ED25519_FAILED
                        ),
                    )

                # Step 6: Genesis enforcement — CHAIN_VIOLATION (runtime, not pre-flight)
                if verified == 0 and env.record_type != RecordType.GENESIS:
                    return VerificationSummary(
                        total_entries=entry_count,
                        chain_valid=False,
                        failure_sequence=line_num,
                        failure_type=FailureType.CHAIN_VIOLATION,   # FIX A
                        failure_detail=FailureDetail.GENESIS_MISSING,
                    )

                # Step 7: Sequence
                if env.sequence != expected_seq:
                    return VerificationSummary(
                        total_entries=entry_count, chain_valid=False,
                        failure_sequence=line_num,
                        failure_type=FailureType.CHAIN_VIOLATION,
                        failure_detail=(
                            f"{FailureDetail.SEQUENCE_GAP}: "
                            f"expected {expected_seq}, got {env.sequence}"
                        ),
                    )

                # Step 8: GEF version
                if gef_version is None:
                    gef_version = env.gef_version
                elif env.gef_version != gef_version:
                    return VerificationSummary(
                        total_entries=entry_count, chain_valid=False,
                        failure_sequence=line_num,
                        failure_type=FailureType.CHAIN_VIOLATION,
                        failure_detail=(
                            f"{FailureDetail.GEF_VERSION_MISMATCH}: "
                            f"ledger={gef_version}, entry={env.gef_version}"
                        ),
                    )

                # Step 9: Causal hash
                if not env.verify_chain(prev):
                    expected_hash = env.expected_causal_hash_from(prev)
                    return VerificationSummary(
                        total_entries=entry_count, chain_valid=False,
                        failure_sequence=line_num,
                        failure_type=FailureType.CHAIN_VIOLATION,
                        failure_detail=(
                            f"{FailureDetail.CAUSAL_HASH_MISMATCH}: "
                            f"expected ...{expected_hash[-12:]}, "
                            f"got ...{env.causal_hash[-12:]}"
                        ),
                    )

                # Step 10: Nonce uniqueness
                if env.nonce in seen_nonces:
                    return VerificationSummary(
                        total_entries=entry_count, chain_valid=False,
                        failure_sequence=line_num,
                        failure_type=FailureType.CHAIN_VIOLATION,
                        failure_detail=(
                            f"{FailureDetail.DUPLICATE_NONCE}: "
                            f"nonce={env.nonce[:16]}... (INV-29)"
                        ),
                    )
                seen_nonces.add(env.nonce)

                prev = env
                verified     += 1
                expected_seq += 1

        return VerificationSummary(
            total_entries=entry_count,   # FIX B
            chain_valid=True,
        )

    # ── RECOVERY MODE ─────────────────────────────────────────────────────────

    def _stream_verify_recovery(self, ledger_path: Path) -> VerificationSummary:
        prev:        Optional[ExecutionEnvelope] = None
        last_valid:  Optional[ExecutionEnvelope] = None
        gef_version: Optional[str]               = None
        seen_nonces: Set[str]                    = set()
        verified      = 0
        entry_count   = 0   # FIX B: non-empty entries processed
        line_count    = 0   # internal: physical lines
        expected_seq  = 0

        def _fail(line_num, ftype, fdetail):
            bh = compute_boundary_hash(last_valid) if last_valid else None
            return VerificationSummary(
                total_entries=entry_count,      # FIX B
                chain_valid=False,
                recovery_mode_active=True,
                partial_integrity=(verified > 0),
                verified_count=verified,
                failure_sequence=line_num,
                failure_type=ftype,
                failure_detail=fdetail,
                integrity_boundary_hash=bh,
                boundary_sequence=last_valid.sequence if last_valid else None,
            )

        with open(ledger_path, "r", encoding="utf-8") as f:
            for line_num, raw in enumerate(f):
                raw = raw.strip()
                if not raw:
                    continue

                entry_count += 1              # FIX B
                line_count = line_num + 1     # keep for internal tracking

                try:
                    data = json.loads(raw)
                except json.JSONDecodeError as exc:
                    return _fail(line_num, FailureType.MALFORMED_JSON,
                                 f"{FailureDetail.JSON_DECODE_ERROR}: {exc}")

                try:
                    env = ExecutionEnvelope.from_dict(data)
                except KeyError as exc:
                    field = str(exc).strip("'\"")
                    return _fail(line_num, FailureType.SCHEMA_VIOLATION,
                                 FailureDetail.missing_field(field))

                schema = env.validate_schema()
                if not schema:
                    return _fail(line_num, FailureType.SCHEMA_VIOLATION,
                                 first_schema_error(schema.errors))

                if not env.signature:
                    return _fail(line_num, FailureType.SCHEMA_VIOLATION,
                                 FailureDetail.MISSING_SIGNATURE)

                sig_ok, sig_reason = env.verify_signature()
                if not sig_ok:
                    return _fail(
                        line_num,
                        FailureType.SIGNATURE_ENCODING_INVALID if sig_reason == "encoding"
                        else FailureType.SIGNATURE_INVALID,
                        FailureDetail.INVALID_BASE64URL if sig_reason == "encoding"
                        else FailureDetail.ED25519_FAILED,
                    )

                # Step 6: Genesis enforcement — CHAIN_VIOLATION (runtime, not pre-flight)
                if verified == 0 and env.record_type != RecordType.GENESIS:
                    return _fail(line_num, FailureType.CHAIN_VIOLATION,   # FIX A
                                 FailureDetail.GENESIS_MISSING)

                if env.sequence != expected_seq:
                    return _fail(line_num, FailureType.CHAIN_VIOLATION,
                                 f"{FailureDetail.SEQUENCE_GAP}: expected {expected_seq}, got {env.sequence}")

                if gef_version is None:
                    gef_version = env.gef_version
                elif env.gef_version != gef_version:
                    return _fail(line_num, FailureType.CHAIN_VIOLATION,
                                 f"{FailureDetail.GEF_VERSION_MISMATCH}: ledger={gef_version}, entry={env.gef_version}")

                if not env.verify_chain(prev):
                    expected_hash = env.expected_causal_hash_from(prev)
                    return _fail(line_num, FailureType.CHAIN_VIOLATION,
                                 f"{FailureDetail.CAUSAL_HASH_MISMATCH}: "
                                 f"expected ...{expected_hash[-12:]}, got ...{env.causal_hash[-12:]}")

                if env.nonce in seen_nonces:
                    return _fail(line_num, FailureType.CHAIN_VIOLATION,
                                 f"{FailureDetail.DUPLICATE_NONCE}: nonce={env.nonce[:16]}... (INV-29)")
                seen_nonces.add(env.nonce)

                last_valid = env
                prev = env
                verified     += 1
                expected_seq += 1

        return VerificationSummary(
            total_entries=entry_count,   # FIX B
            chain_valid=True,
            recovery_mode_active=True,
            partial_integrity=False,
            verified_count=verified,
        )

    # ── LEGACY: load() + verify() ─────────────────────────────────────────────

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
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Malformed JSON at line {line_num}: {exc}") from exc
                try:
                    env = ExecutionEnvelope.from_dict(data)
                except KeyError as exc:
                    raise ValueError(f"Missing GEF field at line {line_num}: {exc}") from exc
                schema = env.validate_schema()
                if not schema:
                    raise ValueError(
                        f"Schema violation at line {line_num} "
                        f"(record_id={data.get('record_id','?')}): {schema.errors}"
                    )
                self.envelopes.append(env)

        self._out_of_order = [
            (fp, env.sequence, env.record_id)
            for fp, env in enumerate(self.envelopes)
            if env.sequence != fp
        ]
        self.envelopes.sort(key=lambda e: e.sequence)

        if self.envelopes:
            versions = {e.gef_version for e in self.envelopes}
            if len(versions) > 1:
                raise GEFVersionError(
                    f"Mixed gef_version in '{ledger_path.name}': {sorted(versions)}"
                )

        if not self._silent:
            print(f"Loaded {len(self.envelopes):,} GEF envelopes from '{ledger_path.name}'")

    def verify(self) -> ReplaySummary:
        self.violations = []
        if not self.envelopes:
            return self._empty_summary()

        chain_violations: List[ChainViolation] = []
        seen_nonces: Set[str] = set()

        for fp, actual_seq, rec_id in self._out_of_order:
            chain_violations.append(ChainViolation(
                at_sequence=actual_seq, record_id=rec_id,
                violation_type="sequence_order",
                detail=f"File position {fp} has sequence {actual_seq} -- reorder detected.",
            ))

        for i, env in enumerate(self.envelopes):
            prev = self.envelopes[i - 1] if i > 0 else None
            if not env.verify_sequence(i):
                chain_violations.append(ChainViolation(
                    at_sequence=i, record_id=env.record_id,
                    violation_type="sequence_gap",
                    detail=f"Expected sequence {i}, got {env.sequence}",
                ))
            if not env.verify_chain(prev):
                expected = env.expected_causal_hash_from(prev)
                chain_violations.append(ChainViolation(
                    at_sequence=env.sequence, record_id=env.record_id,
                    violation_type="chain_break",
                    detail=f"causal_hash mismatch: expected ...{expected[-12:]}, got ...{env.causal_hash[-12:]}",
                ))
            if env.nonce in seen_nonces:
                chain_violations.append(ChainViolation(
                    at_sequence=env.sequence, record_id=env.record_id,
                    violation_type="schema",
                    detail=f"Duplicate nonce '{env.nonce}' at seq {env.sequence} (INV-29)",
                ))
            seen_nonces.add(env.nonce)

        if self.envelopes:
            expected_agent = self.envelopes[0].agent_id
            for env in self.envelopes[1:]:
                if env.agent_id != expected_agent:
                    chain_violations.append(ChainViolation(
                        at_sequence=env.sequence, record_id=env.record_id,
                        violation_type="mixed_agent_id",
                        detail=f"agent_id changed from '{expected_agent}' to '{env.agent_id}' at seq {env.sequence}.",
                    ))
                    break

        use_parallel = self._parallel and len(self.envelopes) >= _PARALLEL_THRESHOLD
        sig_results = (
            self._verify_signatures_parallel() if use_parallel
            else self._verify_signatures_sequential()
        )

        sig_violations: List[ChainViolation] = []
        valid_sigs = 0
        invalid_sigs = 0
        for env in self.envelopes:
            ok, reason = sig_results.get(env.sequence, (False, "mismatch"))
            if ok:
                valid_sigs += 1
            else:
                invalid_sigs += 1
                vtype = "invalid_signature_encoding" if reason == "encoding" else "invalid_signature"
                sig_violations.append(ChainViolation(
                    at_sequence=env.sequence, record_id=env.record_id,
                    violation_type=vtype,
                    detail=(
                        "Signature encoding invalid -- non-canonical base64url "
                        if reason == "encoding" else "Signature bytes invalid "
                    ) + f"(signer: {env.signer_public_key[:16]}...)",
                ))

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

    # ── LEGACY: stream_verify_legacy ─────────────────────────────────────────

    def stream_verify_legacy(self, ledger_path: Path) -> ReplaySummary:
        ledger_path = Path(ledger_path)
        if not ledger_path.exists():
            raise FileNotFoundError(f"GEF ledger not found: {ledger_path}")

        violations: List[ChainViolation] = []
        seen_nonces: Set[str] = set()
        prev:        Optional[ExecutionEnvelope] = None
        gef_version: Optional[str] = None
        valid_sigs = 0; invalid_sigs = 0; total = 0
        counts: Dict[str, int] = defaultdict(int)
        agents: Set[str] = set()
        first_ts: Optional[str] = None; last_ts: Optional[str] = None
        t_start = time.time()

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
                        violation_type="schema", detail=f"Malformed JSON at line {line_num}",
                    ))
                    continue
                try:
                    env = ExecutionEnvelope.from_dict(data)
                except KeyError as exc:
                    violations.append(ChainViolation(
                        at_sequence=total, record_id=data.get("record_id", "?"),
                        violation_type="schema", detail=f"Missing field at line {line_num}: {exc}",
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
                        detail=f"causal_hash mismatch: expected ...{expected[-12:]}, got ...{env.causal_hash[-12:]}",
                    ))

                if env.nonce in seen_nonces:
                    violations.append(ChainViolation(
                        at_sequence=env.sequence, record_id=env.record_id,
                        violation_type="schema", detail=f"Duplicate nonce '{env.nonce}' (INV-29)",
                    ))
                seen_nonces.add(env.nonce)

                sig_ok, sig_reason = env.verify_signature()
                if sig_ok:
                    valid_sigs += 1
                else:
                    invalid_sigs += 1
                    vtype = "invalid_signature_encoding" if sig_reason == "encoding" else "invalid_signature"
                    violations.append(ChainViolation(
                        at_sequence=env.sequence, record_id=env.record_id,
                        violation_type=vtype, detail=f"Signature failed: {sig_reason}",
                    ))

                counts[env.record_type] += 1
                agents.add(env.agent_id)
                if first_ts is None:
                    first_ts = env.timestamp
                last_ts = env.timestamp
                total += 1; prev = env

                if not self._silent and total % _STREAM_PROGRESS_INTERVAL == 0:
                    elapsed = time.time() - t_start
                    print(f"  stream_verify: {total:,} entries ({total/elapsed:,.0f} eps)")

        if not self._silent:
            elapsed = time.time() - t_start
            print(f"stream_verify complete: {total:,} in {elapsed:.1f}s violations: {len(violations)}")

        return ReplaySummary(
            total_entries=total, chain_valid=len(violations) == 0,
            violations=violations, valid_signatures=valid_sigs,
            invalid_signatures=invalid_sigs, record_type_counts=dict(counts),
            agents_seen=sorted(agents), gef_version=gef_version,
            first_timestamp=first_ts, last_timestamp=last_ts,
        )

    # ── LEGACY: stream_verify_fast ────────────────────────────────────────────

    def stream_verify_fast(self, ledger_path: Path, public_key_hex: str) -> ReplaySummary:
        from guardclaw.core.checkpoint import load_latest_checkpoint
        ledger_path = Path(ledger_path)
        ckpt_info   = load_latest_checkpoint(ledger_path, public_key_hex)
        if not ckpt_info:
            if not self._silent:
                print("  No checkpoint found -- falling back to stream_verify_legacy")
            return self.stream_verify_legacy(ledger_path)

        ckpt, num_ckpts = ckpt_info
        if not self._silent:
            print(f"  Checkpoint #{num_ckpts}: seq {ckpt.sequence:,}, offset {ckpt.file_offset:,} bytes")

        violations: List[ChainViolation] = []
        seen_nonces: Set[str] = set()
        prev: Optional[ExecutionEnvelope] = None
        gef_version: Optional[str] = None
        valid_sigs = 0; invalid_sigs = 0; total = 0
        counts: Dict[str, int] = defaultdict(int)
        agents: Set[str] = set()
        first_ts: Optional[str] = None; last_ts: Optional[str] = None

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
                        detail=f"expected ...{expected[-12:]}, got ...{env.causal_hash[-12:]}",
                    ))

                if env.nonce in seen_nonces:
                    violations.append(ChainViolation(
                        at_sequence=env.sequence, record_id=env.record_id,
                        violation_type="schema", detail=f"Duplicate nonce '{env.nonce}' (INV-29)",
                    ))
                seen_nonces.add(env.nonce)

                sig_ok, sig_reason = env.verify_signature()
                if sig_ok:
                    valid_sigs += 1
                else:
                    invalid_sigs += 1
                    violations.append(ChainViolation(
                        at_sequence=env.sequence, record_id=env.record_id,
                        violation_type="invalid_signature", detail=f"Signature failed: {sig_reason}",
                    ))

                counts[env.record_type] += 1
                agents.add(env.agent_id)
                if first_ts is None:
                    first_ts = env.timestamp
                last_ts = env.timestamp
                total += 1; prev = env

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

    # ── LEGACY: print_timeline + export_json ─────────────────────────────────

    def print_timeline(self, max_entries: Optional[int] = None) -> None:
        if not self.envelopes:
            print("No GEF envelopes loaded."); return
        summary = self.verify()
        bar = "=" * 80
        print(f"\n{bar}\nGuardClaw GEF Replay Timeline\n{bar}")
        print(f"  Ledger      : {self._ledger_path or 'in-memory'}")
        print(f"  GEF Version : {summary.gef_version}")
        print(f"  Entries     : {summary.total_entries:,}")
        print(f"  Chain       : {'VALID' if summary.chain_valid else 'VIOLATED'}")
        print(f"  Valid sigs  : {summary.valid_signatures:,}")
        print(f"  Invalid sigs: {summary.invalid_signatures:,}")
        print(f"  Agents      : {', '.join(summary.agents_seen)}")
        print(f"  First entry : {summary.first_timestamp}")
        print(f"  Last entry  : {summary.last_timestamp}\n")
        to_show = self.envelopes[:max_entries] if max_entries else self.envelopes
        for env in to_show:
            prev      = self.envelopes[env.sequence - 1] if env.sequence > 0 else None
            sig_ok, _ = env.verify_signature()
            print(f"  [{env.sequence:04d}] {env.timestamp}  {env.record_type}")
            print(f"         record_id   : {env.record_id}")
            print(f"         causal_hash : ...{env.causal_hash[-12:]}")
            print(f"         sig:{'OK' if sig_ok else 'FAIL'}  chain:{'OK' if env.verify_chain(prev) else 'FAIL'}\n")
        if max_entries and len(self.envelopes) > max_entries:
            print(f"  ... and {len(self.envelopes) - max_entries:,} more not shown\n")
        print("-" * 80)
        if summary.violations:
            print(f"{len(summary.violations)} VIOLATION(S):")
            for v in summary.violations:
                print(f"  [seq {v.at_sequence:04d}] {v.violation_type.upper():30s} | {v.detail}")
        else:
            print("All entries verified -- chain intact, all signatures valid.")
        print("-" * 80 + "\n")

    def export_json(self, output_path: Path) -> None:
        if not self.envelopes:
            raise RuntimeError("No envelopes loaded. Call load() first.")
        summary     = self.verify()
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        report = {
            "gef_replay_report": {
                "version": "1.0", "ledger": str(self._ledger_path or "in-memory"),
                "total_entries": summary.total_entries, "chain_valid": summary.chain_valid,
                "valid_signatures": summary.valid_signatures,
                "invalid_signatures": summary.invalid_signatures,
                "gef_version": summary.gef_version,
                "first_timestamp": summary.first_timestamp,
                "last_timestamp": summary.last_timestamp,
                "agents_seen": summary.agents_seen,
                "record_type_counts": summary.record_type_counts,
                "violations": [
                    {"at_sequence": v.at_sequence, "record_id": v.record_id,
                     "violation_type": v.violation_type, "detail": v.detail}
                    for v in summary.violations
                ],
            }
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        if not self._silent:
            print(f"Replay report exported to: {output_path}")

    def _verify_signatures_parallel(self) -> Dict[int, Tuple[bool, str]]:
        n_workers  = min(os.cpu_count() or 4, 8)
        batch_size = max(500, len(self.envelopes) // (n_workers * _BATCH_SIZE_PER_WORKER_MULTIPLIER))
        all_data   = [(env.to_signing_dict(), env.signature, env.signer_public_key, env.sequence) for env in self.envelopes]
        batches    = [all_data[i:i+batch_size] for i in range(0, len(all_data), batch_size)]
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
        return {env.sequence: env.verify_signature() for env in self.envelopes}

    def _empty_summary(self) -> ReplaySummary:
        return ReplaySummary(
            total_entries=0, chain_valid=True, violations=[], valid_signatures=0,
            invalid_signatures=0, record_type_counts={}, agents_seen=[],
            gef_version=None, first_timestamp=None, last_timestamp=None,
        )