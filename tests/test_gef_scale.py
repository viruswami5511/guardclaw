"""
tests/test_gef_scale.py

GEF Protocol Hardening Suite — Phase 1
========================================

This is not a unit test suite. This is a DURABILITY suite.

It answers one question:
    "Does GEF fail safely under pressure?"

Tests:

  SCALE
    SCALE-01  100K envelope write — throughput, latency, memory, file size
    SCALE-02  1M replay benchmark — envelopes/sec, sig verif throughput
    SCALE-03  Replay scales linearly (O(n)) — not O(n²)

  CRASH CONSISTENCY
    CRASH-01  Half-written JSON line detected and rejected
    CRASH-02  Truncated file (last line cut mid-char) detected
    CRASH-03  Empty last line ignored cleanly
    CRASH-04  Corrupted middle entry detected by replay
    CRASH-05  State restore after clean ledger is correct
    CRASH-06  State restore after corrupted tail emits RuntimeWarning

  CONCURRENCY
    CONC-01   10 threads × 1k emits — no duplicate sequence
    CONC-02   10 threads × 1k emits — no missing sequence
    CONC-03   10 threads × 1k emits — ledger file is valid JSONL

  FUZZ
    FUZZ-01   Flip 1 char in payload field → chain or sig breaks
    FUZZ-02   Flip 1 char in causal_hash → chain breaks
    FUZZ-03   Flip 1 char in nonce → sig breaks
    FUZZ-04   Flip 1 char in signature → sig fails
    FUZZ-05   Remove signature field → is_signed() False
    FUZZ-06   Reorder JSON keys on disk → replay still valid (JCS is key-order agnostic)
    FUZZ-07   100 random single-byte mutations → replay detects all

  BENCHMARKS (printed, not asserted — informational)
    BENCH-01  Emit throughput (envelopes/sec)
    BENCH-02  Sign throughput (signatures/sec)
    BENCH-03  Verify throughput (verifications/sec)
    BENCH-04  Replay throughput — sequential (envelopes/sec)
    BENCH-05  Canonical encode throughput (encodes/sec)
    BENCH-06  Replay throughput — parallel vs sequential comparison
"""

import gc
import json
import os
import random
import secrets
import tempfile
import threading
import time
import tracemalloc
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pytest

from guardclaw.core.canonical import canonical_json_encode
from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.models import (
    ExecutionEnvelope,
    GEF_VERSION,
    GENESIS_HASH,
    RecordType,
)
from guardclaw.core.replay import ReplayEngine
from guardclaw.core.emitter import GEFLedger


# ─────────────────────────────────────────────────────────────
# Tuneable constants
# ─────────────────────────────────────────────────────────────

SCALE_WRITE_COUNT   = 100_000
SCALE_REPLAY_COUNT  = 1_000_000
LINEARITY_SAMPLES   = [1_000, 5_000, 10_000, 50_000]
CONC_THREADS        = 10
CONC_EMITS_PER_THR  = 1_000
FUZZ_RANDOM_COUNT   = 100


# ─────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────

def make_chain_to_file(
    path: Path,
    count: int,
    key: Optional[Ed25519KeyManager] = None,
) -> Ed25519KeyManager:
    """
    Write `count` signed envelopes to `path` as JSONL.
    Returns the key used. Fast path — does not use GEFLedger.
    """
    if key is None:
        key = Ed25519KeyManager.generate()

    prev = None
    with open(path, "w", encoding="utf-8") as f:
        for i in range(count):
            env = ExecutionEnvelope.create(
                record_type=       RecordType.EXECUTION,
                agent_id=          "bench-agent",
                signer_public_key= key.public_key_hex,
                sequence=          i,
                payload=           {"seq": i, "data": "x" * 32},
                prev=              prev,
            ).sign(key)
            f.write(json.dumps(env.to_dict()) + "\n")
            prev = env
    return key


def flip_one_char_in_field(line: str, field: str) -> str:
    """
    Parse a JSONL line, flip one character in the specified field value,
    return the mutated JSON line.
    """
    data = json.loads(line)

    if isinstance(data[field], dict):
        s   = json.dumps(data[field], sort_keys=True)
        idx = random.randint(1, len(s) - 2)
        s   = s[:idx] + ("A" if s[idx] != "A" else "B") + s[idx + 1:]
        try:
            data[field] = json.loads(s)
        except json.JSONDecodeError:
            data[field] = {"mutated": True}
    elif isinstance(data[field], str) and len(data[field]) > 4:
        s        = data[field]
        idx      = random.randint(1, len(s) - 2)
        new_char = "f" if s[idx] != "f" else "0"
        data[field] = s[:idx] + new_char + s[idx + 1:]
    else:
        data[field] = "MUTATED"

    return json.dumps(data)


# ─────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def shared_key():
    """One key for the whole module — avoids keygen overhead in benchmarks."""
    return Ed25519KeyManager.generate()


@pytest.fixture
def tmp_ledger(tmp_path):
    return tmp_path / "ledger.jsonl"


# ─────────────────────────────────────────────────────────────
# SCALE TESTS
# ─────────────────────────────────────────────────────────────

class TestScale:

    def test_SCALE01_100k_write(self, shared_key, tmp_ledger):
        """
        SCALE-01: Write 100K envelopes.
        Measures: throughput, p95 latency, memory growth, file size.
        Asserts: memory growth < 50MB, p99 latency < 100ms.
        """
        latencies = []

        tracemalloc.start()
        gc.collect()
        mem_before = tracemalloc.get_traced_memory()[0]

        prev = None
        with open(tmp_ledger, "w", encoding="utf-8") as f:
            for i in range(SCALE_WRITE_COUNT):
                t0  = time.perf_counter()
                env = ExecutionEnvelope.create(
                    record_type=       RecordType.EXECUTION,
                    agent_id=          "scale-agent",
                    signer_public_key= shared_key.public_key_hex,
                    sequence=          i,
                    payload=           {"seq": i},
                    prev=              prev,
                ).sign(shared_key)
                f.write(json.dumps(env.to_dict()) + "\n")
                prev = env
                latencies.append(time.perf_counter() - t0)

        mem_after  = tracemalloc.get_traced_memory()[0]
        tracemalloc.stop()

        file_mb    = tmp_ledger.stat().st_size / (1024 * 1024)
        mem_growth = (mem_after - mem_before) / (1024 * 1024)

        latencies.sort()
        median     = latencies[len(latencies) // 2]
        p95        = latencies[int(len(latencies) * 0.95)]
        p99        = latencies[int(len(latencies) * 0.99)]
        throughput = SCALE_WRITE_COUNT / sum(latencies)

        print(f"\n{'─'*60}")
        print(f"  SCALE-01  100K Write Results")
        print(f"{'─'*60}")
        print(f"  Throughput  : {throughput:>10,.0f} envelopes/sec")
        print(f"  Median      : {median * 1000:>10.3f} ms")
        print(f"  p95         : {p95 * 1000:>10.3f} ms")
        print(f"  p99         : {p99 * 1000:>10.3f} ms")
        print(f"  File size   : {file_mb:>10.2f} MB")
        print(f"  Memory δ    : {mem_growth:>10.2f} MB")
        print(f"{'─'*60}")

        assert mem_growth < 50, (
            f"Memory growth {mem_growth:.1f} MB exceeds 50 MB — "
            f"likely O(n) chain list accumulation"
        )
        assert p99 < 0.1, (
            f"p99 latency {p99 * 1000:.1f}ms exceeds 100ms — "
            f"possible O(n) bug in sign or chain"
        )
        assert tmp_ledger.stat().st_size > 0

    def test_SCALE02_1m_replay(self, shared_key, tmp_path):
        """
        SCALE-02: Replay 1M envelopes with parallel signature verification.

        Threshold rationale:
            Python Ed25519 single-thread ceiling: ~2,950 envelopes/sec
            With ProcessPoolExecutor (any machine ≥ 2 cores): ~5,000+/sec
            Go/Rust target: ~200,000/sec

        Assertions:
            1. Chain must be 100% valid (no violations)
            2. All 1M signatures must verify
            3. Parallel replay rate must exceed Python single-thread ceiling
               (proves parallelism is actually engaged and helping)
        """
        ledger_path = tmp_path / "1m_ledger.jsonl"

        # Build ledger — write phase (not timed against replay threshold)
        write_start = time.perf_counter()
        make_chain_to_file(ledger_path, SCALE_REPLAY_COUNT, shared_key)
        write_time  = time.perf_counter() - write_start

        file_mb = ledger_path.stat().st_size / (1024 * 1024)

        # ── Parallel replay (primary path) ────────────────────
        engine_par = ReplayEngine(parallel=True)

        load_start = time.perf_counter()
        engine_par.load(ledger_path)
        load_time  = time.perf_counter() - load_start

        verify_start = time.perf_counter()
        summary      = engine_par.verify()
        verify_time  = time.perf_counter() - verify_start

        total_time   = load_time + verify_time
        replay_rate  = SCALE_REPLAY_COUNT / total_time
        sig_rate     = summary.valid_signatures / verify_time if verify_time > 0 else 0

        # ── Sequential replay (for comparison only) ───────────
        engine_seq   = ReplayEngine(parallel=False)
        engine_seq.envelopes = engine_par.envelopes  # reuse loaded envelopes
        t0           = time.perf_counter()
        engine_seq.verify()
        seq_verify_time = time.perf_counter() - t0

        speedup = seq_verify_time / verify_time if verify_time > 0 else 1.0

        n_workers = min(os.cpu_count() or 4, 8)

        print(f"\n{'─'*60}")
        print(f"  SCALE-02  1M Replay Results")
        print(f"{'─'*60}")
        print(f"  CPU cores   : {n_workers}")
        print(f"  Write time  : {write_time:>10.2f} sec")
        print(f"  File size   : {file_mb:>10.2f} MB")
        print(f"  Load time   : {load_time:>10.2f} sec")
        print(f"  Verify (par): {verify_time:>10.2f} sec")
        print(f"  Verify (seq): {seq_verify_time:>10.2f} sec")
        print(f"  Speedup     : {speedup:>10.2f}x")
        print(f"  Total time  : {total_time:>10.2f} sec")
        print(f"  Replay rate : {replay_rate:>10,.0f} envelopes/sec")
        print(f"  Sig rate    : {sig_rate:>10,.0f} sigs/sec")
        print(f"  Chain valid : {summary.chain_valid}")
        print(f"  Violations  : {len(summary.violations)}")
        print(f"{'─'*60}")
        print(f"  Python single-thread ceiling: ~2,950/sec  (Ed25519 bound)")
        print(f"  Go/Rust target              : ~200,000/sec")
        print(f"{'─'*60}")

        # ── Correctness assertions ─────────────────────────────
        assert summary.chain_valid,                     "1M chain must be fully valid"
        assert summary.total_entries == SCALE_REPLAY_COUNT
        assert summary.valid_signatures == SCALE_REPLAY_COUNT

        # ── Performance assertion ──────────────────────────────
        # Threshold: must exceed Python's proven single-thread ceiling.
        # Any machine with ≥2 cores running parallel verification exceeds this.
        # This proves parallelism engaged and delivered measurable benefit.
        SINGLE_THREAD_CEILING = 2_950
        assert replay_rate > SINGLE_THREAD_CEILING, (
            f"Parallel replay rate {replay_rate:.0f}/sec did not exceed "
            f"single-thread ceiling of {SINGLE_THREAD_CEILING}/sec. "
            f"ProcessPoolExecutor may have fallen back to sequential. "
            f"Check: Windows spawn overhead, CPU count, batch sizing."
        )

    def test_SCALE03_replay_linearity(self, shared_key, tmp_path):
        """
        SCALE-03: Replay must scale O(n), not O(n²).
        Asserts: time[max_n] / time[min_n] < max_n/min_n × 1.5
        """
        times = {}

        for count in LINEARITY_SAMPLES:
            ledger_path = tmp_path / f"linearity_{count}.jsonl"
            make_chain_to_file(ledger_path, count, shared_key)

            engine = ReplayEngine(parallel=False)  # sequential for pure linearity test
            engine.load(ledger_path)

            t0 = time.perf_counter()
            engine.verify()
            times[count] = time.perf_counter() - t0

        print(f"\n{'─'*60}")
        print(f"  SCALE-03  Linearity Check (sequential)")
        print(f"{'─'*60}")
        for count, t in sorted(times.items()):
            rate = count / t
            print(f"  {count:>8,}  →  {t:.3f}s  ({rate:>9,.0f}/sec)")
        print(f"{'─'*60}")

        min_n, max_n = LINEARITY_SAMPLES[0], LINEARITY_SAMPLES[-1]
        size_ratio   = max_n / min_n
        time_ratio   = times[max_n] / times[min_n]

        print(f"  Size ratio  : {size_ratio:.1f}x")
        print(f"  Time ratio  : {time_ratio:.1f}x")
        print(f"  Expected    : < {size_ratio * 1.5:.1f}x  (linear + 50% headroom)")

        assert time_ratio < size_ratio * 1.5, (
            f"Replay is super-linear: {size_ratio:.0f}x size → {time_ratio:.1f}x time. "
            f"Possible O(n²) in verify() or chain hash computation."
        )


# ─────────────────────────────────────────────────────────────
# CRASH CONSISTENCY TESTS
# ─────────────────────────────────────────────────────────────

class TestCrashConsistency:

    def test_CRASH01_half_written_json_line(self, shared_key, tmp_ledger):
        """
        CRASH-01: Half-written last line must be detected.
        Simulates: process killed mid-write.
        """
        key  = Ed25519KeyManager.generate()
        prev = None
        with open(tmp_ledger, "w", encoding="utf-8") as f:
            for i in range(3):
                env = ExecutionEnvelope.create(
                    record_type=       RecordType.EXECUTION,
                    agent_id=          "crash-agent",
                    signer_public_key= key.public_key_hex,
                    sequence=          i,
                    payload=           {"seq": i},
                    prev=              prev,
                ).sign(key)
                f.write(json.dumps(env.to_dict()) + "\n")
                prev = env
            f.write('{"gef_version": "1.0", "record_id": "gef-')

        engine = ReplayEngine()
        with pytest.raises((ValueError, json.JSONDecodeError)):
            engine.load(tmp_ledger)

    def test_CRASH02_truncated_last_line(self, shared_key, tmp_ledger):
        """
        CRASH-02: Last line truncated mid-character must be detected.
        """
        key   = Ed25519KeyManager.generate()
        prev  = None
        lines = []
        for i in range(5):
            env = ExecutionEnvelope.create(
                record_type=       RecordType.EXECUTION,
                agent_id=          "crash-agent",
                signer_public_key= key.public_key_hex,
                sequence=          i,
                payload=           {"seq": i},
                prev=              prev,
            ).sign(key)
            lines.append(json.dumps(env.to_dict()) + "\n")
            prev = env

        with open(tmp_ledger, "w", encoding="utf-8") as f:
            for line in lines[:-1]:
                f.write(line)
            f.write(lines[-1][:len(lines[-1]) // 2])

        engine = ReplayEngine()
        with pytest.raises((ValueError, json.JSONDecodeError)):
            engine.load(tmp_ledger)

    def test_CRASH03_empty_last_line_ignored(self, shared_key, tmp_ledger):
        """
        CRASH-03: A trailing newline (empty last line) must not cause failure.
        """
        key  = Ed25519KeyManager.generate()
        prev = None
        with open(tmp_ledger, "w", encoding="utf-8") as f:
            for i in range(5):
                env = ExecutionEnvelope.create(
                    record_type=       RecordType.EXECUTION,
                    agent_id=          "crash-agent",
                    signer_public_key= key.public_key_hex,
                    sequence=          i,
                    payload=           {"seq": i},
                    prev=              prev,
                ).sign(key)
                f.write(json.dumps(env.to_dict()) + "\n")
                prev = env
            f.write("\n\n\n")

        engine = ReplayEngine()
        engine.load(tmp_ledger)
        summary = engine.verify()

        assert summary.total_entries == 5
        assert summary.chain_valid

    def test_CRASH04_corrupted_middle_entry(self, shared_key, tmp_ledger):
        """
        CRASH-04: A corrupted middle entry must be detected by replay.
        """
        key   = Ed25519KeyManager.generate()
        prev  = None
        lines = []
        for i in range(10):
            env = ExecutionEnvelope.create(
                record_type=       RecordType.EXECUTION,
                agent_id=          "crash-agent",
                signer_public_key= key.public_key_hex,
                sequence=          i,
                payload=           {"seq": i},
                prev=              prev,
            ).sign(key)
            lines.append(json.dumps(env.to_dict()))
            prev = env

        data              = json.loads(lines[5])
        data["signature"] = "A" * len(data["signature"])
        lines[5]          = json.dumps(data)

        with open(tmp_ledger, "w", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")

        engine  = ReplayEngine()
        engine.load(tmp_ledger)
        summary = engine.verify()

        assert not summary.chain_valid
        assert summary.invalid_signatures >= 1
        assert any(
            v.at_sequence == 5 and v.violation_type == "invalid_signature"
            for v in summary.violations
        )

    def test_CRASH05_state_restore_correct(self, tmp_path):
        """
        CRASH-05: After clean emit → restart → GEFLedger._restore_state()
        sequence and last_envelope must match the last written entry exactly.
        """
        key     = Ed25519KeyManager.generate()
        ledger1 = GEFLedger(key, "restore-agent", str(tmp_path / "ledger"))

        for i in range(20):
            ledger1.emit(RecordType.EXECUTION, {"i": i})

        stats_before = ledger1.get_stats()

        ledger2      = GEFLedger(key, "restore-agent", str(tmp_path / "ledger"))
        stats_after  = ledger2.get_stats()

        assert stats_after["next_sequence"]  == stats_before["next_sequence"]
        assert stats_after["last_record_id"] == stats_before["last_record_id"]

        env = ledger2.emit(RecordType.EXECUTION, {"after_restore": True})
        assert env.verify_signature()
        assert env.sequence == 20

    def test_CRASH06_state_restore_corrupt_tail_warns(self, tmp_path):
        """
        CRASH-06: If last line is corrupted JSON, _restore_state() must
        emit RuntimeWarning and NOT raise.
        """
        key     = Ed25519KeyManager.generate()
        ledger1 = GEFLedger(key, "restore-agent", str(tmp_path / "ledger"))

        for i in range(5):
            ledger1.emit(RecordType.EXECUTION, {"i": i})

        ledger_file = tmp_path / "ledger" / "ledger.jsonl"
        with open(ledger_file, "a", encoding="utf-8") as f:
            f.write('{"broken": true, "gef_version": "1.0"\n')

        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            ledger2 = GEFLedger(key, "restore-agent", str(tmp_path / "ledger"))
            assert any(issubclass(x.category, RuntimeWarning) for x in w), (
                "RuntimeWarning expected on corrupt tail restore"
            )


# ─────────────────────────────────────────────────────────────
# CONCURRENCY TESTS
# ─────────────────────────────────────────────────────────────

class TestConcurrency:

    def test_CONC01_no_duplicate_sequence(self, tmp_path):
        """
        CONC-01: 10 threads × 1k emits on one GEFLedger → no duplicate sequences.
        """
        key    = Ed25519KeyManager.generate()
        ledger = GEFLedger(key, "conc-agent", str(tmp_path / "ledger"))
        seqs   = []
        lock   = threading.Lock()
        errors = []

        def emit_batch():
            for _ in range(CONC_EMITS_PER_THR):
                try:
                    env = ledger.emit(RecordType.EXECUTION, {"t": threading.get_ident()})
                    with lock:
                        seqs.append(env.sequence)
                except Exception as e:
                    with lock:
                        errors.append(str(e))

        threads = [threading.Thread(target=emit_batch) for _ in range(CONC_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Emit errors: {errors[:3]}"
        assert len(seqs) == CONC_THREADS * CONC_EMITS_PER_THR
        assert len(seqs) == len(set(seqs)), "Duplicate sequences detected"

    def test_CONC02_no_missing_sequence(self, tmp_path):
        """
        CONC-02: After concurrent emit, sequences form a complete range [0, total).
        """
        key    = Ed25519KeyManager.generate()
        ledger = GEFLedger(key, "conc-agent", str(tmp_path / "ledger"))
        seqs   = []
        lock   = threading.Lock()

        def emit_batch():
            for _ in range(CONC_EMITS_PER_THR):
                env = ledger.emit(RecordType.EXECUTION, {"t": threading.get_ident()})
                with lock:
                    seqs.append(env.sequence)

        threads = [threading.Thread(target=emit_batch) for _ in range(CONC_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        expected = set(range(CONC_THREADS * CONC_EMITS_PER_THR))
        missing  = expected - set(seqs)
        assert not missing, f"Missing sequences: {sorted(missing)[:10]}"

    def test_CONC03_ledger_file_valid_after_concurrent_emit(self, tmp_path):
        """
        CONC-03: After concurrent emit, on-disk ledger must be fully valid.
        """
        key    = Ed25519KeyManager.generate()
        ledger = GEFLedger(key, "conc-agent", str(tmp_path / "ledger"))

        def emit_batch():
            for _ in range(CONC_EMITS_PER_THR):
                ledger.emit(RecordType.EXECUTION, {"t": threading.get_ident()})

        threads = [threading.Thread(target=emit_batch) for _ in range(CONC_THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        ledger_file = tmp_path / "ledger" / "ledger.jsonl"
        engine      = ReplayEngine()
        engine.load(ledger_file)
        summary = engine.verify()

        total = CONC_THREADS * CONC_EMITS_PER_THR
        assert summary.total_entries   == total
        assert summary.chain_valid,       "Chain must be valid after concurrent emit"
        assert summary.valid_signatures  == total


# ─────────────────────────────────────────────────────────────
# FUZZ TESTS
# ─────────────────────────────────────────────────────────────

class TestFuzz:

    def _make_clean_ledger(
        self, tmp_path: Path, count: int = 10
    ) -> Tuple[Path, Ed25519KeyManager]:
        key  = Ed25519KeyManager.generate()
        path = tmp_path / "fuzz_ledger.jsonl"
        make_chain_to_file(path, count, key)
        return path, key

    def test_FUZZ01_flip_payload_field(self, tmp_path):
        """FUZZ-01: Flip one char in payload → sig or chain failure."""
        path, _ = self._make_clean_ledger(tmp_path)
        lines   = path.read_text(encoding="utf-8").splitlines()
        lines[3] = flip_one_char_in_field(lines[3], "payload")

        mutated = tmp_path / "mutated.jsonl"
        mutated.write_text("\n".join(lines) + "\n", encoding="utf-8")

        engine = ReplayEngine()
        engine.load(mutated)
        summary = engine.verify()
        assert not summary.chain_valid

    def test_FUZZ02_flip_causal_hash(self, tmp_path):
        """FUZZ-02: Flip one char in causal_hash → chain break."""
        path, _ = self._make_clean_ledger(tmp_path)
        lines   = path.read_text(encoding="utf-8").splitlines()

        data     = json.loads(lines[5])
        ch       = list(data["causal_hash"])
        ch[8]    = "f" if ch[8] != "f" else "0"
        data["causal_hash"] = "".join(ch)
        lines[5] = json.dumps(data)

        mutated = tmp_path / "mutated.jsonl"
        mutated.write_text("\n".join(lines) + "\n", encoding="utf-8")

        engine = ReplayEngine()
        engine.load(mutated)
        summary = engine.verify()
        violations = [
            v for v in summary.violations
            if v.violation_type in ("chain_break", "invalid_signature")
        ]
        assert violations

    def test_FUZZ03_flip_nonce(self, tmp_path):
        """FUZZ-03: Flip one char in nonce → signature invalid."""
        path, _ = self._make_clean_ledger(tmp_path)
        lines   = path.read_text(encoding="utf-8").splitlines()

        data     = json.loads(lines[2])
        n        = list(data["nonce"])
        n[4]     = "f" if n[4] != "f" else "0"
        data["nonce"] = "".join(n)
        lines[2] = json.dumps(data)

        mutated = tmp_path / "mutated.jsonl"
        mutated.write_text("\n".join(lines) + "\n", encoding="utf-8")

        engine = ReplayEngine()
        engine.load(mutated)
        summary = engine.verify()
        assert any(v.violation_type == "invalid_signature" for v in summary.violations)

    def test_FUZZ04_flip_signature(self, tmp_path):
        """FUZZ-04: Flip one char in signature → verify fails."""
        path, _ = self._make_clean_ledger(tmp_path)
        lines   = path.read_text(encoding="utf-8").splitlines()

        data     = json.loads(lines[1])
        sig      = list(data["signature"])
        sig[5]   = "A" if sig[5] != "A" else "B"
        data["signature"] = "".join(sig)
        lines[1] = json.dumps(data)

        mutated = tmp_path / "mutated.jsonl"
        mutated.write_text("\n".join(lines) + "\n", encoding="utf-8")

        engine = ReplayEngine()
        engine.load(mutated)
        summary = engine.verify()
        assert summary.invalid_signatures >= 1

    def test_FUZZ05_remove_signature_field(self, tmp_path):
        """FUZZ-05: Remove signature field → detected as invalid."""
        path, _ = self._make_clean_ledger(tmp_path)
        lines   = path.read_text(encoding="utf-8").splitlines()

        data = json.loads(lines[0])
        del data["signature"]
        lines[0] = json.dumps(data)

        mutated = tmp_path / "mutated.jsonl"
        mutated.write_text("\n".join(lines) + "\n", encoding="utf-8")

        engine = ReplayEngine()
        engine.load(mutated)
        summary = engine.verify()
        assert summary.invalid_signatures >= 1

    def test_FUZZ06_reordered_json_keys_still_valid(self, tmp_path):
        """
        FUZZ-06: Reordering JSON keys on disk must NOT break replay.
        JCS produces deterministic canonical form regardless of storage key order.
        """
        path, _ = self._make_clean_ledger(tmp_path)
        lines   = path.read_text(encoding="utf-8").splitlines()

        reordered = [
            json.dumps(json.loads(line), sort_keys=True)
            for line in lines
        ]

        mutated = tmp_path / "reordered.jsonl"
        mutated.write_text("\n".join(reordered) + "\n", encoding="utf-8")

        engine = ReplayEngine()
        engine.load(mutated)
        summary = engine.verify()

        assert summary.chain_valid
        assert summary.valid_signatures == 10

    def test_FUZZ07_100_random_mutations_all_detected(self, tmp_path):
        """
        FUZZ-07: 100 distinct single-field mutations — zero false negatives.
        """
        MUTABLE_FIELDS = [
            "payload", "causal_hash", "nonce", "agent_id",
            "record_type", "timestamp", "sequence",
        ]

        false_negatives = []
        key = Ed25519KeyManager.generate()

        for attempt in range(FUZZ_RANDOM_COUNT):
            ledger_path = tmp_path / f"fuzz_{attempt}.jsonl"
            make_chain_to_file(ledger_path, 5, key)
            lines     = ledger_path.read_text(encoding="utf-8").splitlines()
            line_idx  = random.randint(0, len(lines) - 1)
            field     = random.choice(MUTABLE_FIELDS)

            try:
                mutated_line = flip_one_char_in_field(lines[line_idx], field)
            except Exception:
                continue

            if field == "sequence":
                data = json.loads(lines[line_idx])
                data["sequence"] = data["sequence"] + 9999
                mutated_line = json.dumps(data)

            lines[line_idx] = mutated_line
            mutated_path    = tmp_path / f"fuzz_{attempt}_mutated.jsonl"
            mutated_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

            try:
                engine = ReplayEngine()
                engine.load(mutated_path)
                summary = engine.verify()

                if summary.chain_valid and summary.invalid_signatures == 0:
                    false_negatives.append({
                        "attempt": attempt,
                        "line":    line_idx,
                        "field":   field,
                    })
            except (ValueError, json.JSONDecodeError):
                pass  # Schema/parse error = mutation was detected

        assert not false_negatives, (
            f"FUZZ-07: {len(false_negatives)} mutations NOT detected:\n"
            + "\n".join(
                f"  [{f['attempt']}] line={f['line']} field={f['field']}"
                for f in false_negatives[:5]
            )
        )


# ─────────────────────────────────────────────────────────────
# BENCHMARKS — Informational Only
# ─────────────────────────────────────────────────────────────

class TestBenchmarks:
    """
    Standalone micro-benchmarks. Printed to stdout. No assertions.
    Run with: pytest tests/test_gef_scale.py::TestBenchmarks -v -s
    """

    BENCH_N = 10_000

    def test_BENCH01_emit_throughput(self, shared_key, tmp_path):
        """BENCH-01: Raw emit throughput (create + sign + write)."""
        ledger = GEFLedger(shared_key, "bench-agent", str(tmp_path / "ledger"))
        t0     = time.perf_counter()
        for i in range(self.BENCH_N):
            ledger.emit(RecordType.EXECUTION, {"i": i})
        elapsed = time.perf_counter() - t0
        print(f"\n  BENCH-01  Emit throughput      : {self.BENCH_N / elapsed:>10,.0f} envelopes/sec")

    def test_BENCH02_sign_throughput(self, shared_key, tmp_path):
        """BENCH-02: Sign throughput (Ed25519 sign over canonical bytes)."""
        env  = ExecutionEnvelope.create(
            record_type=       RecordType.EXECUTION,
            agent_id=          "bench",
            signer_public_key= shared_key.public_key_hex,
            sequence=          0,
            payload=           {"bench": True},
        )
        data = env.canonical_bytes_for_signing()
        t0   = time.perf_counter()
        for _ in range(self.BENCH_N):
            shared_key.sign(data)
        elapsed = time.perf_counter() - t0
        print(f"\n  BENCH-02  Sign throughput       : {self.BENCH_N / elapsed:>10,.0f} sigs/sec")

    def test_BENCH03_verify_throughput(self, shared_key, tmp_path):
        """BENCH-03: Verify throughput (verify_detached, single-thread)."""
        env = ExecutionEnvelope.create(
            record_type=       RecordType.EXECUTION,
            agent_id=          "bench",
            signer_public_key= shared_key.public_key_hex,
            sequence=          0,
            payload=           {"bench": True},
        ).sign(shared_key)
        data   = env.canonical_bytes_for_signing()
        sig    = env.signature
        pubkey = env.signer_public_key
        t0     = time.perf_counter()
        for _ in range(self.BENCH_N):
            Ed25519KeyManager.verify_detached(data, sig, pubkey)
        elapsed = time.perf_counter() - t0
        print(f"\n  BENCH-03  Verify (single-thread): {self.BENCH_N / elapsed:>10,.0f} sigs/sec")

    def test_BENCH04_replay_sequential(self, shared_key, tmp_path):
        """BENCH-04: Sequential replay throughput."""
        ledger_path = tmp_path / "bench_replay.jsonl"
        make_chain_to_file(ledger_path, self.BENCH_N, shared_key)

        engine = ReplayEngine(parallel=False)
        t0     = time.perf_counter()
        engine.load(ledger_path)
        engine.verify()
        elapsed = time.perf_counter() - t0
        print(f"\n  BENCH-04  Replay (sequential)   : {self.BENCH_N / elapsed:>10,.0f} envelopes/sec")

    def test_BENCH05_canonical_encode_throughput(self, shared_key):
        """BENCH-05: JCS canonical encode throughput."""
        env = ExecutionEnvelope.create(
            record_type=       RecordType.EXECUTION,
            agent_id=          "bench",
            signer_public_key= shared_key.public_key_hex,
            sequence=          0,
            payload=           {"key": "value", "nested": {"a": 1}},
        )
        d  = env.to_signing_dict()
        t0 = time.perf_counter()
        for _ in range(self.BENCH_N):
            canonical_json_encode(d)
        elapsed = time.perf_counter() - t0
        print(f"\n  BENCH-05  Canonical encode      : {self.BENCH_N / elapsed:>10,.0f} encodes/sec")

    def test_BENCH06_parallel_vs_sequential(self, shared_key, tmp_path):
        """
        BENCH-06: Parallel vs sequential replay — shows real-world speedup.
        The ratio is your parallelism efficiency on this machine.
        """
        ledger_path = tmp_path / "bench_par.jsonl"
        make_chain_to_file(ledger_path, self.BENCH_N, shared_key)

        engine_s = ReplayEngine(parallel=False)
        engine_s.load(ledger_path)
        t0 = time.perf_counter()
        engine_s.verify()
        seq_time = time.perf_counter() - t0

        engine_p = ReplayEngine(parallel=True)
        engine_p.load(ledger_path)
        t0 = time.perf_counter()
        engine_p.verify()
        par_time = time.perf_counter() - t0

        speedup = seq_time / par_time if par_time > 0 else 1.0

        print(f"\n  BENCH-06  Sequential            : {self.BENCH_N / seq_time:>10,.0f} envelopes/sec")
        print(f"  BENCH-06  Parallel              : {self.BENCH_N / par_time:>10,.0f} envelopes/sec")
        print(f"  BENCH-06  Speedup               : {speedup:>10.2f}x  ({os.cpu_count()} CPUs)")
