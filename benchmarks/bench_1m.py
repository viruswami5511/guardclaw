"""
1M GuardClaw Benchmark
Measures: write + full verify + stream verify + memory at each stage.
"""

import gc
import os
import shutil
import time
from datetime import datetime
from pathlib import Path

import psutil

from guardclaw import Ed25519KeyManager, GEFLedger, RecordType
from guardclaw.core.replay import ReplayEngine


def mem_mb(label: str) -> float:
    process = psutil.Process(os.getpid())
    mb = process.memory_info().rss / 1024 / 1024
    print(f"[{label}] Memory: {mb:.1f} MB")
    return mb


def benchmark_1m(bench_dir: Path):
    if bench_dir.exists():
        shutil.rmtree(bench_dir)
    bench_dir.mkdir()

    ledger_file = bench_dir / GEFLedger.LEDGER_FILENAME

    print("GuardClaw 1M Benchmark")
    print(f"Dir: {bench_dir.absolute()}")
    print("=" * 60)

    key = Ed25519KeyManager.generate()
    ledger = GEFLedger(
        key_manager=key,
        agent_id="bench-agent-1m",
        ledger_path=str(bench_dir),
    )
    print("Ledger created")
    mem_mb("after-ledger-init")

    total = 1_000_000
    t_write_start = time.time()
    for i in range(total):
        ledger.emit(
            record_type=RecordType.EXECUTION,
            payload={"seq": i, "data": "x" * 32},
        )
        if (i + 1) % 100_000 == 0:
            elapsed = time.time() - t_write_start
            rate = (i + 1) / elapsed
            print(f"  wrote {i+1:,}/{total:,} ({rate:,.0f} eps)")
    ledger.close()
    del ledger
    gc.collect()
    t_write = time.time() - t_write_start

    print(f"Wrote {total:,} entries")
    print(f"Write time: {t_write:.1f}s ({total / t_write:,.0f} eps)")
    mem_after_write = mem_mb("after-write")
    size_mb = ledger_file.stat().st_size / 1e6
    print(f"Ledger size: {size_mb:.1f} MB")

    # Full verify — fresh process memory state
    print("")
    print("Full verify (ReplayEngine.verify)")
    gc.collect()
    engine_full = ReplayEngine(silent=True)
    engine_full.load(str(ledger_file))
    t_full_start = time.time()
    summary_full = engine_full.verify()
    t_full = time.time() - t_full_start
    print(f"Entries: {summary_full.total_entries:,}")
    print(f"Time: {t_full:.1f}s ({summary_full.total_entries / t_full:,.0f} eps)")
    print(f"Chain valid: {summary_full.chain_valid}")
    print(f"Invalid sigs: {summary_full.invalid_signatures}")
    mem_after_full = mem_mb("after-full-verify")

    # Release full verify memory before stream verify
    del engine_full
    del summary_full
    gc.collect()
    time.sleep(1)
    mem_mb("after-full-verify-gc")

    # Stream verify — O(1) memory baseline
    print("")
    print("Stream verify (ReplayEngine.stream_verify)")
    engine_stream = ReplayEngine(silent=True)
    t_stream_start = time.time()
    summary_stream = engine_stream.stream_verify(str(ledger_file))
    t_stream = time.time() - t_stream_start
    print(f"Entries: {summary_stream.total_entries:,}")
    print(f"Time: {t_stream:.1f}s ({summary_stream.total_entries / t_stream:,.0f} eps)")
    print(f"Chain valid: {summary_stream.chain_valid}")
    print(f"Invalid sigs: {summary_stream.invalid_signatures}")
    mem_after_stream = mem_mb("after-stream-verify")

    print("")
    print("=" * 60)
    print("FINAL 1M RESULTS")
    print("=" * 60)
    print(f"Entries:                  {total:,}")
    print(f"Ledger size:              {size_mb:.1f} MB")
    print(f"Write speed:              {total / t_write:,.0f} entries/sec")
    print(f"Write memory:             {mem_after_write:.1f} MB")
    print(f"Full verify speed:        {total / t_full:,.0f} entries/sec")
    print(f"Full verify time:         {t_full:.1f}s")
    print(f"Full verify peak memory:  {mem_after_full:.1f} MB")
    print(f"Stream verify speed:      {total / t_stream:,.0f} entries/sec")
    print(f"Stream verify time:       {t_stream:.1f}s")
    print(f"Stream verify memory:     {mem_after_stream:.1f} MB")
    print("=" * 60)
    print("")
    print("Note: Full verify loads all envelopes into RAM (O(N) memory).")
    print("Note: Stream verify is O(1) memory regardless of ledger size.")


if __name__ == "__main__":
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Starting 1M benchmark...")
    benchmark_1m(Path("bench_1m"))
