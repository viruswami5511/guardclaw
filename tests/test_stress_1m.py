"""
GuardClaw — 1M Entry Concurrent Stress Test
Pre-release validation for v0.7.0

Focus:
- No pytest-timeout or external time limits.
- Measure write throughput, verify time, and memory usage.
"""

import threading
import time
import tracemalloc

import pytest
from guardclaw import GEFLedger, Ed25519KeyManager
from guardclaw.core.models import RecordType

TOTAL_ENTRIES   = 1_000_000
NUM_THREADS     = 8
ENTRIES_PER_THR = TOTAL_ENTRIES // NUM_THREADS

_written = 0
_lock = threading.Lock()


def writer_thread(ledger, count, errors, thread_id):
    global _written
    for i in range(count):
        try:
            # GEFLedger.emit: single-entry append, signatures and chain handled internally.
            ledger.emit(
                record_type=RecordType.EXECUTION,
                payload={
                    "thread": thread_id,
                    "seq": i,
                    "action": "stress.write",
                },
            )
            with _lock:
                _written += 1
        except Exception as e:
            errors.append(
                f"Thread {thread_id} @ {i}: "
                f"{type(e).__name__}: {str(e)}"
            )
            break  # stop on first error so we can see the first failure clearly


def progress_monitor(total, stop_event, t_start):
    bar_width = 30
    while not stop_event.is_set():
        time.sleep(5)
        done = _written
        pct = done / total if total else 0.0
        bar_fill = int(bar_width * pct)
        bar = "█" * bar_fill + "░" * (bar_width - bar_fill)
        elapsed = time.perf_counter() - t_start
        rate = done / elapsed if elapsed > 0 else 0.0
        eta = (total - done) / rate if rate > 0 else 0.0
        print(
            f"\r  [{bar}] {done:>9,}/{total:,}  "
            f"{pct*100:5.1f}%  "
            f"{rate:>9,.0f} e/s  "
            f"ETA {eta:5.0f}s  elapsed {elapsed:5.0f}s",
            end="",
            flush=True,
        )


@pytest.mark.slow  # marker only, no timeout
def test_concurrent_1m_writes(tmp_path):
    """
    1M concurrent appends into a single GEFLedger file.

    What you can read from this:
    - Write rate (entries/sec) under multi-threaded emit().
    - End-to-end verify_chain() latency and throughput.
    - Peak Python heap usage via tracemalloc over the whole test.
    """
    global _written
    _written = 0

    ledger_path = tmp_path / "stress.gef"
    key = Ed25519KeyManager.generate()

    ledger = GEFLedger(
        key_manager=key,
        agent_id="stress-agent",
        ledger_path=ledger_path,
    )

    errors: list[str] = []
    threads: list[threading.Thread] = []

    print(f"\n{'=' * 65}")
    print(f"  GuardClaw 1M Concurrent Stress Test")
    print(f"  Threads   : {NUM_THREADS}")
    print(f"  Entries   : {TOTAL_ENTRIES:,}")
    print(f"  Ledger    : {ledger_path}")
    print(f"{'=' * 65}")

    # Start memory tracking before heavy work
    tracemalloc.start()

    t_start = time.perf_counter()
    stop_event = threading.Event()

    mon = threading.Thread(
        target=progress_monitor,
        args=(TOTAL_ENTRIES, stop_event, t_start),
        daemon=True,
    )
    mon.start()

    for tid in range(NUM_THREADS):
        t = threading.Thread(
            target=writer_thread,
            args=(ledger, ENTRIES_PER_THR, errors, tid),
            daemon=False,
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    stop_event.set()
    mon.join(timeout=2.0)

    elapsed_write = time.perf_counter() - t_start
    current_mem_write, peak_mem_write = tracemalloc.get_traced_memory()

    print("\n\n  ── Write Results " + "─" * 44)
    print(f"  {'Entries written':<30}: {_written:,}")
    print(f"  {'Thread errors':<30}: {len(errors)}")
    print(f"  {'Elapsed (write)':<30}: {elapsed_write:.1f}s")
    write_rate = _written / elapsed_write if elapsed_write > 0 else 0.0
    print(f"  {'Write rate':<30}: {write_rate:,.0f} entries/sec")
    print(f"  {'Heap (current)':<30}: {current_mem_write / (1024 * 1024):.2f} MiB")
    print(f"  {'Heap (peak so far)':<30}: {peak_mem_write / (1024 * 1024):.2f} MiB")

    if errors:
        print("\n  ── Thread Errors " + "─" * 44)
        for e in errors:
            print(f"  {e}")

    assert not errors, "Threads crashed! See errors above."
    assert _written == TOTAL_ENTRIES, f"Lost entries! Expected {TOTAL_ENTRIES}, got {_written}"

    print(f"\n  ── Chain Verification " + "─" * 40)
    t_start_verify = time.perf_counter()

    # GEFLedger.verify_chain() will:
    # - Reload the ledger file.
    # - Recompute chain hashes and signatures.
    # - Return True if the chain is intact and signatures pass.
    result = ledger.verify_chain()

    elapsed_verify = time.perf_counter() - t_start_verify
    current_mem_final, peak_mem_final = tracemalloc.get_traced_memory()

    print(f"  {'Chain valid':<30}: {result}")
    print(f"  {'Verify time':<30}: {elapsed_verify:.1f}s")
    verify_rate = _written / elapsed_verify if elapsed_verify > 0 else 0.0
    print(f"  {'Verify rate':<30}: {verify_rate:,.0f} entries/sec")
    print(f"  {'Heap (current end)':<30}: {current_mem_final / (1024 * 1024):.2f} MiB")
    print(f"  {'Heap (peak overall)':<30}: {peak_mem_final / (1024 * 1024):.2f} MiB")

    # Close after verification
    if hasattr(ledger, "close"):
        ledger.close()

    tracemalloc.stop()

    assert result is True, "Hash chain corrupted under concurrency!"

    print(f"\n{'=' * 65}")
    print(f"  ✅  PASSED — 1M concurrent entries, zero loss, valid chain")
    print(f"{'=' * 65}\n")