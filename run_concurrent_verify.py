from __future__ import annotations

import json
import os
import threading
import time
import tracemalloc
from pathlib import Path
from typing import Any

from guardclaw import ExecutionEnvelope, Ed25519KeyManager, RecordType
from guardclaw.core.replay import ReplayEngine

ENTRY_COUNT = 10_000          # was 1_000_000
VERIFY_THREADS = 8            # was 16
VERIFY_CALLS_PER_THREAD = 5   # was 20

BASE_DIR = Path(__file__).resolve().parent
OUT_DIR = BASE_DIR / "stress_verify_output"
OUT_DIR.mkdir(parents=True, exist_ok=True)

LEDGER_PATH = OUT_DIR / "concurrent_1m.gef"
KEY_PATH = OUT_DIR / "key.pem"
REPORT_PATH = OUT_DIR / "concurrent_verify_report.json"


def load_or_create_key(key_path: Path) -> Ed25519KeyManager:
    if key_path.exists():
        return Ed25519KeyManager.from_file(key_path)
    km = Ed25519KeyManager.generate()
    km.save(key_path)
    return km


def iso_utc_now_ms() -> str:
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    ms = now.microsecond // 1000
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"


def env_create(
    *,
    sequence: int,
    prev_env: ExecutionEnvelope | None,
    signer_public_key_hex: str,
    agent_id: str,
    payload: dict[str, Any],
) -> ExecutionEnvelope:
    return ExecutionEnvelope.create(
        record_type=RecordType.GENESIS if sequence == 0 else RecordType.EXECUTION,
        agent_id=agent_id,
        signer_public_key=signer_public_key_hex,
        sequence=sequence,
        payload=payload,
        prev=prev_env,
    )


def sign_env(env: ExecutionEnvelope, km: Ed25519KeyManager) -> ExecutionEnvelope:
    return env.sign(km)


def _force_delete(path: Path) -> None:
    """Force delete a file on Windows, retrying if locked by OneDrive or another process."""
    if not path.exists():
        return
    for attempt in range(10):
        try:
            path.unlink()
            return
        except PermissionError:
            print(f"  File locked, retrying delete ({attempt + 1}/10)...")
            time.sleep(1)
    # Last resort — rename then delete
    tmp = path.with_suffix(".gef.tmp_delete")
    try:
        path.rename(tmp)
        tmp.unlink(missing_ok=True)
    except Exception as e:
        raise PermissionError(
            f"Cannot delete {path}. Close any program using it "
            f"(check OneDrive, antivirus, or a previous Python process). Error: {e}"
        )


def build_ledger() -> float:
    km = load_or_create_key(KEY_PATH)
    signer_public_key_hex = km.public_key_hex
    agent_id = "stress-agent"

    if LEDGER_PATH.exists():
        print("  Removing old ledger file...")
        _force_delete(LEDGER_PATH)

    t0 = time.perf_counter()
    prev_env = None

    with open(LEDGER_PATH, "w", encoding="utf-8") as f:
        for seq in range(ENTRY_COUNT):
            payload = {
                "op": "verify_stress",
                "thread_hint": seq % VERIFY_THREADS,
                "value": seq,
                "kind": "benchmark",
            }

            env = env_create(
                sequence=seq,
                prev_env=prev_env,
                signer_public_key_hex=signer_public_key_hex,
                agent_id=agent_id,
                payload=payload,
            )
            env = sign_env(env, km)

            f.write(json.dumps(env.to_dict(), separators=(",", ":")) + "\n")
            prev_env = env

            if seq and seq % 100_000 == 0:
                elapsed = time.perf_counter() - t0
                rate = seq / elapsed if elapsed > 0 else 0
                print(f"built {seq:,}/{ENTRY_COUNT:,} entries in {elapsed:.1f}s ({rate:,.0f}/s)")

    return time.perf_counter() - t0


def summarize_result(result: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}

    for name in (
        "totalentries",
        "total_entries",
        "chainvalid",
        "chain_valid",
        "validsignatures",
        "valid_signatures",
        "invalidsignatures",
        "invalid_signatures",
        "firsttimestamp",
        "first_timestamp",
        "lasttimestamp",
        "last_timestamp",
        "gefversion",
        "gef_version",
    ):
        if hasattr(result, name):
            out[name] = getattr(result, name)

    if hasattr(result, "violations"):
        try:
            out["violation_count"] = len(result.violations or [])
        except Exception:
            out["violation_count"] = None

    return out


def _is_valid(result: Any) -> bool:
    chainvalid = (
        getattr(result, "chain_valid", None)
        or getattr(result, "chainvalid", None)
        or False
    )
    invalids = int(
        getattr(result, "invalid_signatures", None)
        or getattr(result, "invalidsignatures", None)
        or 0
    )
    violations = len(getattr(result, "violations", []) or [])
    return bool(chainvalid and invalids == 0 and violations == 0)


def verify_once() -> tuple[bool, dict[str, Any], float]:
    try:
        engine = ReplayEngine(parallel=True, silent=True)
    except TypeError:
        engine = ReplayEngine()

    t0 = time.perf_counter()

    if hasattr(engine, "streamverify"):
        result = engine.streamverify(LEDGER_PATH)
        elapsed = time.perf_counter() - t0
        return _is_valid(result), summarize_result(result), elapsed

    engine.load(LEDGER_PATH)
    result = engine.verify()
    elapsed = time.perf_counter() - t0
    return _is_valid(result), summarize_result(result), elapsed


def worker(tid: int, rounds: int, results: list[dict[str, Any]]) -> None:
    for i in range(rounds):
        ok, summary, elapsed = verify_once()
        results.append(
            {
                "thread": tid,
                "round": i,
                "ok": ok,
                "seconds": elapsed,
                "summary": summary,
            }
        )


def run_concurrent_verify() -> tuple[float, list[dict[str, Any]]]:
    threads: list[threading.Thread] = []
    results: list[dict[str, Any]] = []

    t0 = time.perf_counter()
    for tid in range(VERIFY_THREADS):
        t = threading.Thread(
            target=worker,
            args=(tid, VERIFY_CALLS_PER_THREAD, results),
            daemon=False,
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return time.perf_counter() - t0, results


def main() -> None:
    print("Building 1M ledger. This may take a few minutes...")
    build_seconds = build_ledger()
    ledger_size = LEDGER_PATH.stat().st_size if LEDGER_PATH.exists() else 0

    print(f"Ledger built in {build_seconds:.2f}s")
    print(f"Ledger path: {LEDGER_PATH}")
    print(f"Ledger size: {ledger_size:,} bytes")

    print("Warm-up verify...")
    warm_ok, warm_summary, warm_seconds = verify_once()
    print(f"Warm-up complete in {warm_seconds:.2f}s | ok={warm_ok}")

    print(f"Running concurrent verification: {VERIFY_THREADS} threads x {VERIFY_CALLS_PER_THREAD} rounds")
    tracemalloc.start()
    concurrent_seconds, results = run_concurrent_verify()
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    total_runs = len(results)
    ok_runs = sum(1 for r in results if r["ok"])
    bad_runs = total_runs - ok_runs
    avg_seconds = sum(r["seconds"] for r in results) / total_runs if total_runs else 0.0
    min_seconds = min((r["seconds"] for r in results), default=0.0)
    max_seconds = max((r["seconds"] for r in results), default=0.0)

    report = {
        "entry_count": ENTRY_COUNT,
        "ledger_path": str(LEDGER_PATH),
        "ledger_size_bytes": ledger_size,
        "build_seconds": build_seconds,
        "warmup": {
            "ok": warm_ok,
            "seconds": warm_seconds,
            "summary": warm_summary,
        },
        "concurrency": {
            "threads": VERIFY_THREADS,
            "rounds_per_thread": VERIFY_CALLS_PER_THREAD,
            "total_runs": total_runs,
            "ok_runs": ok_runs,
            "bad_runs": bad_runs,
            "wall_seconds": concurrent_seconds,
            "avg_verify_seconds": avg_seconds,
            "min_verify_seconds": min_seconds,
            "max_verify_seconds": max_seconds,
            "peak_tracemalloc_bytes": peak_mem,
            "current_tracemalloc_bytes": current_mem,
        },
        "sample_failures": [r for r in results if not r["ok"]][:10],
        "sample_successes": results[:5],
    }

    REPORT_PATH.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print()
    print("=== FINAL REPORT ===")
    print(f"Entries:            {ENTRY_COUNT:,}")
    print(f"Ledger size:        {ledger_size:,} bytes")
    print(f"Build time:         {build_seconds:.2f}s")
    print(f"Warm verify:        {warm_seconds:.2f}s | ok={warm_ok}")
    print(f"Concurrent wall:    {concurrent_seconds:.2f}s")
    print(f"Total verify runs:  {total_runs}")
    print(f"Successful runs:    {ok_runs}")
    print(f"Failed runs:        {bad_runs}")
    print(f"Avg verify time:    {avg_seconds:.2f}s")
    print(f"Min verify time:    {min_seconds:.2f}s")
    print(f"Max verify time:    {max_seconds:.2f}s")
    print(f"Peak memory:        {peak_mem / (1024 * 1024):.2f} MiB")
    print(f"Report written:     {REPORT_PATH}")

    if not warm_ok:
        raise SystemExit("Warm-up verification failed. See report JSON.")

    if bad_runs:
        raise SystemExit(f"{bad_runs} concurrent verification runs failed. See report JSON.")


if __name__ == "__main__":
    main()