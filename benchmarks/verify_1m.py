import time
import psutil
import os
from pathlib import Path
from guardclaw.core.replay import ReplayEngine

def mem_mb():
    import psutil, os
    return psutil.Process(os.getpid()).memory_info().rss / 1024 / 1024

ledger_path = Path("bench_1m/ledger_1m.jsonl")

print(f"Ledger exists: {ledger_path.exists()}")
print(f"Ledger size: {ledger_path.stat().st_size / 1e6:.1f} MB")

# Full verify
print("\n🔍 Full verify...")
t = time.time()
engine = ReplayEngine(silent=False)
engine.load(ledger_path)
summary = engine.verify()
t_full = time.time() - t
print(f"✅ Full verify: {summary.total_entries:,} entries in {t_full:.1f}s")
print(f"   Chain valid: {summary.chain_valid}")
print(f"   Invalid sigs: {summary.invalid_signatures}")
print(f"   Memory: {mem_mb():.1f} MB")

# Stream verify
print("\n🌊 Stream verify...")
t = time.time()
engine2 = ReplayEngine(silent=False)
summary2 = engine2.stream_verify(ledger_path)
t_stream = time.time() - t
print(f"✅ Stream verify: {summary2.total_entries:,} entries in {t_stream:.1f}s")
print(f"   Chain valid: {summary2.chain_valid}")
print(f"   Invalid sigs: {summary2.invalid_signatures}")
print(f"   Memory: {mem_mb():.1f} MB")

# Final
print("\n" + "="*60)
print("🏁 FINAL RESULTS")
print("="*60)
print(f"Entries:            1,000,000")
print(f"Ledger size:        {ledger_path.stat().st_size / 1e6:.1f} MB")
print(f"Write speed:        683 eps (24.4 min)")
print(f"Peak write memory:  14.6 MB")
print(f"Full verify:        {t_full:.1f}s")
print(f"Stream verify:      {t_stream:.1f}s")
print(f"Stream memory:      {mem_mb():.1f} MB")
