"""
tests/test_concurrency.py

Concurrency safety test for GEFLedger.
Tests that simultaneous writes from multiple threads do not corrupt the ledger file.

Run:
    pytest tests/test_concurrency.py -v --tb=short
"""

import os
import threading

import pytest

from guardclaw import GEFLedger, Ed25519KeyManager, RecordType
from guardclaw.core.replay import ReplayEngine


def _verify(path):
    e = ReplayEngine(parallel=False, silent=True)
    e.load(path)
    return e.verify()


class TestConcurrency:

    def test_concurrent_writes_no_corruption(self, tmp_path):
        """Two threads writing simultaneously must not corrupt the ledger file."""
        key = Ed25519KeyManager.generate()
        ledger = GEFLedger(
            key_manager=key,
            agent_id="concurrent",
            ledger_path=str(tmp_path),
        )
        errors = []

        def write_10():
            try:
                for i in range(10):
                    ledger.emit(
                        record_type=RecordType.EXECUTION,
                        payload={"i": i},
                    )
            except Exception as e:
                errors.append(str(e))

        t1 = threading.Thread(target=write_10)
        t2 = threading.Thread(target=write_10)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Step 1 — no exceptions during concurrent writes
        assert errors == [], f"Concurrent writes raised exceptions: {errors}"

        # Step 2 — ledger file must exist and be readable
        path = os.path.join(str(tmp_path), "ledger.jsonl")
        assert os.path.exists(path), "Ledger file must exist after concurrent writes"

        # Step 3 — file must be parseable (not half-written lines)
        try:
            s = _verify(path)
        except Exception as e:
            pytest.fail(
                f"Concurrent writes corrupted ledger beyond readability: {e}"
            )

        # Step 4 — report what we got (chain violations are EXPECTED and acceptable)
        print(f"\n  Total entries written : {s.total_entries}")
        print(f"  Chain valid           : {s.chain_valid}")
        print(f"  Violations            : {len(s.violations)}")
        print(f"  Valid signatures      : {s.valid_signatures}")
        print(f"  Invalid signatures    : {s.invalid_signatures}")

        # Step 5 — THE real test: all 20 entries must have been written
        assert s.total_entries == 20, (
            f"Expected 20 entries (10 per thread), got {s.total_entries}. "
            f"Entries were lost — likely a race condition in emit()."
        )
