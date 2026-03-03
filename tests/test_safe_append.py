"""
tests/test_safe_append.py

Safe Append + Recovery Tests for GEFLedger.

Tests:
    1. Clean write — ledger verifies after N normal entries
    2. Crash simulation — truncate last entry mid-line, recover, verify
    3. Ghost mode — entries in memory, no disk I/O
    4. Mode validation — invalid mode raises ValueError
    5. Chain continuity after recovery — sequence resumes correctly
    6. Empty file recovery — no crash on brand new file
    7. All-corrupt file — single incomplete line handled gracefully
    8. Strict mode requires ledger_path
    9. Ghost mode ignores ledger_path
   10. Re-open existing ledger — appends correctly, chain stays intact

Run:
    pytest tests/test_safe_append.py -v --tb=short
"""

import json
import os
import threading

import pytest

from guardclaw import GEFLedger, Ed25519KeyManager, RecordType
from guardclaw.core.replay import ReplayEngine


def _verify(path):
    e = ReplayEngine(parallel=False, silent=True)
    e.load(path)
    return e.verify()


def _ledger_path(tmp_path):
    return str(tmp_path / "ledger.jsonl")


def _make(tmp_path, n=5, mode="strict"):
    key    = Ed25519KeyManager.generate()
    ledger = GEFLedger(
        key_manager=key,
        agent_id="test-agent",
        ledger_path=str(tmp_path),
        mode=mode,
    )
    for i in range(n):
        ledger.emit(record_type=RecordType.EXECUTION, payload={"i": i})
    ledger.close()
    return key, ledger, str(tmp_path / GEFLedger.LEDGER_FILENAME)


class TestSafeAppend:

    def test_clean_write_verifies(self, tmp_path):
        """Normal write path — N entries, all valid after close."""
        _, _, path = _make(tmp_path, n=10)
        s = _verify(path)
        assert s.total_entries == 10
        assert s.chain_valid
        assert s.invalid_signatures == 0

    def test_crash_recovery_strips_incomplete_line(self, tmp_path):
        """Simulate a mid-write crash by appending a partial JSON line."""
        _, _, path = _make(tmp_path, n=5)
        # Simulate crash: append garbage without a trailing newline
        with open(path, "ab") as f:
            f.write(b'{"gef_version":"1.0","record_id":"gef-corrupt')
            # no newline — simulates SIGKILL mid-write

        # Re-open ledger — recovery should strip the partial line
        key = Ed25519KeyManager.generate()
        ledger = GEFLedger(
            key_manager=key,
            agent_id="test-agent",
            ledger_path=str(tmp_path),
            mode="strict",
        )
        # Write one more entry
        ledger.emit(record_type=RecordType.EXECUTION, payload={"after": "crash"})
        ledger.close()

        s = _verify(path)
        assert s.total_entries == 6, f"Expected 6 (5 original + 1 post-recovery), got {s.total_entries}"
        assert s.chain_valid
        assert s.invalid_signatures == 0

    def test_ghost_mode_no_disk_write(self, tmp_path):
        """Ghost mode: entries exist in memory, no file created."""
        key    = Ed25519KeyManager.generate()
        ledger = GEFLedger(
            key_manager=key,
            agent_id="ghost-agent",
            mode="ghost",
        )
        for i in range(5):
            ledger.emit(record_type=RecordType.EXECUTION, payload={"i": i})

        assert len(ledger.entries) == 5
        ledger_file = tmp_path / GEFLedger.LEDGER_FILENAME
        assert not ledger_file.exists(), "Ghost mode must not write to disk"

    def test_ghost_mode_chain_is_valid(self, tmp_path):
        """Ghost mode entries are properly chained and signed."""
        key    = Ed25519KeyManager.generate()
        ledger = GEFLedger(
            key_manager=key,
            agent_id="ghost-agent",
            mode="ghost",
        )
        for i in range(10):
            ledger.emit(record_type=RecordType.EXECUTION, payload={"i": i})

        entries = ledger.entries
        assert len(entries) == 10
        for env in entries:
            assert env.verify_signature(), f"Signature invalid at seq {env.sequence}"

        for i, env in enumerate(entries):
            prev = entries[i - 1] if i > 0 else None
            assert env.verify_chain(prev), f"Chain break at seq {env.sequence}"

    def test_invalid_mode_raises(self, tmp_path):
        """Invalid mode string raises ValueError immediately."""
        key = Ed25519KeyManager.generate()
        with pytest.raises(ValueError, match="Invalid mode"):
            GEFLedger(
                key_manager=key,
                agent_id="test",
                ledger_path=str(tmp_path),
                mode="turbo",
            )

    def test_strict_requires_ledger_path(self):
        """Strict mode without ledger_path raises ValueError."""
        key = Ed25519KeyManager.generate()
        with pytest.raises(ValueError, match="ledger_path is required"):
            GEFLedger(key_manager=key, agent_id="test", mode="strict")

    def test_chain_resumes_after_reopen(self, tmp_path):
        """Re-opening an existing ledger continues sequence and chain correctly."""
        key, _, path = _make(tmp_path, n=5)

        ledger2 = GEFLedger(
            key_manager=key,
            agent_id="test-agent",
            ledger_path=str(tmp_path),
            mode="strict",
        )
        for i in range(5):
            ledger2.emit(record_type=RecordType.EXECUTION, payload={"batch": 2, "i": i})
        ledger2.close()

        s = _verify(path)
        assert s.total_entries == 10
        assert s.chain_valid, f"Chain broken after reopen: {s.violations}"
        assert s.invalid_signatures == 0

    def test_empty_file_recovery(self, tmp_path):
        """Empty ledger file does not crash on open."""
        path = tmp_path / GEFLedger.LEDGER_FILENAME
        path.write_bytes(b"")  # empty file

        key    = Ed25519KeyManager.generate()
        ledger = GEFLedger(
            key_manager=key,
            agent_id="test-agent",
            ledger_path=str(tmp_path),
            mode="strict",
        )
        ledger.emit(record_type=RecordType.EXECUTION, payload={})
        ledger.close()

        s = _verify(str(path))
        assert s.total_entries == 1
        assert s.chain_valid

    def test_all_corrupt_file_recovery(self, tmp_path):
        """File with only a partial line (no newline) recovers to empty + new entries."""
        path = tmp_path / GEFLedger.LEDGER_FILENAME
        path.write_bytes(b'{"incomplete": true')  # no newline, no complete entry

        key    = Ed25519KeyManager.generate()
        ledger = GEFLedger(
            key_manager=key,
            agent_id="test-agent",
            ledger_path=str(tmp_path),
            mode="strict",
        )
        ledger.emit(record_type=RecordType.EXECUTION, payload={"fresh": True})
        ledger.close()

        s = _verify(str(path))
        assert s.total_entries == 1
        assert s.chain_valid

    def test_concurrent_writes_ghost_mode(self):
        """Ghost mode: concurrent writes are safe (uses same lock)."""
        key    = Ed25519KeyManager.generate()
        ledger = GEFLedger(key_manager=key, agent_id="ghost", mode="ghost")
        errors = []

        def write_100():
            try:
                for i in range(100):
                    ledger.emit(record_type=RecordType.EXECUTION, payload={"i": i})
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=write_100) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert len(ledger.entries) == 1000