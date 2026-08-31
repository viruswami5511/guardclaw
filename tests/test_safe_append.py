"""
tests/test_safe_append.py

Safe Append + Recovery Tests for GEFLedger.
"""

import json
import os
import threading
from pathlib import Path

import pytest

from guardclaw import GEFLedger, Ed25519KeyManager, RecordType
from guardclaw.core.replay import ReplayEngine


def _verify(path):
    engine = ReplayEngine(mode="strict", silent=True)
    return engine.stream_verify(Path(path))


def _make(tmp_path, n=5, mode="strict", key=None):
    if key is None:
        key = Ed25519KeyManager.generate()
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
        _, _, path = _make(tmp_path, n=10)
        s = _verify(path)
        assert s.total_entries == 11
        assert s.chain_valid

    def test_crash_recovery_strips_incomplete_line(self, tmp_path):
        """Simulate a mid-write crash by appending a partial JSON line."""
        # 1. Create initial ledger
        key, _, path = _make(tmp_path, n=5)
        
        # 2. Simulate crash: append garbage without a trailing newline
        with open(path, "ab") as f:
            f.write(b'{"gef_version":"1.0","record_id":"gef-corrupt')

        # 3. Re-open ledger using SAME KEY (to pass signer_mismatch check)
        ledger = GEFLedger(
            key_manager=key,
            agent_id="test-agent",
            ledger_path=str(tmp_path),
            mode="strict",
        )
        
        # 4. Write one more entry
        ledger.emit(record_type=RecordType.EXECUTION, payload={"after": "crash"})
        ledger.close()

        # 5. Verify: 6 original valid (genesis+5) + 1 post-recovery = 7
        s = _verify(path)
        assert s.total_entries == 7
        assert s.chain_valid

    def test_ghost_mode_no_disk_write(self, tmp_path):
        key = Ed25519KeyManager.generate()
        ledger = GEFLedger(key_manager=key, agent_id="ghost-agent", mode="ghost")
        for i in range(5):
            ledger.emit(record_type=RecordType.EXECUTION, payload={"i": i})
        assert len(ledger.entries) == 5
        assert not (tmp_path / GEFLedger.LEDGER_FILENAME).exists()

    def test_chain_resumes_after_reopen(self, tmp_path):
        key, _, path = _make(tmp_path, n=5)
        ledger2 = GEFLedger(key_manager=key, agent_id="test-agent", ledger_path=str(tmp_path), mode="strict")
        for i in range(5):
            ledger2.emit(record_type=RecordType.EXECUTION, payload={"batch": 2, "i": i})
        ledger2.close()
        s = _verify(path)
        assert s.total_entries == 11
        assert s.chain_valid

    def test_empty_file_recovery(self, tmp_path):
        path = tmp_path / GEFLedger.LEDGER_FILENAME
        path.write_bytes(b"")
        key = Ed25519KeyManager.generate()
        ledger = GEFLedger(key_manager=key, agent_id="test-agent", ledger_path=str(tmp_path), mode="strict")
        ledger.emit(record_type=RecordType.EXECUTION, payload={})
        ledger.close()
        s = _verify(str(path))
        assert s.total_entries == 2
        assert s.chain_valid
