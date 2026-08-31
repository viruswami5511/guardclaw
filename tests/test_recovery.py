"""
tests/test_recovery.py

Refactored for Hardened ReplayEngine v1.0.0
"""

import json
import os
import uuid
import pytest
from pathlib import Path

from guardclaw import ExecutionEnvelope, Ed25519KeyManager, RecordType, GENESIS_HASH
from guardclaw.core.replay import ReplayEngine
from guardclaw.core.failure import FailureType, FailureDetail, VerificationSummary, ProtocolInvariantError

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _make_key():
    return Ed25519KeyManager.generate()

def _make_chain(key, count=5, agent_id="test-agent", start_record_type=RecordType.GENESIS):
    chain = []
    prev = None
    sess_id = str(uuid.uuid4())
    for i in range(count):
        rtype = start_record_type if i == 0 else RecordType.EXECUTION
        env = ExecutionEnvelope.create(
            record_type=rtype,
            agent_id=agent_id,
            session_id=sess_id,
            signer_public_key=key.public_key_hex,
            sequence=i,
            payload={"step": i},
            prev=prev,
        ).sign(key)
        chain.append(env)
        prev = env
    return chain

def _write_ledger(path, chain):
    with open(path, "w", encoding="utf-8") as f:
        for env in chain:
            f.write(json.dumps(env.to_dict(), separators=(",", ":")) + "\n")

# ─────────────────────────────────────────────
# Tests
# ─────────────────────────────────────────────

class TestPreFlight:
    def test_invariant_2(self):
        with pytest.raises(ProtocolInvariantError, match="requires failure_type"):
            VerificationSummary(total_entries=0, chain_valid=False)

    def test_invariant_3(self):
        with pytest.raises(ProtocolInvariantError, match="cannot have an integrity_boundary_hash"):
            VerificationSummary(
                total_entries=0,
                chain_valid=False,
                failure_type=FailureType.LEDGER_INVALID,
                failure_detail=FailureDetail.FILE_NOT_FOUND,
                integrity_boundary_hash="a" * 64,
            )

class TestGenesisEnforcement:
    def test_valid_genesis_first_entry_passes(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=5)
        path = tmp_path / "ledger.jsonl"
        _write_ledger(path, chain)
        s = ReplayEngine(mode="strict").stream_verify(path)
        assert s.chain_valid

    def test_non_genesis_first_entry_strict(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=3, start_record_type=RecordType.EXECUTION)
        path = tmp_path / "bad_start.jsonl"
        _write_ledger(path, chain)
        s = ReplayEngine(mode="strict").stream_verify(path)
        assert s.failure_detail == FailureDetail.GENESIS_MISSING

class TestTotalEntriesCorrectness:
    def test_total_entries_valid_chain(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=20)
        path = tmp_path / "valid.jsonl"
        _write_ledger(path, chain)
        s = ReplayEngine(mode="strict").stream_verify(path)
        assert s.total_entries == 20

class TestRecoveryModeActive:
    def test_recovery_mode_active_on_failure(self, tmp_path):
        key = _make_key()
        chain = _make_chain(key, count=5)
        path = tmp_path / "fail.jsonl"
        _write_ledger(path, chain)
        with open(path, "a") as f: f.write("invalid json\n")
        s = ReplayEngine(mode="recovery").stream_verify(path)
        assert s.recovery_mode_active is True
        assert s.chain_valid is False
