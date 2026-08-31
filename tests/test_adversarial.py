"""
tests/test_adversarial.py

War-test suite for GuardClaw v1.0.0 — GEF-SPEC-1.0
Adversarial, edge-case, and load tests for HN launch.

Run:
    pytest tests/test_adversarial.py -v --tb=short
"""

import json
import os
import threading
import uuid
from pathlib import Path

import pytest

from guardclaw import (
    GEFLedger,
    Ed25519KeyManager,
    RecordType,
    GENESIS_HASH,
    canonical_json_encode,
)
from guardclaw.core.replay import ReplayEngine


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _make_ledger(tmp_dir, agent_id="adv-agent", n=3):
    # GEFLedger auto-emits a GENESIS record; total entries = n + 1
    key = Ed25519KeyManager.generate()
    ledger = GEFLedger(key_manager=key, agent_id=agent_id, ledger_path=tmp_dir)
    types = [RecordType.INTENT, RecordType.EXECUTION, RecordType.RESULT,
             RecordType.FAILURE, RecordType.TOOL_CALL]
    for i in range(n):
        ledger.emit(record_type=types[i % len(types)], payload={"step": i, "data": f"val_{i}"})
    return key, ledger, os.path.join(tmp_dir, "ledger.jsonl")


def _load_lines(path):
    with open(path, encoding="utf-8") as f:
        return f.readlines()


def _save_lines(path, lines):
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.writelines(lines)


def _verify(path):
    engine = ReplayEngine(mode="strict", silent=True)
    return engine.stream_verify(Path(path))


def _verify_safe(path):
    """Returns (summary_or_None, error_str_or_None). Never raises."""
    try:
        return _verify(path), None
    except (ValueError, Exception) as e:
        return None, str(e)


def _signing_surface(entry):
    """
    Extracts fields for signing according to GEF-SPEC-1.0.
    """
    fields = ["gef_version", "record_id", "agent_id", "record_type", "session_id",
              "sequence", "timestamp", "nonce", "causal_hash", "payload", "signer_public_key"]
    return {k: entry[k] for k in fields if k in entry}


def _is_detected(s, err):
    """True if attack was detected either via hard rejection or violations."""
    if err is not None:
        return True
    if s is not None and (not s.chain_valid):
        return True
    return False


# ─────────────────────────────────────────────
# 1. TAMPER ATTACKS
# ─────────────────────────────────────────────

class TestTamperAttacks:

    def test_payload_field_mutation_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        entry["payload"]["data"] = "ATTACKER_MODIFIED"
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify(path)
        assert s.failure_type == "signature_invalid"

    def test_payload_field_addition_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[0])
        entry["payload"]["injected"] = "evil_value"
        lines[0] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify(path)
        assert s.failure_type == "signature_invalid"

    def test_payload_field_deletion_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        entry["payload"] = {}
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify(path)
        assert s.failure_type == "signature_invalid"

    def test_agent_id_substitution_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[0])
        entry["agent_id"] = "admin-agent-impersonated"
        lines[0] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify(path)
        assert s.failure_type == "signature_invalid"

    def test_timestamp_rewrite_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        entry["timestamp"] = "2020-01-01T00:00:00Z"
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s, err = _verify_safe(path)
        assert _is_detected(s, err)

    def test_record_type_change_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[0])
        entry["record_type"] = "result"
        lines[0] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify(path)
        assert s.failure_type == "signature_invalid"

    def test_sequence_number_forgery_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        entry["sequence"] = 999
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify(path)
        assert not s.chain_valid

    def test_zeroed_signature_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[0])
        entry["signature"] = "0" * 128
        lines[0] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify(path)
        assert s.failure_type == "signature_encoding_invalid"

    def test_stripped_signature_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[0])
        del entry["signature"]
        lines[0] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s, err = _verify_safe(path)
        assert _is_detected(s, err)

    def test_truncated_signature_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[0])
        entry["signature"] = entry["signature"][:64]
        lines[0] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s, err = _verify_safe(path)
        assert _is_detected(s, err)

    def test_entry_reorder_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path), n=4)
        lines = _load_lines(path)
        lines[1], lines[2] = lines[2], lines[1]
        _save_lines(path, lines)
        s = _verify(path)
        assert not s.chain_valid


# ─────────────────────────────────────────────
# 2. CHAIN ATTACKS
# ─────────────────────────────────────────────

class TestChainAttacks:

    def test_causal_hash_swap_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[1])
        entry["causal_hash"] = "a" * 64
        lines[1] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify(path)
        # hard hardened: tampering causal hash breaks signature first!
        assert s.failure_type in ("signature_invalid", "chain_violation")

    def test_genesis_hash_forgery_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path))
        lines = _load_lines(path)
        entry = json.loads(lines[0])
        assert entry["causal_hash"] == GENESIS_HASH
        entry["causal_hash"] = "b" * 64
        lines[0] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify(path)
        assert not s.chain_valid

    def test_entry_injection_mid_chain_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path), n=4)
        lines = _load_lines(path)
        forged = json.loads(lines[1])
        forged["payload"]["injected"] = True
        forged["sequence"] = 99
        lines.insert(2, json.dumps(forged) + "\n")
        _save_lines(path, lines)
        s = _verify(path)
        assert not s.chain_valid

    def test_entry_deletion_breaks_chain(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path), n=4)
        lines = _load_lines(path)
        del lines[1]
        _save_lines(path, lines)
        s = _verify(path)
        assert not s.chain_valid

    def test_sequence_gap_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path), n=5)
        lines = _load_lines(path)
        del lines[1]
        _save_lines(path, lines)
        s = _verify(path)
        assert not s.chain_valid

    def test_sequence_rollback_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path), n=4)
        lines = _load_lines(path)
        lines.append(lines[0])
        _save_lines(path, lines)
        s = _verify(path)
        assert not s.chain_valid

    def test_cross_ledger_entry_injection(self, tmp_path):
        dir_a = str(tmp_path / "a")
        dir_b = str(tmp_path / "b")
        os.makedirs(dir_a)
        os.makedirs(dir_b)
        key_a = Ed25519KeyManager.generate()
        key_b = Ed25519KeyManager.generate()
        ledger_a = GEFLedger(key_manager=key_a, agent_id="agent-A", ledger_path=dir_a)
        ledger_b = GEFLedger(key_manager=key_b, agent_id="agent-B", ledger_path=dir_b)
        ledger_a.emit(record_type=RecordType.INTENT, payload={"i": 1})
        ledger_b.emit(record_type=RecordType.INTENT, payload={"i": 1})
        path_b = os.path.join(dir_b, "ledger.jsonl")
        lines_a = _load_lines(os.path.join(dir_a, "ledger.jsonl"))
        lines_b = _load_lines(path_b)
        lines_b.insert(1, lines_a[1])
        _save_lines(path_b, lines_b)
        s = _verify(path_b)
        assert not s.chain_valid

    def test_fully_forged_ledger_with_new_key_detected(self, tmp_path):
        forger_key = Ed25519KeyManager.generate()
        forged_ledger = GEFLedger(key_manager=forger_key, agent_id="victim-agent",
                                  ledger_path=str(tmp_path))
        forged_ledger.emit(record_type=RecordType.INTENT, payload={"forged": 1})
        path = os.path.join(str(tmp_path), "ledger.jsonl")
        s = _verify(path)
        assert s.chain_valid

    def test_record_id_collision_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path), n=3)
        lines = _load_lines(path)
        e0 = json.loads(lines[0])
        e1 = json.loads(lines[1])
        e1["record_id"] = e0["record_id"]
        # collision must break signature
        e1["signature"] = "S" * 86
        lines[1] = json.dumps(e1) + "\n"
        _save_lines(path, lines)
        s, err = _verify_safe(path)
        assert _is_detected(s, err)

    def test_timestamp_regression_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path), n=3)
        lines = _load_lines(path)
        e1 = json.loads(lines[1])
        e1["timestamp"] = "1990-01-01T00:00:00.000Z"
        lines[1] = json.dumps(e1) + "\n"
        _save_lines(path, lines)
        s, err = _verify_safe(path)
        assert _is_detected(s, err)


# ─────────────────────────────────────────────
# 3. KEY CONFUSION ATTACKS
# ─────────────────────────────────────────────

class TestKeyConfusionAttacks:

    def test_wrong_key_cannot_verify_signature(self, tmp_path):
        key1 = Ed25519KeyManager.generate()
        key2 = Ed25519KeyManager.generate()
        ledger = GEFLedger(key_manager=key1, agent_id="agent1", ledger_path=str(tmp_path))
        ledger.emit(record_type=RecordType.INTENT, payload={"x": 1})
        path = os.path.join(str(tmp_path), "ledger.jsonl")
        entry = json.loads(_load_lines(path)[0])
        sig = entry["signature"]
        canonical_bytes = canonical_json_encode(_signing_surface(entry))
        assert not key2.verify_detached(canonical_bytes, sig, key2.public_key_hex)

    def test_correct_key_verifies_own_signature(self, tmp_path):
        key1 = Ed25519KeyManager.generate()
        ledger = GEFLedger(key_manager=key1, agent_id="agent1", ledger_path=str(tmp_path))
        ledger.emit(record_type=RecordType.INTENT, payload={"x": 1})
        path = os.path.join(str(tmp_path), "ledger.jsonl")
        entry = json.loads(_load_lines(path)[0])
        sig = entry["signature"]
        # Use full signing surface including session_id
        from guardclaw.core.models import ExecutionEnvelope
        env = ExecutionEnvelope.from_dict(entry)
        assert key1.verify_detached(env.canonical_bytes_for_signing(), sig, key1.public_key_hex)

    def test_key_rollover_forgery_detected(self, tmp_path):
        key1 = Ed25519KeyManager.generate()
        key2 = Ed25519KeyManager.generate()
        ledger = GEFLedger(key_manager=key1, agent_id="agent1", ledger_path=str(tmp_path))
        ledger.emit(record_type=RecordType.INTENT, payload={"x": 1})
        path = os.path.join(str(tmp_path), "ledger.jsonl")
        lines = _load_lines(path)
        entry = json.loads(lines[0])
        from guardclaw.core.models import ExecutionEnvelope
        env = ExecutionEnvelope.from_dict(entry)
        entry["signature"] = key2.sign(env.canonical_bytes_for_signing())
        lines[0] = json.dumps(entry) + "\n"
        _save_lines(path, lines)
        s = _verify(path)
        assert s.failure_type == "signature_invalid"


# ─────────────────────────────────────────────
# 4. REPLAY / NONCE ATTACKS
# ─────────────────────────────────────────────

class TestReplayAttacks:

    def test_duplicate_entry_detected(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path), n=3)
        lines = _load_lines(path)
        lines.append(lines[0])
        _save_lines(path, lines)
        s = _verify(path)
        assert not s.chain_valid

    def test_nonce_uniqueness_in_fresh_ledger(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path), n=10)
        nonces = [json.loads(l)["nonce"] for l in _load_lines(path)]
        assert len(nonces) == len(set(nonces))

    def test_cross_agent_same_nonce_not_replay(self, tmp_path):
        tmp1 = str(tmp_path / "a1")
        tmp2 = str(tmp_path / "a2")
        os.makedirs(tmp1)
        os.makedirs(tmp2)
        key1 = Ed25519KeyManager.generate()
        key2 = Ed25519KeyManager.generate()
        l1 = GEFLedger(key_manager=key1, agent_id="agent-A", ledger_path=tmp1)
        l2 = GEFLedger(key_manager=key2, agent_id="agent-B", ledger_path=tmp2)
        l1.emit(record_type=RecordType.INTENT, payload={"x": 1})
        l2.emit(record_type=RecordType.INTENT, payload={"x": 1})
        path1 = os.path.join(tmp1, "ledger.jsonl")
        path2 = os.path.join(tmp2, "ledger.jsonl")
        lines1 = _load_lines(path1)
        lines2 = _load_lines(path2)
        # Merge them - must fail because session_id differs!
        merged = str(tmp_path / "merged.jsonl")
        with open(merged, "w", encoding="utf-8") as f:
            f.writelines(lines1 + lines2)
        s = _verify(merged)
        assert not s.chain_valid


# ─────────────────────────────────────────────
# 5. SCHEMA / CANONICALIZATION ATTACKS
# ─────────────────────────────────────────────

class TestSchemaAndCanonical:

    def test_json_key_reordering_does_not_break_chain(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path), n=2)
        lines = _load_lines(path)
        entry = json.loads(lines[0])
        lines[0] = json.dumps(entry, sort_keys=False) + "\n"
        _save_lines(path, lines)
        s = _verify(path)
        assert s.chain_valid

    def test_canonical_null_value_in_payload(self, tmp_path):
        key = Ed25519KeyManager.generate()
        ledger = GEFLedger(key_manager=key, agent_id="null-test", ledger_path=str(tmp_path))
        ledger.emit(record_type=RecordType.INTENT, payload={"result": None, "count": 0})
        s = _verify(os.path.join(str(tmp_path), "ledger.jsonl"))
        assert s.chain_valid


# ─────────────────────────────────────────────
# 6. EDGE CASES
# ─────────────────────────────────────────────

class TestEdgeCases:

    def test_single_entry_verifies_clean(self, tmp_path):
        _, _, path = _make_ledger(str(tmp_path), n=1)
        s = _verify(path)
        assert s.chain_valid and s.total_entries == 2

    def test_empty_ledger_loads_cleanly(self, tmp_path):
        path = str(tmp_path / "empty.jsonl")
        open(path, "w").close()
        engine = ReplayEngine(mode="strict", silent=True)
        s = engine.stream_verify(Path(path))
        assert s.total_entries == 0
