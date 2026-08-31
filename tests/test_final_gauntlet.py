"""
tests/test_final_gauntlet.py
LOCKED v1.0.2 - Final Protocol Gauntlet (Architectural Fix)
"""

import json
import multiprocessing
import os
import uuid
from pathlib import Path

import pytest

from guardclaw.core.crypto import Ed25519KeyManager
from guardclaw.core.failure import FailureType, FailureDetail
from guardclaw.core.ledger import GEFLedger
from guardclaw.core.models import ExecutionEnvelope, RecordType, GENESIS_HASH
from guardclaw.core.replay import ReplayEngine

# ─────────────────────────────────────────────
# GAUNTLET HELPERS
# ─────────────────────────────────────────────

def _get_tools(tmp_path):
    key = Ed25519KeyManager.generate()
    ledger_path = tmp_path / "gauntlet.jsonl"
    return key, ledger_path

def _verify(path, mode="strict"):
    return ReplayEngine(mode=mode, silent=True).stream_verify(Path(path))

def _make_env(key, seq, prev=None, sess_id=None, rtype=RecordType.EXECUTION, payload=None):
    if sess_id is None:
        sess_id = str(uuid.uuid4())
    env = ExecutionEnvelope.create(
        record_type=rtype,
        agent_id="gauntlet-agent",
        session_id=sess_id,
        signer_public_key=key.public_key_hex,
        sequence=seq,
        payload=payload or {"step": seq},
        prev=prev
    )
    env.sign(key)
    return env

# ─────────────────────────────────────────────
# 1. STRUCTURAL & SCHEMA ATTACKS
# ─────────────────────────────────────────────

def test_reject_unknown_fields_strict(tmp_path):
    key, path = _get_tools(tmp_path)
    env = _make_env(key, 0, rtype=RecordType.GENESIS)
    d = env.to_dict()
    d["evil_extension"] = "unsigned_data"
    path.write_text(json.dumps(d) + "\n")
    summary = _verify(path)
    assert summary.chain_valid is False
    assert summary.failure_detail == "unknown_fields"

def test_non_dict_json_rejected(tmp_path):
    _, path = _get_tools(tmp_path)
    path.write_text("[1, 2, 3]\n")
    summary = _verify(path)
    assert summary.chain_valid is False
    assert summary.failure_type in (FailureType.MALFORMED_JSON, FailureType.SCHEMA_VIOLATION)

def test_payload_size_limit(tmp_path):
    key, path = _get_tools(tmp_path)
    # 1MB limit check
    payload = {"data": "x" * (1024 * 1024)}
    env = _make_env(key, 0, rtype=RecordType.GENESIS, payload=payload)
    path.write_text(json.dumps(env.to_dict()) + "\n")
    summary = _verify(path)
    assert summary.failure_detail == FailureDetail.RECORD_TOO_LARGE

def test_signature_with_padding_rejected(tmp_path):
    key, path = _get_tools(tmp_path)
    env = _make_env(key, 0, rtype=RecordType.GENESIS)
    d = env.to_dict()
    d["signature"] += "="
    path.write_text(json.dumps(d) + "\n")
    summary = _verify(path)
    assert summary.failure_type == FailureType.SIGNATURE_ENCODING_INVALID

# ─────────────────────────────────────────────
# 2. CRYPTOGRAPHIC & BINDING ATTACKS
# ─────────────────────────────────────────────

def test_cross_session_replay(tmp_path):
    key, path = _get_tools(tmp_path)
    env = _make_env(key, 0, rtype=RecordType.GENESIS)
    d = env.to_dict()
    d["session_id"] = str(uuid.uuid4())
    path.write_text(json.dumps(d) + "\n")
    summary = _verify(path)
    assert summary.chain_valid is False
    assert summary.failure_type == FailureType.SIGNATURE_INVALID

def test_unicode_normalization_attack(tmp_path):
    key, _ = _get_tools(tmp_path)
    payload1 = {"text": "café"}       
    payload2 = {"text": "cafe\u0301"} 
    env1 = _make_env(key, 0, payload=payload1)
    env2 = _make_env(key, 0, payload=payload2)
    assert env1.signature != env2.signature

# ─────────────────────────────────────────────
# 3. CHAIN & STATE ATTACKS
# ─────────────────────────────────────────────

def test_no_records_after_interrupted(tmp_path):
    key, path = _get_tools(tmp_path)
    sess_id = str(uuid.uuid4()) 
    g = _make_env(key, 0, rtype=RecordType.GENESIS, sess_id=sess_id)
    i = _make_env(key, 1, prev=g, rtype=RecordType.INTERRUPTED, sess_id=sess_id)
    e = _make_env(key, 2, prev=i, sess_id=sess_id)
    with open(path, "w") as f:
        for x in [g, i, e]: f.write(json.dumps(x.to_dict()) + "\n")
    summary = _verify(path)
    assert summary.failure_detail == FailureDetail.POST_INTERRUPTED_RECORD

def test_session_id_mutation_mid_chain(tmp_path):
    key, path = _get_tools(tmp_path)
    g = _make_env(key, 0, rtype=RecordType.GENESIS)
    sess_id = g.session_id
    e1 = _make_env(key, 1, prev=g, sess_id=sess_id)
    e2 = _make_env(key, 2, prev=e1, sess_id=str(uuid.uuid4()))
    with open(path, "w") as f:
        for x in [g, e1, e2]: f.write(json.dumps(x.to_dict()) + "\n")
    summary = _verify(path)
    assert summary.failure_detail == FailureDetail.SESSION_ID_MISMATCH

# ─────────────────────────────────────────────
# 4. DISTRIBUTED & RACE CONDITIONS
# ─────────────────────────────────────────────

def _gauntlet_writer_proc(ledger_dir, agent_id, count, raw_bytes: bytes):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from guardclaw.core.crypto import Ed25519KeyManager
    from guardclaw.core.ledger import GEFLedger
    from guardclaw.core.models import RecordType
    private_key_obj = Ed25519PrivateKey.from_private_bytes(raw_bytes)
    key = Ed25519KeyManager.from_private_bytes(private_key_obj)
    ledger = GEFLedger(key_manager=key, agent_id=agent_id, ledger_path=ledger_dir)
    for i in range(count):
        ledger.emit(RecordType.EXECUTION, {"p": i})


def test_multi_process_same_file_lock(tmp_path):
    key = Ed25519KeyManager.generate()
    ledger_dir = str(tmp_path)
    count_per_proc = 5
    num_procs = 3

    raw_bytes = key.private_bytes_raw()

    procs = [
        multiprocessing.Process(
            target=_gauntlet_writer_proc,
            args=(ledger_dir, f"agent-{i}", count_per_proc, raw_bytes)
        ) for i in range(num_procs)
    ]
    for p in procs: p.start()
    for p in procs: p.join()

    ledger_file = tmp_path / "ledger.jsonl"
    summary = _verify(ledger_file)
    assert summary.chain_valid is True
    assert summary.total_entries == (num_procs * count_per_proc) + 1
# ─────────────────────────────────────────────
# 5. RECOVERY & PARTIAL INTEGRITY
# ─────────────────────────────────────────────

def test_partial_write_recovery(tmp_path):
    key, path = _get_tools(tmp_path)
    g = _make_env(key, 0, rtype=RecordType.GENESIS)
    e1 = _make_env(key, 1, prev=g)
    with open(path, "w") as f:
        f.write(json.dumps(g.to_dict()) + "\n")
        f.write(json.dumps(e1.to_dict())[:50])
    summary = _verify(path, mode="recovery")
    assert summary.verification_level == "PARTIALLY_VALID"
    assert summary.verified_count == 1
