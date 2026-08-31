"""
tests/test_verification.py
"""

import json
import uuid
import secrets
from guardclaw import ExecutionEnvelope, Ed25519KeyManager, RecordType

def create_valid_signed_env():
    km = Ed25519KeyManager.generate()
    sess_id = str(uuid.uuid4())
    env = ExecutionEnvelope(
        gef_version="1.0",
        record_id=str(uuid.uuid4()),
        record_type=RecordType.INTENT,
        agent_id="agent-001",
        session_id=sess_id,
        signer_public_key=km.public_key_hex,
        sequence=0,
        nonce=secrets.token_hex(16),
        timestamp="2026-04-06T00:00:00.000Z",
        causal_hash="0" * 64,
        payload={"action": "test_operation", "amount": 100},
    )
    env.sign(km)
    return env, km

def test_f3_signature_tamper():
    env, km = create_valid_signed_env()
    # verify original
    ok, _ = env.verify_signature()
    assert ok is True
    # tamper
    env.payload["amount"] = 999
    ok, reason = env.verify_signature()
    assert ok is False
    assert reason == "mismatch"

def test_f7_invalid_pubkey():
    env, km = create_valid_signed_env()
    # Verify with different key
    km2 = Ed25519KeyManager.generate()
    ok, reason = env.verify_signature(override_public_key_hex=km2.public_key_hex)
    assert ok is False
    assert reason == "mismatch"

def test_empty_signature():
    env, km = create_valid_signed_env()
    env.signature = ""
    ok, reason = env.verify_signature()
    assert ok is False
    assert reason == "encoding"
